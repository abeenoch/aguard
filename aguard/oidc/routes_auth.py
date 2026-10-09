"""Authorization endpoint: /authorize -> login -> consent -> single-use code.

THE error-handling rule (the open-redirect kill-switch):

  * invalid client_id / redirect_uri  -> render 400 HTML, NEVER redirect
  * any other parameter problem       -> 302 to the *validated* redirect_uri
                                          with error + state

Get this backwards and an attacker who passes their own redirect_uri with a
victim's request harvests authorization codes — i.e. account takeover. The
rule is enforced structurally: `redirectable` can only become True AFTER the
client and redirect_uri have already passed exact-match validation (see
validate_authorize_params ordering).
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from aguard.oidc.clients import Client, ClientRegistry
from aguard.oidc.codes import AuthCodeStore
from aguard.oidc.pages import consent_form, error_page, login_form
from aguard.oidc.session import create_session_token, parse_session_token
from aguard.oidc.users import USERS, find_by_email, verify_password
from aguard.ratelimit import enforce_rate_limit
from aguard.settings import settings

router = APIRouter()

SESSION_COOKIE = "lab_session"


@dataclass(frozen=True)
class ValidatedAuthRequest:
    client: Client
    redirect_uri: str
    scope: str
    state: str
    code_challenge: str
    code_challenge_method: str
    nonce: str | None
    resource: str | None = None   # RFC 8707: validated aud binding



@dataclass(frozen=True)
class ValidationError:
    error: str          # OAuth error code sent to the client
    description: str
    redirectable: bool  # False => render 400 page; True => 302 with error


def validate_authorize_params(
    registry: ClientRegistry,
    *,
    response_type: str | None,
    client_id: str | None,
    redirect_uri: str | None,
    scope: str | None,
    state: str | None,
    code_challenge: str | None,
    code_challenge_method: str | None,
    nonce: str | None,
    resource: str | None = None,
) -> tuple[ValidatedAuthRequest | None, ValidationError | None]:
    """Shared by GET /authorize and POST /consent.

    ORDER MATTERS. The first two checks are the only non-redirectable ones —
    everything after them may safely 302 because we now know BOTH parties
    (client identity + redirect target) are legitimate.

    Consent re-runs this whole function: hidden form fields are
    attacker-controlled input, validated exactly like the original query.
    """
    client = registry.get(client_id or "")
    if client is None:
        return None, ValidationError(
            "invalid_client", "unknown client_id", redirectable=False
        )
    # Exact match, byte-for-byte — no prefix/wildcard/normalization tricks.
    if not client.redirect_uri_matches(redirect_uri or ""):
        return None, ValidationError(
            "invalid_request",
            "redirect_uri does not exactly match a registered URI",
            redirectable=False,
        )

    # ---- from here on, redirecting is safe ----
    if "authorization_code" not in client.grant_types:
        return None, ValidationError(
            "unauthorized_client", "client may not use authorization_code", True
        )
    if response_type != "code":
        return None, ValidationError(
            "unsupported_response_type", "only response_type=code is supported", True
        )

    # MCP clients are not OIDC clients: `openid` is optional at /authorize
    # (it only gates id_token issuance later at /token), and a client may
    # legitimately omit `scope` entirely — Cline historically did, and strict
    # providers rejecting it was a reported interop failure. RFC 6749 §3.3
    # leaves the omitted-scope default to the AS: we grant the client's own
    # REGISTERED scopes (the most it could ever be given, never more), and the
    # consent screen shows exactly what is being granted. Anything outside the
    # registration is still refused.
    if scope:
        scopes = set(scope.split())
        if not client.allows_scopes(scopes):
            return None, ValidationError(
                "invalid_scope", "requested scope not allowed for this client", True
            )
        granted_scope = " ".join(sorted(scopes))
    else:
        granted_scope = " ".join(sorted(client.allowed_scopes))

    if not state:
        # state is the CSRF binding between request and callback — required,
        # not "recommended": without it, login-CSRF is back.
        return None, ValidationError(
            "invalid_request", "state parameter is required", True
        )

    if not code_challenge or code_challenge_method != "S256":
        # OAuth 2.1: PKCE mandatory for ALL clients, S256 only. `plain`
        # would let an interceptor of the authorize URL redeem the code.
        return None, ValidationError(
            "invalid_request",
            "PKCE with code_challenge_method=S256 is required",
            True,
        )

    # RFC 8707 (resource indicators): the requested aud binding must be on
    # our EXACT-match allowlist. An unvalidated resource param would let a
    # client mint tokens audience-bound to someone else's API — the
    # audience-forgery vector RFC 8707 §2.1 exists to prevent.
    if resource is not None and resource not in settings.allowed_resources:
        return None, ValidationError(
            "invalid_target",
            "resource is not a registered resource of this authorization server",
            True,
        )

    return ValidatedAuthRequest(
        client=client,
        redirect_uri=redirect_uri or "",
        scope=granted_scope,
        state=state or "",
        code_challenge=code_challenge or "",
        code_challenge_method="S256",
        nonce=nonce,
        resource=resource,
    ), None



# -- helpers -------------------------------------------------------------


def _current_sub(request: Request) -> str | None:
    return parse_session_token(request.cookies.get(SESSION_COOKIE))


def _safe_next(next_url: str | None) -> str:
    """Open-redirect guard for post-login navigation.

    `startswith('/')` is NOT enough: `//evil.com` is a protocol-relative URL
    the browser will happily navigate off-origin, and backslash variants
    (`/\\evil.com`) are normalized to `//` by some browsers."""
    if not next_url:
        return "/"
    if next_url.startswith("/") and not next_url.startswith("//") and "\\" not in next_url:
        return next_url
    return "/"


def _redirect_with(uri: str, params: dict[str, str]) -> RedirectResponse:
    return RedirectResponse(f"{uri}?{urlencode(params)}", 302)


def _fail(verr: ValidationError, *, state: str | None,
          redirect_uri: str | None) -> Response:
    if verr.redirectable and redirect_uri:
        params = {"error": verr.error, "error_description": verr.description}
        if state:
            params["state"] = state
        return _redirect_with(redirect_uri, params)
    return HTMLResponse(
        error_page(title=verr.error, detail=verr.description), status_code=400
    )


# -- routes --------------------------------------------------------------


@router.get("/authorize", response_class=HTMLResponse)
def authorize(
    request: Request,
    response_type: str | None = None,
    client_id: str | None = None,
    redirect_uri: str | None = None,
    scope: str | None = None,
    state: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    nonce: str | None = None,
    resource: str | None = None,
) -> Response:
    registry: ClientRegistry = request.app.state.registry
    validated, verr = validate_authorize_params(
        registry,
        response_type=response_type,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        nonce=nonce,
        resource=resource,
    )
    if verr is not None:
        return _fail(verr, state=state, redirect_uri=redirect_uri)
    if validated is None:              # contract violation: fail closed
        raise RuntimeError("validate_authorize_params returned no result")

    sub = _current_sub(request)
    if sub is None or sub not in USERS:
        # Full authorize URL (path+query) as `next` — /login validates it
        # with _safe_next; it starts with "/authorize" so it round-trips.
        return RedirectResponse(
            f"/login?{urlencode({'next': str(request.url)})}", 302
        )

    user = USERS[sub]
    return HTMLResponse(
        consent_form(
            client_id=validated.client.client_id,
            redirect_uri=validated.redirect_uri,
            scope=validated.scope,
            state=validated.state,
            code_challenge=validated.code_challenge,
            code_challenge_method=validated.code_challenge_method,
            nonce=validated.nonce,
            resource=validated.resource,
            # email shown ONLY to its owner in their own browser — never logged
            user_label=f"{user.display_name} <{user.email}>",
        )
    )


@router.get("/login", response_class=HTMLResponse)
def login_page(next_url: str = Query("/", alias="next")) -> HTMLResponse:
    # Same `next` naming rule as POST /login: the wire parameter is `next`,
    # the Python name is not.
    return HTMLResponse(login_form(next_url=_safe_next(next_url)))


@router.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    email: str = Form(""),
    password: str = Form(""),
    # alias: the WIRE field stays `next` (the form and every /authorize
    # redirect have always used that name), but the Python parameter must not
    # be called `next` — that shadows the builtin, and the dummy verify below
    # needs it. Naming it `next` is how this broke once already: mypy's
    # "str is not callable" is the whole bug report.
    next_url: str = Form("/", alias="next"),
) -> Response:
    # Two limits, because they see different attacks: the address catches one
    # host hammering the form, the account catches a botnet spending many
    # addresses on one victim. Both are checked before any password hashing —
    # the cost of that hash is the thing an attacker is trying to buy.
    limited = enforce_rate_limit(
        request, "login",
        per_identity=[("login_account", email or None)],
        as_html=True,
    )
    if limited is not None:
        return limited

    user = find_by_email(email)
    if user is None:
        # Dummy verify: keeps unknown-email timing indistinguishable from
        # wrong-password timing, so the login form can't enumerate accounts.
        # Any user will do; builtin next() is available because the route
        # parameter above is named next_url.
        from aguard.oidc.users import USERS as _all
        verify_password(next(iter(_all.values())), password)
        ok = False
    else:
        ok = verify_password(user, password)

    # `user is None` can only mean ok is False, but saying both here is what
    # lets the type checker see that user.sub below is safe.
    if not ok or user is None:
        return HTMLResponse(
            login_form(next_url=_safe_next(next_url),
                       error="Invalid email or password."),
            status_code=401,
        )

    resp = RedirectResponse(_safe_next(next_url), 303)
    resp.set_cookie(
        SESSION_COOKIE,
        create_session_token(user.sub),
        httponly=True,     # JS can never read the session — no XSS exfil path
        samesite="lax",    # blocks cross-site POST carry; still works for top-level GETs
        # Never offered over plaintext HTTP: this cookie mints authorization
        # codes, so an http hop would hand out session hijack. Derived from the
        # issuer scheme unless explicitly overridden (see settings).
        secure=settings.session_cookie_is_secure,
        max_age=settings.session_ttl,
        path="/",
    )
    return resp


@router.post("/consent", response_class=HTMLResponse)
def consent(
    request: Request,
    decision: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(...),
    state: str = Form(...),
    code_challenge: str = Form(...),
    code_challenge_method: str = Form(...),
    nonce: str | None = Form(None),
    resource: str | None = Form(None),
) -> Response:
    registry: ClientRegistry = request.app.state.registry
    # FULL re-validation of every echoed field — they came from the browser.
    validated, verr = validate_authorize_params(
        registry,
        response_type="code",
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        nonce=nonce,
        resource=resource,
    )
    if verr is not None:
        return _fail(verr, state=state, redirect_uri=redirect_uri)
    if validated is None:              # contract violation: fail closed
        raise RuntimeError("validate_authorize_params returned no result")

    sub = _current_sub(request)
    if sub is None or sub not in USERS:
        return HTMLResponse("Not authenticated — sign in first.", status_code=403)

    if decision != "approve":
        return _redirect_with(redirect_uri, {
            "error": "access_denied",
            "error_description": "the resource owner denied the request",
            "state": state,
        })

    codes: AuthCodeStore = request.app.state.codes
    raw_code = codes.issue(
        client_id=validated.client.client_id,
        redirect_uri=validated.redirect_uri,
        subject=sub,               # identity → token binding starts here
        scope=validated.scope,
        code_challenge=validated.code_challenge,
        code_challenge_method=validated.code_challenge_method,
        nonce=validated.nonce,
        resource=validated.resource,   # RFC 8707: carried into the code record
    )
    return _redirect_with(redirect_uri, {"code": raw_code, "state": state})


@router.get("/logout")
def logout() -> Response:
    resp = RedirectResponse("/", 303)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@router.get("/demo/callback", response_class=HTMLResponse)
def demo_callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> HTMLResponse:
    """Registered redirect URI — renders what the client received so the
    whole flow is inspectable in a browser."""
    from aguard.oidc.pages import callback_page
    return HTMLResponse(callback_page(
        code=code, state=state, error=error, error_description=error_description
    ))

