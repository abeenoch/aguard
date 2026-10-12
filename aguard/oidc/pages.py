"""HTML pages: sign in, sign up, consent, errors, demo callback.

Rendered with Jinja2, autoescape ON (docs/DESIGN.md E1): the ENGINE escapes
every interpolated value by default, so "echo what the user sent" — signup
name/email, authorize params — cannot smuggle markup. Templates ship inside
the package (aguard/oidc/templates/), and the shared stylesheet is a real
static file (aguard/oidc/static/aguard.css) served at /static — which is what
lets html_response() stamp `style-src 'self'`: no inline <style>, no scripts,
no third-party assets.

Security properties carried over unchanged from the hand-rolled version:
- every form action is prefixed with the AS's public path prefix (see
  aguard/oidc/urls.py): behind a path-stripping proxy the app sees "/login",
  but the BROWSER must post to "/api/login" or it hits the origin root
- `next` is a hidden field validated server-side to start with "/"
  (open-redirect guard) — a form is just another way to be handed attacker data
- consent form echoes the *validated* authorize params, but the server
  RE-VALIDATES all of them on POST (hidden fields are attacker-controlled)
"""
from __future__ import annotations

from urllib.parse import quote

from fastapi.responses import HTMLResponse
from jinja2 import Environment, PackageLoader

_env = Environment(
    loader=PackageLoader("aguard.oidc", "templates"),
    # Every value in these templates is text or attribute content — there is
    # no trusted HTML anywhere — so escaping must be the engine's default,
    # not a per-site discipline. A template wanting raw output has to ask
    # for |safe explicitly, and none does.
    autoescape=True,
)

#: These pages load exactly one first-party stylesheet and do nothing else:
#: no images, no fonts, no scripts. `default-src 'none'` covers the rest;
#: form-action / frame-ancestors / base-uri close the usual remaining holes.
CSP = (
    "default-src 'none'; style-src 'self'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)


def html_response(
    markup: str, *, status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> HTMLResponse:
    """A rendered page as a response, CSP attached (extra headers merged)."""
    return HTMLResponse(
        markup,
        status_code=status_code,
        headers={"Content-Security-Policy": CSP, **(headers or {})},
    )


def _render(template: str, **context: object) -> str:
    return _env.get_template(template).render(**context)


def error_page(*, title: str, detail: str, prefix: str = "") -> str:
    """Shown when a redirect would be UNSAFE (bad client_id / redirect_uri).

    Rendering instead of redirecting is the open-redirect kill-switch: we never
    send the browser anywhere we have not verified."""
    return _render("error.html", title=title, detail=detail, prefix=prefix)


def rate_limited_page(*, retry_after: int, prefix: str = "") -> str:
    """Too many attempts from this client.

    Rendered rather than redirected for the same reason as error_page(): the
    browser is never sent anywhere we have not verified.
    """
    return _render("rate_limited.html", retry_after=retry_after, prefix=prefix)


def login_form(*, next_url: str, error: str | None = None, prefix: str = "",
               allow_signup: bool = True, demo_users: bool = False) -> str:
    signup_href = (
        f"{prefix}/signup?next={quote(next_url, safe='')}"
        if allow_signup else None
    )
    return _render("login.html", next_url=next_url, error=error, prefix=prefix,
                   signup_href=signup_href, demo_users=demo_users)


def signup_form(*, next_url: str, error: str | None = None, prefix: str = "",
                email: str = "", name: str = "") -> str:
    """Self-service account creation.

    Field values are echoed back on error so a mistyped password does not cost
    the user their name and email too — and each is escaped by the ENGINE,
    because "echo what the user sent" is exactly where XSS lives.
    """
    login_href = f"{prefix}/login?next={quote(next_url, safe='')}"
    return _render("signup.html", next_url=next_url, error=error, prefix=prefix,
                   email=email, name=name, login_href=login_href)


def consent_form(
    *,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
    nonce: str | None,
    user_label: str,
    resource: str | None = None,
    prefix: str = "",
) -> str:
    return _render(
        "consent.html",
        client_id=client_id, redirect_uri=redirect_uri,
        scope=scope, scopes=scope.split(), state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        nonce=nonce, resource=resource, user_label=user_label, prefix=prefix,
    )


def callback_page(*, code: str | None, state: str | None,
                  error: str | None, error_description: str | None,
                  prefix: str = "") -> str:
    """Landing page for the lab's registered redirect URI — shows what the
    client received, so the flow is inspectable in a browser."""
    # None renders as the string "None" in a template, so blank them first.
    return _render("callback.html", code=code or "", state=state or "",
                   error=error, error_description=error_description or "",
                   prefix=prefix)
