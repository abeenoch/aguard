"""Refresh rotation, family revocation, and client_credentials tests."""
from __future__ import annotations

from app.oidc.validation import verify_access_token
from tests.test_token_grants import REGISTERED_REDIRECT, _basic, _exchange, _obtain_code, app


def _get_refresh(*, client_id="demo-spa", scope="openid orders:read",
                 headers=None, extra: dict | None = None) -> str:
    code, verifier = _obtain_code(client_id=client_id, scope=scope)
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REGISTERED_REDIRECT,
        "code_verifier": verifier,
    }
    if headers is None:
        # public clients authenticate by client_id in the body
        payload["client_id"] = client_id
    payload.update(extra or {})
    resp = _exchange(payload, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["refresh_token"]



def _refresh_exchange(refresh: str, *, client_id="demo-spa",
                      headers=None, scope: str | None = None) -> object:
    payload = {"grant_type": "refresh_token", "refresh_token": refresh}
    if scope:
        payload["scope"] = scope
    if client_id is not None and not headers:
        payload["client_id"] = client_id
    return _exchange(payload, headers=headers)


# -- refresh rotation ------------------------------------------------------


def test_refresh_happy_path_and_rotation():
    rt1 = _get_refresh()
    resp = _refresh_exchange(rt1)
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert "refresh_token" in body
    rt2 = body["refresh_token"]
    assert rt2 != rt1                                   # rotation actually rotates
    assert "id_token" in body                          # OIDC: id_token, no nonce
    claims = verify_access_token(body["access_token"], keys=app.state.keys)
    assert claims["sub"] == "usr_alice"

    # the second generation works...
    resp = _refresh_exchange(rt2)
    assert resp.status_code == 200


def test_refresh_reuse_burns_the_whole_family():
    rt1 = _get_refresh()
    rt2 = _refresh_exchange(rt1).json()["refresh_token"]

    # attacker replays the retired rt1 -> reuse detected, family burned
    attack = _refresh_exchange(rt1)
    assert attack.status_code == 400
    assert attack.json()["error"] == "invalid_grant"

    # the LEGITIMATE owner's still-fresh rt2 is dead too — that is the point:
    # on reuse we cannot tell attacker from victim, so the family dies.
    aftermath = _refresh_exchange(rt2)
    assert aftermath.status_code == 400
    assert aftermath.json()["error"] == "invalid_grant"


def test_refresh_scope_narrowing_allowed_expansion_refused():
    rt1 = _get_refresh()
    narrowed = _refresh_exchange(rt1, scope="orders:read")
    assert narrowed.status_code == 200
    assert narrowed.json()["scope"] == "orders:read"

    # can't happen again from the same rt1 (it's retired) — get a fresh family
    rt_fresh = _get_refresh()
    expanded = _refresh_exchange(rt_fresh, scope="openid orders:read email")
    assert expanded.status_code == 400
    assert expanded.json()["error"] == "invalid_scope"


def test_refresh_presented_to_wrong_client_rejected():
    rt1 = _get_refresh(client_id="demo-spa")
    resp = _refresh_exchange(rt1, headers=_basic("demo-conf", "demo-conf-secret"))
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


# -- client_credentials ----------------------------------------------------


def test_client_credentials_happy_path():
    resp = _exchange(
        {"grant_type": "client_credentials", "scope": "orders:read"},
        headers=_basic("cli-agent", "cli-agent-secret"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert "refresh_token" not in body    # no user => nothing to keep alive
    assert "id_token" not in body         # no identity => no OIDC identity token

    claims = verify_access_token(body["access_token"], keys=app.state.keys)
    assert claims["sub"] == "svc:cli-agent"   # machine principal
    assert claims["roles"] == ["agent"]
    assert claims["client_id"] == "cli-agent"


def test_client_credentials_scope_cannot_exceed_allowed():
    resp = _exchange(
        {"grant_type": "client_credentials", "scope": "orders:write"},
        headers=_basic("cli-agent", "cli-agent-secret"),
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_scope"


def test_client_credentials_rejected_for_wrong_grant_client():
    resp = _exchange(
        {"grant_type": "client_credentials"},
        headers=_basic("demo-spa", "anything"),
    )
    # demo-spa is public AND lacks the grant => invalid_client at auth
    assert resp.status_code in (400, 401)


# -- the Option 6 linchpin: human sub, agent roles -------------------------


def test_chat_agent_token_is_human_identity_with_agent_capability():
    code, verifier = _obtain_code(client_id="chat-agent", scope="openid orders:read")
    resp = _exchange({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REGISTERED_REDIRECT,
        "code_verifier": verifier,
    }, headers=_basic("chat-agent", "chat-agent-secret"))
    assert resp.status_code == 200, resp.text
    body = resp.json()

    claims = verify_access_token(body["access_token"], keys=app.state.keys)
    assert claims["sub"] == "usr_alice"   # identity: the human
    assert claims["roles"] == ["agent"]   # capability: agent (read-only later)
    assert claims["client_id"] == "chat-agent"
