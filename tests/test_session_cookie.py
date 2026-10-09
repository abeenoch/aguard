"""Session-cookie attributes: the flags that keep a live session off the wire.

The session cookie is what mints authorization codes, so `Secure` matters as
much as `HttpOnly`: without it a single plaintext HTTP hop (a misconfigured
proxy, a user typing http://, TLS terminated in front of an http issuer) hands
out an 8-hour session. These tests pin all four attributes.
"""
from __future__ import annotations

import dataclasses

from fastapi.testclient import TestClient

import aguard.oidc.routes_auth as routes_auth
from aguard.main import app
from aguard.settings import settings

client = TestClient(app)


def _cookie_attributes(header: str) -> dict[str, str]:
    """Cookie attributes from a Set-Cookie header (flags map to '')."""
    attributes = {}
    for segment in header.split(";")[1:]:          # [0] is name=value
        name, _, value = segment.strip().partition("=")
        attributes[name.lower()] = value
    return attributes


def _login_cookie_header(monkeypatch, **settings_changes) -> str:
    """Log in and return the raw Set-Cookie header.

    Settings is a frozen dataclass, so tests replace the module's reference —
    routes_auth reads it at call time, which is what makes the swap effective.
    """
    if settings_changes:
        monkeypatch.setattr(
            routes_auth, "settings",
            dataclasses.replace(routes_auth.settings, **settings_changes))
    response = client.post(
        "/login",
        data={"email": "alice@example.com",
              "password": "correct-horse-battery", "next": "/"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    return response.headers["set-cookie"]


def test_session_cookie_is_httponly_lax_and_root_scoped(monkeypatch):
    attributes = _cookie_attributes(_login_cookie_header(monkeypatch))
    assert "httponly" in attributes
    assert attributes["samesite"].lower() == "lax"
    assert attributes["path"] == "/"
    # One source of truth for the lifetime: cookie Max-Age == token exp.
    assert attributes["max-age"] == str(settings.session_ttl)


def test_session_cookie_is_secure_when_the_issuer_is_https(monkeypatch):
    header = _login_cookie_header(monkeypatch, issuer="https://as.example.com")
    assert "secure" in _cookie_attributes(header)


def test_session_cookie_is_not_secure_for_a_plain_http_dev_issuer(monkeypatch):
    header = _login_cookie_header(monkeypatch, issuer="http://localhost:8000")
    assert "secure" not in _cookie_attributes(header)


def test_secure_can_be_forced_on_for_an_http_issuer(monkeypatch):
    """TLS terminated in front of an http issuer: a scheme-derived default
    cannot see that, so the operator forces it."""
    header = _login_cookie_header(monkeypatch, session_cookie_secure="true")
    assert "secure" in _cookie_attributes(header)


def test_secure_can_be_forced_off_for_local_experiments(monkeypatch):
    header = _login_cookie_header(monkeypatch, session_cookie_secure="false",
                                  issuer="https://as.example.com")
    assert "secure" not in _cookie_attributes(header)


def test_auto_follows_the_issuer_scheme():
    assert dataclasses.replace(
        settings, session_cookie_secure="auto",
        issuer="https://as.example.com").session_cookie_is_secure is True
    assert dataclasses.replace(
        settings, session_cookie_secure="auto",
        issuer="http://localhost:8000").session_cookie_is_secure is False


def test_unrecognised_setting_degrades_to_auto_not_off():
    """A typo must not be able to silently downgrade the cookie to plaintext
    transport, so an unknown value behaves like "auto" (safe for an https
    issuer) rather than like "false"."""
    typo = dataclasses.replace(settings, session_cookie_secure="ture")
    assert typo.session_cookie_is_secure is \
        typo.issuer.startswith("https://")


def test_explicit_values_win_over_the_issuer():
    for literal in ("1", "true", "yes", "on"):
        assert dataclasses.replace(
            settings, session_cookie_secure=literal,
            issuer="http://localhost:8000").session_cookie_is_secure is True
    for literal in ("0", "false", "no", "off"):
        assert dataclasses.replace(
            settings, session_cookie_secure=literal,
            issuer="https://as.example.com").session_cookie_is_secure is False
