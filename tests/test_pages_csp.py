"""E1: the auth pages are Jinja2 templates behind a strict CSP.

Two properties are new and load-bearing:

* autoescape — rendered output escapes interpolated values by ENGINE DEFAULT,
  not because each f-string remembered html.escape(). The signup form echoes
  user input, so a hostile value must come back inert.
* style-src 'self' — the stylesheet is a real file at /static/aguard.css, so
  pages carry no inline <style> and no scripts, and html_response() stamps a
  CSP with no 'unsafe-inline' anywhere.

Everything else is a port contract: prefix-prefixed form actions, the `next`
hidden field, consent's echoed (server-revalidated) params.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from aguard.main import app
from aguard.oidc.pages import (
    CSP,
    callback_page,
    consent_form,
    error_page,
    login_form,
    rate_limited_page,
    signup_form,
)

client = TestClient(app)


def _no_inline_problems(markup: str) -> list[str]:
    problems = []
    if "<style" in markup:
        problems.append("inline <style> present")
    if "<script" in markup:
        problems.append("inline <script> present")
    if 'rel="stylesheet"' not in markup:
        problems.append("stylesheet link missing")
    return problems


def test_no_inline_style_or_script_in_any_page():
    rendered = {
        "login": login_form(next_url="/"),
        "signup": signup_form(next_url="/"),
        "consent": consent_form(
            client_id="demo-spa", redirect_uri="https://demo.test/cb",
            scope="openid profile", state="st", code_challenge="cc",
            code_challenge_method="S256", nonce="n", user_label="Alice",
        ),
        "error": error_page(title="invalid_client", detail="unknown client_id"),
        "rate_limited": rate_limited_page(retry_after=12),
        "callback": callback_page(code="abc", state="st", error=None,
                                  error_description=None),
    }
    for name, markup in rendered.items():
        assert _no_inline_problems(markup) == [], name


def test_autoescape_survives_hostile_signup_echo():
    markup = signup_form(
        next_url="/",
        name='<script>alert(1)</script>" onmouseover="x',
        email='"><img src=x onerror=alert(2)>',
    )
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in markup
    assert "<script>" not in markup
    assert 'onmouseover="x' not in markup          # quotes are escaped
    assert "<img" not in markup


def test_csp_header_is_strict_and_without_unsafe_inline():
    resp = client.get("/login")
    assert resp.status_code == 200
    assert resp.headers["content-security-policy"] == CSP
    assert "unsafe-inline" not in CSP
    assert "default-src 'none'" in CSP


def test_stylesheet_served_as_first_party_static():
    resp = client.get("/static/aguard.css")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/css")
    assert "--gold" in resp.text


def test_prefixed_pages_link_and_post_through_the_prefix():
    markup = login_form(next_url="/x", prefix="/api")
    assert 'action="/api/login"' in markup
    assert 'href="/api/static/aguard.css"' in markup
    assert 'href="/api/signup?next=' in markup     # still created for sign-up
    assert 'href="/api/static/aguard.css"' in error_page(title="t", detail="d",
                                                         prefix="/api")
    assert 'href="/api/static/aguard.css"' in rate_limited_page(retry_after=3,
                                                                prefix="/api")


def test_consent_renders_scope_list_and_optional_hidden_fields():
    base = {
        "client_id": "demo-spa", "redirect_uri": "https://demo.test/cb",
        "scope": "", "state": "st", "code_challenge": "cc",
        "code_challenge_method": "S256", "user_label": "Alice",
        "prefix": "/api",
    }
    markup = consent_form(**base, nonce=None, resource=None)
    assert "basic access" in markup                # empty scope falls back
    assert 'name="nonce"' not in markup
    assert 'name="resource"' not in markup
    assert 'action="/api/consent"' in markup

    scoped = consent_form(**{**base, "scope": "openid profile"}, nonce="n1",
                          resource="https://api.test")
    assert "<li><span class=\"tick\">&#10003;</span>openid</li>" in scoped
    assert 'name="nonce" value="n1"' in scoped
    assert 'name="resource" value="https://api.test"' in scoped


def test_callback_page_renders_both_branches():
    ok = callback_page(code="c0de", state="st1", error=None,
                       error_description=None)
    assert "Authorization code received" in ok
    assert "code&nbsp;= c0de" in ok
    bad = callback_page(code=None, state="st1", error="access_denied",
                        error_description="the resource owner denied")
    assert "Authorization failed" in bad
    assert "access_denied — the resource owner denied" in bad
