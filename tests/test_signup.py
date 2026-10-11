"""Self-service sign-up: anybody can create an account, then use it.

The seeded demo users are fixtures for the demo suite; /signup is the path a
real visitor takes, and it is the reason the directory is no longer just Python
constants.
"""
from __future__ import annotations

import secrets
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from aguard.main import app
from aguard.oidc import routes_auth
from aguard.oidc import users as users_module

client = TestClient(app)


@pytest.fixture
def store():
    """A fresh directory per test, so one test's account is not another's fixture."""
    users_module.reset_user_store()
    yield users_module.user_store()
    users_module.reset_user_store()


def _email() -> str:
    return f"user-{secrets.token_hex(4)}@example.com"


def test_signup_page_renders_a_form():
    resp = client.get("/signup", follow_redirects=False)
    assert resp.status_code == 200
    assert 'action="/signup"' in resp.text
    assert 'name="email"' in resp.text


def test_signup_creates_an_account_and_signs_the_visitor_in(store):
    email = _email()
    resp = client.post("/signup", data={
        "name": "Ada Lovelace", "email": email,
        "password": "a-good-long-passphrase", "next": "/",
    }, follow_redirects=False)
    assert resp.status_code == 303
    assert "lab_session" in resp.cookies          # signed in, not sent to /login

    created = users_module.find_by_email(email)
    assert created is not None
    assert created.display_name == "Ada Lovelace"
    assert created.password_hash.startswith(  # stored hashed, never plaintext
        created.password_hash.split("$", 1)[0])
    assert "a-good-long-passphrase" not in created.password_hash


def test_a_new_account_can_sign_in_afterwards(store):
    email = _email()
    client.post("/signup", data={
        "name": "Grace Hopper", "email": email,
        "password": "another-long-passphrase", "next": "/",
    }, follow_redirects=False)
    client.cookies.clear()                        # a different browser session

    resp = client.post("/login", data={
        "email": email, "password": "another-long-passphrase", "next": "/",
    }, follow_redirects=False)
    assert resp.status_code == 303


def test_signup_rejects_weak_password_and_duplicate_email(store):
    short = client.post("/signup", data={
        "name": "Bob", "email": _email(), "password": "tooshort", "next": "/",
    }, follow_redirects=False)
    assert short.status_code == 400
    assert "at least 10 characters" in short.text

    # alice is a seeded account: one account per address, however it is typed.
    dup = client.post("/signup", data={
        "name": "Impostor", "email": "ALICE@Example.com",
        "password": "a-good-long-passphrase", "next": "/",
    }, follow_redirects=False)
    assert dup.status_code == 400
    assert "already exists" in dup.text


def test_signup_can_be_closed_by_configuration(monkeypatch):
    monkeypatch.setattr(routes_auth, "settings",
                        SimpleNamespace(allow_signup=False))
    assert client.get("/signup", follow_redirects=False).status_code == 404
    resp = client.post("/signup", data={
        "name": "Nobody", "email": _email(), "password": "a-long-passphrase",
    }, follow_redirects=False)
    assert resp.status_code == 404
