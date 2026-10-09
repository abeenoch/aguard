"""The `roles` claim is a capability class — its default must fail SAFE.

`roles` decides which database role a request borrows, so the default for a
missing claim is a security decision: ["human"] -> app_user (read/write),
["agent"] -> agent_readonly (read-only). A missing claim used to resolve to
"human", i.e. absent evidence granted the strongest capability in the system.
These tests pin the direction of the default.
"""
from __future__ import annotations

from aguard.oidc.claims import LEAST_PRIVILEGE_ROLE, roles_from_claims


def test_least_privilege_role_is_the_read_only_one():
    assert LEAST_PRIVILEGE_ROLE == "agent"


def test_missing_roles_claim_degrades_to_least_privilege():
    assert roles_from_claims({}) == frozenset({LEAST_PRIVILEGE_ROLE})
    assert roles_from_claims(None) == frozenset({LEAST_PRIVILEGE_ROLE})
    assert roles_from_claims({"sub": "usr_alice"}) == frozenset({LEAST_PRIVILEGE_ROLE})


def test_explicit_roles_are_honoured():
    assert roles_from_claims({"roles": ["human"]}) == frozenset({"human"})
    assert roles_from_claims({"roles": ["agent"]}) == frozenset({"agent"})
    assert roles_from_claims({"roles": ["human", "agent"]}) == \
        frozenset({"human", "agent"})


def test_scalar_role_claim_is_tolerated():
    assert roles_from_claims({"roles": "human"}) == frozenset({"human"})


def test_unknown_role_names_are_discarded_not_trusted():
    """Role names end in a SET LOCAL ROLE, so the allowlist decides — a token
    cannot invent a capability by naming it."""
    assert roles_from_claims({"roles": ["human", "superuser"]}) == \
        frozenset({"human"})
    assert roles_from_claims({"roles": ["superuser"]}) == \
        frozenset({LEAST_PRIVILEGE_ROLE})


def test_malformed_roles_claim_cannot_grant_anything():
    for bad in (None, 0, [], {}, "   ", ["", None], ("bogus",), [["human"]]):
        assert roles_from_claims({"roles": bad}) == \
            frozenset({LEAST_PRIVILEGE_ROLE}), f"unexpected for {bad!r}"
