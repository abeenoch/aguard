"""Capability class derived from a verified token's claims.

`roles` decides which database role a request borrows:

    ["agent"]  -> agent_readonly   (read-only, own tenant rows)
    ["human"]  -> app_user         (read/write, own rows)

which makes the *default* for a missing claim a security decision. Defaulting
to ["human"] — what the API and MCP layers did before this module existed —
meant a token carrying no `roles` claim silently received the strongest
capability in the system. Absent capability evidence must degrade to the
weakest class, never the strongest.

The claim is always set by our own AS (routes_token._mint_access_token), so
this is defence in depth rather than the primary control — but it is exactly
the sort of default that becomes load-bearing when a second token issuer,
a migration, or a hand-rolled admin token appears.

Unknown role names are dropped rather than trusted: role names are an
allowlist because they end in a `SET LOCAL ROLE` inside the database.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

#: The class assumed when a token carries no usable `roles` claim.
LEAST_PRIVILEGE_ROLE = "agent"

#: Roles this system actually maps to a database role. Anything else is an
#: unknown capability and is discarded — the allowlist, not the token, decides.
_KNOWN_ROLES = frozenset({"human", "agent"})


def roles_from_claims(claims: Mapping[str, Any] | None) -> frozenset[str]:
    """Roles for a verified token. Never empty, never over-privileged."""
    raw = (claims or {}).get("roles")
    if isinstance(raw, str):                 # tolerate a scalar claim
        raw = [raw]
    if not isinstance(raw, (list, tuple, set, frozenset)):
        return frozenset({LEAST_PRIVILEGE_ROLE})
    roles = {str(role) for role in raw if str(role) in _KNOWN_ROLES}
    # `or` covers both "claim absent" and "claim held only unknown names".
    return frozenset(roles) or frozenset({LEAST_PRIVILEGE_ROLE})


__all__ = ["LEAST_PRIVILEGE_ROLE", "roles_from_claims"]
