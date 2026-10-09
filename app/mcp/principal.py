"""Principal: identity + capability class for one authenticated MCP caller.

Mirrors app.api.deps.Principal (same four fields the REST handlers use) so
both surfaces map identity the same way: `roles` -> DB session kind,
`sub` -> the RLS tenant key. Kept as its own type because the MCP transport
supplies identity through the SDK's contextvar, not a FastAPI dependency.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    sub: str                # identity: human user or svc:client
    roles: frozenset[str]   # capability class -> DB role mapping
    scopes: frozenset[str]  # operation grants
    client_id: str
