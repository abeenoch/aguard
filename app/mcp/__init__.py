"""MCP resource-server package: Streamable HTTP transport + audience-bound auth.

Security shape (MCP spec §Authorization):
  1. No/invalid token -> 401 + WWW-Authenticate: Bearer resource_metadata="..."
     (clients discover the AS from RFC 9728, never from folklore)
  2. Token verified  -> signature/iss/exp/aud checked by AGuardTokenVerifier;
     aud MUST equal settings.mcp_resource_id, so a token minted for /api is
     REJECTED here (the cross-API replay test from Phase B, now enforced live)
  3. Valid token     -> identity (sub + roles) reaches the tool handlers, which
     open least-privilege Postgres sessions. The tools don't decide
     permissions; the database does.
"""

