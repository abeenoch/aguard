"""A-guard MCP resource server: documents as tools, the DB as the enforcer.

Four tools, one privilege story:
  list_documents   read, own tenant
  read_document    read, own tenant, by id
  delete_document  the handler EXISTS (so the refusal is visible), but an
                   agent's scoped session makes Postgres raise
                   InsufficientPrivilege before a single row is touched.
  redact_text      scrub PII from arbitrary text with the SAME engine that
                   guards this server's own logs — the reusable, chat-facing
                   face of the library. Authed like every other tool.

Handlers stay dumb: read the verified principal, open a scoped session, run
SQL. All permission logic lives in GRANTs, RLS, and column grants — the very
same tables the REST API uses, so one policy change covers both surfaces.

Authentication is handled by the SDK, wired in build_mcp(): the MCP
Streamable HTTP app carries a BearerAuthBackend + AuthContextMiddleware +
RequireAuthMiddleware (401 + RFC 9728 resource_metadata when unauthenticated)
and the AGuardTokenVerifier (audience-bound to settings.mcp_resource_id).
Tool handlers read the resulting identity via current_principal().
"""
from __future__ import annotations

import logging
import uuid

from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl

from aguard.db.session import scoped_session
from aguard.mcp.auth import AGuardTokenVerifier, current_principal
from aguard.mcp.principal import Principal
from aguard.oidc.validation import KeySet
from aguard.settings import settings

logger = logging.getLogger("a-guard.mcp")

INSTRUCTIONS = (
    "A-guard demo document server. Read tools return only the caller's own "
    "tenant rows (row-level security). Write tools exist but are refused for "
    "agent tokens by database policy — the refusal is the lesson, not a bug. "
    "redact_text scrubs PII (cards, emails, phones, addresses, IPs, secrets) "
    "from any text using the same engine that redacts this server's own audit "
    "trail — use it BEFORE echoing user-provided sensitive values back or "
    "forwarding content to another tool or provider."
)


def _kind(principal: Principal) -> str:
    """Capability class -> connection pool. Agent tokens can never borrow a
    human session: the two pools use different least-privilege logins."""
    return "agent" if "agent" in principal.roles else "human"


def _redacted_statement(text: str) -> str:
    """Audit rows are log records too — run statement text through the SAME
    redactor so a `WHERE email='...'` can never land raw in agent_audit."""
    from aguard.redact.redactor import redact_event
    return str(redact_event({"statement": text}, settings.log_pepper)["statement"])


def _audit(cur, principal: Principal, request_id: str,
           statement: str, rows_returned: int) -> None:
    cur.execute(
        "INSERT INTO agent_audit(subject, client_id, request_id, statement,"
        " rows_returned) VALUES (%s, %s, %s, %s, %s)",
        (principal.sub, principal.client_id, request_id,
         _redacted_statement(statement), rows_returned))


#: Loopback hosts the MCP SDK protects by default. A DNS-rebinding attack needs
#: a browser on the victim's machine to reach a server on localhost, so loopback
#: is the threat this guards; public names/IPs are opt-in via MCP_ALLOWED_HOSTS.
_LOOPBACK_HOSTS = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
_LOOPBACK_ORIGINS = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]


def _transport_security() -> TransportSecuritySettings:
    """Host/Origin allowlist for the Streamable HTTP transport.

    Protection stays ON (it is a real DNS-rebinding defence), widened only by
    exactly what the operator configured. Serving off-box without listing the
    host here means every request is refused with 421 — a footgun worth naming.
    """
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[*_LOOPBACK_HOSTS, *settings.mcp_allowed_hosts],
        allowed_origins=[*_LOOPBACK_ORIGINS, *settings.mcp_allowed_origins],
    )


def _audit_denied(principal: Principal, request_id: str, statement: str) -> None:
    """A refused write must still be auditable — but the refused transaction
    rolled back, so its rows are gone. Log the denial on a fresh session."""
    try:
        with scoped_session(kind=_kind(principal), sub=principal.sub) as conn:  # type: ignore[arg-type]
            with conn.cursor() as cur:
                _audit(cur, principal, request_id, statement, 0)
    except Exception:  # pragma: no cover - auditing must never mask the denial
        logger.exception("failed to audit denied MCP operation")


def _row(r) -> dict:
    return {"id": r[0], "owner_sub": r[1], "title": r[2], "body": r[3]}


def list_documents(ctx: Context) -> list[dict]:
    """List the caller's own documents (tenant-scoped, agent-safe projection)."""
    principal = current_principal()
    rid = uuid.uuid4().hex[:16]
    logger.info({"event": "mcp.documents.list", "request_id": rid,
                 "sub": principal.sub, "client_id": principal.client_id})
    with scoped_session(kind=_kind(principal), sub=principal.sub) as conn:  # type: ignore[arg-type]
        with conn.cursor() as cur:
            cur.execute("SELECT id, owner_sub, title, body FROM agent_documents "
                        "ORDER BY id")
            rows = cur.fetchall()
            _audit(cur, principal, rid, "MCP list_documents", len(rows))
    return [_row(r) for r in rows]


def read_document(document_id: int, ctx: Context) -> dict | None:
    """Read one document by id (RLS still applies — other tenants invisible)."""
    principal = current_principal()
    rid = uuid.uuid4().hex[:16]
    logger.info({"event": "mcp.documents.read", "request_id": rid,
                 "sub": principal.sub, "document_id": document_id})
    with scoped_session(kind=_kind(principal), sub=principal.sub) as conn:  # type: ignore[arg-type]
        with conn.cursor() as cur:
            cur.execute("SELECT id, owner_sub, title, body FROM agent_documents "
                        "WHERE id = %s", (document_id,))
            row = cur.fetchone()
            _audit(cur, principal, rid,
                   f"MCP read_document id={document_id}", 1 if row else 0)
    return _row(row) if row is not None else None


def delete_document(document_id: int, ctx: Context) -> dict:
    """Attempt to delete a document. Agents: Postgres refuses (read-only
    role). Humans: their own rows only. The tool exists so an agent can ASK —
    the database decides, and every refusal is logged and audited."""
    principal = current_principal()
    rid = uuid.uuid4().hex[:16]
    logger.info({"event": "mcp.documents.delete", "request_id": rid,
                 "sub": principal.sub, "document_id": document_id})
    statement = f"MCP delete_document id={document_id}"
    try:
        with scoped_session(kind=_kind(principal), sub=principal.sub) as conn:  # type: ignore[arg-type]
            with conn.cursor() as cur:
                cur.execute("DELETE FROM documents WHERE id = %s RETURNING id",
                            (document_id,))
                deleted = cur.fetchone()
                _audit(cur, principal, rid, statement, 1 if deleted else 0)
    except Exception as exc:
        # The money path: an agent session meets InsufficientPrivilege from
        # the DBMS itself. We REPORT it — never retry, escalate, or translate
        # it into success.
        logger.info({"event": "mcp.documents.delete_refused", "request_id": rid,
                     "sub": principal.sub, "reason": type(exc).__name__})
        _audit_denied(principal, rid, statement)
        return {"deleted": False,
                "reason": "refused by database policy — insufficient privilege"}
    if deleted is None:
        return {"deleted": False, "reason": "no such document (or not yours)"}
    return {"deleted": True, "id": deleted[0]}


def redact_text(text: str, ctx: Context) -> dict:
    """Scrub PII from arbitrary text (the library engine, over MCP).

    Cards (Luhn-gated), emails (keyed-HMAC correlation tags), phones, IPv4,
    JWTs, bearer tokens, secret assignments, sensitive query params. Returns
    the redacted string plus per-type counts — never the detected values.

    Intended for an agent loop: run text through here BEFORE echoing
    user-provided sensitive values back into the chat or handing them to
    another tool/provider. The audit row records only character/finding
    counts — the raw text never touches the database.
    """
    from aguard.redact.patterns import redact_text as scrub
    from aguard.redact.patterns import scan_findings

    principal = current_principal()
    rid = uuid.uuid4().hex[:16]
    findings = scan_findings(text, settings.log_pepper)
    redacted = scrub(text, settings.log_pepper)
    total = sum(f["count"] for f in findings)
    logger.info({"event": "mcp.redact.text", "request_id": rid,
                 "sub": principal.sub, "client_id": principal.client_id,
                 "chars": len(text), "findings": total})
    with scoped_session(kind=_kind(principal), sub=principal.sub) as conn:  # type: ignore[arg-type]
        with conn.cursor() as cur:
            # Statement carries counts only: the audit trail must not become
            # the leak the tool exists to prevent.
            _audit(cur, principal, rid,
                   f"MCP redact_text chars={len(text)} findings={total}",
                   total)
    return {"redacted": redacted, "findings": findings}


def build_mcp(keys: KeySet) -> FastMCP:
    """Construct the MCP server bound to a key set.

    ``keys`` is any ``KeySet``: the AS's ``KeyManager`` (single-process/tests)
    or a ``RemoteKeyStore`` pointed at the issuer's JWKS (the split service, which
    holds no signing key).

    stateless_http=True: our tokens are self-contained JWTs and the tools are
    pure request/response, so we don't need server-side MCP sessions — each
    POST is verified and served independently (scales horizontally, no
    session store to poison).
    """
    server = FastMCP(
        name="a-guard-documents",
        instructions=INSTRUCTIONS,
        token_verifier=AGuardTokenVerifier(keys),
        auth=AuthSettings(
            # AnyHttpUrl rather than a bare str: the SDK's model declares a URL
            # type, and passing a string only worked because pydantic coerced
            # it — the annotations should say what the model expects.
            issuer_url=AnyHttpUrl(settings.issuer),
            resource_server_url=AnyHttpUrl(settings.mcp_resource_id),
            required_scopes=[],
            validate_token_resource=True,   # aud must name THIS resource
        ),
        stateless_http=True,
        # main.py attaches this ASGI app at exactly "/mcp" via a Starlette
        # Route, which does NOT strip the path prefix — so the sub-app's own
        # route must match the FULL public path. (A Mount would strip it, but
        # Mount only matches "/mcp/" and would 307-redirect POST /mcp, which
        # breaks MCP clients; Mount("/") would instead swallow every unmatched
        # path and disable trailing-slash redirects app-wide.)
        streamable_http_path="/mcp",
        json_response=True,   # request/response only: plain JSON, no SSE framing
        warn_on_duplicate_tools=False,
        transport_security=_transport_security(),
    )
    for fn in (list_documents, read_document, delete_document, redact_text):
        server.add_tool(fn)
    return server
