"""Protected resource API: the surface humans and agents SHARE.

One endpoint set, one middleware chain, two realities:
  human token (roles=["human"]) -> app_user, read+write, own rows
  agent token (roles=["agent"]) -> agent_readonly, read-only, own tenant rows

Every handler takes a scoped connection — privilege is a property of the
SESSION, not of branching application code. Handlers stay dumb; the database
stays in charge.
"""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.api.deps import Principal, require_principal, require_scope
from app.db.session import scoped_session

logger = logging.getLogger("a-guard.api")

router = APIRouter(prefix="/api")


class DocumentIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=10000)


def _request_id(request: Request) -> str:
    rid = request.headers.get("x-request-id")
    return rid if rid else uuid.uuid4().hex[:16]


def _session_kind(principal: Principal) -> str:
    return "agent" if "agent" in principal.roles else "human"


@router.get("/documents")
def list_documents(request: Request,
                   principal: Principal = Depends(require_principal)):
    require_scope(principal, "orders:read")
    kind = _session_kind(principal)
    rid = _request_id(request)
    logger.info({"event": "documents.list", "request_id": rid,
                 "sub": principal.sub, "client_id": principal.client_id,
                 "role": kind})
    with scoped_session(kind=kind, sub=principal.sub) as conn:  # type: ignore[arg-type]
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, owner_sub, title, body FROM agent_documents "
                "ORDER BY id")
            rows = cur.fetchall()
            _audit(cur, principal, rid,
                   "SELECT id, owner_sub, title, body FROM agent_documents",
                   len(rows))
    return {"documents": [
        {"id": r[0], "owner_sub": r[1], "title": r[2], "body": r[3]}
        for r in rows]}


@router.post("/documents", status_code=201)
def create_document(payload: DocumentIn, request: Request,
                    principal: Principal = Depends(require_principal)):
    require_scope(principal, "orders:write")
    kind = _session_kind(principal)
    rid = _request_id(request)
    # NOTE: title/body are USER-CONTROLLED and may contain PII — this dict is
    # exactly the shape the redactor exists for (it hits the logger INFO
    # line below, pre-serialization, via RedactionFilter).
    logger.info({"event": "documents.create", "request_id": rid,
                 "sub": principal.sub, "client_id": principal.client_id,
                 "title": payload.title})
    with scoped_session(kind=kind, sub=principal.sub) as conn:  # type: ignore[arg-type]
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO documents(owner_sub, title, body) "
                "VALUES (%s, %s, %s) RETURNING id",
                (principal.sub, payload.title, payload.body))
            new_id = cur.fetchone()[0]
            _audit(cur, principal, rid,
                   "INSERT INTO documents(owner_sub, title, body) VALUES (...)",
                   1)
    return {"id": new_id, "owner_sub": principal.sub}


@router.get("/whoami")
def whoami(principal: Principal = Depends(require_principal)):
    """Debug seam: shows what the token became. (Read-only, no secrets.)"""
    return {"sub": principal.sub, "roles": sorted(principal.roles),
            "scope": sorted(principal.scopes), "client_id": principal.client_id}


def _audit(cur, principal: Principal, request_id: str,
           statement: str, rows_returned: int) -> None:
    """Audit rows are log records too — statement text passes through the
    SAME redactor so a WHERE email='...' can never land raw in agent_audit."""
    from app.redact.redactor import redact_event
    from app.settings import settings
    clean = redact_event({"statement": statement}, settings.log_pepper)
    cur.execute(
        "INSERT INTO agent_audit(subject, client_id, request_id, statement,"
        " rows_returned) VALUES (%s, %s, %s, %s, %s)",
        (principal.sub, principal.client_id, request_id,
         str(clean["statement"]), rows_returned))
