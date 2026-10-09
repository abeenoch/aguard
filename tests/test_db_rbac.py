"""Database enforcement tests: grants, RLS, session isolation.

These tests talk to the REAL agent_auth database — the claims under test
(GRANTs, RLS, SET LOCAL semantics) only exist in Postgres, so mocking would
test nothing.

Each test re-establishes GUCs via scoped_session: exactly what the API layer
does per request. A test that leaks privileges across sessions would catch
the pool-contamination bug.
"""
from __future__ import annotations

import psycopg
import pytest

from aguard.db.session import close_pools, scoped_session

ALICE = "usr_alice"
BOB = "usr_bob"


@pytest.fixture(scope="module", autouse=True)
def _pools():
    _seed_rows()
    yield
    close_pools()


def _seed_rows() -> None:
    """Seed one row per tenant.

    These tests assert on *existing* rows, so without this they silently
    depended on data left behind by whichever module ran last — a latent
    ordering dependency that surfaced when another test module re-applied
    schema.sql mid-suite.
    """
    try:
        for sub in (ALICE, BOB):
            with scoped_session(kind="human", sub=sub) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT count(*) FROM documents WHERE owner_sub = %s",
                        (sub,))
                    if cur.fetchone()[0] == 0:
                        cur.execute(
                            "INSERT INTO documents(owner_sub, title, body) "
                            "VALUES (%s, %s, %s)", (sub, "seed-title", "seed-body"))
    except psycopg.errors.UndefinedTable:
        pytest.skip("documents table missing — apply aguard/db/schema.sql first")


def _fetch(kind, sub, sql, params=(), role_override=None):
    with scoped_session(kind=kind, sub=sub, role_override=role_override) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            try:
                return cur.fetchall()
            except psycopg.ProgrammingError:
                return []   # no result set (writes)


def test_human_sees_only_own_rows():
    alice_rows = _fetch("human", ALICE, "SELECT owner_sub FROM documents")
    assert {r[0] for r in alice_rows} == {ALICE}
    bob_rows = _fetch("human", BOB, "SELECT owner_sub FROM documents")
    assert {r[0] for r in bob_rows} == {BOB}


def test_human_can_write_own_rows():
    rows = _fetch("human", ALICE,
                  "INSERT INTO documents(owner_sub,title,body) "
                  "VALUES (%s,'t','b') RETURNING owner_sub",
                  (ALICE,))
    assert rows == [(ALICE,)]


def test_human_cannot_write_other_tenant_rows():
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        _fetch("human", ALICE,
               "INSERT INTO documents(owner_sub,title,body) "
               "VALUES (%s,'evil','b')", (BOB,))


def test_agent_can_read_own_tenant_rows():
    rows = _fetch("agent", ALICE, "SELECT owner_sub FROM documents")
    assert rows and all(r[0] == ALICE for r in rows)


def test_agent_cannot_see_other_tenant_rows():
    rows = _fetch("agent", ALICE,
                  "SELECT owner_sub FROM documents WHERE owner_sub = %s", (BOB,))
    assert rows == []


def test_agent_cannot_write():
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        _fetch("agent", ALICE,
               "INSERT INTO documents(owner_sub,title,body) "
               "VALUES (%s,'evil','b')", (ALICE,))


def test_agent_cannot_delete():
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        _fetch("agent", ALICE, "DELETE FROM documents")


def test_agent_cannot_create_tables():
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        _fetch("agent", ALICE, "CREATE TABLE pwn(id int)")


def test_agent_cannot_read_sensitive_column():
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        _fetch("agent", ALICE, "SELECT internal_notes FROM documents")


def test_agent_view_hides_sensitive_column():
    rows = _fetch("agent", ALICE,
                  "SELECT id, owner_sub, title, body FROM agent_documents")
    assert rows and all(r[1] == ALICE for r in rows)


def test_role_cannot_be_escalated_from_agent_pool():
    # app_login_agent is not a member of app_user: the database itself
    # refuses — no application code stands between attacker and this error.
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        _fetch("agent", ALICE, "SET ROLE app_user")


def test_session_state_does_not_leak_across_borrowers():
    # borrow, set nothing extra, then check the NEXT borrower is clean
    with scoped_session(kind="agent", sub=ALICE) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT current_user")
            inside = cur.fetchone()[0]
    assert inside == "agent_readonly"
    with scoped_session(kind="agent", sub=BOB) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT current_user, current_setting('app.sub')")
            user, sub = cur.fetchone()
    assert (user, sub) == ("agent_readonly", BOB)


def test_rls_predicate_column_is_indexed():
    """owner_sub is filtered on for EVERY query against documents, so it must
    be indexed — otherwise each tenant read scans every tenant's rows and the
    cost grows with other tenants' data."""
    rows = _fetch("human", ALICE,
                  "SELECT indexdef FROM pg_indexes WHERE tablename = 'documents'")
    definitions = " ".join(r[0] for r in rows)
    assert "owner_sub" in definitions, f"documents is missing an owner_sub index: {definitions!r}"
