"""Test-database setup: create the throwaway DB, apply schema LOUDLY.

Why this module exists: pytest applies aguard/db/schema.sql, whose first act is
to DROP every table it defines. Historically the two schema-applying modules
ran it against ``agent_auth`` — whichever database the deployment happened to
be serving — so a pytest run on a live box wiped live data (documents, audit
rows, dynamically registered clients). It actually happened.

Now: conftest.py defaults PG_TEST_DATABASE to ``agent_auth_test`` and derives
every DB_DSN_* default from it, and THIS module is the only thing that touches
the superuser account. Two deliberate differences from the code it replaced:

* ``CREATE DATABASE`` if missing — a fresh clone needs no manual setup step,
  and idempotence means re-running the suite is always safe.
* Fail LOUD: the old call used ``check=False`` with ``ON_ERROR_STOP=0``, so a
  schema that half-applied produced confusing failures far downstream. Here a
  failed apply raises with psql's stderr attached, at the moment it happened.
"""
import os
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA = PROJECT_ROOT / "aguard" / "db" / "schema.sql"


def _superuser_env() -> dict[str, str]:
    from aguard.settings import settings
    if not settings.pg_superuser_password:
        raise RuntimeError(
            "PG_SUPERUSER_PASSWORD not set — copy .env.example to .env "
            "and fill in the superuser password (tests apply schema.sql "
            "as the superuser; application code never does)."
        )
    return dict(os.environ, PGPASSWORD=settings.pg_superuser_password)


def _psql(db: str, *args: str) -> "subprocess.CompletedProcess[bytes]":
    return subprocess.run(
        ["psql", "-U", "postgres", "-h", "localhost", "-d", db, *args],
        env=_superuser_env(), capture_output=True,
    )


def apply_schema() -> str:
    """CREATE the test database if missing, then apply schema.sql into it.

    Returns the database name (handy in messages). Raises — with psql's
    stderr, at the actual failure point — if either step fails.
    """
    test_db = os.environ.get("PG_TEST_DATABASE", "agent_auth_test")

    exists = _psql("postgres", "-tAc",
                   f"SELECT 1 FROM pg_database WHERE datname = '{test_db}'")
    if exists.returncode != 0:
        raise RuntimeError(
            "could not query pg_database: " + exists.stderr.decode())
    if exists.stdout.decode().strip() != "1":
        created = _psql("postgres", "-c", f'CREATE DATABASE "{test_db}"')
        if created.returncode != 0:
            raise RuntimeError(
                f"could not create {test_db}: " + created.stderr.decode())

    applied = _psql(test_db, "-v", f"dbname={test_db}",
                    "-v", "ON_ERROR_STOP=1", "-q", "-f", str(SCHEMA))
    if applied.returncode != 0:
        raise RuntimeError(
            f"schema.sql failed against {test_db}:\n"
            + applied.stderr.decode())
    return test_db
