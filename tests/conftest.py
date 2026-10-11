"""Suite-wide test configuration.

Why this file exists: every test module imports the SAME app object
(``from aguard.main import app``), so the rate limiter inside it accumulates
the requests of the entire run — a couple of hundred, all from the
TestClient's single peer address, which is far more than one human at a
browser ever makes and all inside one 60s window. With the production
defaults the suite would throttle itself, and the failures would read "429"
instead of naming the real bug.

So the counts are raised here, and the limiter's own behaviour is covered
deliberately in tests/test_rate_limit.py, which swaps a strict limiter into
app.state and restores it afterwards. No production default is asserted here.

os.environ must be populated BEFORE aguard.settings is imported: Settings is a
frozen dataclass built at import time. pytest imports conftest before any test
module, which makes this the only place it can happen.
"""
import os

import pytest

# setdefault, not assignment: an explicit override (CI, a debugging shell)
# still wins over these.
for _name, _value in {
    "RATE_LIMIT_TOKEN": "1000000",
    "RATE_LIMIT_LOGIN": "1000000",
    "RATE_LIMIT_LOGIN_ACCOUNT": "1000000",
    "RATE_LIMIT_REGISTER": "1000000",
    # /readyz reuses its result for a second by default. Tests assert on
    # individual probes, so a cached answer from an earlier test would make
    # them order-dependent — disable the cache here and cover it explicitly in
    # tests/test_rate_limit.py (test_readyz_reuses_its_result_briefly).
    "READYZ_CACHE_SECONDS": "0",
    # Pin the limiter backend for the suite regardless of the ambient .env:
    # these tests assert the in-process DEFAULT, and a developer running with
    # RATE_LIMIT_BACKEND=postgres must not see them fail. The shared backend is
    # covered on its own terms in tests/test_rate_limit_shared.py.
    "RATE_LIMIT_BACKEND": "memory",
    # Pin the authorization/user stores for the suite too. test_integration and
    # test_mcp_resource_server re-apply schema.sql per module for a deterministic
    # start, and schema.sql DROPs every table — including `users`. A DB-backed
    # directory would lose its seeded accounts mid-run and every later /login
    # would 401. Memory keeps the directory process-local (with its seeded demo
    # users), which is also the code's own default. The durable backends are
    # covered on their own terms in tests/test_stores_persistence.py.
    "STORE_BACKEND": "memory",
    # Pin the issuer/resource set so the suite does not depend on how a given
    # deployment is exposed. Tests describe the code's behaviour; a host serving
    # an http issuer on a public IP (fine for a demo, refused by the DCR
    # redirect policy for dynamic clients) would otherwise change their outcome.
    # ALLOWED_RESOURCES must move with these — they are coupled.
    "OIDC_ISSUER": "http://localhost:8080",
    "MCP_RESOURCE_URL": "http://localhost:8081",
    "MCP_RESOURCE_ID": "http://localhost:8081/mcp",
    "ALLOWED_RESOURCES": ("http://localhost:8081/mcp,"
                          "http://localhost:8080/api"),
    # Test-database isolation. pytest applies schema.sql, which DROPs every
    # table it defines — pointing that at a deployment database destroys it
    # (this exact accident wiped the production box's documents mid-session).
    # So the suite defaults to a DEDICATED throwaway database: the schema-
    # applying modules create it (tests/dbutil.py) and every DB-touching test
    # reads its DSNs from here, so nothing in a run can touch the live data.
    # Set PG_TEST_DATABASE=agent_auth to restore the old shared-DB behaviour,
    # or point DB_DSN_* explicitly if you have your own arrangement.
    "PG_TEST_DATABASE": "agent_auth_test",
}.items():
    os.environ.setdefault(_name, _value)

# Derive the pool DSNs from the test-database choice BEFORE aguard.settings is
# imported (its frozen Settings reads these). Only the DEFAULTS are rewritten:
# an explicitly set DB_DSN_* is an operator's own arrangement and wins, which
# is exactly what setdefault semantics give us here.
_test_db = os.environ["PG_TEST_DATABASE"]
for _name, _default in (
    ("DB_DSN_HUMAN",
     "postgresql://app_login_human:human-pool-secret-dev@localhost:5432/agent_auth"),
    ("DB_DSN_AGENT",
     "postgresql://app_login_agent:agent-pool-secret-dev@localhost:5432/agent_auth"),
    ("DB_DSN_AUTH",
     "postgresql://app_login_auth:auth-pool-secret-dev@localhost:5432/agent_auth"),
):
    os.environ.setdefault(
        _name, _default.replace("/agent_auth", f"/{_test_db}"))


@pytest.fixture(scope="session", autouse=True)
def _ensure_test_database():
    """Apply schema.sql into the throwaway test database, once, up front.

    Why session scope: alphabetical module order used to decide whether the
    DB-backed modules ran at all. test_db_rbac connects before
    test_integration — the module whose fixture calls dbutil.apply_schema —
    so on a fresh CI runner the test database did not exist yet and every
    pool in it burned a 30s timeout before failing. Creating the schema here,
    before any module runs, makes collection order irrelevant.

    The failure path is deliberate: if there is no reachable Postgres (or no
    superuser password), the DB-backed modules still skip via their own
    table-existence checks, exactly as they did before this fixture existed.
    """
    try:
        from dbutil import apply_schema
        apply_schema()
    except Exception:
        pass
    yield
