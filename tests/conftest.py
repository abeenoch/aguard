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
}.items():
    os.environ.setdefault(_name, _value)
