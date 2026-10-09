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
}.items():
    os.environ.setdefault(_name, _value)
