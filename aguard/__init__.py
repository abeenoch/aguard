"""A-guard package.

Importing the package loads .env FIRST (via aguard.settings) so every module
in the package — including ones that read os.environ directly at import
time (clients.py, users.py) — sees the same configuration regardless of
import order.

Public surface for resource servers:

    from aguard import ResourceServerGuard     # protects YOUR MCP server

Resolved lazily (PEP 562) so that importing the package — or running the CLI —
does not drag in FastAPI for users who only want the redaction helpers.
"""
from aguard.settings import settings as _settings  # noqa: F401

__all__ = ["ResourceServerGuard", "TokenError"]


def __getattr__(name: str):
    if name in __all__:
        from aguard import resource_server
        return getattr(resource_server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

