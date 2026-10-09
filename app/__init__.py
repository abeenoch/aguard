"""A-guard (agent-auth-lab) package.

Importing the package loads .env FIRST (via app.settings) so every module
in the package — including ones that read os.environ directly at import
time (clients.py, users.py) — sees the same configuration regardless of
import order.
"""
from app.settings import settings as _settings  # noqa: F401
