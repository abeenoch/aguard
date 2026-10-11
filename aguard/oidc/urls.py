"""Where the AS is PUBLISHED vs. where it is MOUNTED.

The AS is commonly behind a reverse proxy that strips a path prefix, e.g.

    location /api/ { proxy_pass http://127.0.0.1:8080/; }   # strips "/api"

so the app only ever sees ``/authorize``, ``/login``, ... — it has no idea the
browser reached it at ``/api/authorize``. Any URL the app hands back to the
browser (a redirect target, a form ``action``) must therefore be rebuilt with
the public prefix, or the browser is sent to the ORIGIN root, where the host may
well serve something else entirely (a marketing page, another app).

The issuer is the source of truth for where clients reach us, so its path IS
that prefix. It is empty for the dev default (``http://localhost:8080``), which
keeps every call site a no-op locally.
"""
from __future__ import annotations

from urllib.parse import urlparse

from aguard.settings import settings


def public_path_prefix() -> str:
    """Path prefix the AS is published under, taken from the issuer.

    ``""`` when the issuer has no path (dev), ``"/api"`` when it does. The
    trailing slash is stripped so a config typo cannot produce a ``//`` path.
    """
    return urlparse(settings.issuer).path.rstrip("/")
