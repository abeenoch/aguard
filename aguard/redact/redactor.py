"""Structural redaction: the recursive walker + the fail-closed choke point.

Key-over-content: when a field name says EMAIL and content says "no PII
here", the KEY wins (mask it); when content says "alice@x.com" under a
meaningless key, CONTENT wins (mask it). And when the walker itself breaks,
the whole record dies (fail closed — never fail open).
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from aguard.redact.patterns import (
    CARD_KEY_RE,
    EMAIL_KEY_RE,
    NAME_KEY_RE,
    PHONE_KEY_RE,
    SECRET_KEY_RE,
    correlate,
    redact_text,
)

MAX_DEPTH = 10       # deeper = suspicious; crafted payloads stay landable
MAX_STRING = 100_000  # beyond this, treat as blob (never walk partial)


def _redact_value(value: Any, key: str | None, pepper: bytes,
                  depth: int, seen: set[int]) -> Any:
    """One node of the walk. Order: key rules -> type rules -> content rules."""
    if depth > MAX_DEPTH:
        return "[REDACTED:depth]"
    if key is not None and SECRET_KEY_RE.search(key):
        return "[REDACTED]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if len(value) > MAX_STRING:
            return "[REDACTED:oversize]"
        if key is not None:
            if EMAIL_KEY_RE.search(key):
                return correlate(value, pepper, "email")
            if PHONE_KEY_RE.search(key):
                return "***-***-" + "".join(c for c in value if c.isdigit())[-4:] \
                    if value.strip() else value
            if CARD_KEY_RE.search(key):
                digits = "".join(c for c in value if c.isdigit())
                return ("****-****-****-" + digits[-4:]
                        if len(digits) >= 4 else "[REDACTED]")
            if NAME_KEY_RE.search(key):
                return "[REDACTED]"
        if value.lstrip().startswith(("{", "[")):
            try:
                nested = json.loads(value)
            except ValueError:
                pass
            else:
                if isinstance(nested, (dict, list)):
                    walked = _redact_value(nested, key, pepper, depth + 1, seen)
                    return json.dumps(walked, default=str)
        return redact_text(value, pepper)
    if isinstance(value, Mapping):
        if id(value) in seen:
            return "[REDACTED:cyclic]"
        seen.add(id(value))
        try:
            return {
                k: _redact_value(v, str(k), pepper, depth + 1, seen)
                for k, v in value.items()
            }
        finally:
            seen.discard(id(value))
    if isinstance(value, (list, tuple)):
        walked = [_redact_value(v, key, pepper, depth + 1, seen) for v in value]
        return walked if isinstance(value, list) else tuple(walked)
    return value  # dates, UUIDs, enums: formatting happens downstream


def redact_event(event: Mapping[str, Any], pepper: bytes) -> dict:
    """Redact a whole log event. NOT idempotent (correlate() is, tagging
    isn't) — always run on raw events, never on already-redacted ones."""
    return _redact_value(dict(event), None, pepper, 0, set())
