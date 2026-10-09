"""Content-based PII detection: regex engine + Luhn-gated cards.

Pipeline ORDER (specific -> generic): a generic pattern must never chew a
string a specific one needed. JWTs first (a JWT contains dots and base64
that looser patterns could fragment), cards before phones (shared digits),
query-params before bare emails (key context matters).

Every replacement preserves *type* information (`email[h:…]`,
`****-****-****-1111`) so support can still recognize records and analytics
can still count shapes — while learning nothing about the person.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from urllib.parse import unquote

_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.IGNORECASE
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")
_AWS_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ \-.]*?){13,19}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE_RUN_RE = re.compile(r"(?<!\w)(?<![\w]-)(?:\+?\d[ \-.()]*?){7,16}(?!\d)")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9\-._~+/=]{8,}\b")
# Bare key=value secrets in free text (config dumps, debug prints, DSNs):
# "password=hunter2", "api_key: sk-live-9f3a". Value class excludes leading
# "[" so already-redacted markers are never re-processed.
_BARE_SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b(password|passwd|secret|api[_-]?key|client_secret|"
    r"code_verifier|authorization|cookie)\s*[:=]\s*\"?[^\s\"',;}\[]+\"?"
)
_QUERY_PARAM_RE = re.compile(r"([?&])([A-Za-z_][\w.\-]*)=([^&\s'\"<>]*)")
_DATE_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?$")

# Key names that MEAN PII, wherever they appear (case-insensitive).
SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|client_secret|"
    r"code_verifier|authorization|cookie|set-cookie|x-api-key|cvv|cvc)$",
    re.IGNORECASE,
)
EMAIL_KEY_RE = re.compile(r"e-?mail$", re.IGNORECASE)
PHONE_KEY_RE = re.compile(r"(phone|mobile|tel(ephone)?|fax)$", re.IGNORECASE)
CARD_KEY_RE = re.compile(r"(card(_?number)?|pan)$", re.IGNORECASE)
# Name-like fields — but NOT identifiers: `username`, `user`, `sub`,
# `user_id` stay readable (needed for joins, not identifying alone).
NAME_KEY_RE = re.compile(
    r"^(?!username$|user$|user_id$|id$|sub$)"
    r"((first|last|full|display|given|family)_?name|^name$|address|city|dob|"
    r"date_of_birth|ssn|social_security)$",
    re.IGNORECASE,
)


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def correlate(value: str, pepper: bytes, tag: str) -> str:
    """Keyed-HMAC correlation ID: same input -> same output, not reversible.

    Normalization before hashing is load-bearing: without it, case/whitespace
    variants of one identity hash differently and correlation is useless."""
    normalized = value.strip().lower()
    digest = hmac.new(pepper, normalized.encode("utf-8"), hashlib.sha256)
    return f"{tag}[h:{digest.hexdigest()[:12]}]"


def _mask_card(candidate: str) -> str:
    digits = re.sub(r"\D", "", candidate)
    if not (13 <= len(digits) <= 19):
        return candidate
    if not _luhn_ok(digits):          # regex alone false-positives on hashes
        return candidate
    return "****-****-****-" + digits[-4:]


def _mask_phone(candidate: str) -> str:
    digits = re.sub(r"\D", "", candidate)
    if _DATE_ISO_RE.match(candidate.strip()):
        return candidate                                # invoice dates survive
    if len(digits) < 7 or len(digits) > 15:
        return candidate
    if len(digits) <= 8 and not re.search(r"[ \-.()+]", candidate):
        # bare short digit runs (order ids, yyyymmdd) are NOT phones
        return candidate
    return "***-***-" + digits[-4:]


def _mask_ipv4(match: re.Match) -> str:
    octets = match.group(0).split(".")
    if all(o.isdigit() and int(o) <= 255 for o in octets):
        return "[IP_REDACTED]"
    return match.group(0)          # 999.999.999.999 is not an address


def _mask_query_param(match: re.Match, pepper: bytes) -> str:
    sep, key, value = match.groups()
    if SECRET_KEY_RE.search(key):
        return f"{sep}{key}=[REDACTED]"
    if EMAIL_KEY_RE.search(key) or _EMAIL_RE.fullmatch(value):
        return f"{sep}{key}={correlate(value, pepper, 'email')}"
    if NAME_KEY_RE.search(key):
        return f"{sep}{key}=[REDACTED]"
    masked_value = _mask_scalars(value, pepper)
    if masked_value != value:
        return f"{sep}{key}={masked_value}"
    # Percent-encoding hides PII from every pattern above: '@' is %40, '?'
    # is %3F. Decode BEFORE pattern matching or access logs leak "encoded"
    # PII that trivially decodes back (Phase 1 live finding).
    decoded = unquote(value)
    if decoded != value:
        masked_decoded = _mask_scalars(decoded, pepper)
        if masked_decoded != decoded:
            return f"{sep}{key}={masked_decoded}"
    return match.group(0)



def _mask_scalars(text: str, pepper: bytes) -> str:
    """Pattern-only pass (no URL handling — avoids self-recursion).

    Order: most-specific first, so a generic rule can never fragment input a
    specific rule needed (IPv4 before phones: 203.0.113.42 is an address,
    not "203.0.113"+"suspicious suffix")."""
    text = _JWT_RE.sub("[JWT_REDACTED]", text)
    text = _AWS_RE.sub("[AWS_KEY_REDACTED]", text)
    text = _BEARER_RE.sub(lambda m: f"{m.group(1)} [REDACTED]", text)
    text = _BARE_SECRET_ASSIGN_RE.sub(
        lambda m: f"{m.group(1)}=[REDACTED]", text)
    text = _IPV4_RE.sub(_mask_ipv4, text)
    text = _CARD_CANDIDATE_RE.sub(lambda m: _mask_card(m.group(0)), text)
    text = _SSN_RE.sub(lambda m: "***-**-" + m.group(0)[-4:], text)
    text = _EMAIL_RE.sub(lambda m: correlate(m.group(0), pepper, "email"), text)
    text = _PHONE_RUN_RE.sub(lambda m: _mask_phone(m.group(0)), text)
    return text


def redact_text(text: str, pepper: bytes) -> str:
    """Full content pass: query params (key context) first, then scalars."""
    text = _QUERY_PARAM_RE.sub(lambda m: _mask_query_param(m, pepper), text)
    return _mask_scalars(text, pepper)
