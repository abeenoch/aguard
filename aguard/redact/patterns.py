"""Content-based PII detection: regex engine + Luhn-gated cards.

Pipeline ORDER (specific -> generic): a generic pattern must never chew a
string a specific one needed. JWTs first (a JWT contains dots and base64
that looser patterns could fragment), cards before phones (shared digits),
query-params before bare emails (key context matters), addresses before
IPv4/phones (house-number digit runs would otherwise tempt them).

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
# Free-form street addresses: house number (optionally "no/plot/flat/apt/unit"
# prefixed, or "12B/14"-style) + up to three name words + a street-type word.
# Anchored on the street-type word and refusing "the/a/an" immediately before
# it — prose like "chapter 4 covers the road" then fails, while "nos 4
# oguntunde estate", "12 Marina Road", "flat 3b, Allen Avenue" all match.
# A heuristic, not a validator like Luhn: ships as its own finding type so
# users can see exactly what it did.
_ADDRESS_STREET_TYPE = (
    r"(?:street|st|road|rd|avenue|ave|drive|dr|estate|close|lane|way|"
    r"boulevard|blvd|court|crescent|terrace|walk|place|pl)"
)
_ADDRESS_RE = re.compile(
    r"(?i)\b(?:nos?\.?\s*|plot\s+|flat\s+|apt\.?\s*|apartment\s+|unit\s+|"
    r"house\s+|#\s*)?"
    r"\d{1,5}[a-z]?(?:\s*[/,&-]\s*\d{1,5}[a-z]?)*[\s,]+"
    r"(?:[a-z][a-z'-]*[\s,]+){0,3}?"
    r"(?<!\bthe )(?<!\ba )(?<!\ban )" + _ADDRESS_STREET_TYPE + r"\b\.?"
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


#: A tag we have already emitted (``email[h:abcd…]``). Kept next to correlate()
#: so the producer and the recognizer of its output can never drift apart.
_ALREADY_CORRELATED_RE = re.compile(r"^[a-z]+\[h:[0-9a-f]{1,64}\]$")
#: Any correlation tag anywhere in the text (our own output — never re-pii).
_TAG_RE = re.compile(r"\b[a-z]+\[h:[0-9a-f]{1,64}\]")


def correlate(value: str, pepper: bytes, tag: str) -> str:
    """Keyed-HMAC correlation ID: same input -> same output, not reversible.

    Normalization before hashing is load-bearing: without it, case/whitespace
    variants of one identity hash differently and correlation is useless.

    Idempotent: if ``value`` is ALREADY a correlation tag (our own output),
    return it unchanged. redact_event() is documented as non-idempotent overall,
    but that rests on this one detail — correlate() recognizing its own result
    means a record that loses its "already done" marker is re-masked to the SAME
    tag rather than to ``email[h:…]`` nested inside another tag. So the worst
    case is a redundant pass, never corrupted output.
    """
    if _ALREADY_CORRELATED_RE.match(value.strip()):
        return value
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
    text = _ADDRESS_RE.sub("[ADDRESS_REDACTED]", text)
    text = _IPV4_RE.sub(_mask_ipv4, text)
    text = _CARD_CANDIDATE_RE.sub(lambda m: _mask_card(m.group(0)), text)
    text = _SSN_RE.sub(lambda m: "***-**-" + m.group(0)[-4:], text)
    # Correlation tags are OUR output, not PII: stash them so digit-hungry
    # passes can't nibble the digest (a 12-hex tag routinely contains a 7+
    # digit run; a second redaction pass must also be a no-op on tags).
    stash: list[str] = []

    def _stash(m: re.Match) -> str:
        stash.append(m.group(0))
        return f"\x00{len(stash) - 1}\x00"

    text = _TAG_RE.sub(_stash, text)
    text = _PHONE_RUN_RE.sub(lambda m: _mask_phone(m.group(0)), text)
    text = _EMAIL_RE.sub(lambda m: correlate(m.group(0), pepper, "email"), text)
    return re.sub(r"\x00(\d+)\x00",
                  lambda m: stash[int(m.group(1))], text)


def redact_text(text: str, pepper: bytes) -> str:
    """Full content pass: query params (key context) first, then scalars."""
    text = _QUERY_PARAM_RE.sub(lambda m: _mask_query_param(m, pepper), text)
    text = _QUERY_PARAM_RE.sub(lambda m: _mask_query_param(m, pepper), text)
    return _mask_scalars(text, pepper)


def scan_findings(text: str, pepper: bytes) -> list[dict]:
    """What WOULD redact_text() mask? Per-type counts, never the values.

    The library-level API behind the MCP ``redact_text`` tool: lets an agent
    (or an operator via ``agctl``) ask "is there anything sensitive in here?"
    BEFORE echoing or forwarding text. Each count uses the same detector the
    redaction pass uses — including the validators (Luhn for cards, date/order
    exclusion for phones, octet range for IPv4) — so "found: 1 card" always
    means "redact_text() will mask exactly one card".

    Counts mirror what redact_text() actually masks: detection runs
    progressively over the text as each pattern is applied, so a card's digit
    run is never also counted as a phone and an email tag is never re-counted.
    The one documented overlap: an email inside a URL query param counts as
    both ``query_param`` and ``email``.
    """
    hits: list[tuple[str, int]] = []

    def add(name: str, n: int) -> None:
        if n:
            hits.append((name, n))

    add("jwt", len(_JWT_RE.findall(text)))
    add("aws_key", len(_AWS_RE.findall(text)))
    add("bearer_token", len(_BEARER_RE.findall(text)))
    add("secret_assignment", len(_BARE_SECRET_ASSIGN_RE.findall(text)))
    # Progressive staging: count each detector against the text as the
    # redaction pass leaves it, so counts == what actually gets masked.
    staged = _ADDRESS_RE.sub("[ADDRESS_REDACTED]", text)
    add("address", len(_ADDRESS_RE.findall(text)))
    add("ipv4", sum(1 for m in _IPV4_RE.finditer(staged)
                    if _mask_ipv4(m) != m.group(0)))
    staged = _IPV4_RE.sub(_mask_ipv4, staged)
    add("card", sum(1 for m in _CARD_CANDIDATE_RE.finditer(staged)
                    if _mask_card(m.group(0)) != m.group(0)))
    staged = _CARD_CANDIDATE_RE.sub(lambda m: _mask_card(m.group(0)), staged)
    add("ssn", len(_SSN_RE.findall(staged)))
    staged = _SSN_RE.sub(lambda m: "***-**-" + m.group(0)[-4:], staged)
    add("phone", sum(1 for m in _PHONE_RUN_RE.finditer(staged)
                     if _mask_phone(m.group(0)) != m.group(0)))
    staged = _PHONE_RUN_RE.sub(lambda m: _mask_phone(m.group(0)), staged)
    add("email", len(_EMAIL_RE.findall(staged)))
    add("query_param", sum(1 for m in _QUERY_PARAM_RE.finditer(text)
                           if _mask_query_param(m, pepper) != m.group(0)))
    return [{"type": name, "count": n} for name, n in hits]
    return _mask_scalars(text, pepper)
