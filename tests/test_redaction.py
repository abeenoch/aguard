"""PII redaction tests: fixture-driven contract + adversarial properties.

Two documents of record live in tests/fixtures/:
- redact_must_catch.json      every case must be scrubbed (add new attacks HERE)
- redact_must_not_catch.json  every case must pass through byte-identical

To cover a new attack: append a fixture, watch it fail, harden the engine.
"""
from __future__ import annotations

import io
import json
import logging
from pathlib import Path

import pytest

from aguard.redact.logging import RedactionFilter, install
from aguard.redact.patterns import correlate
from aguard.redact.redactor import redact_event

PEPPER = b"test-pepper-do-not-use"
FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _flatten(node) -> str:
    if isinstance(node, str):
        return node
    if isinstance(node, dict):
        return " ".join(_flatten(v) for v in node.values())
    if isinstance(node, (list, tuple)):
        return " ".join(_flatten(v) for v in node)
    return str(node)


@pytest.mark.parametrize("case", _load("redact_must_catch.json"),
                         ids=lambda c: c["name"])
def test_fixture_must_be_caught(case):
    out = redact_event({"event": case["in"]} if not isinstance(case["in"], dict)
                       else case["in"], PEPPER)
    rendered = _flatten(out)
    for forbidden in case["not"]:
        assert forbidden not in rendered, (
            f"{case['name']}: raw PII leaked -> {forbidden!r}")
    for required in case["has"]:
        assert required in rendered, (
            f"{case['name']}: expected marker missing -> {required!r}")


def test_list_argument_is_redacted_instead_of_dropping_the_record():
    """A list logging argument must be WALKED, not handed to the mapping-only
    redactor: redact_event() does dict(event), which raises on a list, and the
    fail-closed handler turns that into [LOG_DROPPED] — a legitimate log line
    silently disappearing. The mypy gate caught this one."""
    stream = io.StringIO()
    name = "a-guard.test.list-arg"
    logger = logging.getLogger(name)
    logger.handlers.clear()
    logger.addHandler(logging.StreamHandler(stream))
    install(name, PEPPER)

    logger.info("items: %s", ["alice@example.com", "order-123"])

    rendered = stream.getvalue()
    assert "[LOG_DROPPED" not in rendered, rendered
    assert "alice@example.com" not in rendered, rendered
    assert "email[h:" in rendered           # scrubbed, not vanished
    assert "order-123" in rendered          # structure and safe content kept


@pytest.mark.parametrize("case", _load("redact_must_not_catch.json"),
                         ids=lambda c: c["name"])
def test_fixture_must_not_be_caught(case):
    out = redact_event({"event": case["value"]}, PEPPER)
    assert out == {"event": case["value"]}, (
        f"{case['name']}: false positive — {out!r}")


# -- properties ------------------------------------------------------------


def test_correlation_is_deterministic_and_normalized():
    a = correlate("Alice@Example.com ", PEPPER, "email")
    b = correlate("alice@example.com", PEPPER, "email")
    c = correlate("bob@example.com", PEPPER, "email")
    assert a == b                      # normalization before hashing
    assert a != c                      # distinct identities stay distinct
    assert "alice" not in a            # not reversible from the marker


def test_deterministic_hash_stable_across_calls():
    first = redact_event({"email": "sam@example.com"}, PEPPER)
    second = redact_event({"from": "wrote sam@example.com"}, PEPPER)
    import re
    hashes = set(re.findall(r"email\[h:([0-9a-f]{12})\]", str([first, second])))
    assert len(hashes) == 1            # key-rule and content-rule agree


def test_cyclic_objects_do_not_crash():
    evil: dict = {"a": 1}
    evil["self"] = evil
    out = redact_event({"payload": evil}, PEPPER)
    assert "[REDACTED:cyclic]" in str(out)


def test_deep_nesting_is_capped():
    nested: object = "alice@example.com"
    for _ in range(30):
        nested = {"layer": nested}
    out = redact_event({"payload": nested}, PEPPER)
    assert "alice@example.com" not in str(out)


def test_redactor_never_throws_on_hostile_input():
    hostile = {"k": object(), "n": float("nan"),
               "deep": [[[[{"email": "z@example.com"}]]]]}
    out = redact_event(hostile, PEPPER)   # must not raise
    assert "z@example.com" not in str(out)


def test_log_record_dict_msg_is_redacted_pre_format():
    logger = logging.getLogger("test-choke-dict")
    logger.handlers = []
    logger.addFilter(RedactionFilter(PEPPER))
    captured: list[str] = []

    class Cap(logging.Handler):
        def emit(self, record):
            captured.append(record.getMessage())

    logger.addHandler(Cap())
    logger.setLevel(logging.INFO)
    logger.info({"user_email": "amy@example.com", "order_id": "ORD-1"})
    assert "amy@example.com" not in captured[0]
    assert "ORD-1" in captured[0]
    assert "email[h:" in captured[0]


def test_structured_args_mapping_is_redacted():
    logger = logging.getLogger("test-choke-args")
    logger.handlers = []
    logger.addFilter(RedactionFilter(PEPPER))
    captured: list[str] = []

    class Cap(logging.Handler):
        def emit(self, record):
            captured.append(record.getMessage())

    logger.addHandler(Cap())
    logger.setLevel(logging.INFO)
    logger.info("payment %(action)s", {"action": "card 4111111111111111 billed"})
    assert "4111111111111111" not in captured[0]
    assert "****-****-****-1111" in captured[0]


def test_install_is_idempotent_and_keeps_existing_records_clean():
    logger = logging.getLogger("test-install")
    logger.handlers = []
    stream_records: list[str] = []

    class Cap(logging.Handler):
        def emit(self, record):
            stream_records.append(self.format(record))

    handler = Cap()
    logger.addHandler(handler)
    install("test-install", PEPPER)    # adds filter + JSON formatter
    install("test-install", PEPPER)    # second call must not double-install
    logger.warning("leak bob@example.com and password=hunter2")
    line = stream_records[0]
    assert "bob@example.com" not in line
    assert "hunter2" not in line
    import json as _json
    parsed = _json.loads(line)          # valid single-line JSON
    assert parsed["level"] == "WARNING"
    assert "email[h:" in parsed["msg"]


def test_filter_failure_emits_degraded_marker_not_raw():
    # %-format mismatch (2 placeholders, 1 arg) raises INSIDE the filter.
    # The degraded marker must appear *instead of* the raw message — the one
    # place the user's unsanitized PII sat.
    record = logging.LogRecord("x", logging.INFO, __file__, 1,
                               "leak alice@example.com %s %s", ("one",), None)
    f = RedactionFilter(PEPPER)
    assert f.filter(record) is True
    assert record.msg == "[LOG_DROPPED: redactor_error]"
    assert "alice" not in record.msg


# ------------------------------ scan_findings ------------------------------


def test_scan_findings_counts_match_what_redact_text_masks():
    from aguard.redact.patterns import redact_text, scan_findings
    text = ("card 4111 1111 1111 1111, mail bob@example.com, "
            "from 203.0.113.42, page /login?next=carol@s.com")
    findings = {f["type"]: f["count"] for f in scan_findings(text, PEPPER)}
    assert findings["card"] == 1
    assert findings["email"] == 2      # one bare + one in the query param
    assert findings["ipv4"] == 1
    assert findings["query_param"] >= 1
    masked = redact_text(text, PEPPER)
    assert "4111 1111 1111 1111" not in masked
    assert "bob@example.com" not in masked
    assert "203.0.113.42" not in masked


def test_scan_findings_never_returns_values():
    """The report is for COUNTS — the raw values must not leak through it."""
    from aguard.redact.patterns import scan_findings
    text = "secret password=hunter2 card 5555555555554444"
    report = str(scan_findings(text, PEPPER))
    assert "hunter2" not in report
    assert "5555555555554444" not in report


def test_scan_findings_validators_apply():
    """Luhn-invalid 16-digit runs and future dates are not findings."""
    from aguard.redact.patterns import scan_findings
    text = "order 1234567812345678 due 2026-10-11"
    assert scan_findings(text, PEPPER) == []


def test_scan_findings_clean_text_is_empty():
    from aguard.redact.patterns import scan_findings
    assert scan_findings("nothing to see here", PEPPER) == []


# --------------------------- address detection -----------------------------


def test_address_pattern_catches_real_forms():
    from aguard.redact.patterns import redact_text, scan_findings
    for text in ("my address is nos 4 oguntunde estate",
                 "I live at 12 Marina Road",
                 "flat 3b, Allen Avenue, Lagos",
                 "Plot 14, Adeola Odeku Street",
                 "send it to 45B/2 Unity Crescent"):
        findings = {f["type"]: f["count"] for f in scan_findings(text, PEPPER)}
        assert findings.get("address") == 1, text
        assert "[ADDRESS_REDACTED]" in redact_text(text, PEPPER), text


def test_address_pattern_leaves_prose_alone():
    """The street-word anchor must not fire on everyday sentences."""
    from aguard.redact.patterns import redact_text, scan_findings
    for text in ("chapter 4 covers the road",
                 "we drove 40 miles per hour down the drive",
                 "there is no 4 in the list",
                 "take exit 7 then turn around"):
        assert scan_findings(text, PEPPER) == [], text
        assert redact_text(text, PEPPER) == text, text


def test_email_tag_not_nibbled_by_phone_pass():
    """A digit-heavy email tag must survive the phone detector — the tag is
    our own output, not PII (live finding from a card+email chat message)."""
    from aguard.redact.patterns import redact_text
    masked = redact_text("mail alice1234567@example.com now", PEPPER)
    tag = masked.split()[1]
    assert tag.startswith("email[h:") and tag.endswith("]")
    inner = tag[len("email[h:"):-1]
    assert "***" not in inner, "phone pass chewed the correlation tag"


def test_scan_counts_match_actual_masking():
    """A card's digit run must count as a card, not also as two phones."""
    from aguard.redact.patterns import scan_findings
    text = "card 4111 1111 1111 1111 and bob@example.com"
    findings = {f["type"]: f["count"] for f in scan_findings(text, PEPPER)}
    assert findings.get("card") == 1
    assert "phone" not in findings

