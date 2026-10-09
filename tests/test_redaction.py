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

