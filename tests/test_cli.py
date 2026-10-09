"""The operator CLI (scripts/agctl.py).

The redaction commands are pure and fast; the audit commands read Postgres
through the same least-privilege session layer the API uses.

The CLI is loaded by path (scripts/ is not a package), which is exactly how a
user runs it: `python scripts/agctl.py ...`.
"""
from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest

from app.db.session import close_pools, scoped_session

ROOT = Path(__file__).resolve().parents[1]


def _load_agctl():
    spec = importlib.util.spec_from_file_location("agctl",
                                                  ROOT / "scripts" / "agctl.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)          # type: ignore[union-attr]
    return module


agctl = _load_agctl()


def _run(argv, monkeypatch, stdin_text=None):
    """Invoke main() with captured stdio."""
    if stdin_text is not None:
        monkeypatch.setattr(sys, "stdin", io.StringIO(stdin_text))
    return agctl.main(argv)


# ------------------------------ redaction ----------------------------------


def test_redact_text_masks_email_card_and_ip(capsys, monkeypatch):
    assert _run(["redact", "alice@example.com", "4111", "1111", "1111", "1111"],
                monkeypatch) == 0
    out = capsys.readouterr().out
    assert "email[h:" in out
    assert "****-****-****-1111" in out
    assert "alice@example.com" not in out


def test_redact_json_object_masks_by_key(capsys, monkeypatch):
    payload = json.dumps({"email": "a@b.com", "api_key": "sk-live",
                          "order_id": "A-1"})
    assert _run(["redact", "--json", "-"], monkeypatch, payload) == 0
    out = capsys.readouterr().out
    assert "email[h:" in out
    assert "[REDACTED]" in out
    assert "A-1" in out                    # non-PII survives


def test_redact_rejects_non_object_json(capsys, monkeypatch):
    assert _run(["redact", "--json", "123"], monkeypatch) == 2
    assert "expects a JSON object" in capsys.readouterr().err


def test_redact_file_line_by_line(capsys, tmp_path, monkeypatch):
    log = tmp_path / "access.log"
    log.write_text("GET /u?email=alice@example.com\nplain line\n", encoding="utf-8")
    assert _run(["redact", "--file", str(log)], monkeypatch) == 0
    out = capsys.readouterr().out
    assert "email[h:" in out
    assert "plain line" in out


def test_verify_self_check_passes():
    assert agctl.main(["verify"]) == 0


# -------------------------------- audit ------------------------------------


@pytest.fixture(scope="module", autouse=True)
def _schema():
    # Deliberately DOES NOT apply schema.sql: that DROPs and recreates tables,
    # which would wipe rows other modules in the suite depend on. We only
    # require the schema to already exist (as test_db_rbac does).
    try:
        with scoped_session(kind="human", sub="usr_agctl_probe") as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM agent_audit LIMIT 1")
    except Exception:                                    # pragma: no cover
        pytest.skip("agent_audit missing — apply app/db/schema.sql first")
    yield
    close_pools()


def test_fetch_audit_reads_rows_newest_first():
    with scoped_session(kind="human", sub="usr_agctl_test") as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO agent_audit(subject, client_id, request_id,"
                " statement, rows_returned) VALUES (%s,%s,%s,%s,%s)",
                ("usr_agctl_test", "cli-test", "rid-1", "selftest op", 0))
    rows = agctl._fetch_audit(limit=5, sub="usr_agctl_test")
    assert rows and rows[0][2] == "usr_agctl_test"
    assert rows[0][6] == 0                       # rows_returned


def test_audit_denied_filter_only_zero_row_ops(capsys, monkeypatch):
    assert agctl.main(["audit", "--denied", "--limit", "50",
                       "--sub", "usr_agctl_test"]) == 0
    out = capsys.readouterr().out
    assert "selftest op" in out


# ---------------------------------- init -----------------------------------


def test_read_env_file_parses_and_ignores_comments(tmp_path):
    path = tmp_path / ".env"
    path.write_text('# comment\n\nA=1\nB="two"\nC=\n', encoding="utf-8")
    assert agctl._read_env_file(path) == {"A": "1", "B": "two", "C": ""}


def test_read_env_file_missing_is_empty(tmp_path):
    assert agctl._read_env_file(tmp_path / "nope") == {}


def test_write_env_file_generates_real_secrets(tmp_path):
    example = tmp_path / ".env.example"
    example.write_text("# template\nPG_SUPERUSER_PASSWORD=\n# SESSION_SECRET=\n",
                       encoding="utf-8")
    out = tmp_path / ".env"
    agctl._write_env_file(out, example, "s3cret")
    text = out.read_text(encoding="utf-8")
    values = agctl._read_env_file(out)

    # substituted, not appended: first-occurrence-wins in the dotenv loader
    assert values["PG_SUPERUSER_PASSWORD"] == "s3cret"
    assert text.count("PG_SUPERUSER_PASSWORD=s3cret") == 1
    assert len(values["SESSION_SECRET"]) == 64          # token_hex(32)
    assert len(values["LOG_HASH_PEPPER"]) == 64
    assert values["SESSION_SECRET"] != values["LOG_HASH_PEPPER"]
    for placeholder in ("dev-session-secret-change-me", "dev-only-pepper-change-me"):
        assert placeholder not in text


def test_write_env_file_without_password_keeps_template_placeholder(tmp_path):
    example = tmp_path / ".env.example"
    example.write_text("PG_SUPERUSER_PASSWORD=\n", encoding="utf-8")
    out = tmp_path / ".env"
    agctl._write_env_file(out, example, None)
    values = agctl._read_env_file(out)
    assert values["PG_SUPERUSER_PASSWORD"] == ""        # still unset
    assert len(values["SESSION_SECRET"]) == 64          # but secrets are real
