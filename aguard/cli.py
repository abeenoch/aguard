"""a-guard operator CLI — observability without a privileged web surface.

A dashboard would mean a new authenticated surface spanning tenants, i.e. the
one screen that could violate the guarantee this project exists to provide.
Everything an operator needs is already reachable from the command line:

  agctl init                                 bootstrap .env + DB + schema, then
                                             verify the enforcement model holds

  agctl redact "call alice@example.com"      what the redactor does to a string
  agctl redact --file access.log             redact a log file line by line
  agctl redact -                             read from stdin (pipe a log in)
  agctl redact --json '{"email":"a@b.com"}'  structural walk (key + content)
  agctl verify                               built-in redaction self-check
  agctl audit  [--sub S] [--denied] [--json] the audit trail, newest first
  agctl export [--format jsonl|csv]          dump the trail for shipping

Stdlib only (argparse, no new dependency) — matches the project's "boring
stack" principle. The redaction commands need no database; the audit commands
read Postgres through the same least-privilege session layer the API uses.

Exposed as the `agctl` console script by `pip install a-guard`, and runnable
from a checkout as `python -m aguard.cli` (scripts/agctl.py is a thin shim, so the
`python scripts/agctl.py ...` form used in the docs keeps working).
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

from aguard.db import __file__ as _db_package_file
from aguard.db.session import scoped_session
from aguard.redact.patterns import correlate, redact_text
from aguard.redact.redactor import redact_event
from aguard.settings import settings

# The schema ships INSIDE the package (see [tool.setuptools.package-data]), so
# an installed agctl finds it without needing a source checkout.
SCHEMA_PATH = Path(_db_package_file).resolve().parent / "schema.sql"

AUDIT_COLUMNS = ("id", "ts", "subject", "client_id", "request_id",
                 "statement", "rows_returned")


# --------------------------------- redact ---------------------------------


def cmd_redact(args: argparse.Namespace) -> int:
    pepper = settings.log_pepper

    if args.json is not None:
        raw = sys.stdin.read() if args.json == "-" else args.json
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            print(f"not valid JSON: {exc}", file=sys.stderr)
            return 2
        if not isinstance(payload, dict):
            print("--json expects a JSON object", file=sys.stderr)
            return 2
        print(json.dumps(redact_event(payload, pepper), indent=2))
        return 0

    source = args.file
    if source is None and args.text == ["-"]:
        source = "-"                      # `agctl redact -` reads stdin
    if source:
        try:
            stream = (sys.stdin if source == "-"
                      else Path(source).open(encoding="utf-8", errors="replace"))
        except OSError as exc:
            print(f"cannot read {source}: {exc}", file=sys.stderr)
            return 2
        with stream:
            for line in stream:
                print(redact_text(line.rstrip("\n"), pepper))
        return 0

    if not args.text:
        print("nothing to redact — pass text, --file, or '-' for stdin",
              file=sys.stderr)
        return 2
    print(redact_text(" ".join(args.text), pepper))
    return 0


# --------------------------------- verify ---------------------------------

# Canonical cases: each is PII the log layer must never emit in the clear.
_VERIFY_CASES = (
    ("email",            "alice@example.com",              "email[h:"),
    ("email in prose",   "ping alice@example.com now",     "email[h:"),
    ("luhn card",        "4111111111111111",               "****-****-****-1111"),
    ("spaced card",      "4111 1111 1111 1111",            "****-****-****-1111"),
    ("jwt",              "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123",
                         "[JWT_REDACTED]"),
    ("secret field",     json.dumps({"api_key": "sk-live-9"}), "[REDACTED]"),
    ("email field",      json.dumps({"email": "x@y.com"}),     "email[h:"),
)


def cmd_verify(_: argparse.Namespace) -> int:
    pepper = settings.log_pepper
    failures = 0
    for name, raw, must_contain in _VERIFY_CASES:
        # A bare digit run ("4111111111111111") parses as a NUMBER, not an
        # object — only route real JSON objects through the structural walker.
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            out = json.dumps(redact_event(parsed, pepper))
        else:
            out = redact_text(raw, pepper)
        ok = must_contain in out
        failures += 0 if ok else 1
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {out}")

    # Correlatable but not reversible: same identity -> same token, even when
    # case or surrounding whitespace differs (normalisation happens before
    # hashing — without it, correlation would be useless in practice).
    a = correlate("alice@example.com", pepper, "email")
    b = correlate("ALICE@Example.com ", pepper, "email")
    same = a == b
    failures += 0 if same else 1
    print(f"[{'PASS' if same else 'FAIL'}] correlation stable across case/spacing: {a} == {b}")

    print(f"\n{'all redaction checks passed' if not failures else f'{failures} FAILED'}")
    return 1 if failures else 0


# ------------------------------ audit / export -----------------------------


def _fetch_audit(*, limit: int, sub: str | None = None,
                 denied: bool = False) -> list[tuple]:
    """Read the audit trail through the SAME least-privilege layer the API
    uses. agent_audit carries no RLS (it is the cross-actor record), and the
    human data role already holds SELECT on it."""
    sql = ("SELECT id, ts, subject, client_id, request_id, statement, "
           "rows_returned FROM agent_audit")
    where: list[str] = []
    params: list[object] = []
    if sub:
        where.append("subject = %s")
        params.append(sub)
    if denied:
        # rows_returned = 0 means the operation touched nothing: a refusal
        # (e.g. the agent delete Postgres rejected) or a genuinely empty read.
        where.append("rows_returned = 0")
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT %s"
    params.append(limit)
    with scoped_session(kind="human", sub="agctl-cli") as conn:
        with conn.cursor() as cur:
            cur.execute(sql, tuple(params))
            return cur.fetchall()


def _as_dicts(rows: list[tuple]) -> list[dict]:
    # strict=True: the SELECT lists exactly AUDIT_COLUMNS, so a column/schema
    # change must raise here rather than silently truncate every audit record.
    return [dict(zip(AUDIT_COLUMNS, row, strict=True)) for row in rows]


def _scalar(cur):
    """The single value of a one-row, one-column query.

    count(*) always returns exactly one row, so None here means the connection
    or the query is not what we think it is — worth failing loudly rather than
    leaking an IndexError out of a tuple index.
    """
    row = cur.fetchone()
    if row is None:
        raise RuntimeError("expected one row from a scalar query, got none")
    return row[0]


def cmd_audit(args: argparse.Namespace) -> int:
    rows = _fetch_audit(limit=args.limit, sub=args.sub, denied=args.denied)
    if args.json:
        print(json.dumps(_as_dicts(rows), default=str, indent=2))
        return 0
    if not rows:
        print("(no audit rows)")
        return 0
    print(f"{'id':>5}  {'ts':<20}  {'subject':<12}  {'client':<11}  "
          f"{'rows':>4}  statement")
    for row in rows:
        rid, ts, subject, client_id, _request_id, statement, affected = row
        print(f"{rid:>5}  {str(ts)[:19]:<20}  {subject[:12]:<12}  "
              f"{client_id[:11]:<11}  {affected:>4}  {statement}")
    print(f"\n{len(rows)} row(s). rows=0 means the operation changed nothing "
          f"(refusal or empty read).")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    rows = _fetch_audit(limit=args.limit, sub=args.sub, denied=args.denied)
    records = _as_dicts(rows)
    handle = None
    out = sys.stdout
    if args.out:
        handle = Path(args.out).open("w", encoding="utf-8", newline="")
        out = handle
    try:
        if args.format == "csv":
            # lineterminator="\n": csv defaults to \r\n, which Windows stdout
            # then translates again, emitting \r\r\n.
            writer = csv.DictWriter(out, fieldnames=list(AUDIT_COLUMNS),
                                    lineterminator="\n")
            writer.writeheader()
            for record in records:
                writer.writerow({k: ("" if v is None else v)
                                 for k, v in record.items()})
        else:  # jsonl — one self-contained record per line
            for record in records:
                out.write(json.dumps(record, default=str) + "\n")
    finally:
        if handle is not None:
            handle.close()
    if args.out:
        print(f"wrote {len(records)} row(s) to {args.out}", file=sys.stderr)
    return 0


# ----------------------------------- init ----------------------------------

DB_NAME_DEFAULT = "agent_auth"
_GENERATED_SECRETS = ("SESSION_SECRET", "LOG_HASH_PEPPER")
# These dev logins match the ones aguard/db/schema.sql creates.
_HUMAN_DSN = "postgresql://app_login_human:human-pool-secret-dev@localhost:5432/{db}"
_AGENT_DSN = "postgresql://app_login_agent:agent-pool-secret-dev@localhost:5432/{db}"
_SUPER_DSN = "postgresql://postgres:{pw}@localhost:5432/{db}"


def _read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


# Used only when no .env.example is present — e.g. installed from PyPI, where
# the repository template is not shipped. The repo's .env.example stays the
# canonical, fully-commented reference.
_EMBEDDED_ENV_TEMPLATE = """\
# a-guard configuration (generated by `agctl init`)
PG_SUPERUSER_PASSWORD=

# --- Database (dev defaults; match aguard/db/schema.sql) ---
# DB_DSN_HUMAN=postgresql://app_login_human:human-pool-secret-dev@localhost:5432/agent_auth
# DB_DSN_AGENT=postgresql://app_login_agent:agent-pool-secret-dev@localhost:5432/agent_auth
# DB_DSN_AUTH=postgresql://app_login_auth:auth-pool-secret-dev@localhost:5432/agent_auth

# memory = single process (default); postgres = shared + restart-durable.
# REQUIRED before running more than one worker.
# STORE_BACKEND=postgres
"""


def _write_env_file(env_path: Path, example: Path, pg_password: str | None) -> None:
    """Seed .env from the template with REAL, freshly generated secrets.

    The template ships dev placeholders so the project runs on a fresh clone.
    `init` exists so nobody *deploys* those placeholders by accident.

    The password is SUBSTITUTED into the template's existing line rather than
    appended: aguard.settings._load_dotenv is first-occurrence-wins, so an
    appended duplicate would be silently ignored."""
    template = (example.read_text(encoding="utf-8") if example.is_file()
                else _EMBEDDED_ENV_TEMPLATE)
    lines = template.rstrip().splitlines()
    if pg_password:
        for i, line in enumerate(lines):
            if line.strip().startswith("PG_SUPERUSER_PASSWORD="):
                lines[i] = f"PG_SUPERUSER_PASSWORD={pg_password}"
                break
        else:
            lines.append(f"PG_SUPERUSER_PASSWORD={pg_password}")
    lines.extend(["", "# --- generated by `agctl init` ---"])
    for name in _GENERATED_SECRETS:
        lines.append(f"{name}={secrets.token_hex(32)}")
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _audit_row_count(pg_password: str, db_name: str) -> int | None:
    import psycopg
    try:
        with psycopg.connect(_SUPER_DSN.format(pw=pg_password, db=db_name)) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM agent_audit")
                return _scalar(cur)
    except Exception:
        return None                     # no database, or no table yet -> fresh


def _ensure_database(pg_password: str, db_name: str) -> None:
    import psycopg
    with psycopg.connect(_SUPER_DSN.format(pw=pg_password, db="postgres"),
                         autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (db_name,))
            if cur.fetchone() is None:
                cur.execute(f'CREATE DATABASE "{db_name}"')
                print(f"created database {db_name}")


def _apply_schema(pg_password: str, db_name: str) -> bool:
    proc = subprocess.run(
        ["psql", "-U", "postgres", "-h", "localhost", "-d", db_name,
         "-v", "ON_ERROR_STOP=1", "-q", "-f", str(SCHEMA_PATH)],
        env=dict(os.environ, PGPASSWORD=pg_password),
        capture_output=True, text=True)
    if proc.returncode != 0:
        print((proc.stderr or proc.stdout).strip()[:600], file=sys.stderr)
    return proc.returncode == 0


def _verify(db_name: str) -> bool:
    """Prove the enforcement model holds on THIS database.

    An init that only reports "applied schema.sql" tells you nothing about
    whether the guarantee is real; this checks it against live connections."""
    import psycopg
    failures = 0

    def check(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        failures += 0 if ok else 1
        print(f"[{'PASS' if ok else 'FAIL'}] {name}"
              + (f" — {detail}" if detail else ""))

    with psycopg.connect(_HUMAN_DSN.format(db=db_name)) as conn:
        with conn.cursor() as cur:
            cur.execute("SET ROLE app_user")
            cur.execute("SELECT count(*) FROM documents")
            check("human role reads documents", True, f"{_scalar(cur)} row(s)")

    with psycopg.connect(_AGENT_DSN.format(db=db_name)) as conn:
        with conn.cursor() as cur:
            cur.execute("SET ROLE agent_readonly")
            cur.execute("SELECT count(*) FROM agent_documents")   # granted view
            check("agent role reads its tenant", True, f"{_scalar(cur)} row(s)")
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM documents")
            check("agent DELETE refused by the database", False,
                  "DELETE SUCCEEDED — grants are wrong")
        except psycopg.errors.InsufficientPrivilege:
            conn.rollback()
            check("agent DELETE refused by the database", True,
                  "InsufficientPrivilege")
        try:
            with conn.cursor() as cur:
                cur.execute("SET ROLE app_user")
            check("agent cannot escalate to app_user", False,
                  "escalation SUCCEEDED — role membership is wrong")
        except psycopg.errors.InsufficientPrivilege:
            conn.rollback()
            check("agent cannot escalate to app_user", True, "membership violation")
    return failures == 0


def cmd_init(args: argparse.Namespace) -> int:
    # .env lives next to wherever you run the command, not inside the package.
    env_path = Path.cwd() / ".env"
    if not env_path.is_file():
        _write_env_file(env_path, Path.cwd() / ".env.example", args.pg_password)
        print("created .env with freshly generated secrets")

    env_file = _read_env_file(env_path)
    pg_password = (args.pg_password
                   or os.environ.get("PG_SUPERUSER_PASSWORD")
                   or env_file.get("PG_SUPERUSER_PASSWORD"))
    if not pg_password:
        print("PG_SUPERUSER_PASSWORD is unset.\n"
              "  edit .env, or re-run:  agctl init --pg-password <postgres-password>",
              file=sys.stderr)
        return 2

    db_name = os.environ.get("DB_NAME") or env_file.get("DB_NAME") or DB_NAME_DEFAULT
    existing = _audit_row_count(pg_password, db_name)
    if existing and not args.force:
        print(f"{db_name}.agent_audit already holds {existing} row(s).\n"
              "  init re-applies schema.sql, which DROPS and recreates tables.\n"
              "  re-run with --force if that is what you want.", file=sys.stderr)
        return 2

    _ensure_database(pg_password, db_name)
    if not _apply_schema(pg_password, db_name):
        print("applying aguard/db/schema.sql failed", file=sys.stderr)
        return 1
    print(f"applied aguard/db/schema.sql to {db_name}")

    if not _verify(db_name):
        print("\nenforcement check FAILED — do not trust this database",
              file=sys.stderr)
        return 1
    print("\nready. next:\n"
          "  python -m uvicorn aguard.main:app --port 8000\n"
          "  python scripts/agctl.py verify\n"
          "  python scripts/mcp_smoke.py")
    return 0


# ---------------------------------- main -----------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agctl",
        description="a-guard operator CLI: redaction proof + audit trail")
    sub = parser.add_subparsers(dest="command", required=True)

    red = sub.add_parser("redact", help="show what the redactor does")
    red.add_argument("text", nargs="*", help="text to redact ('-' = stdin)")
    red.add_argument("--file", help="redact each line of a file")
    red.add_argument("--json", help="redact a JSON object (key + content rules)")
    red.set_defaults(func=cmd_redact)

    ver = sub.add_parser("verify", help="built-in redaction self-check")
    ver.set_defaults(func=cmd_verify)

    aud = sub.add_parser("audit", help="show the audit trail, newest first")
    aud.add_argument("--limit", type=int, default=25)
    aud.add_argument("--sub", help="filter by subject")
    aud.add_argument("--denied", action="store_true",
                     help="only rows where the operation changed 0 rows")
    aud.add_argument("--json", action="store_true", help="emit JSON")
    aud.set_defaults(func=cmd_audit)

    exp = sub.add_parser("export", help="export the audit trail")
    exp.add_argument("--format", choices=("jsonl", "csv"), default="jsonl")
    exp.add_argument("--out", help="output file (default: stdout)")
    exp.add_argument("--limit", type=int, default=1000)
    exp.add_argument("--sub", help="filter by subject")
    exp.add_argument("--denied", action="store_true")
    exp.set_defaults(func=cmd_export)

    ini = sub.add_parser("init",
                         help="bootstrap: .env + database + schema + self-check")
    ini.add_argument("--pg-password",
                     help="postgres superuser password (written to .env)")
    ini.add_argument("--force", action="store_true",
                     help="proceed even if the database already holds audit rows")
    ini.set_defaults(func=cmd_init)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

