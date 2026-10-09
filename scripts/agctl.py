"""a-guard operator CLI — observability without a privileged web surface.

A dashboard would mean a new authenticated surface spanning tenants, i.e. the
one screen that could violate the guarantee this project exists to provide.
Everything an operator needs is already reachable from the command line:

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

Run:  python scripts/agctl.py redact "hello alice@example.com"
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

# Run as a plain script (`python scripts/agctl.py`): sys.path[0] is scripts/,
# so put the repo root on the path before importing the app package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.session import scoped_session          # noqa: E402
from app.redact.patterns import correlate, redact_text   # noqa: E402
from app.redact.redactor import redact_event       # noqa: E402
from app.settings import settings                  # noqa: E402

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
    return [dict(zip(AUDIT_COLUMNS, row)) for row in rows]


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

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

