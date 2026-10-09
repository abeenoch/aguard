"""The choke point: redact BEFORE serialization, for EVERY record, fail closed.

WHY HANDLER-LEVEL FILTERS (Phase 1 live-server lesson):
Python applies logger-level filters only at the ORIGINATING logger — a
filter on the root logger never sees records issued by child loggers, and
uvicorn's access logger doesn't propagate to root at all. The only place
that guarantees "every record reaching this handler is scrubbed, no matter
who issued it" is a filter on the HANDLER. So `install()` wires filters
onto handlers, ensures root HAS a handler (under uvicorn it had none ->
INFO records were silently dropped), and sweeps every string attribute on
the record so a formatter that reads custom fields (uvicorn's
AccessFormatter reads request_line/client_addr) cannot bypass msg-redaction.

Fail-closed contract: anything the redactor cannot process becomes
`[LOG_DROPPED: redactor_error]` — raw data never flows.
"""
from __future__ import annotations

import datetime
import json
import logging
import re
from typing import Any

from app.redact.patterns import redact_text
from app.redact.redactor import redact_event

_marker = object()   # per-handler idempotency sentinel
_FACTORY_FLAG = "_pii_factory_installed"


def redact_record(record: logging.LogRecord, pepper: bytes) -> None:
    """In-place redaction of one record. The ONE routine — called from both
    the record factory (creation time) and any handler filter (emit time)."""
    if getattr(record, "_pii_done", False):
        return
    try:
        if isinstance(record.msg, dict):
            record.msg = redact_event(record.msg, pepper)
        if record.args:
            # Redact args REGARDLESS of msg type — a dict msg with args is
            # nonsensical but must still not carry raw args to a formatter.
            # (Validation below will degrade the combo to the marker: fail closed.)
            # PRESERVE structure — formatters read record.args directly
            # (uvicorn's AccessFormatter unpacks it into 5 values; rendering
            # msg % args and clearing args broke exactly that in Phase 1).
            if isinstance(record.args, dict):
                new_args = redact_event(dict(record.args), pepper)
            else:
                items = (record.args if isinstance(record.args, tuple)
                         else (record.args,))
                new_args = tuple(_redact_arg(a, pepper) for a in items)
                if not isinstance(record.args, tuple):
                    new_args = new_args[0]
            # Redact literal segments of the format string while keeping
            # %-specifiers intact ("password=%s wrong" must stay formatable).
            record.msg = _redact_format(str(record.msg), pepper)
            record.args = new_args
            # Fail closed BEFORE any formatter: prove msg % args works, so a
            # malformed %-string degrades to the marker instead of crashing
            # the handler mid-emit (its error block would print raw parts).
            str(record.msg) % record.args
        else:
            record.msg = _redact_message(str(record.msg), pepper)

        if record.exc_info and record.exc_info[0] is not None:
            import traceback
            record.exc_text = _redact_message(
                "".join(traceback.format_exception(*record.exc_info)), pepper)
            record.exc_info = None   # deterministic: text is now the source

        # formatter-agnostic sweep: AccessFormatter and friends read
        # CUSTOM string attributes — redact every non-structural string
        # so downstream formatters can't smuggle raw PII past us.
        for key, value in list(record.__dict__.items()):
            if key in _SWEEP_SKIP:
                continue
            if isinstance(value, str):
                record.__dict__[key] = redact_text(value, pepper)
    except Exception:   # noqa: BLE001 — fail CLOSED: raw data must not flow
        record.msg, record.args, record.exc_info, record.exc_text = (
            "[LOG_DROPPED: redactor_error]", (), None, None)
    record._pii_done = True   # noqa: SLF001 (marker attr, deliberate)


class RedactionFilter(logging.Filter):
    """Belt to the factory's suspenders: catches any record path that
    somehow bypassed record creation (re-emission, wrapped handlers).
    Idempotent via `_pii_done` — first redaction wins."""

    def __init__(self, pepper: bytes, name: str = "pii-redact"):
        super().__init__(name)
        self.pepper = pepper

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        redact_record(record, self.pepper)
        return True


# record.__dict__ keys that are pure identifiers/formatting — skip the sweep
_SWEEP_SKIP = {
    "msg", "args", "name", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "taskName", "message", "asctime",
}


def _redact_arg(value: Any, pepper: bytes) -> Any:
    """Element-wise arg redaction: strings scrubbed, containers walked,
    primitives (ints — status codes etc.) untouched. Structure preserved."""
    if isinstance(value, str):
        return redact_text(value, pepper)
    if isinstance(value, (dict, list)):
        return redact_event(value, pepper)
    return value


_SPEC_RE = re.compile(
    # %-conversion specifiers: %s, %(name)s, %5.2f, %%, ... — kept verbatim
    r"%(?:\([^)]*\))?[#0+ -]?\d*(?:\.\d+)?[sdiouxXeEfFgGcrsa%]"
)


def _redact_format(fmt: str, pepper: bytes) -> str:
    """Redact the LITERAL segments of a %-format string, keep specifiers.

    'password=%s for alice@example.com' -> 'password=%s for email[h:…]'
    so the formatter can still substitute, and no PII hides in the literals.
    """
    out: list[str] = []
    last = 0
    for match in _SPEC_RE.finditer(fmt):
        out.append(redact_text(fmt[last:match.start()], pepper))
        out.append(match.group(0))
        last = match.end()
    out.append(redact_text(fmt[last:], pepper))
    return "".join(out)


def _redact_message(message: str, pepper: bytes) -> str:
    from app.redact.patterns import redact_text
    return redact_text(message, pepper)


class JsonFormatter(logging.Formatter):
    """UTC ISO-8601 timestamps, single-line JSON — parseable AND complete."""

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        event = {
            "ts": datetime.datetime.fromtimestamp(
                record.created, tz=datetime.timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": message,
        }
        if getattr(record, "exc_text", None):
            event["exc"] = record.exc_text
        return json.dumps(event, default=str)


def install(logger_name: str, pepper: bytes,
            *, force_json: bool = True) -> logging.Logger:
    """Wire the choke point — THREE layers, in order of authority:

    1. RECORD FACTORY (primary): every LogRecord in the process is born
       through logging.setLogRecordFactory — before ANY handler or formatter
       exists, including handlers pytest/uvicorn attach LATER. Creation time
       is the only choke point that cannot be bypassed by configuration.
    2. HANDLER FILTERS (belt): re-assert on emit for records that predate
       the factory or arrive via exotic paths (re-emission, wrapping).
    3. ROOT HANDLER (liveness): under uvicorn root has NO handler -> INFO
       records were silently dropped (Phase 1 Finding 2). Add a stream.

    Idempotent: factory guarded by a flag, handlers by `_marker`.
    """
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)

    # --- layer 1: record factory ---
    if not getattr(logging.LogRecord, _FACTORY_FLAG, False):
        previous_factory = logging.getLogRecordFactory()

        def factory(*args, **kwargs) -> logging.LogRecord:
            record = previous_factory(*args, **kwargs)
            redact_record(record, pepper)   # born clean
            return record

        logging.setLogRecordFactory(factory)
        logging.LogRecord._pii_factory_installed = True  # type: ignore[attr-defined]

    # --- layers 2+3: handlers ---
    redactor = RedactionFilter(pepper)
    if logger.handlers:
        targets = list(logger.handlers)
    else:
        stream = logging.StreamHandler()
        logger.addHandler(stream)
        targets = [stream]

    for handler in targets:
        if getattr(handler, "_pii_installed", None) is _marker:
            continue
        handler.addFilter(redactor)
        if force_json:
            handler.setFormatter(JsonFormatter())
        handler._pii_installed = _marker   # noqa: SLF001 (deliberate marker)
    return logger


def wire_uvicorn(pepper: bytes) -> None:
    """Attach redaction filters to uvicorn's OWN handlers.

    uvicorn.access / uvicorn.error have `propagate: False` and their own
    formatters — records issued there never reach root handlers, so we
    cannot fix them by configuring root. Attaching our filter DIRECTLY to
    their handlers is the only reliable choke point for access-log lines
    (which contain full URLs — query strings included).
    """
    redactor = RedactionFilter(pepper)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        for handler in list(logging.getLogger(name).handlers):
            if getattr(handler, "_pii_installed", None) is _marker:
                continue
            handler.addFilter(redactor)
            handler._pii_installed = _marker   # noqa: SLF001

