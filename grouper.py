"""Core log parsing, multiline stack trace stitching, token normalization,
and SHA-256 error signature grouping engine.

100% pure Python 3.9+ standard library with zero external dependencies.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
import hashlib
import io
import ipaddress
import json
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

SEVERITY_RANKS: Dict[str, int] = {
    "DEBUG": 10,
    "INFO": 20,
    "WARNING": 30,
    "ERROR": 40,
    "CRITICAL": 50,
}

SEVERITY_ALIASES: Dict[str, str] = {
    "TRACE": "DEBUG",
    "DEBUG": "DEBUG",
    "DBG": "DEBUG",
    "INFO": "INFO",
    "NOTICE": "INFO",
    "WARN": "WARNING",
    "WARNING": "WARNING",
    "ERR": "ERROR",
    "ERROR": "ERROR",
    "SEVERE": "ERROR",
    "CRIT": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "FATAL": "CRITICAL",
    "PANIC": "CRITICAL",
    "ALERT": "CRITICAL",
    "EMERG": "CRITICAL",
    "EMERGENCY": "CRITICAL",
}

# Timestamp regexes (ordered from most specific to least specific)
_ISO_TS_RE = re.compile(
    r"\b\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
_APACHE_TS_RE = re.compile(
    r"\b\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?\b"
)
_SYSLOG_TS_RE = re.compile(
    r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"
)
_ISO_DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")

# Leading log timestamp extraction
_LEADING_TS_RE = re.compile(
    r"^\s*(?:"
    r"\[(?P<ts_br>\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)\]"
    r"|(?P<ts_iso>\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"|\[(?P<ts_ap>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?)\]"
    r"|(?P<ts_sys>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r")\s*"
)

# Severity patterns after stripping leading timestamp
_LEADING_SEV_RE = re.compile(
    r"^(?:\[|\()?(?:[A-Za-z0-9_.-]+\.)?"
    r"(?P<sev>TRACE|DEBUG|DBG|INFO|NOTICE|WARNING|WARN|ERROR|ERR|SEVERE|CRITICAL|CRIT|FATAL|PANIC|ALERT|EMERG|EMERGENCY)"
    r"(?:\]|\))?(?:\s*[:|-]\s*|\s+|$)",
    re.IGNORECASE,
)

# Severity after an initial bracketed thread/logger token e.g. `[http-nio-8080-exec-1] ERROR com.example - msg`
_PREFIX_TAG_THEN_SEV_RE = re.compile(
    r"^(?P<tag>\[[^\]]+\]|\([^)]+\))\s+"
    r"(?:\[|\()?(?:[A-Za-z0-9_.-]+\.)?"
    r"(?P<sev>TRACE|DEBUG|DBG|INFO|NOTICE|WARNING|WARN|ERROR|ERR|SEVERE|CRITICAL|CRIT|FATAL|PANIC|ALERT|EMERG|EMERGENCY)"
    r"(?:\]|\))?(?:\s*[:|-]\s*|\s+|$)",
    re.IGNORECASE,
)

# logfmt-style `level=error` or `severity=WARN`
_LOGFMT_SEV_RE = re.compile(
    r"(?:^|\s)(?:level|severity|lvl)=[\"']?"
    r"(?P<sev>trace|debug|dbg|info|notice|warn|warning|err|error|severe|crit|critical|fatal|panic)"
    r"[\"']?(?=\s|$)",
    re.IGNORECASE,
)

# Stack trace / continuation detectors
_PY_TRACEBACK_START_RE = re.compile(r"^Traceback \(most recent call last\):\s*$")
_PY_CAUSE_RE = re.compile(
    r"^(?:The above exception was the direct cause of the following exception:|"
    r"During handling of the above exception, another exception occurred:)\s*$"
)
_PY_FRAME_RE = re.compile(r'^\s+File ".*", line \d+.*$')
_PY_CARET_RE = re.compile(r"^\s+[~^]+\s*$")
_JAVA_AT_RE = re.compile(r"^\s+at\s+\S+")
_JAVA_CAUSED_BY_RE = re.compile(r"^\s*(?:Caused by|Suppressed):\s+.+")
_JAVA_MORE_RE = re.compile(r"^\s+\.\.\.\s+\d+\s+(?:more|common frames omitted)\s*$")
_JAVA_THREAD_EXC_RE = re.compile(
    r'^Exception in thread "[^"]+"\s+(?P<exc>[A-Za-z_$][\w.$]*)'
)
_EXC_LINE_RE = re.compile(
    r"^(?P<exc>(?:[A-Za-z_$][\w.$]*\.)?"
    r"[A-Za-z_$][\w$]*(?:Error|Exception|Throwable|Interrupt|Exit|Warning))"
    r"(?:\s*:\s*.*|\s*)$"
)

# Normalization patterns
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_KV_REQ_ID_RE = re.compile(
    r"\b((?:x-)?(?:request|req|correlation|corr|trace|span|session|sess|invocation)[_-]?id)"
    r"(\s*[:=]\s*)([\"']?[A-Za-z0-9._-]{4,}[\"']?)",
    re.IGNORECASE,
)
_PREFIX_REQ_ID_RE = re.compile(
    r"\b(?:req|trace|corr|span|sess)[_-][A-Za-z0-9]{6,}\b",
    re.IGNORECASE,
)
_LONG_HEX_ID_RE = re.compile(r"\b[0-9a-fA-F]{24,}\b")
_IPV4_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?(?![\w.])")
_BRACKET_IPV6_RE = re.compile(
    r"\[([0-9a-fA-F:]{2,39}(?:%[A-Za-z0-9_.-]+)?)\](?::(\d{1,5}))?"
)
_BARE_IPV6_RE = re.compile(
    r"(?<![A-Za-z0-9_.:-])"
    r"([0-9a-fA-F]{0,4}:[0-9a-fA-F:]{1,38})"
    r"(?![A-Za-z0-9_.:-])"
)
_HEX_ADDR_RE = re.compile(r"\b0[xX][0-9a-fA-F]+\b")
_JAVA_OBJ_HASH_RE = re.compile(r"(?<=[A-Za-z0-9_$])@[0-9a-fA-F]{6,16}\b")
_COMPOUND_DURATION_RE = re.compile(
    r"\b(?:\d+h\d+m(?:\d+(?:\.\d+)?s)?|\d+m\d+(?:\.\d+)?s)\b",
    re.IGNORECASE,
)
_DURATION_RE = re.compile(
    r"\b\d+(?:\.\d+)?\s*(?:ms|µs|us|ns|msec|usec|millis|secs?|seconds?|minutes?|mins?)\b",
    re.IGNORECASE,
)
_SHORT_SEC_RE = re.compile(r"(?:(?<=^)|(?<=[\s=:(]))\d+(?:\.\d+)?s\b")
_WORKER_NUM_RE = re.compile(
    r"\b(pid|tid|worker|thread|exec|pool)([-_:=#])(\d+)\b",
    re.IGNORECASE,
)


def normalize_severity(level: str) -> str:
    """Resolve a severity label or alias to a canonical severity level."""
    cleaned = level.strip().upper()
    if cleaned not in SEVERITY_ALIASES:
        valid = ", ".join(SEVERITY_RANKS.keys())
        raise ValueError(f"Unknown severity '{level}'. Expected one of: {valid}")
    return SEVERITY_ALIASES[cleaned]


def normalize_text(text: str) -> str:
    """Normalize noisy dynamic tokens inside a single log line or message.

    Replaces timestamps, UUIDs, request/trace IDs, IPv4/IPv6 addresses,
    hex memory addresses, durations, and worker/PID numbers with canonical
    placeholders while preserving structural context.
    """
    if not text:
        return ""

    out = text
    out = _ISO_TS_RE.sub("<TS>", out)
    out = _APACHE_TS_RE.sub("<TS>", out)
    out = _SYSLOG_TS_RE.sub("<TS>", out)
    out = _ISO_DATE_RE.sub("<TS>", out)

    out = _UUID_RE.sub("<UUID>", out)
    out = _KV_REQ_ID_RE.sub(r"\1\2<REQ_ID>", out)
    out = _PREFIX_REQ_ID_RE.sub("<REQ_ID>", out)
    out = _LONG_HEX_ID_RE.sub("<HEX>", out)

    def _replace_ipv4(match: re.Match[str]) -> str:
        ip_str = match.group(1)
        port_str = match.group(2)
        try:
            ipaddress.IPv4Address(ip_str)
        except ValueError:
            return match.group(0)
        if port_str is not None and int(port_str) > 65535:
            return match.group(0)
        return "<IP>"

    out = _IPV4_RE.sub(_replace_ipv4, out)

    def _replace_bracket_ipv6(match: re.Match[str]) -> str:
        ip_str = match.group(1).split("%", 1)[0]
        port_str = match.group(2)
        try:
            ipaddress.IPv6Address(ip_str)
        except ValueError:
            return match.group(0)
        if port_str is not None and int(port_str) > 65535:
            return match.group(0)
        return "<IP>"

    out = _BRACKET_IPV6_RE.sub(_replace_bracket_ipv6, out)

    def _replace_bare_ipv6(match: re.Match[str]) -> str:
        candidate = match.group(1)
        if candidate.count(":") < 2:
            return candidate
        # Handle IPv6 with trailing :port like 2001:db8::1:8080 if unbracketed isn't ambiguous
        try:
            ipaddress.IPv6Address(candidate)
            return "<IP>"
        except ValueError:
            return candidate

    out = _BARE_IPV6_RE.sub(_replace_bare_ipv6, out)

    out = _HEX_ADDR_RE.sub("<HEX>", out)
    out = _JAVA_OBJ_HASH_RE.sub("@<HEX>", out)

    out = _COMPOUND_DURATION_RE.sub("<DURATION>", out)
    out = _DURATION_RE.sub("<DURATION>", out)
    out = _SHORT_SEC_RE.sub("<DURATION>", out)

    out = _WORKER_NUM_RE.sub(r"\1\2<NUM>", out)

    # Collapse repeated internal horizontal whitespace while keeping single spaces
    out = re.sub(r"[ \t]+", " ", out).strip()
    return out


def normalize_multiline_signature(lines: Sequence[str]) -> str:
    """Normalize a list of stitched log lines into a canonical multiline signature."""
    cleaned_lines: List[str] = []
    for raw_line in lines:
        stripped = raw_line.rstrip("\r\n")
        if not stripped.strip():
            continue
        indent = "  " if stripped[:1].isspace() else ""
        norm = normalize_text(stripped)
        if norm:
            cleaned_lines.append(f"{indent}{norm}")
    return "\n".join(cleaned_lines)


def compute_fingerprint(severity: str, canonical_body: str) -> str:
    """Compute a deterministic SHA-256 hex fingerprint for (severity, canonical_body)."""
    payload = f"{severity}\n{canonical_body}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass
class LogEvent:
    severity: str
    message_lines: List[str]
    raw_lines: List[str]
    source: str
    line_number: int
    timestamp: Optional[str] = None
    exception_type: Optional[str] = None
    in_python_tb: bool = False
    awaiting_py_exc: bool = False


@dataclass
class ErrorGroup:
    fingerprint: str
    short_fingerprint: str
    severity: str
    count: int
    signature: str
    canonical_body: str
    exception_type: Optional[str]
    first_seen: Optional[str]
    last_seen: Optional[str]
    sources: List[str] = field(default_factory=list)
    sample_line: int = 1
    sample: str = ""

    def to_dict(self, include_sample: bool = True) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "fingerprint": self.fingerprint,
            "short_fingerprint": self.short_fingerprint,
            "severity": self.severity,
            "count": self.count,
            "exception_type": self.exception_type,
            "signature": self.signature,
            "canonical_body": self.canonical_body,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "sources": list(self.sources),
            "sample_line": self.sample_line,
        }
        if include_sample:
            data["sample"] = self.sample
        return data


@dataclass
class GroupingReport:
    total_lines: int
    total_events: int
    matched_events: int
    min_severity: str
    sources: List[str]
    by_severity: Dict[str, int]
    groups: List[ErrorGroup]

    def to_dict(self, include_samples: bool = True) -> Dict[str, Any]:
        return {
            "summary": {
                "total_lines": self.total_lines,
                "total_events": self.total_events,
                "matched_events": self.matched_events,
                "unique_signatures": len(self.groups),
                "min_severity": self.min_severity,
                "by_severity": dict(self.by_severity),
                "sources": list(self.sources),
            },
            "groups": [g.to_dict(include_sample=include_samples) for g in self.groups],
        }


def _extract_exception_type(lines: Sequence[str]) -> Optional[str]:
    """Identify the primary or final exception class from message/trace lines."""
    found: Optional[str] = None
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        m_thread = _JAVA_THREAD_EXC_RE.match(stripped)
        if m_thread:
            found = m_thread.group("exc")
            continue
        if stripped.startswith("Caused by:"):
            rest = stripped[len("Caused by:") :].strip()
            m_caused = _EXC_LINE_RE.match(rest)
            if m_caused:
                found = m_caused.group("exc")
            continue
        m_exc = _EXC_LINE_RE.match(stripped)
        if m_exc:
            found = m_exc.group("exc")
    return found


def _try_parse_json_line(
    line: str, source: str, line_number: int
) -> Optional[LogEvent]:
    stripped = line.strip()
    if not (stripped.startswith("{") and stripped.endswith("}")):
        return None
    try:
        obj = json.loads(stripped)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None

    raw_sev = None
    for key in ("level", "severity", "levelname", "lvl", "status"):
        val = obj.get(key)
        if isinstance(val, str) and val.strip().upper() in SEVERITY_ALIASES:
            raw_sev = SEVERITY_ALIASES[val.strip().upper()]
            break

    msg = None
    for key in ("message", "msg", "error", "err", "detail"):
        val = obj.get(key)
        if isinstance(val, str) and val.strip():
            msg = val.strip()
            break

    if raw_sev is None and msg is None:
        return None

    severity = raw_sev or "INFO"
    ts_val = None
    for key in ("timestamp", "ts", "time", "@timestamp", "created_at"):
        val = obj.get(key)
        if isinstance(val, str) and val.strip():
            ts_val = val.strip()
            break

    logger_name = None
    for key in ("logger", "logger_name", "service", "component", "module"):
        val = obj.get(key)
        if isinstance(val, str) and val.strip():
            logger_name = val.strip()
            break

    first_line = f"{logger_name} - {msg}" if (logger_name and msg) else (msg or stripped)
    message_lines = first_line.splitlines()

    for key in ("traceback", "stacktrace", "stack_trace", "exc_info", "stack"):
        val = obj.get(key)
        if isinstance(val, str) and val.strip():
            message_lines.extend(val.rstrip().splitlines())
            break

    exc_type = _extract_exception_type(message_lines)
    if raw_sev is None and exc_type:
        severity = "ERROR"

    return LogEvent(
        severity=severity,
        message_lines=message_lines,
        raw_lines=[line.rstrip("\r\n")],
        source=source,
        line_number=line_number,
        timestamp=ts_val,
        exception_type=exc_type,
    )


def _parse_header(line: str) -> Tuple[bool, Optional[str], Optional[str], str]:
    """Inspect a non-empty log line for timestamp and/or severity header.

    Returns `(is_header, timestamp, severity, remainder_message)`.
    """
    raw = line.rstrip("\r\n")
    rest = raw
    ts: Optional[str] = None
    has_ts = False

    m_ts = _LEADING_TS_RE.match(rest)
    if m_ts:
        has_ts = True
        ts = (
            m_ts.group("ts_br")
            or m_ts.group("ts_iso")
            or m_ts.group("ts_ap")
            or m_ts.group("ts_sys")
        )
        rest = rest[m_ts.end() :]

    severity: Optional[str] = None
    m_sev = _LEADING_SEV_RE.match(rest)
    if m_sev:
        severity = SEVERITY_ALIASES[m_sev.group("sev").upper()]
        rest = rest[m_sev.end() :]
    else:
        m_tag_sev = _PREFIX_TAG_THEN_SEV_RE.match(rest)
        if m_tag_sev:
            tag = m_tag_sev.group("tag")
            severity = SEVERITY_ALIASES[m_tag_sev.group("sev").upper()]
            after_sev = rest[m_tag_sev.end() :]
            rest = f"{tag} {after_sev}".strip()
        else:
            m_logfmt = _LOGFMT_SEV_RE.search(rest)
            if m_logfmt:
                severity = SEVERITY_ALIASES[m_logfmt.group("sev").upper()]

    # Handle case like `2026-03-15 10:00:00 [worker-1] something` with no explicit level
    if not rest.strip() and has_ts:
        rest = raw

    is_header = has_ts or (severity is not None)
    return is_header, ts, severity, rest.strip() if is_header else raw


def _is_continuation_line(line: str, active: LogEvent) -> bool:
    """Return True if a non-header line belongs to the active multiline LogEvent."""
    stripped = line.rstrip("\r\n")
    if not stripped:
        return False

    if _PY_TRACEBACK_START_RE.match(stripped):
        return active.severity in ("WARNING", "ERROR", "CRITICAL")
    if _PY_CAUSE_RE.match(stripped):
        return True
    if _PY_FRAME_RE.match(stripped) or _PY_CARET_RE.match(stripped):
        return True
    if _JAVA_AT_RE.match(stripped) or _JAVA_CAUSED_BY_RE.match(stripped) or _JAVA_MORE_RE.match(stripped):
        return True

    # Leading whitespace indicates stack frame / indented context
    if stripped[0].isspace():
        return True

    # Closing exception line of a Python traceback, or Java exception line right under a log header
    if active.in_python_tb and active.awaiting_py_exc:
        return True

    if _EXC_LINE_RE.match(stripped.strip()) and active.severity in ("WARNING", "ERROR", "CRITICAL"):
        return True

    return False


def parse_log_lines(lines: Iterable[str], source: str = "stdin") -> Tuple[List[LogEvent], int]:
    """Parse raw lines into stitched LogEvent records.

    Handles single-line logs, JSON log lines, Python tracebacks (including
    chained exceptions separated by blank lines), and Java/JVM stack traces.
    Returns `(events, total_line_count)`.
    """
    events: List[LogEvent] = []
    active: Optional[LogEvent] = None
    pending_blanks: List[str] = []
    total_lines = 0

    def _flush_active() -> None:
        nonlocal active, pending_blanks
        if active is not None:
            active.exception_type = active.exception_type or _extract_exception_type(
                active.message_lines
            )
            events.append(active)
            active = None
        pending_blanks.clear()

    for line_no, raw_line in enumerate(lines, start=1):
        total_lines += 1
        line = raw_line.rstrip("\r\n")

        if not line.strip():
            if active is not None and active.in_python_tb:
                pending_blanks.append(line)
            else:
                _flush_active()
            continue

        # Check JSON log object first
        json_event = _try_parse_json_line(line, source=source, line_number=line_no)
        if json_event is not None:
            _flush_active()
            events.append(json_event)
            continue

        is_header, ts, sev, remainder = _parse_header(line)

        # If we buffered blank lines inside a Python traceback, only keep stitching if
        # this line is a chained Python exception marker or another traceback start.
        if pending_blanks:
            if (
                not is_header
                and active is not None
                and (_PY_CAUSE_RE.match(line) or _PY_TRACEBACK_START_RE.match(line))
            ):
                active.raw_lines.extend(pending_blanks)
                pending_blanks.clear()
                active.message_lines.append(line)
                active.raw_lines.append(line)
                active.awaiting_py_exc = True
                continue
            _flush_active()

        if is_header:
            _flush_active()
            event_sev = sev or "INFO"
            active = LogEvent(
                severity=event_sev,
                message_lines=[remainder] if remainder else [line.strip()],
                raw_lines=[line],
                source=source,
                line_number=line_no,
                timestamp=ts,
            )
            continue

        # Non-header line: check if it continues the current event
        if active is not None and _is_continuation_line(line, active):
            active.raw_lines.append(line)
            active.message_lines.append(line)

            if _PY_TRACEBACK_START_RE.match(line) or _PY_CAUSE_RE.match(line):
                active.in_python_tb = True
                active.awaiting_py_exc = True
            elif active.in_python_tb:
                if (
                    _PY_FRAME_RE.match(line)
                    or _PY_CARET_RE.match(line)
                    or line[0].isspace()
                ):
                    active.awaiting_py_exc = True
                else:
                    # Non-indented exception line closes this traceback block unless chained next
                    active.awaiting_py_exc = False
            continue

        # Start a new standalone event (e.g. unprefixed Python Traceback or Java Exception)
        _flush_active()
        is_py_tb = bool(_PY_TRACEBACK_START_RE.match(line))
        is_java_thread_exc = bool(_JAVA_THREAD_EXC_RE.match(line))
        is_exc = bool(_EXC_LINE_RE.match(line.strip()))

        event_sev = "ERROR" if (is_py_tb or is_java_thread_exc or is_exc) else "INFO"
        active = LogEvent(
            severity=event_sev,
            message_lines=[line],
            raw_lines=[line],
            source=source,
            line_number=line_no,
            timestamp=None,
            in_python_tb=is_py_tb,
            awaiting_py_exc=is_py_tb,
        )

    _flush_active()
    return events, total_lines


def group_log_streams(
    streams: Sequence[Tuple[str, Iterable[str]]],
    *,
    min_severity: str = "ERROR",
    sort_by: str = "count",
) -> GroupingReport:
    """Scan one or more `(source_name, lines)` streams and group recurring errors."""
    canonical_min = normalize_severity(min_severity)
    min_rank = SEVERITY_RANKS[canonical_min]

    total_lines = 0
    total_events = 0
    matched_events = 0
    source_names: List[str] = []
    by_severity: Dict[str, int] = {
        sev: 0
        for sev, rank in sorted(SEVERITY_RANKS.items(), key=lambda kv: -kv[1])
        if rank >= min_rank
    }

    buckets: Dict[str, ErrorGroup] = {}
    bucket_sources: Dict[str, set[str]] = {}

    for source_name, line_iter in streams:
        if source_name not in source_names:
            source_names.append(source_name)
        events, lines_read = parse_log_lines(line_iter, source=source_name)
        total_lines += lines_read
        total_events += len(events)

        for ev in events:
            if SEVERITY_RANKS[ev.severity] < min_rank:
                continue
            matched_events += 1
            by_severity[ev.severity] = by_severity.get(ev.severity, 0) + 1

            canonical_body = normalize_multiline_signature(ev.message_lines)
            if not canonical_body:
                canonical_body = normalize_text(" ".join(ev.raw_lines))
            first_sig_line = canonical_body.splitlines()[0] if canonical_body else ""
            fp = compute_fingerprint(ev.severity, canonical_body)

            if fp not in buckets:
                buckets[fp] = ErrorGroup(
                    fingerprint=fp,
                    short_fingerprint=fp[:12],
                    severity=ev.severity,
                    count=1,
                    signature=first_sig_line,
                    canonical_body=canonical_body,
                    exception_type=ev.exception_type,
                    first_seen=ev.timestamp,
                    last_seen=ev.timestamp,
                    sources=[ev.source],
                    sample_line=ev.line_number,
                    sample="\n".join(ev.raw_lines),
                )
                bucket_sources[fp] = {ev.source}
            else:
                grp = buckets[fp]
                grp.count += 1
                if ev.timestamp:
                    if grp.first_seen is None or ev.timestamp < grp.first_seen:
                        grp.first_seen = ev.timestamp
                    if grp.last_seen is None or ev.timestamp > grp.last_seen:
                        grp.last_seen = ev.timestamp
                if ev.source not in bucket_sources[fp]:
                    bucket_sources[fp].add(ev.source)
                    grp.sources.append(ev.source)
                if not grp.exception_type and ev.exception_type:
                    grp.exception_type = ev.exception_type

    groups = list(buckets.values())
    for grp in groups:
        grp.sources.sort()

    if sort_by == "severity":
        groups.sort(
            key=lambda g: (
                -SEVERITY_RANKS[g.severity],
                -g.count,
                g.fingerprint,
            )
        )
    else:
        groups.sort(
            key=lambda g: (
                -g.count,
                -SEVERITY_RANKS[g.severity],
                g.fingerprint,
            )
        )

    return GroupingReport(
        total_lines=total_lines,
        total_events=total_events,
        matched_events=matched_events,
        min_severity=canonical_min,
        sources=source_names,
        by_severity=by_severity,
        groups=groups,
    )


def group_log_files(
    paths: Sequence[Path],
    *,
    min_severity: str = "ERROR",
    sort_by: str = "count",
) -> GroupingReport:
    """Read and group errors across one or more log file paths."""
    streams: List[Tuple[str, List[str]]] = []
    for path in paths:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            streams.append((str(path), fh.readlines()))
    return group_log_streams(streams, min_severity=min_severity, sort_by=sort_by)


def format_json(
    report: GroupingReport,
    *,
    top: Optional[int] = None,
    include_samples: bool = True,
) -> str:
    """Render GroupingReport as pretty-printed JSON."""
    limited_groups = report.groups[:top] if top is not None else report.groups
    payload = report.to_dict(include_samples=include_samples)
    payload["groups"] = [
        g.to_dict(include_sample=include_samples) for g in limited_groups
    ]
    if top is not None:
        payload["summary"]["displayed_signatures"] = len(limited_groups)
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _md_escape(text: str) -> str:
    collapsed = " ".join(text.splitlines()).strip()
    return collapsed.replace("|", "\\|")


def format_markdown(
    report: GroupingReport,
    *,
    top: Optional[int] = None,
    include_samples: bool = True,
) -> str:
    """Render GroupingReport as a clean Markdown summary."""
    limited = report.groups[:top] if top is not None else report.groups
    sev_parts = ", ".join(
        f"{sev}: {cnt}" for sev, cnt in report.by_severity.items() if cnt > 0
    ) or "none"
    sources_str = ", ".join(report.sources) if report.sources else "(none)"

    lines: List[str] = [
        "# Log Error Signature Summary",
        "",
        f"- **Sources:** {sources_str}",
        f"- **Min severity:** `{report.min_severity}`",
        (
            f"- **Totals:** {report.total_lines} lines | "
            f"{report.total_events} log events | "
            f"{report.matched_events} matched events | "
            f"{len(report.groups)} unique signatures"
        ),
        f"- **Severity breakdown:** {sev_parts}",
        "",
    ]

    if not limited:
        lines.append("No matching error signatures found.")
        return "\n".join(lines)

    lines.extend(
        [
            "| Count | Severity | Fingerprint | Exception | Signature | First Seen | Last Seen | Sources |",
            "| ---: | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
    )

    for grp in limited:
        exc_cell = _md_escape(grp.exception_type or "-")
        sig_cell = _md_escape(grp.signature)
        if len(sig_cell) > 100:
            sig_cell = sig_cell[:97] + "..."
        first_cell = _md_escape(grp.first_seen or "-")
        last_cell = _md_escape(grp.last_seen or "-")
        src_cell = _md_escape(", ".join(grp.sources))
        lines.append(
            f"| {grp.count} | {grp.severity} | `{grp.short_fingerprint}` | "
            f"{exc_cell} | {sig_cell} | {first_cell} | {last_cell} | {src_cell} |"
        )

    if include_samples:
        lines.extend(["", "## Signature Details", ""])
        for idx, grp in enumerate(limited, start=1):
            lines.append(
                f"### {idx}. [{grp.severity}] `{grp.short_fingerprint}` (count: {grp.count})"
            )
            lines.append("")
            lines.append(f"- **SHA-256:** `{grp.fingerprint}`")
            if grp.exception_type:
                lines.append(f"- **Exception:** `{grp.exception_type}`")
            lines.append(f"- **Sources:** {', '.join(grp.sources)} (first at line {grp.sample_line})")
            lines.append("")
            lines.append("```text")
            lines.append(grp.canonical_body)
            lines.append("```")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def format_csv(
    report: GroupingReport,
    *,
    top: Optional[int] = None,
    include_bom: bool = True,
) -> str:
    """Render GroupingReport as UTF-8 BOM CSV for spreadsheet compatibility."""
    limited = report.groups[:top] if top is not None else report.groups
    buf = io.StringIO()
    if include_bom:
        buf.write("\ufeff")

    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(
        [
            "fingerprint",
            "short_fingerprint",
            "severity",
            "count",
            "exception_type",
            "signature",
            "first_seen",
            "last_seen",
            "sources",
            "sample_line",
            "canonical_body",
        ]
    )
    for grp in limited:
        writer.writerow(
            [
                grp.fingerprint,
                grp.short_fingerprint,
                grp.severity,
                grp.count,
                grp.exception_type or "",
                grp.signature,
                grp.first_seen or "",
                grp.last_seen or "",
                ";".join(grp.sources),
                grp.sample_line,
                grp.canonical_body,
            ]
        )

    return buf.getvalue()
