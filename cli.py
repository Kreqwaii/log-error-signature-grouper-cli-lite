"""CLI entrypoint for log-error-signature-grouper-cli-lite.

Scans one or more log files (or stdin), stitches multiline Python/Java stack
traces, normalizes dynamic tokens into canonical SHA-256 error signatures,
groups recurring errors by severity and count, and exports Markdown, JSON,
or UTF-8 BOM CSV reports.

100% pure Python 3.9+ standard library with zero external dependencies.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Iterable, List, Optional, Sequence, Tuple

from grouper import (
    SEVERITY_RANKS,
    GroupingReport,
    format_csv,
    format_json,
    format_markdown,
    group_log_streams,
    normalize_severity,
)

__version__ = "1.0.0"

FAIL_ON_THRESHOLDS = {
    "none": None,
    "warning": SEVERITY_RANKS["WARNING"],
    "error": SEVERITY_RANKS["ERROR"],
    "critical": SEVERITY_RANKS["CRITICAL"],
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-error-grouper",
        description=(
            "Deduplicate noisy server/application logs into canonical SHA-256 "
            "error signatures with Python/Java multiline traceback stitching."
        ),
    )
    parser.add_argument(
        "files",
        nargs="*",
        metavar="FILE",
        help="Log file path(s) to scan (use '-' or pipe input to read from stdin).",
    )
    parser.add_argument(
        "-s",
        "--min-severity",
        default="ERROR",
        help=(
            "Minimum severity level to include: DEBUG, INFO, WARNING (or WARN), "
            "ERROR, CRITICAL (default: ERROR)."
        ),
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=("markdown", "md", "json", "csv"),
        default="markdown",
        help="Output format: markdown (default), md, json, or csv (UTF-8 BOM).",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="Optional output file path instead of writing to stdout.",
    )
    parser.add_argument(
        "-n",
        "--top",
        type=int,
        default=None,
        metavar="N",
        help="Limit output to the top N grouped error signatures.",
    )
    parser.add_argument(
        "--sort",
        choices=("count", "severity"),
        default="count",
        help="Sort error groups by 'count' descending (default) or 'severity' descending.",
    )
    parser.add_argument(
        "--no-samples",
        action="store_true",
        help="Omit detailed stack samples in Markdown/JSON outputs.",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none", "warning", "error", "critical"),
        default="none",
        help=(
            "Exit with code 1 if any matched group reaches severity threshold: "
            "none (default), warning, error, or critical."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _should_fail(report: GroupingReport, policy: str) -> bool:
    threshold = FAIL_ON_THRESHOLDS.get(policy)
    if threshold is None:
        return False
    return any(SEVERITY_RANKS[grp.severity] >= threshold for grp in report.groups)


def _write_output(text: str, output_path: Optional[str]) -> None:
    if output_path:
        out = Path(output_path)
        if out.parent and not out.parent.exists():
            out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        return

    if hasattr(sys.stdout, "buffer"):
        sys.stdout.buffer.write(text.encode("utf-8"))
        sys.stdout.buffer.flush()
    else:
        sys.stdout.write(text)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        min_sev = normalize_severity(args.min_severity)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.top is not None and args.top <= 0:
        print("Error: --top must be a positive integer (>= 1).", file=sys.stderr)
        return 2

    file_args: List[str] = list(args.files)
    if not file_args:
        is_tty = getattr(sys.stdin, "isatty", lambda: False)()
        if is_tty:
            parser.print_usage(sys.stderr)
            print(
                "Error: provide one or more log file paths or pipe input via stdin ('-').",
                file=sys.stderr,
            )
            return 2
        file_args = ["-"]

    streams: List[Tuple[str, Iterable[str]]] = []
    stdin_consumed = False
    for raw_target in file_args:
        if raw_target == "-":
            if stdin_consumed:
                continue
            stdin_consumed = True
            streams.append(("stdin", sys.stdin.read().splitlines(keepends=True)))
            continue

        path = Path(raw_target)
        if not path.exists():
            print(f"Error: log file not found: {raw_target}", file=sys.stderr)
            return 2
        if not path.is_file():
            print(f"Error: path is not a regular file: {raw_target}", file=sys.stderr)
            return 2
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"Error reading '{raw_target}': {exc}", file=sys.stderr)
            return 2
        streams.append((raw_target, content.splitlines(keepends=True)))

    report = group_log_streams(
        streams,
        min_severity=min_sev,
        sort_by=args.sort,
    )

    include_samples = not args.no_samples
    if args.format in ("markdown", "md"):
        rendered = format_markdown(
            report,
            top=args.top,
            include_samples=include_samples,
        )
    elif args.format == "json":
        rendered = format_json(
            report,
            top=args.top,
            include_samples=include_samples,
        ) + "\n"
    else:
        rendered = format_csv(report, top=args.top, include_bom=True)

    try:
        _write_output(rendered, args.output)
    except OSError as exc:
        print(f"Error writing output '{args.output}': {exc}", file=sys.stderr)
        return 2

    return 1 if _should_fail(report, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
