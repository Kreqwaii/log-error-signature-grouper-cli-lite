# log-error-signature-grouper-cli-lite

**Log Error Signature Grouper & Multiline Stack Trace Deduplicator CLI (Lite)** — 100% pure Python 3.9+ standard library utility with zero external dependencies.

Scan one or more server/application log files (or `stdin`), stitch multiline Python and Java/JVM stack traces into single logical events, normalize noisy dynamic tokens into canonical error signatures with deterministic SHA-256 fingerprints, group recurring errors by severity and occurrence count, and export clean Markdown, JSON, or UTF-8 BOM CSV reports.

---

## Features

- **Zero external dependencies**: 100% Python 3.9+ standard library (`argparse`, `csv`, `dataclasses`, `hashlib`, `ipaddress`, `json`, `pathlib`, `re`). No `pip install` required.
- **Multiline stack trace stitching**:
  - **Python tracebacks**: Attaches `Traceback (most recent call last):` blocks, frame/code lines, caret markers, and closing exception lines to their parent log header, including Python 3 chained exceptions (`The above exception was the direct cause...` / `During handling of the above exception...`) across blank lines.
  - **Java / JVM stack traces**: Stitches exception headers, `\tat ...` frames, `Caused by:` / `Suppressed:` chains, and `... N more` / `common frames omitted` lines.
  - **JSON-lines logs**: Automatically extracts `level`/`severity`, `timestamp`, `service`/`logger`, `message`, and embedded `traceback`/`stacktrace` fields from structured JSON log lines.
- **Deterministic token normalization & SHA-256 fingerprinting**:
  - Replaces ISO-8601, Apache/Nginx, syslog timestamps, and dates with `<TS>`
  - Replaces UUIDs with `<UUID>`
  - Replaces IPv4 (with optional `:port`) and IPv6 (bracketed, compressed, or full, validated via `ipaddress`) with `<IP>`
  - Replaces `0x...` hex pointers, long hex trace IDs, and Java `@hash` object suffixes with `<HEX>`
  - Replaces `request_id` / `trace_id` / `correlation_id` / `session_id` key-value pairs and `req_` / `trace_` tokens with `<REQ_ID>`
  - Replaces durations (`5012ms`, `1.25s`, `450 µs`, `2m30s`) with `<DURATION>`
  - Normalizes worker/thread/PID numbers (`worker-7`, `exec-3`, `pid=9982`) to `<NUM>`
  - Computes a deterministic 64-character SHA-256 fingerprint for every `(severity, canonical_body)` pair
- **Flexible filtering & sorting**: Filter by `--min-severity` (`DEBUG`, `INFO`, `WARNING`/`WARN`, `ERROR`, `CRITICAL`), sort by occurrence `--sort count` (default) or `--sort severity`, and limit results with `--top N`.
- **Three clean output formats**:
  - `markdown` / `md`: Summary metrics, escaped Markdown table, and canonical signature details
  - `json`: Machine-readable `summary` + `groups` payload for CI/CD pipelines and dashboards
  - `csv`: RFC-4180 CSV with UTF-8 BOM (`EF BB BF`) so Microsoft Excel opens reports cleanly without encoding issues

---

## Quick Start

Analyze one or more log files and print a Markdown summary:

```bash
python cli.py /var/log/app.log /var/log/worker.log
```

Read from `stdin` and filter from `WARNING` and above in JSON format:

```bash
cat app.log | python cli.py --min-severity WARNING --format json
```

Export top 20 recurring error signatures to a UTF-8 BOM CSV spreadsheet:

```bash
python cli.py app.log --format csv --top 20 --output error_groups.csv
```

Gate CI/CD log checks so the command exits with code `1` if any `ERROR` or `CRITICAL` event appears:

```bash
python cli.py test_run.log --min-severity WARNING --fail-on error --format markdown
```

Run the offline unit test suite:

```bash
py -m unittest discover -s tests -v
```

---

## Example Output

```markdown
# Log Error Signature Summary

- **Sources:** stdin
- **Min severity:** `ERROR`
- **Totals:** 16 lines | 5 log events | 4 matched events | 3 unique signatures
- **Severity breakdown:** CRITICAL: 1, ERROR: 3

| Count | Severity | Fingerprint | Exception | Signature | First Seen | Last Seen | Sources |
| ---: | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 2 | ERROR | `24120d420202` | TimeoutError | [worker-<NUM>] Charge failed req_id=<REQ_ID> order=<UUID> after <DURATION> | 2026-10-01 14:22:11,004 | 2026-10-01 14:22:15,888 | stdin |
| 1 | CRITICAL | `6091dc397106` | - | [worker-<NUM>] Redis cluster unreachable at <IP> after <DURATION> | 2026-10-01 14:24:05,300 | 2026-10-01 14:24:05,300 | stdin |
| 1 | ERROR | `7f9b09dea007` | java.lang.IllegalStateException | [http-nio-8080-exec-<NUM>] c.e.OrderService - Validation failed for session_id=<REQ_ID> | 2026-10-01 14:23:01.412 | 2026-10-01 14:23:01.412 | stdin |
```

---

## CLI Options & Exit Codes

| Flag | Default | Description |
| :--- | :--- | :--- |
| `files` | `stdin` | One or more log file paths (`-` or piped stdin reads from standard input) |
| `-s`, `--min-severity` | `ERROR` | Minimum severity: `DEBUG`, `INFO`, `WARNING` (`WARN`), `ERROR`, `CRITICAL` |
| `-f`, `--format` | `markdown` | Output format: `markdown` (`md`), `json`, or `csv` (UTF-8 BOM) |
| `-o`, `--output` | `stdout` | Write rendered output to a file path |
| `-n`, `--top` | `all` | Limit output to the top N grouped signatures |
| `--sort` | `count` | Sort groups by `count` descending or `severity` descending |
| `--no-samples` | `false` | Omit stack signature blocks / raw sample payloads in Markdown and JSON |
| `--fail-on` | `none` | Return exit code `1` if matched groups meet `warning`, `error`, or `critical` |
| `--version` | — | Print CLI version and exit |

### Exit Codes

- `0`: Completed successfully and `--fail-on` threshold was not triggered
- `1`: One or more matched error signatures met or exceeded `--fail-on`
- `2`: Invalid CLI arguments, missing/unreadable input file, or output write error

---

## Need 24/7 Live Log Tailing, Light Web Dashboard & Telegram Alerts?

This Lite CLI analyzes static log files and piped streams offline on demand. When you need **always-on log monitoring, historical incident tracking, and instant alerting across live production servers**, check out **Self-Hosted Log Anomaly Alert Studio**:

| Capability | Lite CLI (Free / MIT) | Self-Hosted Log Anomaly Alert Studio (Pro) |
| :--- | :--- | :--- |
| Python/Java multiline traceback stitching | Yes | Yes |
| Token normalization & SHA-256 error signatures | Yes | Yes |
| Markdown, JSON & UTF-8 BOM CSV export | Yes | Yes (plus live Web UI CSV download) |
| Live multi-file & glob tailer (`logrotate` / truncation safe) | — | Yes (24/7 inode & offset tracking) |
| Persistent signature & occurrence history | — | SQLite WAL persistence |
| Browser triage dashboard with Ack workflow | — | Lightweight built-in Web UI |
| Instant incident notifications | — | Cooldown-guarded Telegram Bot alerts |
| Verification coverage | 17 offline unit tests | 26 built-in self-tests |

- **Get Self-Hosted Log Anomaly Alert Studio:** https://funpay.com/lots/offer?id=82603274

---

## License

MIT License — see [LICENSE](LICENSE).
