import csv
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import cli
from grouper import (
    compute_fingerprint,
    format_csv,
    format_json,
    format_markdown,
    group_log_files,
    group_log_streams,
    normalize_severity,
    normalize_text,
    parse_log_lines,
)


class TestNormalization(unittest.TestCase):
    def test_normalizes_timestamps_and_dates(self):
        line = (
            "Failed at 2026-03-15T14:22:10.123Z and 2026-03-16 09:00:01,456 "
            "apache 15/Mar/2026:14:22:10 +0000 syslog Mar 15 14:22:10 on 2026-03-17"
        )
        norm = normalize_text(line)
        self.assertNotIn("2026", norm)
        self.assertNotIn("14:22:10", norm)
        self.assertEqual(norm.count("<TS>"), 5)

    def test_normalizes_uuids_and_request_ids(self):
        line = (
            "Order 550e8400-e29b-41d4-a716-446655440000 failed "
            "request_id=req_98a7bc12df trace_id=4bf92f3577b34da6a3ce929d0e0e4736 "
            "corr-ab12cd34ef"
        )
        norm = normalize_text(line)
        self.assertIn("<UUID>", norm)
        self.assertIn("request_id=<REQ_ID>", norm)
        self.assertIn("trace_id=<REQ_ID>", norm)
        self.assertNotIn("550e8400", norm)
        self.assertNotIn("req_98a7bc12df", norm)
        self.assertNotIn("corr-ab12cd34ef", norm)

    def test_normalizes_ipv4_and_ipv6_addresses(self):
        line = (
            "Upstream 10.24.8.19:54321 refused; fallback [2001:db8:85a3::8a2e:370:7334]:443 "
            "peer fe80::1 loopback ::1 invalid 999.1.2.3 version 1.2.3"
        )
        norm = normalize_text(line)
        self.assertEqual(norm.count("<IP>"), 4)
        self.assertIn("999.1.2.3", norm)
        self.assertIn("1.2.3", norm)

    def test_normalizes_hex_addresses_durations_and_worker_ids(self):
        line = (
            "<Conn object at 0x7f8b4c012ab0> java.lang.Object@3f99bd52 "
            "timed out after 5012ms (1.25s, 2m30s, 450 µs) in worker-14 pid=9982"
        )
        norm = normalize_text(line)
        self.assertIn("<HEX>", norm)
        self.assertIn("@<HEX>", norm)
        self.assertEqual(norm.count("<DURATION>"), 4)
        self.assertIn("worker-<NUM>", norm)
        self.assertIn("pid=<NUM>", norm)
        self.assertNotIn("0x7f8b4c012ab0", norm)
        self.assertNotIn("3f99bd52", norm)


class TestMultilineStackTraces(unittest.TestCase):
    def test_stitches_python_traceback_under_log_header(self):
        lines = [
            "2026-10-01 10:00:00,100 INFO [app] Starting batch\n",
            "2026-10-01 10:00:01,200 ERROR [worker-1] Job failed req_id=req_111111\n",
            "Traceback (most recent call last):\n",
            '  File "/srv/app/worker.py", line 42, in process\n',
            "    return payload['user_id']\n",
            "KeyError: 'user_id'\n",
            "2026-10-01 10:00:02,000 INFO [app] Continuing\n",
        ]
        events, total_lines = parse_log_lines(lines, source="app.log")
        self.assertEqual(total_lines, 7)
        self.assertEqual(len(events), 3)
        err_ev = events[1]
        self.assertEqual(err_ev.severity, "ERROR")
        self.assertEqual(err_ev.exception_type, "KeyError")
        self.assertEqual(len(err_ev.raw_lines), 5)
        self.assertIn("Traceback (most recent call last):", err_ev.canonical_body if hasattr(err_ev, "canonical_body") else "\n".join(err_ev.message_lines))

    def test_stitches_python_chained_exceptions_across_blank_lines(self):
        lines = [
            "2026-10-01T10:00:01Z ERROR Request crashed\n",
            "Traceback (most recent call last):\n",
            '  File "/app/db.py", line 18, in query\n',
            "    conn.execute()\n",
            "ConnectionRefusedError: [Errno 111] Connection refused from 10.0.0.5:5432\n",
            "\n",
            "The above exception was the direct cause of the following exception:\n",
            "\n",
            "Traceback (most recent call last):\n",
            '  File "/app/api.py", line 55, in handle\n',
            "    fetch()\n",
            "RuntimeError: upstream db unavailable\n",
            "\n",
            "2026-10-01T10:00:02Z INFO Ready\n",
        ]
        events, _ = parse_log_lines(lines, source="chained.log")
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].severity, "ERROR")
        self.assertEqual(events[0].exception_type, "RuntimeError")
        self.assertIn("ConnectionRefusedError", "\n".join(events[0].message_lines))
        self.assertIn("RuntimeError: upstream db unavailable", "\n".join(events[0].message_lines))

    def test_stitches_java_multiline_stack_trace(self):
        lines = [
            "2026-10-01 14:25:00.412 [http-nio-8080-exec-4] ERROR c.e.OrderController - Submit failed\n",
            "java.lang.IllegalStateException: Order 550e8400-e29b-41d4-a716-446655440000 invalid\n",
            "\tat com.example.OrderController.submit(OrderController.java:91)\n",
            "\tat java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\n",
            "Caused by: java.io.IOException: Broken pipe from 10.24.8.19:54321\n",
            "\tat java.base/sun.nio.ch.SocketDispatcher.write0(Native Method)\n",
            "\t... 28 more\n",
            "2026-10-01 14:25:01.001 INFO c.e.Health - ok\n",
        ]
        events, _ = parse_log_lines(lines, source="java.log")
        self.assertEqual(len(events), 2)
        java_ev = events[0]
        self.assertEqual(java_ev.severity, "ERROR")
        self.assertEqual(java_ev.exception_type, "java.io.IOException")
        self.assertEqual(len(java_ev.raw_lines), 7)

    def test_unprefixed_python_traceback_after_info_becomes_error(self):
        lines = [
            "2026-10-01 09:00:00 INFO Normal startup\n",
            "Traceback (most recent call last):\n",
            '  File "run.py", line 3, in <module>\n',
            "    1 / 0\n",
            "ZeroDivisionError: division by zero\n",
        ]
        events, _ = parse_log_lines(lines)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].severity, "INFO")
        self.assertEqual(events[1].severity, "ERROR")
        self.assertEqual(events[1].exception_type, "ZeroDivisionError")

    def test_parses_structured_json_log_lines(self):
        lines = [
            json.dumps(
                {
                    "timestamp": "2026-10-01T12:00:00Z",
                    "level": "error",
                    "service": "billing",
                    "message": "Charge failed for 192.168.1.10 after 120ms",
                }
            )
            + "\n",
            json.dumps(
                {
                    "timestamp": "2026-10-01T12:00:05Z",
                    "level": "error",
                    "service": "billing",
                    "message": "Charge failed for 192.168.1.99 after 480ms",
                }
            )
            + "\n",
        ]
        report = group_log_streams([("json.log", lines)], min_severity="ERROR")
        self.assertEqual(report.matched_events, 2)
        self.assertEqual(len(report.groups), 1)
        self.assertEqual(report.groups[0].count, 2)
        self.assertIn("billing - Charge failed for <IP> after <DURATION>", report.groups[0].signature)


class TestGroupingAndFiltering(unittest.TestCase):
    def test_deduplication_counts_and_sha256_fingerprints(self):
        log_a = [
            "2026-10-01 10:00:00,001 ERROR [worker-1] DB timeout connecting to 10.0.1.5:5432 after 5000ms req_id=req_aaaaaa\n",
            "2026-10-01 10:01:00,002 ERROR [worker-7] DB timeout connecting to 10.0.1.9:5432 after 5120ms req_id=req_bbbbbb\n",
            "2026-10-01 10:02:00,003 CRITICAL [worker-2] Out of disk space on /dev/sda1\n",
        ]
        log_b = [
            "2026-10-01 10:03:00,004 ERROR [worker-9] DB timeout connecting to 10.0.1.12:5432 after 4999ms req_id=req_cccccc\n",
        ]
        report = group_log_streams(
            [("node1.log", log_a), ("node2.log", log_b)],
            min_severity="ERROR",
        )
        self.assertEqual(report.matched_events, 4)
        self.assertEqual(len(report.groups), 2)

        top_grp = report.groups[0]
        self.assertEqual(top_grp.count, 3)
        self.assertEqual(top_grp.severity, "ERROR")
        self.assertEqual(top_grp.first_seen, "2026-10-01 10:00:00,001")
        self.assertEqual(top_grp.last_seen, "2026-10-01 10:03:00,004")
        self.assertEqual(top_grp.sources, ["node1.log", "node2.log"])
        self.assertEqual(
            top_grp.fingerprint,
            compute_fingerprint("ERROR", top_grp.canonical_body),
        )
        self.assertEqual(len(top_grp.fingerprint), 64)

    def test_severity_filtering_and_sort_by_severity(self):
        lines = [
            "2026-10-01 08:00:00 DEBUG Cache lookup\n",
            "2026-10-01 08:00:01 INFO Server listening\n",
            "2026-10-01 08:00:02 WARN Slow query took 950ms\n",
            "2026-10-01 08:00:03 WARN Slow query took 1100ms\n",
            "2026-10-01 08:00:04 WARN Slow query took 1250ms\n",
            "2026-10-01 08:00:05 ERROR Payment gateway error\n",
            "2026-10-01 08:00:06 CRITICAL Kernel panic imminent\n",
        ]
        err_only = group_log_streams([("srv.log", lines)], min_severity="ERROR")
        self.assertEqual(err_only.matched_events, 2)
        self.assertEqual(len(err_only.groups), 2)

        with_warn = group_log_streams(
            [("srv.log", lines)], min_severity="WARN", sort_by="severity"
        )
        self.assertEqual(with_warn.matched_events, 5)
        self.assertEqual(with_warn.groups[0].severity, "CRITICAL")
        self.assertEqual(with_warn.groups[1].severity, "ERROR")
        self.assertEqual(with_warn.groups[2].severity, "WARNING")
        self.assertEqual(with_warn.groups[2].count, 3)

    def test_invalid_severity_raises_value_error(self):
        with self.assertRaises(ValueError):
            normalize_severity("BOGUS")


class TestOutputFormatsAndCLI(unittest.TestCase):
    def _sample_report(self):
        lines = [
            "2026-10-01 11:00:00 ERROR Pipe | failure from 10.0.0.1\n",
            "2026-10-01 11:01:00 ERROR Pipe | failure from 10.0.0.2\n",
            "2026-10-01 11:02:00 CRITICAL Fatal shutdown req_id=req_123456\n",
        ]
        return group_log_streams([("api.log", lines)], min_severity="ERROR")

    def test_json_and_markdown_outputs(self):
        report = self._sample_report()
        raw_json = format_json(report, top=1, include_samples=False)
        parsed = json.loads(raw_json)
        self.assertEqual(parsed["summary"]["unique_signatures"], 2)
        self.assertEqual(parsed["summary"]["displayed_signatures"], 1)
        self.assertEqual(len(parsed["groups"]), 1)
        self.assertEqual(parsed["groups"][0]["count"], 2)
        self.assertNotIn("sample", parsed["groups"][0])

        md = format_markdown(report, include_samples=True)
        self.assertIn("# Log Error Signature Summary", md)
        self.assertIn("Pipe \\| failure from <IP>", md)
        self.assertIn("## Signature Details", md)

    def test_utf8_bom_csv_output(self):
        report = self._sample_report()
        csv_text = format_csv(report, include_bom=True)
        self.assertTrue(csv_text.startswith("\ufeff"))
        rows = list(csv.DictReader(io.StringIO(csv_text.lstrip("\ufeff"))))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["count"], "2")
        self.assertEqual(rows[0]["severity"], "ERROR")
        self.assertEqual(len(rows[0]["fingerprint"]), 64)

    def test_cli_file_output_utf8_bom_csv_and_group_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            log_path = tmp_dir / "app.log"
            out_csv = tmp_dir / "report.csv"
            log_path.write_text(
                "2026-10-01 10:00:00 ERROR Failed user 550e8400-e29b-41d4-a716-446655440000\n"
                "2026-10-01 10:01:00 ERROR Failed user 123e4567-e89b-12d3-a456-426614174000\n",
                encoding="utf-8",
            )

            direct_report = group_log_files([log_path], min_severity="ERROR")
            self.assertEqual(direct_report.groups[0].count, 2)

            rc = cli.main(
                [str(log_path), "--format", "csv", "--output", str(out_csv)]
            )
            self.assertEqual(rc, 0)
            raw_bytes = out_csv.read_bytes()
            self.assertTrue(raw_bytes.startswith(b"\xef\xbb\xbf"))

    def test_cli_stdin_and_exit_codes(self):
        sample_log = (
            "2026-10-01 09:00:00 WARNING Disk 85% full\n"
            "2026-10-01 09:01:00 ERROR Timeout after 300ms\n"
        )

        # --fail-on none returns 0
        out_buf = io.StringIO()
        with patch("sys.stdin", io.StringIO(sample_log)), redirect_stdout(out_buf):
            rc_ok = cli.main(["-", "--format", "json", "--fail-on", "none"])
        self.assertEqual(rc_ok, 0)
        payload = json.loads(out_buf.getvalue())
        self.assertEqual(payload["summary"]["matched_events"], 1)

        # --fail-on error returns 1 when ERROR exists
        out_buf2 = io.StringIO()
        with patch("sys.stdin", io.StringIO(sample_log)), redirect_stdout(out_buf2):
            rc_err = cli.main(["--min-severity", "WARNING", "--fail-on", "error"])
        self.assertEqual(rc_err, 1)

        # --fail-on critical returns 0 when only WARNING/ERROR exist
        out_buf3 = io.StringIO()
        with patch("sys.stdin", io.StringIO(sample_log)), redirect_stdout(out_buf3):
            rc_crit = cli.main(["--min-severity", "WARNING", "--fail-on", "critical"])
        self.assertEqual(rc_crit, 0)

        # Missing file returns 2
        err_buf = io.StringIO()
        with redirect_stderr(err_buf):
            rc_missing = cli.main(["nonexistent_missing_file_xyz.log"])
        self.assertEqual(rc_missing, 2)

        # Invalid --top returns 2
        err_buf2 = io.StringIO()
        with redirect_stderr(err_buf2):
            rc_bad_top = cli.main(["-", "--top", "0"])
        self.assertEqual(rc_bad_top, 2)

    def test_empty_log_stream_produces_clean_zero_report(self):
        report = group_log_streams([("empty.log", ["\n", "   \n"])])
        self.assertEqual(report.matched_events, 0)
        self.assertEqual(report.groups, [])
        md = format_markdown(report)
        self.assertIn("No matching error signatures found.", md)


if __name__ == "__main__":
    unittest.main()
