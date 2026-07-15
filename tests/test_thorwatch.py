#!/usr/bin/env python3

from __future__ import print_function

import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest


HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

from thorwatch_collector import (  # noqa: E402
    Collector,
    ProcessReader,
    calculate_mysql_user_deltas,
    calculate_cpu_percent,
    parse_mysql_user_statistics,
    read_system_snapshot,
)
from thorwatch_common import (  # noqa: E402
    Settings,
    connect_database,
    event_reason,
    event_report_data,
    load_settings,
    parse_access_line,
    process_category,
    render_text_report,
)


class ThorWatchTestCase(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tempdir.name, "thorwatch.db")
        self.config_path = os.path.join(self.tempdir.name, "thorwatch.conf")
        with open(self.config_path, "w") as handle:
            handle.write(
                """[thorwatch]
database = {database}
normal_interval = 2
burst_interval = 1
load_threshold = 999999
cpu_busy_threshold = 999999
burst_hold_seconds = 2
top_process_limit = 10
process_cpu_threshold = 0
retention_days = 2
access_logs_enabled = false
access_log_interval = 1
access_log_pretrigger_bytes = 4096
access_log_read_limit_bytes = 65536
http_unique_limit = 100
""".format(database=self.db_path)
            )
        self.settings = load_settings(self.config_path)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_cpu_percent_math(self):
        previous = {
            "user": 100,
            "nice": 0,
            "system": 50,
            "idle": 800,
            "iowait": 20,
            "irq": 10,
            "softirq": 20,
            "steal": 0,
        }
        current = {
            "user": 120,
            "nice": 0,
            "system": 60,
            "idle": 850,
            "iowait": 25,
            "irq": 10,
            "softirq": 25,
            "steal": 0,
        }
        result = calculate_cpu_percent(previous, current)
        self.assertAlmostEqual(result["cpu_user"], 20.0 / 90.0 * 100.0)
        self.assertAlmostEqual(result["cpu_iowait"], 5.0 / 90.0 * 100.0)
        self.assertAlmostEqual(result["cpu_busy"], 35.0 / 90.0 * 100.0)

    def test_access_log_parser(self):
        line = (
            '203.0.113.9 - - [15/Jul/2026:14:48:23 +0530] '
            '"GET /wp-admin/admin-ajax.php?action=ping HTTP/1.1" 200 42 '
            '"-" "LoadBot/1.0"'
        )
        parsed = parse_access_line(line)
        self.assertEqual(parsed["ip"], "203.0.113.9")
        self.assertEqual(parsed["uri"], "/wp-admin/admin-ajax.php?action=ping")
        self.assertEqual(parsed["status"], 200)
        self.assertEqual(parsed["ua"], "LoadBot/1.0")
        stripped = parse_access_line(line, strip_query=True)
        self.assertEqual(stripped["uri"], "/wp-admin/admin-ajax.php")

    def test_mysql_user_statistics_deltas(self):
        baseline = parse_mysql_user_statistics(
            "alpha\t100\t5\t20\t2.5000\t1.2500\n"
            "beta\t10\t1\t2\t0.5000\t0.2000\n"
        )
        current = parse_mysql_user_statistics(
            "alpha\t140\t8\t24\t4.7500\t2.0000\n"
            "beta\t12\t1\t3\t0.6500\t0.2500\n"
        )
        rows = calculate_mysql_user_deltas(baseline, current, 10)
        self.assertEqual(rows[0]["mysql_user"], "alpha")
        self.assertEqual(rows[0]["total_queries"], 47)
        self.assertEqual(rows[0]["select_commands"], 40)
        self.assertAlmostEqual(rows[0]["busy_time"], 2.25)

    def test_mysql_tracking_lifecycle_restores_userstat(self):
        collector = Collector(self.settings)
        cursor = collector.conn.execute(
            """
            INSERT INTO mysql_tracking_runs(requested_ts, status, duration_seconds)
            VALUES(?, 'pending', 1)
            """,
            (time.time(),),
        )
        collector.conn.commit()
        run_id = cursor.lastrowid
        states = []
        snapshots = iter(
            (
                {"demo": {"select_commands": 10, "update_commands": 2, "other_commands": 3, "busy_time": 1.0, "cpu_time": 0.4}},
                {"demo": {"select_commands": 31, "update_commands": 4, "other_commands": 8, "busy_time": 2.5, "cpu_time": 0.9}},
            )
        )
        collector._mysql_userstat_state = lambda: 0
        collector._set_mysql_userstat = lambda enabled: states.append(enabled)
        collector._mysql_statistics_snapshot = lambda: next(snapshots)
        self.assertTrue(collector.process_mysql_tracking())
        collector.conn.execute(
            "UPDATE mysql_tracking_runs SET started_ts = ? WHERE id = ?",
            (time.time() - 2, run_id),
        )
        collector.conn.commit()
        self.assertFalse(collector.process_mysql_tracking())
        run = collector.conn.execute(
            "SELECT * FROM mysql_tracking_runs WHERE id = ?", (run_id,)
        ).fetchone()
        result = collector.conn.execute(
            "SELECT * FROM mysql_tracking_results WHERE run_id = ?", (run_id,)
        ).fetchone()
        self.assertEqual(run["status"], "completed")
        self.assertEqual(result["mysql_user"], "demo")
        self.assertEqual(result["total_queries"], 28)
        self.assertEqual(states, [True, False])

    def test_appconfig_entryurl_does_not_duplicate_cgi_prefix(self):
        appconfig = {}
        with open(os.path.join(ROOT, "plugin", "thorwatch.conf"), "r") as handle:
            for line in handle:
                if "=" in line and not line.lstrip().startswith("#"):
                    key, value = line.strip().split("=", 1)
                    appconfig[key] = value
        self.assertEqual(appconfig["url"], "/cgi/thorwatch/index.cgi")
        self.assertEqual(appconfig["entryurl"], "thorwatch/index.cgi")
        self.assertFalse(appconfig["entryurl"].startswith("cgi/"))

    def test_process_categories(self):
        self.assertEqual(process_category("lsphp", "lsphp:/home/demo/public_html/index.php"), "PHP")
        self.assertEqual(process_category("mariadbd", "/usr/sbin/mariadbd"), "MariaDB")
        self.assertEqual(process_category("doveadm", "doveadm expunge"), "Dovecot")
        self.assertEqual(process_category("lshttpd", "litespeed"), "LiteSpeed")

    def test_threshold_reason(self):
        quiet = event_reason(10.0, 10.0, self.settings)
        self.assertEqual(quiet, "")
        values = self.settings.as_dict()
        values["load_threshold"] = "20"
        reason = event_reason(21.5, 10.0, Settings(values))
        self.assertIn("load1 21.50", reason)

    def test_database_and_event_report(self):
        collector = Collector(self.settings)
        snapshot = collector.run_once(force_event=True)
        self.assertGreaterEqual(snapshot["load1"], 0)
        row = collector.conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(row["status"], "test")
        data = event_report_data(collector.conn, row["id"])
        self.assertEqual(data["event"]["id"], row["id"])
        self.assertTrue(data["samples"])
        report = render_text_report(data)
        self.assertIn("Thor Watch Load Event", report)

    def test_normal_sample_updates_live_process_table(self):
        collector = Collector(self.settings)
        collector.run_once(force_event=False)
        event_count = collector.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        process_count = collector.conn.execute("SELECT COUNT(*) FROM live_processes").fetchone()[0]
        self.assertEqual(event_count, 0)
        self.assertGreater(process_count, 0)

    def test_access_log_event_correlation(self):
        log_root = os.path.join(self.tempdir.name, "domlogs")
        user_dir = os.path.join(log_root, "demo")
        os.makedirs(user_dir)
        log_path = os.path.join(user_dir, "example.test")
        now_text = time.strftime("%d/%b/%Y:%H:%M:%S %z")
        line = (
            '198.51.100.44 - - [{when}] "GET /index.php HTTP/1.1" '
            '200 123 "-" "SpikeBot/2.0"\n'
        ).format(when=now_text)
        with open(log_path, "w") as handle:
            handle.write(line)
        values = self.settings.as_dict()
        values["access_logs_enabled"] = "true"
        values["access_log_root"] = log_root
        settings = Settings(values)
        collector = Collector(settings)
        snapshot, collector.cpu_previous = read_system_snapshot(None)
        collector.start_event(snapshot, "test HTTP correlation")
        collector.event.php_users.add("demo")
        collector.capture_access_logs(force=True)
        row = collector.conn.execute("SELECT * FROM http_hits").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["source_ip"], "198.51.100.44")
        self.assertEqual(row["uri"], "/index.php")
        self.assertEqual(row["hits"], 1)
        with open(log_path, "a") as handle:
            handle.write(line)
        collector.capture_access_logs(force=True)
        row = collector.conn.execute("SELECT * FROM http_hits").fetchone()
        self.assertEqual(row["hits"], 2)
        collector.close_event("test")

    def test_live_proc_readers(self):
        first, cpu = read_system_snapshot(None)
        second, _cpu = read_system_snapshot(cpu)
        self.assertIn("cpu_busy", second)
        reader = ProcessReader()
        processes = reader.read(5, 0, second["mem_total_kb"])
        self.assertTrue(processes)
        self.assertIn("args", processes[0])

    def test_cgi_renders_root_dashboard(self):
        collector = Collector(self.settings)
        collector.run_once(force_event=True)
        env = dict(os.environ)
        env.update(
            {
                "REMOTE_USER": "root",
                "QUERY_STRING": "",
                "THORWATCH_CONFIG": self.config_path,
                "PYTHONPATH": SRC,
            }
        )
        process = subprocess.Popen(
            [sys.executable, os.path.join(SRC, "thorwatch.cgi")],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        stdout, stderr = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 0, stderr.decode("utf-8", "replace"))
        page = stdout.decode("utf-8", "replace")
        self.assertIn("Content-Type: text/html", page)
        self.assertIn("Thor Watch", page)
        self.assertIn("Load event history", page)
        self.assertIn('href="../../" target="_top">← Back to WHM</a>', page)
        self.assertIn('<header class="site-header">', page)
        self.assertIn('<footer class="site-footer">', page)
        self.assertIn('aria-label="Thor Watch sections"', page)
        self.assertIn('<summary>Logs ', page)
        self.assertIn('href="?view=processes"', page)
        self.assertIn('href="?view=mysql"', page)
        self.assertIn('href="?view=events"', page)
        self.assertIn("a,button,summary{cursor:pointer}", page)
        self.assertIn(
            'href="https://www.peekhosting.com" target="_blank" rel="noopener noreferrer">PEEK Hosting</a>',
            page,
        )
        self.assertIn('id="load-chart"', page)
        self.assertIn('id="cpu-chart"', page)
        self.assertNotIn('id="realtime-processes"', page)
        self.assertNotIn('id="live-process-body"', page)
        self.assertNotIn('id="mysql-track-button"', page)
        self.assertNotIn('id="load-event-history"', page)
        self.assertIn("?action=api-live", page)

        view_expectations = (
            ("processes", 'id="realtime-processes"', 'id="live-process-body"'),
            ("mysql", 'id="mysql-tracker"', 'id="mysql-track-button"'),
            ("events", 'id="load-event-history"', "Load event history"),
        )
        for view, first_expected, second_expected in view_expectations:
            env["QUERY_STRING"] = "view={}".format(view)
            process = subprocess.Popen(
                [sys.executable, os.path.join(SRC, "thorwatch.cgi")],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            stdout, stderr = process.communicate(timeout=15)
            self.assertEqual(process.returncode, 0, stderr.decode("utf-8", "replace"))
            view_page = stdout.decode("utf-8", "replace")
            self.assertIn(first_expected, view_page)
            self.assertIn(second_expected, view_page)
            self.assertIn('href="?view={}">Refresh</a>'.format(view), view_page)
            self.assertIn(
                'class="active" aria-current="page" href="?view={}"'.format(view),
                view_page,
            )

        env["QUERY_STRING"] = "action=api-live"
        process = subprocess.Popen(
            [sys.executable, os.path.join(SRC, "thorwatch.cgi")],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        stdout, stderr = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 0, stderr.decode("utf-8", "replace"))
        response = stdout.decode("utf-8", "replace")
        self.assertIn("Content-Type: application/json", response)
        payload = __import__("json").loads(response.split("\n\n", 1)[1])
        self.assertIn("latest", payload)
        self.assertIn("processes", payload)
        self.assertIn("series", payload)
        self.assertIn("mysql_tracking", payload)
        self.assertTrue(payload["processes"])

        env.update(
            {
                "QUERY_STRING": "action=mysql-track-start",
                "REQUEST_METHOD": "POST",
                "HTTP_X_THORWATCH_REQUEST": "1",
            }
        )
        process = subprocess.Popen(
            [sys.executable, os.path.join(SRC, "thorwatch.cgi")],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        stdout, stderr = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 0, stderr.decode("utf-8", "replace"))
        response = stdout.decode("utf-8", "replace")
        self.assertIn("Status: 202 Accepted", response)
        payload = __import__("json").loads(response.split("\n\n", 1)[1])
        self.assertTrue(payload["accepted"])
        queued = collector.conn.execute(
            "SELECT * FROM mysql_tracking_runs WHERE id = ?", (payload["run_id"],)
        ).fetchone()
        self.assertEqual(queued["status"], "pending")

        event_id = collector.conn.execute("SELECT id FROM events LIMIT 1").fetchone()[0]
        env.update({"QUERY_STRING": "event={}".format(event_id), "REQUEST_METHOD": "GET"})
        process = subprocess.Popen(
            [sys.executable, os.path.join(SRC, "thorwatch.cgi")],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        stdout, stderr = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 0, stderr.decode("utf-8", "replace"))
        self.assertIn("Top process commands", stdout.decode("utf-8", "replace"))

    def test_cgi_rejects_non_root(self):
        env = dict(os.environ)
        env.update({"REMOTE_USER": "reseller", "QUERY_STRING": "", "PYTHONPATH": SRC})
        process = subprocess.Popen(
            [sys.executable, os.path.join(SRC, "thorwatch.cgi")],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        stdout, _stderr = process.communicate(timeout=15)
        self.assertIn("Status: 403 Forbidden", stdout.decode("utf-8", "replace"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
