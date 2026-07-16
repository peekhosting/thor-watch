#!/usr/bin/env python3
"""Shared configuration, database, and reporting helpers for Thor Watch."""

from __future__ import print_function

import configparser
import datetime
import hashlib
import json
import os
import re
import sqlite3


VERSION = "0.5.1"
DEFAULT_CONFIG = "/etc/thorwatch/thorwatch.conf"


DEFAULTS = {
    "database": "/var/lib/thorwatch/thorwatch.db",
    "normal_interval": "15",
    "burst_interval": "2",
    "live_processes_enabled": "true",
    "live_process_interval": "5",
    "live_process_limit": "20",
    "live_process_cpu_threshold": "0.5",
    "long_running_processes_enabled": "true",
    "long_running_process_limit": "200",
    "load_threshold": "20",
    "cpu_busy_threshold": "25",
    "burst_hold_seconds": "180",
    "max_event_seconds": "3600",
    "top_process_limit": "60",
    "process_cpu_threshold": "2",
    "retention_days": "14",
    "access_logs_enabled": "true",
    "access_log_root": "/usr/local/apache/domlogs",
    "access_log_interval": "10",
    "access_log_pretrigger_bytes": "262144",
    "access_log_read_limit_bytes": "4194304",
    "access_log_global_limit_bytes": "16777216",
    "http_unique_limit": "5000",
    "strip_query_strings": "false",
    "mysql_client": "",
    "mysql_tracking_duration": "60",
    "mysql_tracking_limit": "10",
    "email_monitoring_enabled": "true",
    "email_log_path": "/var/log/exim_mainlog",
    "email_userdomains_path": "/etc/userdomains",
    "email_monitor_interval": "5",
    "email_read_limit_bytes": "4194304",
    "email_top_limit": "25",
    "alert_email": "",
    "email_on_close": "false",
}


class Settings(object):
    """Small typed wrapper around the INI configuration."""

    def __init__(self, values):
        self._values = values

    def get(self, name):
        return self._values.get(name, DEFAULTS.get(name, ""))

    def integer(self, name):
        return int(self.get(name))

    def floating(self, name):
        return float(self.get(name))

    def boolean(self, name):
        return str(self.get(name)).strip().lower() in ("1", "true", "yes", "on")

    def as_dict(self):
        return dict(self._values)


def load_settings(path=None):
    path = path or os.environ.get("THORWATCH_CONFIG", DEFAULT_CONFIG)
    parser = configparser.ConfigParser(defaults=DEFAULTS)
    parser.read(path)
    values = dict(DEFAULTS)
    if parser.has_section("thorwatch"):
        for key, value in parser.items("thorwatch"):
            values[key] = value.strip()
    settings = Settings(values)
    validate_settings(settings)
    return settings


def validate_settings(settings):
    positive_ints = (
        "normal_interval",
        "burst_interval",
        "live_process_interval",
        "live_process_limit",
        "long_running_process_limit",
        "burst_hold_seconds",
        "max_event_seconds",
        "top_process_limit",
        "retention_days",
        "access_log_interval",
        "access_log_pretrigger_bytes",
        "access_log_read_limit_bytes",
        "access_log_global_limit_bytes",
        "http_unique_limit",
        "mysql_tracking_duration",
        "mysql_tracking_limit",
        "email_monitor_interval",
        "email_read_limit_bytes",
        "email_top_limit",
    )
    for name in positive_ints:
        if settings.integer(name) <= 0:
            raise ValueError("{} must be greater than zero".format(name))
    for name in (
        "load_threshold",
        "cpu_busy_threshold",
        "process_cpu_threshold",
        "live_process_cpu_threshold",
    ):
        if settings.floating(name) < 0:
            raise ValueError("{} cannot be negative".format(name))


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_ts REAL NOT NULL,
    end_ts REAL,
    status TEXT NOT NULL DEFAULT 'open',
    trigger_reason TEXT NOT NULL,
    peak_load1 REAL NOT NULL DEFAULT 0,
    peak_cpu_busy REAL NOT NULL DEFAULT 0,
    peak_running INTEGER NOT NULL DEFAULT 0,
    sample_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    ts REAL NOT NULL,
    load1 REAL NOT NULL,
    load5 REAL NOT NULL,
    load15 REAL NOT NULL,
    running INTEGER NOT NULL,
    total_processes INTEGER NOT NULL,
    cpu_user REAL NOT NULL,
    cpu_system REAL NOT NULL,
    cpu_iowait REAL NOT NULL,
    cpu_steal REAL NOT NULL,
    cpu_busy REAL NOT NULL,
    mem_used_pct REAL NOT NULL,
    swap_used_pct REAL NOT NULL,
    http_established INTEGER NOT NULL DEFAULT 0,
    http_syn_recv INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS process_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    pid INTEGER NOT NULL,
    ppid INTEGER NOT NULL,
    username TEXT NOT NULL,
    state TEXT NOT NULL,
    elapsed REAL NOT NULL,
    cpu_pct REAL NOT NULL,
    mem_pct REAL NOT NULL,
    comm TEXT NOT NULL,
    category TEXT NOT NULL,
    args TEXT NOT NULL,
    FOREIGN KEY(sample_id) REFERENCES samples(id) ON DELETE CASCADE,
    FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS http_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    cpanel_user TEXT NOT NULL,
    domain TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    method TEXT NOT NULL,
    uri TEXT NOT NULL,
    status INTEGER NOT NULL,
    user_agent TEXT NOT NULL,
    hits INTEGER NOT NULL DEFAULT 0,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE(event_id, fingerprint),
    FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS live_processes (
    rank INTEGER PRIMARY KEY,
    updated_ts REAL NOT NULL,
    pid INTEGER NOT NULL,
    ppid INTEGER NOT NULL,
    username TEXT NOT NULL,
    state TEXT NOT NULL,
    elapsed REAL NOT NULL,
    cpu_pct REAL NOT NULL,
    mem_pct REAL NOT NULL,
    comm TEXT NOT NULL,
    category TEXT NOT NULL,
    args TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS long_running_processes (
    rank INTEGER PRIMARY KEY,
    updated_ts REAL NOT NULL,
    pid INTEGER NOT NULL,
    ppid INTEGER NOT NULL,
    username TEXT NOT NULL,
    state TEXT NOT NULL,
    elapsed REAL NOT NULL,
    cpu_pct REAL NOT NULL,
    mem_pct REAL NOT NULL,
    comm TEXT NOT NULL,
    category TEXT NOT NULL,
    args TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mysql_tracking_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requested_ts REAL NOT NULL,
    started_ts REAL,
    finished_ts REAL,
    status TEXT NOT NULL DEFAULT 'pending',
    duration_seconds INTEGER NOT NULL DEFAULT 60,
    original_userstat INTEGER,
    baseline_json TEXT,
    error_message TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS mysql_tracking_results (
    run_id INTEGER NOT NULL,
    rank INTEGER NOT NULL,
    mysql_user TEXT NOT NULL,
    total_queries INTEGER NOT NULL DEFAULT 0,
    select_commands INTEGER NOT NULL DEFAULT 0,
    update_commands INTEGER NOT NULL DEFAULT 0,
    other_commands INTEGER NOT NULL DEFAULT 0,
    busy_time REAL NOT NULL DEFAULT 0,
    cpu_time REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(run_id, rank),
    FOREIGN KEY(run_id) REFERENCES mysql_tracking_runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS email_activity (
    bucket_ts INTEGER NOT NULL,
    cpanel_user TEXT NOT NULL,
    email_account TEXT NOT NULL,
    messages INTEGER NOT NULL DEFAULT 0,
    last_seen REAL NOT NULL,
    PRIMARY KEY(bucket_ts, cpanel_user, email_account)
);

CREATE TABLE IF NOT EXISTS email_log_state (
    path TEXT PRIMARY KEY,
    device INTEGER NOT NULL DEFAULT 0,
    inode INTEGER NOT NULL DEFAULT 0,
    offset INTEGER NOT NULL DEFAULT 0,
    updated_ts REAL NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
CREATE INDEX IF NOT EXISTS idx_samples_event ON samples(event_id, ts);
CREATE INDEX IF NOT EXISTS idx_process_event ON process_samples(event_id, sample_id);
CREATE INDEX IF NOT EXISTS idx_process_user ON process_samples(event_id, username);
CREATE INDEX IF NOT EXISTS idx_http_event ON http_hits(event_id, hits DESC);
CREATE INDEX IF NOT EXISTS idx_mysql_tracking_status ON mysql_tracking_runs(status, requested_ts);
CREATE INDEX IF NOT EXISTS idx_email_activity_time ON email_activity(bucket_ts);
CREATE INDEX IF NOT EXISTS idx_email_activity_rank ON email_activity(bucket_ts, messages DESC);
"""


def connect_database(path, read_only=False):
    if read_only:
        uri = "file:{}?mode=ro".format(path.replace("?", "%3f"))
        conn = sqlite3.connect(uri, uri=True, timeout=5)
    else:
        parent = os.path.dirname(path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, 0o700)
        conn = sqlite3.connect(path, timeout=15)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    if not read_only:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.executescript(SCHEMA)
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', '5')"
        )
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('app_version', ?)",
            (VERSION,),
        )
        conn.commit()
    return conn


ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<when>[^]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)(?:\s+[^\"]*)?"\s+'
    r'(?P<status>\d{3})\s+\S+(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)

EXIM_RECEIVE_RE = re.compile(
    r"^(?P<when>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?\s+"
    r"\S+\s+<=\s+(?P<sender>\S+)"
)
EXIM_AUTH_RE = re.compile(r"(?:^|\s)A=[^\s:]+:(?P<account>\S+)")
EXIM_LOCAL_USER_RE = re.compile(r"(?:^|\s)U=(?P<username>[A-Za-z0-9._-]+)(?:\s|$)")


def parse_access_line(line, strip_query=False):
    """Parse a common/combined Apache or LiteSpeed access log line."""
    match = ACCESS_RE.match(line)
    if not match:
        return None
    item = match.groupdict()
    if strip_query:
        item["uri"] = item["uri"].split("?", 1)[0]
    item["status"] = int(item["status"])
    item["ua"] = item.get("ua") or "-"
    return item


def parse_exim_line(line):
    """Return one locally submitted Exim message acceptance, excluding inbound mail."""
    received = EXIM_RECEIVE_RE.match(line)
    if not received:
        return None
    auth = EXIM_AUTH_RE.search(line)
    local_user = EXIM_LOCAL_USER_RE.search(line)
    if not auth and not local_user:
        return None
    sender = received.group("sender").strip("<>") or "[bounce]"
    account = auth.group("account") if auth else sender
    return {
        "when": received.group("when"),
        "sender": sender[:320],
        "email_account": account[:320],
        "local_user": local_user.group("username")[:64] if local_user else "",
        "authenticated": bool(auth),
    }


def http_fingerprint(item):
    raw = "\x1f".join(
        str(item.get(key, ""))
        for key in ("cpanel_user", "domain", "source_ip", "method", "uri", "status", "ua")
    )
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()


def process_category(comm, args):
    value = "{} {}".format(comm or "", args or "").lower()
    if "lsphp" in value or re.search(r"(^|[/ ])php(?:-cgi|\d|$)", value):
        return "PHP"
    if "mariadbd" in value or "mysqld" in value:
        return "MariaDB"
    if "doveadm" in value or "dovecot" in value or "imap-login" in value:
        return "Dovecot"
    if "lshttpd" in value or "litespeed" in value:
        return "LiteSpeed"
    if "imunify" in value or "cloudlinux" in value:
        return "Security/CloudLinux"
    if comm and (comm.startswith("kworker") or comm.startswith("ksoftirq")):
        return "Kernel"
    return "Other"


def event_reason(load1, cpu_busy, settings):
    reasons = []
    if load1 >= settings.floating("load_threshold"):
        reasons.append("load1 {:.2f} >= {:.2f}".format(load1, settings.floating("load_threshold")))
    if cpu_busy >= settings.floating("cpu_busy_threshold"):
        reasons.append(
            "CPU busy {:.1f}% >= {:.1f}%".format(
                cpu_busy, settings.floating("cpu_busy_threshold")
            )
        )
    return "; ".join(reasons)


def human_duration(seconds):
    seconds = max(0, int(seconds or 0))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if days:
        return "{}d {:02d}:{:02d}:{:02d}".format(days, hours, minutes, seconds)
    return "{:02d}:{:02d}:{:02d}".format(hours, minutes, seconds)


def local_time(timestamp):
    if timestamp is None:
        return "-"
    return datetime.datetime.fromtimestamp(float(timestamp)).strftime("%Y-%m-%d %H:%M:%S")


def rows_as_dicts(rows):
    return [dict(row) for row in rows]


def event_report_data(conn, event_id):
    event = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if not event:
        return None
    samples = conn.execute(
        "SELECT * FROM samples WHERE event_id = ? ORDER BY ts", (event_id,)
    ).fetchall()
    users = conn.execute(
        """
        SELECT username, AVG(sample_cpu) AS avg_cpu, MAX(sample_cpu) AS peak_cpu,
               SUM(processes) AS appearances
        FROM (
            SELECT sample_id, username, SUM(cpu_pct) AS sample_cpu, COUNT(*) AS processes
            FROM process_samples WHERE event_id = ? GROUP BY sample_id, username
        ) grouped
        GROUP BY username ORDER BY peak_cpu DESC, avg_cpu DESC LIMIT 40
        """,
        (event_id,),
    ).fetchall()
    categories = conn.execute(
        """
        SELECT category, AVG(sample_cpu) AS avg_cpu, MAX(sample_cpu) AS peak_cpu
        FROM (
            SELECT sample_id, category, SUM(cpu_pct) AS sample_cpu
            FROM process_samples WHERE event_id = ? GROUP BY sample_id, category
        ) grouped
        GROUP BY category ORDER BY peak_cpu DESC
        """,
        (event_id,),
    ).fetchall()
    commands = conn.execute(
        """
        SELECT username, category, args, MAX(cpu_pct) AS peak_cpu,
               MAX(elapsed) AS max_elapsed, COUNT(*) AS appearances
        FROM process_samples WHERE event_id = ?
        GROUP BY username, category, args
        ORDER BY peak_cpu DESC LIMIT 50
        """,
        (event_id,),
    ).fetchall()
    ips = conn.execute(
        """
        SELECT source_ip, SUM(hits) AS hits, COUNT(DISTINCT cpanel_user) AS accounts
        FROM http_hits WHERE event_id = ? AND source_ip <> '[overflow]'
        GROUP BY source_ip
        ORDER BY hits DESC LIMIT 30
        """,
        (event_id,),
    ).fetchall()
    overflow_hits = conn.execute(
        """
        SELECT COALESCE(SUM(hits), 0)
        FROM http_hits WHERE event_id = ? AND source_ip = '[overflow]'
        """,
        (event_id,),
    ).fetchone()[0]
    domains = conn.execute(
        """
        SELECT domain, SUM(hits) AS hits,
               COUNT(DISTINCT cpanel_user) AS accounts,
               COUNT(DISTINCT CASE
                   WHEN source_ip <> '[overflow]' THEN source_ip
               END) AS source_ips,
               100.0 * SUM(hits) / NULLIF(
                   (SELECT SUM(hits) FROM http_hits WHERE event_id = ?), 0
               ) AS share_pct
        FROM http_hits WHERE event_id = ? GROUP BY domain
        ORDER BY hits DESC, domain LIMIT 30
        """,
        (event_id, event_id),
    ).fetchall()
    routes = conn.execute(
        """
        SELECT cpanel_user, domain, method, uri, SUM(hits) AS hits
        FROM http_hits WHERE event_id = ?
        GROUP BY cpanel_user, domain, method, uri
        ORDER BY hits DESC LIMIT 40
        """,
        (event_id,),
    ).fetchall()
    agents = conn.execute(
        """
        SELECT user_agent, SUM(hits) AS hits
        FROM http_hits WHERE event_id = ? GROUP BY user_agent
        ORDER BY hits DESC LIMIT 20
        """,
        (event_id,),
    ).fetchall()
    return {
        "event": dict(event),
        "samples": rows_as_dicts(samples),
        "users": rows_as_dicts(users),
        "categories": rows_as_dicts(categories),
        "commands": rows_as_dicts(commands),
        "top_ips": rows_as_dicts(ips),
        "http_overflow_hits": int(overflow_hits),
        "top_domains": rows_as_dicts(domains),
        "top_routes": rows_as_dicts(routes),
        "top_agents": rows_as_dicts(agents),
    }


def render_text_report(data):
    event = data["event"]
    end_ts = event.get("end_ts") or (data["samples"][-1]["ts"] if data["samples"] else event["start_ts"])
    lines = [
        "Thor Watch Load Event #{}".format(event["id"]),
        "Start: {}".format(local_time(event["start_ts"])),
        "End: {}".format(local_time(event.get("end_ts"))),
        "Duration: {}".format(human_duration(end_ts - event["start_ts"])),
        "Status: {}".format(event["status"]),
        "Trigger: {}".format(event["trigger_reason"]),
        "Peak load1: {:.2f}".format(event["peak_load1"]),
        "Peak CPU busy: {:.1f}%".format(event["peak_cpu_busy"]),
        "",
        "Top cPanel users (peak / average CPU):",
    ]
    for row in data["users"]:
        lines.append(
            "  {:20s} {:8.1f}% peak  {:8.1f}% avg".format(
                row["username"][:20], row["peak_cpu"], row["avg_cpu"]
            )
        )
    lines.append("")
    lines.append("Top process commands:")
    for row in data["commands"][:25]:
        lines.append(
            "  {:16s} {:8.1f}% {:10s} {}".format(
                row["username"][:16], row["peak_cpu"], row["category"][:10], row["args"][:180]
            )
        )
    lines.append("")
    lines.append("Top HTTP source IPs:")
    for row in data["top_ips"]:
        lines.append(
            "  {:8d} hits  {:3d} accounts  {}".format(
                row["hits"], row["accounts"], row["source_ip"]
            )
        )
    if data["http_overflow_hits"]:
        lines.append(
            "  {:8d} additional hits omitted: source IP unavailable after unique-request limit".format(
                data["http_overflow_hits"]
            )
        )
    lines.append("")
    lines.append("Top HTTP domains:")
    for row in data["top_domains"]:
        lines.append(
            "  {:8d} hits  {:5.1f}%  {:3d} accounts  {:4d} source IPs  {}".format(
                row["hits"], row["share_pct"], row["accounts"],
                row["source_ips"], row["domain"][:120]
            )
        )
    lines.append("")
    lines.append("Top HTTP routes:")
    for row in data["top_routes"]:
        lines.append(
            "  {:8d} {:16s} {:24s} {} {}".format(
                row["hits"], row["cpanel_user"][:16], row["domain"][:24], row["method"], row["uri"][:160]
            )
        )
    return "\n".join(lines) + "\n"


def report_json(data):
    return json.dumps(data, indent=2, sort_keys=True)
