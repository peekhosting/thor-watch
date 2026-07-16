#!/usr/bin/python3
"""Adaptive load-event collector for the Thor Watch WHM plugin."""

from __future__ import print_function

import argparse
import datetime
import glob
import json
import logging
import os
import pwd
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

from thorwatch_common import (
    VERSION,
    connect_database,
    event_reason,
    event_report_data,
    http_fingerprint,
    load_settings,
    parse_access_line,
    parse_exim_line,
    process_category,
    render_text_report,
)


LOG = logging.getLogger("thorwatch.collector")
CLK_TCK = float(os.sysconf(os.sysconf_names["SC_CLK_TCK"]))
PAGE_SIZE = float(os.sysconf("SC_PAGE_SIZE"))
LONG_RUNNING_MIN_SECONDS = 30 * 86400

MYSQL_USER_STATS_SQL = """
SELECT
    COALESCE(USER, ''),
    COALESCE(SELECT_COMMANDS, 0),
    COALESCE(UPDATE_COMMANDS, 0),
    COALESCE(OTHER_COMMANDS, 0),
    COALESCE(BUSY_TIME, 0),
    COALESCE(CPU_TIME, 0)
FROM INFORMATION_SCHEMA.USER_STATISTICS
""".strip()


def parse_mysql_user_statistics(output):
    """Parse tab-separated USER_STATISTICS rows emitted by the MariaDB CLI."""
    result = {}
    for number, line in enumerate(output.splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 6:
            raise ValueError("Unexpected USER_STATISTICS output on line {}".format(number))
        username = parts[0] or "[anonymous]"
        try:
            result[username] = {
                "select_commands": int(parts[1]),
                "update_commands": int(parts[2]),
                "other_commands": int(parts[3]),
                "busy_time": float(parts[4]),
                "cpu_time": float(parts[5]),
            }
        except ValueError:
            raise ValueError("Invalid USER_STATISTICS values on line {}".format(number))
    return result


def calculate_mysql_user_deltas(baseline, current, limit=10):
    """Return ranked per-user activity accrued between two counter snapshots."""
    integer_keys = ("select_commands", "update_commands", "other_commands")
    float_keys = ("busy_time", "cpu_time")
    rows = []
    for username, values in current.items():
        previous = baseline.get(username, {})
        row = {"mysql_user": username}
        for key in integer_keys:
            current_value = int(values.get(key, 0))
            previous_value = int(previous.get(key, 0))
            row[key] = max(0, current_value - previous_value)
        for key in float_keys:
            current_value = float(values.get(key, 0))
            previous_value = float(previous.get(key, 0))
            row[key] = max(0.0, current_value - previous_value)
        row["total_queries"] = sum(row[key] for key in integer_keys)
        if row["total_queries"] or row["busy_time"] or row["cpu_time"]:
            rows.append(row)
    rows.sort(
        key=lambda row: (row["total_queries"], row["busy_time"], row["cpu_time"]),
        reverse=True,
    )
    return rows[: max(1, int(limit))]


def read_loadavg():
    with open("/proc/loadavg", "r") as handle:
        parts = handle.read().split()
    running, total = parts[3].split("/", 1)
    return {
        "load1": float(parts[0]),
        "load5": float(parts[1]),
        "load15": float(parts[2]),
        "running": int(running),
        "total_processes": int(total),
    }


def read_cpu_times():
    with open("/proc/stat", "r") as handle:
        values = handle.readline().split()
    if not values or values[0] != "cpu":
        raise RuntimeError("Unable to read aggregate CPU counters")
    numbers = [int(value) for value in values[1:]]
    while len(numbers) < 8:
        numbers.append(0)
    names = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
    return dict(zip(names, numbers[:8]))


def calculate_cpu_percent(previous, current):
    empty = {"cpu_user": 0.0, "cpu_system": 0.0, "cpu_iowait": 0.0, "cpu_steal": 0.0, "cpu_busy": 0.0}
    if not previous:
        return empty
    delta = {}
    for key in current:
        delta[key] = max(0, current[key] - previous.get(key, current[key]))
    total = float(sum(delta.values()))
    if total <= 0:
        return empty
    user = 100.0 * (delta["user"] + delta["nice"]) / total
    system = 100.0 * (delta["system"] + delta["irq"] + delta["softirq"]) / total
    iowait = 100.0 * delta["iowait"] / total
    steal = 100.0 * delta["steal"] / total
    return {
        "cpu_user": user,
        "cpu_system": system,
        "cpu_iowait": iowait,
        "cpu_steal": steal,
        "cpu_busy": user + system + steal,
    }


def read_memory():
    values = {}
    with open("/proc/meminfo", "r") as handle:
        for line in handle:
            key, value = line.split(":", 1)
            values[key] = int(value.strip().split()[0])
    total = float(values.get("MemTotal", 0))
    available = float(values.get("MemAvailable", values.get("MemFree", 0)))
    swap_total = float(values.get("SwapTotal", 0))
    swap_free = float(values.get("SwapFree", 0))
    return {
        "mem_total_kb": total,
        "mem_used_pct": (100.0 * (total - available) / total) if total else 0.0,
        "swap_used_pct": (100.0 * (swap_total - swap_free) / swap_total) if swap_total else 0.0,
    }


def read_uptime():
    with open("/proc/uptime", "r") as handle:
        return float(handle.read().split()[0])


def read_http_sockets():
    established = 0
    syn_recv = 0
    for filename in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(filename, "r") as handle:
                next(handle, None)
                for line in handle:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    local = parts[1]
                    state = parts[3]
                    try:
                        port = int(local.rsplit(":", 1)[1], 16)
                    except (IndexError, ValueError):
                        continue
                    if port not in (80, 443):
                        continue
                    if state == "01":
                        established += 1
                    elif state == "03":
                        syn_recv += 1
        except (IOError, OSError):
            continue
    return {"http_established": established, "http_syn_recv": syn_recv}


def read_system_snapshot(previous_cpu):
    load = read_loadavg()
    cpu_now = read_cpu_times()
    snapshot = {}
    snapshot.update(load)
    snapshot.update(calculate_cpu_percent(previous_cpu, cpu_now))
    snapshot.update(read_memory())
    snapshot.update(read_http_sockets())
    snapshot["ts"] = time.time()
    return snapshot, cpu_now


class ProcessReader(object):
    def __init__(self):
        self.previous = {}
        self.previous_time = None
        self.user_cache = {}
        self.candidates = []

    def username(self, uid):
        if uid not in self.user_cache:
            try:
                self.user_cache[uid] = pwd.getpwuid(uid).pw_name
            except KeyError:
                self.user_cache[uid] = str(uid)
        return self.user_cache[uid]

    @staticmethod
    def _read_stat(pid):
        with open("/proc/{}/stat".format(pid), "r") as handle:
            line = handle.read()
        closing = line.rfind(")")
        if closing < 0:
            raise ValueError("Malformed process stat")
        fields = line[closing + 2 :].split()
        return {
            "state": fields[0],
            "ppid": int(fields[1]),
            "ticks": int(fields[11]) + int(fields[12]),
            "start_ticks": int(fields[19]),
            "rss_pages": int(fields[21]),
        }

    @staticmethod
    def _read_comm(pid):
        with open("/proc/{}/comm".format(pid), "r") as handle:
            return handle.read().strip()[:128]

    @staticmethod
    def _read_args(pid, comm):
        try:
            with open("/proc/{}/cmdline".format(pid), "rb") as handle:
                value = handle.read(8192).replace(b"\x00", b" ").strip()
            if value:
                return value.decode("utf-8", "replace")[:4096]
        except (IOError, OSError):
            pass
        return "[{}]".format(comm)

    def scan(self, mem_total_kb):
        now_mono = time.monotonic()
        uptime = read_uptime()
        interval = (now_mono - self.previous_time) if self.previous_time is not None else None
        current = {}
        candidates = []
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            pid = int(name)
            try:
                info = self._read_stat(pid)
                uid = os.stat("/proc/{}".format(pid)).st_uid
                comm = self._read_comm(pid)
            except (IOError, OSError, ValueError, IndexError):
                continue
            key = (info["start_ticks"], info["ticks"])
            current[pid] = key
            elapsed = max(0.01, uptime - (info["start_ticks"] / CLK_TCK))
            previous = self.previous.get(pid)
            if previous and previous[0] == info["start_ticks"] and interval and interval > 0:
                cpu_pct = 100.0 * max(0, info["ticks"] - previous[1]) / (CLK_TCK * interval)
            else:
                cpu_pct = 100.0 * info["ticks"] / (CLK_TCK * elapsed)
            rss_kb = info["rss_pages"] * PAGE_SIZE / 1024.0
            mem_pct = (100.0 * rss_kb / mem_total_kb) if mem_total_kb else 0.0
            candidates.append(
                {
                    "pid": pid,
                    "ppid": info["ppid"],
                    "username": self.username(uid),
                    "state": info["state"],
                    "elapsed": elapsed,
                    "cpu_pct": cpu_pct,
                    "mem_pct": mem_pct,
                    "comm": comm,
                }
            )
        self.previous = current
        self.previous_time = now_mono
        candidates.sort(key=lambda row: (row["cpu_pct"], row["elapsed"]), reverse=True)
        self.candidates = candidates
        return candidates

    def _complete(self, item):
        item = dict(item)
        if "args" not in item:
            item["args"] = self._read_args(item["pid"], item["comm"])
        if "category" not in item:
            item["category"] = process_category(item["comm"], item["args"])
        return item

    def read(self, limit, minimum_cpu, mem_total_kb):
        candidates = self.scan(mem_total_kb)
        selected = []
        for item in candidates:
            if len(selected) >= limit:
                break
            if item["cpu_pct"] < minimum_cpu and selected:
                break
            selected.append(self._complete(item))
        return selected

    def long_running(self, minimum_elapsed, limit):
        candidates = [
            item for item in self.candidates if item["elapsed"] >= minimum_elapsed
        ]
        candidates.sort(key=lambda row: (row["elapsed"], row["pid"]), reverse=True)
        return [self._complete(item) for item in candidates[:limit]]


class EventState(object):
    def __init__(self, event_id, start_ts):
        self.id = event_id
        self.start_ts = start_ts
        self.last_trigger_ts = start_ts
        self.last_log_scan = 0
        self.log_positions = {}
        self.http_keys = set()
        self.php_users = set()


class Collector(object):
    def __init__(self, settings):
        self.settings = settings
        self.conn = connect_database(settings.get("database"))
        self.mysql_client_path = None
        self.cpu_previous = None
        self.process_reader = ProcessReader()
        self.event = None
        self.stop_requested = False
        self.last_cleanup = 0
        self.last_email_scan = 0
        self.email_domains = {}
        self.email_domains_signature = None
        self._interrupt_stale_events()
        if not self.settings.boolean("live_processes_enabled"):
            self.conn.execute("DELETE FROM live_processes")
            self.conn.commit()
        if not self.settings.boolean("long_running_processes_enabled"):
            self.conn.execute("DELETE FROM long_running_processes")
            self.conn.commit()

    def _interrupt_stale_events(self):
        now = time.time()
        self.conn.execute(
            "UPDATE events SET status = 'interrupted', end_ts = COALESCE(end_ts, ?) WHERE status = 'open'",
            (now,),
        )
        self.conn.commit()

    def request_stop(self, _signum=None, _frame=None):
        self.stop_requested = True

    def start_event(self, snapshot, reason):
        cursor = self.conn.execute(
            """
            INSERT INTO events(start_ts, status, trigger_reason, peak_load1, peak_cpu_busy, peak_running)
            VALUES(?, 'open', ?, ?, ?, ?)
            """,
            (
                snapshot["ts"],
                reason,
                snapshot["load1"],
                snapshot["cpu_busy"],
                snapshot["running"],
            ),
        )
        self.conn.commit()
        self.event = EventState(cursor.lastrowid, snapshot["ts"])
        LOG.warning("Load event %s started: %s", self.event.id, reason)

    def close_event(self, status="closed"):
        if not self.event:
            return
        event_id = self.event.id
        try:
            self.capture_access_logs(force=True)
        except Exception:
            LOG.exception("Final access-log capture failed for event %s", event_id)
        self.conn.execute(
            "UPDATE events SET status = ?, end_ts = ? WHERE id = ?",
            (status, time.time(), event_id),
        )
        self.conn.commit()
        LOG.warning("Load event %s %s", event_id, status)
        if status == "closed" and self.settings.boolean("email_on_close"):
            self.send_email(event_id)
        self.event = None

    def write_sample(self, snapshot, processes=None):
        event_id = self.event.id if self.event else None
        cursor = self.conn.execute(
            """
            INSERT INTO samples(
                event_id, ts, load1, load5, load15, running, total_processes,
                cpu_user, cpu_system, cpu_iowait, cpu_steal, cpu_busy,
                mem_used_pct, swap_used_pct, http_established, http_syn_recv
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                snapshot["ts"],
                snapshot["load1"],
                snapshot["load5"],
                snapshot["load15"],
                snapshot["running"],
                snapshot["total_processes"],
                snapshot["cpu_user"],
                snapshot["cpu_system"],
                snapshot["cpu_iowait"],
                snapshot["cpu_steal"],
                snapshot["cpu_busy"],
                snapshot["mem_used_pct"],
                snapshot["swap_used_pct"],
                snapshot["http_established"],
                snapshot["http_syn_recv"],
            ),
        )
        sample_id = cursor.lastrowid
        if self.event and processes:
            values = []
            for item in processes:
                values.append(
                    (
                        sample_id,
                        event_id,
                        item["pid"],
                        item["ppid"],
                        item["username"],
                        item["state"],
                        item["elapsed"],
                        item["cpu_pct"],
                        item["mem_pct"],
                        item["comm"],
                        item["category"],
                        item["args"],
                    )
                )
                if item["category"] == "PHP":
                    self.event.php_users.add(item["username"])
            self.conn.executemany(
                """
                INSERT INTO process_samples(
                    sample_id, event_id, pid, ppid, username, state, elapsed,
                    cpu_pct, mem_pct, comm, category, args
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
        if self.event:
            self.conn.execute(
                """
                UPDATE events SET
                    peak_load1 = MAX(peak_load1, ?),
                    peak_cpu_busy = MAX(peak_cpu_busy, ?),
                    peak_running = MAX(peak_running, ?),
                    sample_count = sample_count + 1
                WHERE id = ?
                """,
                (snapshot["load1"], snapshot["cpu_busy"], snapshot["running"], event_id),
            )
        self.conn.commit()
        return sample_id

    def write_live_processes(self, processes, updated_ts):
        """Atomically replace the small current-process snapshot used by AJAX."""
        self.conn.execute("DELETE FROM live_processes")
        if processes:
            rows = []
            for rank, item in enumerate(processes, 1):
                rows.append(
                    (
                        rank,
                        updated_ts,
                        item["pid"],
                        item["ppid"],
                        item["username"],
                        item["state"],
                        item["elapsed"],
                        item["cpu_pct"],
                        item["mem_pct"],
                        item["comm"],
                        item["category"],
                        item["args"],
                    )
                )
            self.conn.executemany(
                """
                INSERT INTO live_processes(
                    rank, updated_ts, pid, ppid, username, state, elapsed,
                    cpu_pct, mem_pct, comm, category, args
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        self.conn.commit()

    def write_long_running_processes(self, processes, updated_ts):
        """Replace the current snapshot of processes aged 30 days or longer."""
        self.conn.execute("DELETE FROM long_running_processes")
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('long_running_updated_ts', ?)",
            (str(updated_ts),),
        )
        if processes:
            rows = []
            for rank, item in enumerate(processes, 1):
                rows.append(
                    (
                        rank,
                        updated_ts,
                        item["pid"],
                        item["ppid"],
                        item["username"],
                        item["state"],
                        item["elapsed"],
                        item["cpu_pct"],
                        item["mem_pct"],
                        item["comm"],
                        item["category"],
                        item["args"],
                    )
                )
            self.conn.executemany(
                """
                INSERT INTO long_running_processes(
                    rank, updated_ts, pid, ppid, username, state, elapsed,
                    cpu_pct, mem_pct, comm, category, args
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        self.conn.commit()

    def discover_logs(self, username):
        root = os.path.realpath(self.settings.get("access_log_root"))
        pattern = os.path.join(self.settings.get("access_log_root"), username, "*")
        found = []
        seen = set()
        for path in glob.glob(pattern):
            try:
                real = os.path.realpath(path)
                common = os.path.commonpath((root, real))
                stat = os.stat(real)
            except (OSError, ValueError):
                continue
            if common != root or not os.path.isfile(real) or real in seen:
                continue
            basename = os.path.basename(path)
            if basename.endswith((".gz", ".bkup", ".bytes", ".offset")):
                continue
            seen.add(real)
            found.append((real, basename))
        return found

    def _read_log_chunk(self, path, domain, budget):
        try:
            stat = os.stat(path)
        except OSError:
            return [], None, 0
        previous = self.event.log_positions.get(path)
        if previous and previous[0] == stat.st_ino and previous[1] <= stat.st_size:
            offset = previous[1]
            initial = False
        else:
            offset = max(0, stat.st_size - self.settings.integer("access_log_pretrigger_bytes"))
            initial = offset > 0
        limit = min(self.settings.integer("access_log_read_limit_bytes"), max(0, budget))
        if limit <= 0:
            return [], (stat.st_ino, offset, domain), 0
        try:
            with open(path, "rb") as handle:
                handle.seek(offset)
                chunk = handle.read(limit)
        except (IOError, OSError):
            return [], None, 0
        if not chunk:
            return [], (stat.st_ino, offset, domain), 0
        start = 0
        if initial:
            first_newline = chunk.find(b"\n")
            if first_newline < 0:
                return [], (stat.st_ino, offset + len(chunk), domain), len(chunk)
            start = first_newline + 1
        last_newline = chunk.rfind(b"\n")
        if last_newline < start:
            return [], (stat.st_ino, offset, domain), len(chunk)
        complete = chunk[start : last_newline + 1]
        new_offset = offset + last_newline + 1
        lines = complete.decode("utf-8", "replace").splitlines()
        return lines, (stat.st_ino, new_offset, domain), len(chunk)

    @staticmethod
    def _access_timestamp(value, fallback):
        try:
            parsed = datetime.datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
            return parsed.timestamp()
        except (TypeError, ValueError, OverflowError):
            return fallback

    def capture_access_logs(self, force=False):
        if not self.event or not self.settings.boolean("access_logs_enabled"):
            return
        now = time.time()
        if not force and now - self.event.last_log_scan < self.settings.integer("access_log_interval"):
            return
        self.event.last_log_scan = now
        aggregate = {}
        budget = self.settings.integer("access_log_global_limit_bytes")
        for username in sorted(self.event.php_users):
            if budget <= 0:
                break
            for path, domain in self.discover_logs(username):
                if budget <= 0:
                    break
                lines, position, bytes_read = self._read_log_chunk(path, domain, budget)
                budget -= bytes_read
                if position:
                    self.event.log_positions[path] = position
                for line in lines:
                    item = parse_access_line(line, self.settings.boolean("strip_query_strings"))
                    if not item:
                        continue
                    seen_ts = self._access_timestamp(item.get("when"), now)
                    if seen_ts < self.event.start_ts - 180:
                        continue
                    item["source_ip"] = item.pop("ip")
                    item.update({"cpanel_user": username, "domain": domain})
                    item["uri"] = item["uri"][:1024]
                    item["ua"] = item["ua"][:512]
                    fingerprint = http_fingerprint(item)
                    if fingerprint not in self.event.http_keys:
                        if len(self.event.http_keys) >= self.settings.integer("http_unique_limit"):
                            item.update(
                                {
                                    "source_ip": "[overflow]",
                                    "method": "-",
                                    "uri": "[other unique requests]",
                                    "status": 0,
                                    "ua": "[various]",
                                }
                            )
                            fingerprint = http_fingerprint(item)
                        self.event.http_keys.add(fingerprint)
                    key = fingerprint
                    if key not in aggregate:
                        aggregate[key] = [item, 0, seen_ts, seen_ts]
                    aggregate[key][1] += 1
                    aggregate[key][2] = min(aggregate[key][2], seen_ts)
                    aggregate[key][3] = max(aggregate[key][3], seen_ts)
        if not aggregate:
            return
        rows = []
        for fingerprint, value in aggregate.items():
            item, hits, first_seen, last_seen = value
            rows.append(
                (
                    self.event.id,
                    fingerprint,
                    item["cpanel_user"],
                    item["domain"],
                    item["source_ip"],
                    item["method"],
                    item["uri"],
                    item["status"],
                    item["ua"],
                    hits,
                    first_seen,
                    last_seen,
                )
            )
        self.conn.executemany(
            """
            INSERT OR IGNORE INTO http_hits(
                event_id, fingerprint, cpanel_user, domain, source_ip, method,
                uri, status, user_agent, hits, first_seen, last_seen
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
            """,
            [row[:9] + row[10:] for row in rows],
        )
        self.conn.executemany(
            """
            UPDATE http_hits SET
                hits = hits + ?,
                first_seen = MIN(first_seen, ?),
                last_seen = MAX(last_seen, ?)
            WHERE event_id = ? AND fingerprint = ?
            """,
            [(row[9], row[10], row[11], row[0], row[1]) for row in rows],
        )
        self.conn.commit()

    def _load_email_domains(self):
        path = self.settings.get("email_userdomains_path")
        try:
            stat = os.stat(path)
            signature = (stat.st_dev, stat.st_ino, stat.st_mtime, stat.st_size)
        except OSError:
            self.email_domains = {}
            self.email_domains_signature = None
            return self.email_domains
        if signature == self.email_domains_signature:
            return self.email_domains
        domains = {}
        try:
            with open(path, "r") as handle:
                for line in handle:
                    domain, separator, username = line.partition(":")
                    domain = domain.strip().lower()
                    username = username.strip().split(None, 1)[0] if separator and username.strip() else ""
                    if domain and username:
                        domains[domain] = username[:64]
        except (IOError, OSError):
            domains = {}
        self.email_domains = domains
        self.email_domains_signature = signature
        return domains

    def _save_email_log_state(self, path, stat, offset, now, error=""):
        device = stat.st_dev if stat else 0
        inode = stat.st_ino if stat else 0
        cursor = self.conn.execute(
            """
            UPDATE email_log_state
            SET device = ?, inode = ?, offset = ?, updated_ts = ?, last_error = ?
            WHERE path = ?
            """,
            (device, inode, offset, now, error[:800], path),
        )
        if not cursor.rowcount:
            self.conn.execute(
                """
                INSERT INTO email_log_state(path, device, inode, offset, updated_ts, last_error)
                VALUES(?, ?, ?, ?, ?, ?)
                """,
                (path, device, inode, offset, now, error[:800]),
            )
        self.conn.commit()

    def capture_email_activity(self, force=False):
        """Aggregate locally submitted Exim messages into five-second scans."""
        if not self.settings.boolean("email_monitoring_enabled"):
            return
        now = time.time()
        interval = self.settings.integer("email_monitor_interval")
        if not force and now - self.last_email_scan < interval:
            return
        self.last_email_scan = now
        path = self.settings.get("email_log_path")
        state = self.conn.execute(
            "SELECT * FROM email_log_state WHERE path = ?", (path,)
        ).fetchone()
        try:
            stat = os.stat(path)
        except OSError as exc:
            self._save_email_log_state(path, None, state["offset"] if state else 0, now, str(exc))
            return
        if not os.path.isfile(path):
            self._save_email_log_state(path, stat, 0, now, "Configured Exim log is not a regular file")
            return
        if not state:
            self._save_email_log_state(path, stat, stat.st_size, now)
            return
        if state["device"] == stat.st_dev and state["inode"] == stat.st_ino and state["offset"] <= stat.st_size:
            offset = state["offset"]
        else:
            offset = 0
        limit = self.settings.integer("email_read_limit_bytes")
        try:
            with open(path, "rb") as handle:
                handle.seek(offset)
                chunk = handle.read(limit)
        except (IOError, OSError) as exc:
            self._save_email_log_state(path, stat, offset, now, str(exc))
            return
        if not chunk:
            self._save_email_log_state(path, stat, offset, now)
            return
        last_newline = chunk.rfind(b"\n")
        if last_newline < 0:
            self._save_email_log_state(path, stat, offset, now)
            return
        lines = chunk[: last_newline + 1].decode("utf-8", "replace").splitlines()
        new_offset = offset + last_newline + 1
        domains = self._load_email_domains()
        bucket_ts = int(now // interval) * interval
        aggregate = {}
        for line in lines:
            item = parse_exim_line(line)
            if not item:
                continue
            account = item["email_account"].lower()
            username = item["local_user"]
            if not username and "@" in account:
                username = domains.get(account.rsplit("@", 1)[1], "")
            username = username or "[unmapped]"
            try:
                seen_ts = datetime.datetime.strptime(
                    item["when"], "%Y-%m-%d %H:%M:%S"
                ).timestamp()
            except (TypeError, ValueError, OverflowError):
                seen_ts = now
            key = (username[:64], account[:320])
            if key not in aggregate:
                aggregate[key] = [0, seen_ts]
            aggregate[key][0] += 1
            aggregate[key][1] = max(aggregate[key][1], seen_ts)
        if aggregate:
            self.conn.executemany(
                """
                INSERT OR IGNORE INTO email_activity(
                    bucket_ts, cpanel_user, email_account, messages, last_seen
                ) VALUES(?, ?, ?, 0, ?)
                """,
                [
                    (bucket_ts, username, account, values[1])
                    for (username, account), values in aggregate.items()
                ],
            )
            self.conn.executemany(
                """
                UPDATE email_activity
                SET messages = messages + ?, last_seen = MAX(last_seen, ?)
                WHERE bucket_ts = ? AND cpanel_user = ? AND email_account = ?
                """,
                [
                    (values[0], values[1], bucket_ts, username, account)
                    for (username, account), values in aggregate.items()
                ],
            )
        self._save_email_log_state(path, stat, new_offset, now)

    def _find_mysql_client(self):
        if self.mysql_client_path:
            return self.mysql_client_path
        configured = self.settings.get("mysql_client").strip()
        candidates = []
        if configured:
            candidates.append(configured)
        candidates.extend(("/usr/bin/mariadb", "/usr/bin/mysql", "mariadb", "mysql"))
        seen = set()
        for candidate in candidates:
            path = candidate if os.path.isabs(candidate) else shutil.which(candidate)
            if not path or path in seen:
                continue
            seen.add(path)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                self.mysql_client_path = path
                return path
        raise RuntimeError(
            "MariaDB client not found; set mysql_client in /etc/thorwatch/thorwatch.conf"
        )

    def _run_mysql(self, sql):
        command = [
            self._find_mysql_client(),
            "--batch",
            "--raw",
            "--skip-column-names",
            "--connect-timeout=5",
            "--execute",
            sql,
        ]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise RuntimeError("MariaDB command timed out after 15 seconds")
        if process.returncode:
            message = stderr.decode("utf-8", "replace").strip()
            message = " ".join(message.split())[:800]
            raise RuntimeError(message or "MariaDB client exited with an error")
        return stdout.decode("utf-8", "replace")

    def _mysql_userstat_state(self):
        values = [value.strip().lower() for value in self._run_mysql(
            "SELECT @@GLOBAL.userstat"
        ).splitlines() if value.strip()]
        if not values:
            raise RuntimeError("MariaDB did not return @@GLOBAL.userstat")
        if values[-1] in ("1", "on", "true"):
            return 1
        if values[-1] in ("0", "off", "false"):
            return 0
        raise RuntimeError("Unexpected @@GLOBAL.userstat value: {}".format(values[-1][:40]))

    def _set_mysql_userstat(self, enabled):
        self._run_mysql("SET GLOBAL userstat = {}".format(1 if enabled else 0))

    def _mysql_statistics_snapshot(self):
        return parse_mysql_user_statistics(self._run_mysql(MYSQL_USER_STATS_SQL))

    def _restore_mysql_userstat(self, original_userstat):
        if original_userstat == 0:
            self._set_mysql_userstat(False)

    def _fail_mysql_tracking(self, run_id, error, original_userstat=None):
        message = str(error)
        if original_userstat == 0:
            try:
                self._restore_mysql_userstat(original_userstat)
            except Exception as restore_error:
                message = "{}; WARNING: could not restore userstat=0: {}".format(
                    message, restore_error
                )
        self.conn.execute(
            """
            UPDATE mysql_tracking_runs
            SET status = 'failed', finished_ts = ?, error_message = ?
            WHERE id = ?
            """,
            (time.time(), message[:1600], run_id),
        )
        self.conn.commit()
        LOG.error("MySQL tracking run %s failed: %s", run_id, message)

    def _start_mysql_tracking(self, row):
        original_userstat = None
        try:
            original_userstat = self._mysql_userstat_state()
            self.conn.execute(
                "UPDATE mysql_tracking_runs SET original_userstat = ? WHERE id = ?",
                (original_userstat, row["id"]),
            )
            self.conn.commit()
            if original_userstat == 0:
                self._set_mysql_userstat(True)
            baseline = self._mysql_statistics_snapshot()
            started = time.time()
            self.conn.execute(
                """
                UPDATE mysql_tracking_runs
                SET status = 'running', started_ts = ?, baseline_json = ?, error_message = ''
                WHERE id = ? AND status = 'pending'
                """,
                (started, json.dumps(baseline, separators=(",", ":")), row["id"]),
            )
            self.conn.commit()
            LOG.info("MySQL tracking run %s started for %s seconds", row["id"], row["duration_seconds"])
        except Exception as exc:
            self._fail_mysql_tracking(row["id"], exc, original_userstat)

    def _finish_mysql_tracking(self, row):
        original_userstat = row["original_userstat"]
        try:
            current = self._mysql_statistics_snapshot()
        except Exception as exc:
            self._fail_mysql_tracking(row["id"], exc, original_userstat)
            return
        try:
            self._restore_mysql_userstat(original_userstat)
        except Exception as exc:
            self._fail_mysql_tracking(row["id"], exc, original_userstat)
            return
        try:
            baseline = json.loads(row["baseline_json"] or "{}")
            results = calculate_mysql_user_deltas(
                baseline, current, self.settings.integer("mysql_tracking_limit")
            )
            self.conn.execute("DELETE FROM mysql_tracking_results WHERE run_id = ?", (row["id"],))
            if results:
                self.conn.executemany(
                    """
                    INSERT INTO mysql_tracking_results(
                        run_id, rank, mysql_user, total_queries, select_commands,
                        update_commands, other_commands, busy_time, cpu_time
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            row["id"],
                            rank,
                            item["mysql_user"],
                            item["total_queries"],
                            item["select_commands"],
                            item["update_commands"],
                            item["other_commands"],
                            item["busy_time"],
                            item["cpu_time"],
                        )
                        for rank, item in enumerate(results, 1)
                    ],
                )
            self.conn.execute(
                """
                UPDATE mysql_tracking_runs
                SET status = 'completed', finished_ts = ?, baseline_json = NULL,
                    error_message = ''
                WHERE id = ?
                """,
                (time.time(), row["id"]),
            )
            self.conn.commit()
            LOG.info("MySQL tracking run %s completed with %s users", row["id"], len(results))
        except Exception as exc:
            self._fail_mysql_tracking(row["id"], exc, original_userstat)

    def process_mysql_tracking(self):
        """Advance the latest on-demand MariaDB tracking request without blocking."""
        running = self.conn.execute(
            "SELECT * FROM mysql_tracking_runs WHERE status = 'running' ORDER BY id LIMIT 1"
        ).fetchone()
        if running:
            target = running["started_ts"] + running["duration_seconds"]
            if time.time() >= target:
                self._finish_mysql_tracking(running)
                return False
            return True
        pending = self.conn.execute(
            "SELECT * FROM mysql_tracking_runs WHERE status = 'pending' ORDER BY id LIMIT 1"
        ).fetchone()
        if pending:
            self._start_mysql_tracking(pending)
            refreshed = self.conn.execute(
                "SELECT status FROM mysql_tracking_runs WHERE id = ?", (pending["id"],)
            ).fetchone()
            return bool(refreshed and refreshed["status"] == "running")
        return False

    def interrupt_mysql_tracking(self):
        running = self.conn.execute(
            "SELECT * FROM mysql_tracking_runs WHERE status = 'running' ORDER BY id LIMIT 1"
        ).fetchone()
        if running:
            try:
                self._restore_mysql_userstat(running["original_userstat"])
                message = "Collector stopped before the tracking window completed"
            except Exception as exc:
                message = "Collector stopped; WARNING: could not restore userstat: {}".format(exc)
            self.conn.execute(
                """
                UPDATE mysql_tracking_runs
                SET status = 'interrupted', finished_ts = ?, baseline_json = NULL,
                    error_message = ? WHERE id = ?
                """,
                (time.time(), message[:1600], running["id"]),
            )
        self.conn.execute(
            """
            UPDATE mysql_tracking_runs SET status = 'interrupted', finished_ts = ?,
                error_message = 'Collector stopped before tracking started'
            WHERE status = 'pending'
            """,
            (time.time(),),
        )
        self.conn.commit()

    def cleanup(self, force=False):
        now = time.time()
        if not force and now - self.last_cleanup < 3600:
            return
        self.last_cleanup = now
        cutoff = now - self.settings.integer("retention_days") * 86400
        self.conn.execute("DELETE FROM events WHERE COALESCE(end_ts, start_ts) < ?", (cutoff,))
        self.conn.execute("DELETE FROM samples WHERE event_id IS NULL AND ts < ?", (cutoff,))
        self.conn.execute(
            """
            DELETE FROM mysql_tracking_runs
            WHERE status NOT IN ('pending', 'running')
              AND COALESCE(finished_ts, requested_ts) < ?
            """,
            (cutoff,),
        )
        self.conn.execute("DELETE FROM email_activity WHERE bucket_ts < ?", (cutoff,))
        self.conn.commit()

    def send_email(self, event_id):
        recipient = self.settings.get("alert_email").strip()
        if not recipient or not re.match(r"^[A-Za-z0-9_.+@-]+$", recipient):
            return
        sendmail = "/usr/sbin/sendmail"
        if not os.path.exists(sendmail):
            LOG.error("Cannot send event report: %s does not exist", sendmail)
            return
        data = event_report_data(self.conn, event_id)
        if not data:
            return
        body = render_text_report(data)
        message = (
            "To: {recipient}\n"
            "Subject: [Thor Watch] Load event #{event_id} on {host}\n"
            "Content-Type: text/plain; charset=UTF-8\n\n"
            "{body}"
        ).format(recipient=recipient, event_id=event_id, host=socket.gethostname(), body=body)
        try:
            process = subprocess.Popen([sendmail, "-t", "-oi"], stdin=subprocess.PIPE)
            process.communicate(message.encode("utf-8"), timeout=15)
        except Exception:
            LOG.exception("Unable to email event %s", event_id)

    def run_once(self, force_event=False):
        self.process_mysql_tracking()
        self.capture_email_activity(force=True)
        first, self.cpu_previous = read_system_snapshot(self.cpu_previous)
        time.sleep(0.2)
        snapshot, self.cpu_previous = read_system_snapshot(self.cpu_previous)
        reason = "manual diagnostic capture" if force_event else event_reason(
            snapshot["load1"], snapshot["cpu_busy"], self.settings
        )
        if reason:
            self.start_event(snapshot, reason)
            processes = self.process_reader.read(
                self.settings.integer("top_process_limit"),
                self.settings.floating("process_cpu_threshold"),
                snapshot["mem_total_kb"],
            )
            self.write_sample(snapshot, processes)
            self.write_live_processes(processes, snapshot["ts"])
            if self.settings.boolean("long_running_processes_enabled"):
                long_running = self.process_reader.long_running(
                    LONG_RUNNING_MIN_SECONDS,
                    self.settings.integer("long_running_process_limit"),
                )
                self.write_long_running_processes(long_running, snapshot["ts"])
            self.capture_access_logs(force=True)
            self.close_event("test" if force_event else "closed")
        else:
            processes = None
            if self.settings.boolean("live_processes_enabled"):
                processes = self.process_reader.read(
                    self.settings.integer("live_process_limit"),
                    self.settings.floating("live_process_cpu_threshold"),
                    snapshot["mem_total_kb"],
                )
            elif self.settings.boolean("long_running_processes_enabled"):
                self.process_reader.scan(snapshot["mem_total_kb"])
            self.write_sample(snapshot)
            if processes is not None:
                self.write_live_processes(processes, snapshot["ts"])
            if self.settings.boolean("long_running_processes_enabled"):
                long_running = self.process_reader.long_running(
                    LONG_RUNNING_MIN_SECONDS,
                    self.settings.integer("long_running_process_limit"),
                )
                self.write_long_running_processes(long_running, snapshot["ts"])
        self.cleanup(force=True)
        return snapshot

    def run(self):
        LOG.info("Thor Watch %s collector started", VERSION)
        while not self.stop_requested:
            started = time.monotonic()
            mysql_tracking_active = False
            try:
                mysql_tracking_active = self.process_mysql_tracking()
                self.capture_email_activity()
                snapshot, self.cpu_previous = read_system_snapshot(self.cpu_previous)
                reason = event_reason(snapshot["load1"], snapshot["cpu_busy"], self.settings)
                if reason and not self.event:
                    self.start_event(snapshot, reason)
                if self.event and reason:
                    self.event.last_trigger_ts = snapshot["ts"]
                processes = None
                if self.event:
                    processes = self.process_reader.read(
                        self.settings.integer("top_process_limit"),
                        self.settings.floating("process_cpu_threshold"),
                        snapshot["mem_total_kb"],
                    )
                elif self.settings.boolean("live_processes_enabled"):
                    processes = self.process_reader.read(
                        self.settings.integer("live_process_limit"),
                        self.settings.floating("live_process_cpu_threshold"),
                        snapshot["mem_total_kb"],
                    )
                elif self.settings.boolean("long_running_processes_enabled"):
                    self.process_reader.scan(snapshot["mem_total_kb"])
                self.write_sample(snapshot, processes)
                if processes is not None:
                    self.write_live_processes(processes, snapshot["ts"])
                if self.settings.boolean("long_running_processes_enabled"):
                    long_running = self.process_reader.long_running(
                        LONG_RUNNING_MIN_SECONDS,
                        self.settings.integer("long_running_process_limit"),
                    )
                    self.write_long_running_processes(long_running, snapshot["ts"])
                if self.event:
                    self.capture_access_logs()
                    event_age = snapshot["ts"] - self.event.start_ts
                    quiet_age = snapshot["ts"] - self.event.last_trigger_ts
                    if event_age >= self.settings.integer("max_event_seconds"):
                        self.close_event("closed")
                    elif quiet_age >= self.settings.integer("burst_hold_seconds"):
                        self.close_event("closed")
                self.cleanup()
            except Exception:
                LOG.exception("Collector iteration failed")
            if self.event:
                interval = self.settings.integer("burst_interval")
            elif self.settings.boolean("live_processes_enabled"):
                interval = min(
                    self.settings.integer("normal_interval"),
                    self.settings.integer("live_process_interval"),
                )
            else:
                interval = self.settings.integer("normal_interval")
            if mysql_tracking_active:
                interval = min(interval, 1)
            if self.settings.boolean("email_monitoring_enabled"):
                interval = min(interval, self.settings.integer("email_monitor_interval"))
            remaining = max(0.2, interval - (time.monotonic() - started))
            end = time.monotonic() + remaining
            while not self.stop_requested and time.monotonic() < end:
                time.sleep(min(0.5, end - time.monotonic()))
        self.interrupt_mysql_tracking()
        if self.event:
            self.close_event("interrupted")
        LOG.info("Thor Watch collector stopped")


def build_parser():
    parser = argparse.ArgumentParser(description="Thor Watch adaptive load collector")
    parser.add_argument("--config", help="configuration file path")
    parser.add_argument("--once", action="store_true", help="take one sample and exit")
    parser.add_argument(
        "--force-event", action="store_true", help="create a one-sample test event (requires --once)"
    )
    parser.add_argument("--check", action="store_true", help="validate configuration and database")
    parser.add_argument("--version", action="version", version=VERSION)
    return parser


def main():
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if args.force_event and not args.once:
        raise SystemExit("--force-event requires --once")
    settings = load_settings(args.config)
    collector = Collector(settings)
    if args.check:
        print("Thor Watch {} configuration and database: OK".format(VERSION))
        return 0
    if args.once:
        snapshot = collector.run_once(args.force_event)
        print(
            "load={:.2f}/{:.2f}/{:.2f} cpu_busy={:.1f}% running={}/{}".format(
                snapshot["load1"],
                snapshot["load5"],
                snapshot["load15"],
                snapshot["cpu_busy"],
                snapshot["running"],
                snapshot["total_processes"],
            )
        )
        return 0
    signal.signal(signal.SIGTERM, collector.request_stop)
    signal.signal(signal.SIGINT, collector.request_stop)
    collector.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
