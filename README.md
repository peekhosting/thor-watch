# Thor Watch — WHM Load Investigator

Thor Watch is a root-only diagnostic WHM plugin for cPanel, CloudLinux, and
LiteSpeed servers. It keeps lightweight system baselines and automatically
switches to detailed process and HTTP evidence capture during a load spike.

Version: **0.3.0**

Public project identity:

- Product name: **Thor Watch**
- Recommended GitHub repository: `thor-watch`
- Internal service, AppConfig, and filesystem identifier: `thorwatch`

The internal identifier intentionally remains unchanged so existing installations
can upgrade without losing configuration, reports, or service management.

## What it captures

- 1, 5, and 15 minute load averages
- CPU user, system, I/O wait, steal, and total busy percentages
- run queue, process count, memory, swap, and HTTP socket counts
- top processes with cPanel/system user, PID, CPU, memory, elapsed time, and command
- CPU totals grouped by cPanel user and service category
- active PHP script paths exposed by the LiteSpeed `lsphp` process title
- source IP, domain/log, URI, status, and User-Agent correlation from cPanel domlogs
- AJAX live cards refreshed every three seconds
- continuously refreshed high-CPU process table with user, PID, elapsed time, category, and command
- on-demand 60-second Top MySQL Users tracking with query, busy-time, and CPU-time deltas
- responsive rolling load and CPU canvas charts with configured trigger markers
- TXT, JSON, and process CSV exports for each event

Thor Watch does **not** kill processes, modify websites, or block IP addresses.
The MySQL tracker changes the dynamic MariaDB `userstat` variable only after a
root user clicks the tracking button, then restores its previous state.

## Install

**Download:** [thor-watch-main.tar.gz](https://github.com/peekhosting/thor-watch/archive/refs/heads/main.tar.gz)

Download and install the current version directly from GitHub as `root`:

```bash
cd /usr/local/src
curl -fL https://github.com/peekhosting/thor-watch/archive/refs/heads/main.tar.gz \
  -o thor-watch-main.tar.gz
tar -xzf thor-watch-main.tar.gz
cd thor-watch-main
bash install.sh
```

Open WHM and search for **Thor Watch - Load Investigator**.

See the complete **[WHM installation, download, upgrade, and troubleshooting
guide](INSTALL.md)** for source archives, versioned release downloads, checksum
verification, and post-install validation.

The official cPanel AppConfig registration utility restarts `cpsrvd` while the
plugin is registered. Existing websites and LiteSpeed are not restarted.

## Threshold defaults

The supplied load threshold is appropriate for a larger shared-hosting server.
Review it against the target server's CPU count and normal baseline:

```ini
load_threshold = 20
cpu_busy_threshold = 25
normal_interval = 15
burst_interval = 2
live_processes_enabled = true
live_process_interval = 5
burst_hold_seconds = 180
max_event_seconds = 3600
retention_days = 14
mysql_tracking_duration = 60
mysql_tracking_limit = 10
```

An event begins when either threshold is met. The collector keeps a small top-20
process snapshot for the realtime dashboard every five seconds. Full top-60
process history and access-log correlation are stored only during an event.

## Top MySQL Users tracker

Click **Track MySQL Users** in the dashboard to start an asynchronous 60-second
measurement. Thor Watch records a counter snapshot, waits for the configured
window, records a second snapshot, and ranks the deltas for:

- total, SELECT, UPDATE, and OTHER commands
- MariaDB busy time
- MariaDB CPU time

Thor Watch deliberately does not run `FLUSH USER_STATISTICS`, so counters used
by another monitoring system are not discarded. If `userstat` was initially
off, it is enabled for the window and restored to off. If it was already on,
Thor Watch leaves it on.

The collector auto-detects `/usr/bin/mariadb` or `/usr/bin/mysql` and uses the
server's normal root socket/default-file authentication. No database password is
stored by Thor Watch. Set `mysql_client` in the configuration only when the
client lives elsewhere. Servers without MariaDB `USER_STATISTICS` return a
visible error in the tracker panel and do not produce a report.

## Operations

```bash
systemctl status thorwatch
journalctl -u thorwatch -f

# Validate config and database
PYTHONPATH=/usr/local/thorwatch/lib \
python3 /usr/local/thorwatch/bin/thorwatch_collector.py \
  --config /etc/thorwatch/thorwatch.conf --check

# Generate a safe one-sample test event
PYTHONPATH=/usr/local/thorwatch/lib \
python3 /usr/local/thorwatch/bin/thorwatch_collector.py \
  --config /etc/thorwatch/thorwatch.conf --once --force-event
```

After editing `/etc/thorwatch/thorwatch.conf`:

```bash
systemctl restart thorwatch
```

## Storage and privacy

- Database: `/var/lib/thorwatch/thorwatch.db` (`0600`, SQLite WAL)
- Configuration: `/etc/thorwatch/thorwatch.conf` (`0600`)
- Service log: system journal (`journalctl -u thorwatch`)
- Retention: 14 days by default

URLs, query strings, and User-Agents can contain sensitive values. The database
is root-only and the CGI independently requires the authenticated WHM user to be
`root`. Set `strip_query_strings = true` if query data should not be retained.

Cardinality and read-size limits prevent random URLs or large access logs from
growing the report database without bounds.

## Email reports

Event-closed emails are disabled by default. To enable them:

```ini
email_on_close = true
alert_email = root
```

Thor Watch invokes `/usr/sbin/sendmail` directly without a shell.

## Uninstall

Run the uninstaller as `root` **from the cloned or extracted Thor Watch project
folder**. The uninstaller is not copied into `/usr/local/thorwatch`.

If you installed from the downloadable `thor-watch-main.tar.gz` archive:

```bash
cd /usr/local/src/thor-watch-main
bash uninstall.sh
```

If you installed with `git clone`:

```bash
cd /usr/local/src/thor-watch
bash uninstall.sh
```

These commands remove the service, collector, and WHM plugin while preserving
the configuration in `/etc/thorwatch` and reports in `/var/lib/thorwatch`.

To remove everything, including the configuration and captured reports, enter
the same project folder and add `--purge`:

```bash
cd /usr/local/src/thor-watch-main  # Use thor-watch for a Git installation
bash uninstall.sh --purge
```

If the original project folder no longer exists, download it again before
uninstalling:

```bash
cd /usr/local/src
curl -fL https://github.com/peekhosting/thor-watch/archive/refs/heads/main.tar.gz \
  -o thor-watch-main.tar.gz
tar -xzf thor-watch-main.tar.gz
cd thor-watch-main
bash uninstall.sh                  # Or: bash uninstall.sh --purge
```

## Compatibility

- cPanel & WHM with AppConfig
- CloudLinux/cPanel-style `/usr/local/apache/domlogs/<user>/` logs
- Python 3.6 or newer
- systemd
- MariaDB with the `userstat` / `INFORMATION_SCHEMA.USER_STATISTICS` feature for MySQL user tracking

The UI and collector use only the Python standard library; there are no pip,
npm, or external web dependencies.

## GitHub releases

The repository includes CI and release workflows. Pushing a version tag that
matches `VERSION` runs the tests and publishes a release archive plus SHA-256
checksum automatically:

```bash
git tag v0.3.0
git push origin v0.3.0
```
