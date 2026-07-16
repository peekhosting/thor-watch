# Installing Thor Watch on cPanel & WHM

Thor Watch must be installed as `root` on the WHM server. The installer copies
the collector and WHM plugin into their system locations, registers the plugin
with cPanel AppConfig, and enables the `thorwatch` systemd service.

## Requirements

- cPanel & WHM with `/usr/local/cpanel/bin/register_appconfig`
- A systemd-based server
- Python 3.6 or newer at `/usr/bin/python3`
- Root SSH access
- Exim with the standard cPanel `/var/log/exim_mainlog` for email monitoring
- MariaDB `userstat` support for the optional Top MySQL Users tracker

The dashboard and collector have no pip, npm, or other third-party runtime
dependencies.

## Option 1: Download the current source archive

This method works without Git:

```bash
ssh root@YOUR_SERVER_IP
cd /usr/local/src
curl -fL https://github.com/peekhosting/thor-watch/archive/refs/heads/main.tar.gz \
  -o thor-watch-main.tar.gz
tar -xzf thor-watch-main.tar.gz
cd thor-watch-main
bash install.sh
```

## Option 2: Clone with Git

Use this method when you want to update the installation later with `git pull`:

```bash
ssh root@YOUR_SERVER_IP
cd /usr/local/src
git clone https://github.com/peekhosting/thor-watch.git
cd thor-watch
bash install.sh
```

On AlmaLinux, Rocky Linux, or CloudLinux, install Git first if necessary:

```bash
dnf install -y git
```

## Option 3: Install a versioned GitHub release

Versioned release archives and their SHA-256 checksum files are published on
the [Releases page](https://github.com/peekhosting/thor-watch/releases). Replace
`0.5.1` below with the release you want to install:

```bash
ssh root@YOUR_SERVER_IP
cd /usr/local/src
VERSION=0.5.1
curl -fLO "https://github.com/peekhosting/thor-watch/releases/download/v${VERSION}/thor-watch-${VERSION}.tar.gz"
curl -fLO "https://github.com/peekhosting/thor-watch/releases/download/v${VERSION}/thor-watch-${VERSION}.sha256"
sha256sum -c "thor-watch-${VERSION}.sha256"
tar -xzf "thor-watch-${VERSION}.tar.gz"
cd "thor-watch-${VERSION}"
bash install.sh
```

Do not use the versioned commands until that version appears on the Releases
page. The current-source and Git methods above are always available.

## Open the plugin

Sign in to WHM as `root`, then search for:

```text
Thor Watch - Load Investigator
```

AppConfig restarts the cPanel `cpsrvd` service while registering the plugin.
The installer does not restart hosted websites, Apache, or LiteSpeed.

## Verify the installation

```bash
systemctl status thorwatch --no-pager
journalctl -u thorwatch -n 50 --no-pager
```

Validate the installed configuration and SQLite database:

```bash
PYTHONPATH=/usr/local/thorwatch/lib \
python3 /usr/local/thorwatch/bin/thorwatch_collector.py \
  --config /etc/thorwatch/thorwatch.conf --check
```

Generate a safe, one-sample test event:

```bash
PYTHONPATH=/usr/local/thorwatch/lib \
python3 /usr/local/thorwatch/bin/thorwatch_collector.py \
  --config /etc/thorwatch/thorwatch.conf --once --force-event
```

## Configure thresholds

Edit the root-only configuration file:

```bash
nano /etc/thorwatch/thorwatch.conf
```

Review these defaults against the server's CPU count and normal workload:

```ini
load_threshold = 20
cpu_busy_threshold = 25
normal_interval = 15
burst_interval = 2
retention_days = 14
email_monitoring_enabled = true
email_log_path = /var/log/exim_mainlog
email_userdomains_path = /etc/userdomains
email_monitor_interval = 5
```

Apply changes with:

```bash
systemctl restart thorwatch
```

The configuration is preserved when the installer is run again. Captured data
is stored in `/var/lib/thorwatch/thorwatch.db` and is also preserved during an
upgrade.

## Upgrade

For a Git installation:

```bash
cd /usr/local/src/thor-watch
git pull --ff-only
bash install.sh
```

For an archive installation, download and extract the newer archive, enter its
directory, and run `bash install.sh` again.

## Uninstall

Run the uninstaller as `root` from the cloned or extracted project directory.
For an installation made from the current source archive:

```bash
cd /usr/local/src/thor-watch-main
bash uninstall.sh
```

For a Git installation:

```bash
cd /usr/local/src/thor-watch
bash uninstall.sh
```

This preserves `/etc/thorwatch` and `/var/lib/thorwatch`. To also delete the
configuration and all captured reports, enter the same project directory and
run:

```bash
bash uninstall.sh --purge
```

The uninstaller is not copied to `/usr/local/thorwatch`. If the source project
directory was deleted, download and extract the current archive again using
[Option 1](#option-1-download-the-current-source-archive), enter the resulting
`thor-watch-main` directory, and then run the appropriate uninstall command.

## Troubleshooting

Follow the background collector log:

```bash
journalctl -u thorwatch -f
```

If the plugin is not visible, confirm that it is registered and that the
collector is active:

```bash
test -f /var/cpanel/apps/thorwatch.conf && echo "AppConfig registered"
systemctl is-active thorwatch
```

The Top MySQL Users measurement is performed by the background collector. Once
the request has been queued, closing the WHM page does not stop the measurement
or prevent MariaDB `userstat` from being restored to its original state.
