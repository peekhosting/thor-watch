#!/usr/bin/env bash
set -euo pipefail

PURGE=false
if [[ "${1:-}" == "--purge" ]]; then
    PURGE=true
elif [[ -n "${1:-}" ]]; then
    echo "Usage: $0 [--purge]" >&2
    exit 2
fi

if [[ "${EUID}" -ne 0 ]]; then
    echo "Thor Watch must be uninstalled as root." >&2
    exit 1
fi

systemctl disable --now thorwatch.service 2>/dev/null || true
rm -f /etc/systemd/system/thorwatch.service
systemctl daemon-reload

# cPanel recommends removing plugin files before unregistering AppConfig.
rm -rf /usr/local/cpanel/whostmgr/docroot/cgi/thorwatch
rm -f /usr/local/cpanel/whostmgr/docroot/addon_plugins/thorwatch.png
rm -rf /usr/local/thorwatch

if [[ -x /usr/local/cpanel/bin/unregister_appconfig ]]; then
    /usr/local/cpanel/bin/unregister_appconfig /var/cpanel/apps/thorwatch.conf || true
fi

if [[ "${PURGE}" == true ]]; then
    rm -rf /etc/thorwatch /var/lib/thorwatch
    echo "Thor Watch removed, including configuration and captured reports."
else
    echo "Thor Watch removed. Configuration and reports were preserved."
    echo "Run '$0 --purge' to remove /etc/thorwatch and /var/lib/thorwatch too."
fi
