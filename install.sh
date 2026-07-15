#!/usr/bin/env bash
set -euo pipefail

APP="thorwatch"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/usr/local/thorwatch"
CONFIG_DIR="/etc/thorwatch"
DATA_DIR="/var/lib/thorwatch"
CGI_DIR="/usr/local/cpanel/whostmgr/docroot/cgi/thorwatch"
ICON_DIR="/usr/local/cpanel/whostmgr/docroot/addon_plugins"
SYSTEMD_DIR="/etc/systemd/system"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Thor Watch must be installed as root." >&2
    exit 1
fi

for required in /usr/bin/python3 /usr/local/cpanel/bin/register_appconfig /usr/local/cpanel/bin/unregister_appconfig /bin/systemctl; do
    if [[ ! -x "${required}" ]]; then
        echo "Required executable not found: ${required}" >&2
        exit 1
    fi
done

/usr/bin/python3 - <<'PY'
import sys
if sys.version_info < (3, 6):
    raise SystemExit("Thor Watch requires Python 3.6 or newer")
PY

echo "Installing Thor Watch..."
if systemctl is-active --quiet thorwatch.service 2>/dev/null; then
    echo "Stopping the existing Thor Watch service for a clean upgrade..."
    systemctl stop thorwatch.service
fi

install -d -m 755 "${INSTALL_DIR}/bin" "${INSTALL_DIR}/lib"
install -d -m 700 "${CONFIG_DIR}" "${DATA_DIR}"
install -d -m 755 "${CGI_DIR}" "${ICON_DIR}"

install -m 755 "${ROOT_DIR}/src/thorwatch_collector.py" "${INSTALL_DIR}/bin/thorwatch_collector.py"
install -m 644 "${ROOT_DIR}/src/thorwatch_common.py" "${INSTALL_DIR}/lib/thorwatch_common.py"
install -m 755 "${ROOT_DIR}/src/thorwatch.cgi" "${CGI_DIR}/index.cgi"
install -m 644 "${ROOT_DIR}/assets/thorwatch.png" "${ICON_DIR}/thorwatch.png"
install -m 644 "${ROOT_DIR}/systemd/thorwatch.service" "${SYSTEMD_DIR}/thorwatch.service"
install -m 600 "${ROOT_DIR}/config/thorwatch.conf" "${CONFIG_DIR}/thorwatch.conf.dist"

if [[ ! -f "${CONFIG_DIR}/thorwatch.conf" ]]; then
    install -m 600 "${ROOT_DIR}/config/thorwatch.conf" "${CONFIG_DIR}/thorwatch.conf"
else
    echo "Preserving existing ${CONFIG_DIR}/thorwatch.conf"
fi

if command -v restorecon >/dev/null 2>&1; then
    restorecon -RF "${INSTALL_DIR}" "${CGI_DIR}" "${ICON_DIR}/thorwatch.png" "${DATA_DIR}" || true
fi

PYTHONPATH="${INSTALL_DIR}/lib" /usr/bin/python3 -m py_compile \
    "${INSTALL_DIR}/lib/thorwatch_common.py" \
    "${INSTALL_DIR}/bin/thorwatch_collector.py" \
    "${CGI_DIR}/index.cgi"

PYTHONPATH="${INSTALL_DIR}/lib" /usr/bin/python3 \
    "${INSTALL_DIR}/bin/thorwatch_collector.py" \
    --config "${CONFIG_DIR}/thorwatch.conf" --check

if [[ -f /var/cpanel/apps/thorwatch.conf ]]; then
    /usr/local/cpanel/bin/unregister_appconfig /var/cpanel/apps/thorwatch.conf
fi
/usr/local/cpanel/bin/register_appconfig "${ROOT_DIR}/plugin/thorwatch.conf"

systemctl daemon-reload
systemctl enable --now thorwatch.service

sleep 2
if ! systemctl is-active --quiet thorwatch.service; then
    echo "Thor Watch service did not start. Recent log follows:" >&2
    journalctl -u thorwatch.service -n 50 --no-pager >&2 || true
    exit 1
fi

echo
echo "Thor Watch installed successfully."
echo "Open WHM and search for: Thor Watch - Load Investigator"
echo "Config: ${CONFIG_DIR}/thorwatch.conf"
echo "Service: systemctl status thorwatch"
echo "Logs: journalctl -u thorwatch -f"
