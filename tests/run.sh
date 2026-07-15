#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="${ROOT_DIR}/src"
python3 -m py_compile \
    "${ROOT_DIR}/src/thorwatch_common.py" \
    "${ROOT_DIR}/src/thorwatch_collector.py" \
    "${ROOT_DIR}/src/thorwatch.cgi"
python3 -m unittest discover -s "${ROOT_DIR}/tests" -p 'test_*.py' -v
bash -n "${ROOT_DIR}/install.sh" "${ROOT_DIR}/uninstall.sh"
