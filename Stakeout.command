#!/bin/sh
# Double-click this file to open Stakeout: it starts the page's local server and opens the page in
# the browser. Closing this window (or Ctrl+C) quits Stakeout.
cd "$(dirname "$0")" || exit 1
# The first Python that is 3.12 or newer (MIN_PYTHON in stakeout.py): each newer version by name, then
# python3, which may be an older one (the Python 3.9 of Apple's command line tools).
for py in python3.14 python3.13 python3.12 python3; do
    if command -v "$py" >/dev/null 2>&1 && "$py" -c 'import sys; sys.exit(sys.version_info < (3, 12))' 2>/dev/null; then
        exec "$py" stakeout.py ui
    fi
done
echo "找不到 Python 3.12 或更新的版本。请从 https://www.python.org 安装。" >&2
exit 1
