#!/bin/sh
# Double-click this file to open Stakeout: it starts the page's local server and opens the page in
# the browser. Closing this window (or Ctrl+C) quits Stakeout.
cd "$(dirname "$0")" || exit 1
exec python3 stakeout.py ui
