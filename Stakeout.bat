@echo off
rem Double-click this file to open Stakeout on Windows: it starts the page's local server and opens the
rem page in the browser. Closing this window (or Ctrl+C) quits Stakeout.
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel% equ 0 (
    py -3 stakeout.py ui
) else (
    python stakeout.py ui
)
rem Keep the window open when Stakeout could not start, so that its message can be read.
if errorlevel 1 pause
