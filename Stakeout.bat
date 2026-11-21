@echo off
rem Double-click this file to open Stakeout on Windows: it starts the page's local server and opens the
rem page in the browser. Closing this window (or Ctrl+C) quits Stakeout.
cd /d "%~dp0"
rem The first Python that is 3.12 or newer (MIN_PYTHON in stakeout.py): the Python launcher py with its default
rem (python.org installs py), python on PATH, then py with each newer version by name, for when the default is
rem an older one. A Python that is not there, or the Microsoft Store's stand-in for one, fails the check.
rem Stakeout.exe looks in the same order.
set "STAKEOUT_PY="
for %%P in ("py -3" "python" "py -3.14" "py -3.13" "py -3.12") do (
    if not defined STAKEOUT_PY (
        %%~P -c "import sys; sys.exit(sys.version_info < (3, 12))" >nul 2>nul && set "STAKEOUT_PY=%%~P"
    )
)
if defined STAKEOUT_PY goto run
rem The message below is UTF-8, as is this file: cmd reads the lines after chcp with the new code page.
chcp 65001 >nul
echo 找不到 Python 3.12 或更新的版本。请从 https://www.python.org 安装，安装时勾上“Add python.exe to PATH”。
pause
exit /b 1

:run
%STAKEOUT_PY% stakeout.py ui
rem Keep the window open when Stakeout could not start, so that its message can be read.
if errorlevel 1 pause
