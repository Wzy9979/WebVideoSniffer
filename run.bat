@echo off
rem Launch the WebVideoSniffer GUI (pythonw keeps the console window hidden).
rem ASCII-only on purpose: cmd.exe reads .bat using the system OEM codepage,
rem so non-ASCII text here breaks on some machines. Chinese docs live in README.md.
cd /d "%~dp0"

where pythonw >nul 2>nul
if errorlevel 1 (
    echo [ERROR] pythonw not found.
    echo Install Python 3.10+ and tick "Add Python to PATH", then retry.
    pause
    exit /b 1
)

start "" pythonw "%~dp0app.py"
exit /b 0
