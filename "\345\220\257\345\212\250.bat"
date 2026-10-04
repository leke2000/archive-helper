@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    py main.py
    goto :eof
)
where python >nul 2>nul
if %errorlevel%==0 (
    python main.py
    goto :eof
)
echo Python not found. Please install Python 3.9 or newer.
pause
