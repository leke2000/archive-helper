@echo off
rem 通用解压归档助手 启动脚本
setlocal
cd /d "%~dp0"

rem 优先使用 py 启动器，其次 python
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
echo 未找到 Python，请先安装 Python 3.9 或更高版本。
pause
