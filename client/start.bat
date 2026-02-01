@echo off
chcp 65001 >nul
title SmartProxy
cd /d "%~dp0"
python smartproxy.py
pause
