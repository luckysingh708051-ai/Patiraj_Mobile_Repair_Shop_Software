@echo off
cd /d "%~dp0"
title Patiraj Repair Shop - Web Server (Android & Windows)

echo ==============================================================
echo   PATIRAJ MOBILE REPAIR SHOP - WEB & MOBILE SERVER
echo ==============================================================
echo.

where python >nul 2>nul
if %errorlevel% equ 0 (
  python web_app.py
  goto done
)

if exist "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" (
  "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" web_app.py
  goto done
)

if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
  "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" web_app.py
  goto done
)

py web_app.py
:done
pause
