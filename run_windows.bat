@echo off
cd /d "%~dp0"
title Patiraj Mobile Repair Shop - Windows App

if exist "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" (
  "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" app.py
  goto done
)

if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" (
  "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" app.py
  goto done
)

if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
  "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" app.py
  goto done
)

if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
  "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" app.py
  goto done
)

where python >nul 2>nul
if %errorlevel% equ 0 (
  python app.py
  goto done
)

where py >nul 2>nul
if %errorlevel% equ 0 (
  py app.py
  goto done
)

echo.
echo [ERROR] Could not start the app. Make sure Python is installed and added to PATH.
pause

:done
