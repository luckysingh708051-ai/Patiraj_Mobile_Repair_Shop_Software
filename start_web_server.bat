@echo off
cd /d "%~dp0"
title Patiraj Mobile Repair Shop - Web & Mobile Server

echo =================================================================
echo   PATIRAJ MOBILE REPAIR SHOP - WEB ^& MOBILE SERVER
echo =================================================================
echo.

set PY_EXE=

if exist "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" (
  set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
  goto found_py
)

if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" (
  set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
  goto found_py
)

if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
  set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
  goto found_py
)

if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
  set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
  goto found_py
)

where python >nul 2>nul
if %errorlevel% equ 0 (
  set "PY_EXE=python"
  goto found_py
)

where py >nul 2>nul
if %errorlevel% equ 0 (
  set "PY_EXE=py"
  goto found_py
)

echo [ERROR] Python nahi mila! Kripya Python install karein ya PATH me add karein.
echo.
pause
exit /b 1

:found_py
echo [*] Using Python: %PY_EXE%
echo [*] Checking dependencies (Flask)...
"%PY_EXE%" -c "import flask" >nul 2>nul
if %errorlevel% neq 0 (
  echo [!] Flask library install nahi hai. Installing Flask now...
  "%PY_EXE%" -m pip install flask
  if %errorlevel% neq 0 (
    echo [ERROR] Flask install nahi ho paya. Kripya internet connection check karein.
    pause
    exit /b 1
  )
  echo [OK] Flask successfully installed!
)

echo.
echo [*] Starting Web ^& Mobile Server...
echo =================================================================
echo   NOTE: Is command prompt window ko band MAT karein!
echo   Jab tak ye window open rahegi, tab tak mobile/web link chalega.
echo =================================================================
echo.
"%PY_EXE%" web_app.py

:done
pause
