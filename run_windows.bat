@echo off
cd /d "%~dp0"

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

if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
  "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" app.py
  goto done
)

echo.
echo Could not start the app. Make sure Python is installed and added to PATH.
pause

:done
