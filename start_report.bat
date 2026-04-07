@echo off
REM ─────────────────────────────────────────────────────────────
REM Mist Deny Log Intelligence — Windows Launcher
REM Double-click this file to start the report tool.
REM ─────────────────────────────────────────────────────────────

cd /d "%~dp0"

SET PORT=8765

REM Check for Python
python --version >nul 2>&1
IF ERRORLEVEL 1 (
  echo ERROR: Python is not installed or not in your PATH.
  echo Please install Python from https://www.python.org/downloads/
  echo Make sure to check "Add Python to PATH" during installation.
  pause
  exit /b 1
)

REM Kill anything already on this port
FOR /F "tokens=5" %%P IN ('netstat -ano ^| findstr ":%PORT% "') DO (
  taskkill /PID %%P /F >nul 2>&1
)

REM Start the local web server
echo Starting local web server on port %PORT%...
start /b python -c "import os,http.server,socketserver; os.chdir(r'%~dp0'); h=http.server.SimpleHTTPRequestHandler; h.log_message=lambda *a:None; socketserver.TCPServer(('',%PORT%),h).serve_forever()"

REM Give the server a moment to start
timeout /t 2 /nobreak >nul

REM Open the browser
start http://localhost:%PORT%/deny_dashboard.html

echo.
echo  Deny Log Intelligence is running at:
echo  http://localhost:%PORT%/deny_dashboard.html
echo.
echo  Leave this window open while you use the tool.
echo  Close this window to stop the server.
echo.
pause
