@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "PYRUN=python"
where python >nul 2>&1
if errorlevel 1 (
  set "PYRUN=py -3"
  py -3 --version >nul 2>&1
  if errorlevel 1 (
    echo [ERROR] No se encontro Python. Instala Python 3 y/o agregalo al PATH.
    pause
    exit /b 1
  )
) else (
  python --version >nul 2>&1
  if errorlevel 1 (
    echo [ERROR] python en PATH no funciona.
    pause
    exit /b 1
  )
)

if not exist ".venv\Scripts\python.exe" (
  echo [INFO] Creando entorno virtual .venv ...
  %PYRUN% -m venv .venv
  if errorlevel 1 (
    echo [ERROR] No se pudo ejecutar: %PYRUN% -m venv .venv
    pause
    exit /b 1
  )
)

echo [INFO] Dependencias: flask, requests, pyperclip, cryptography ...
".venv\Scripts\pip.exe" install -q -r "%~dp0requirements.txt"
if errorlevel 1 (
  echo [ERROR] pip install fallo.
  pause
  exit /b 1
)

echo.
echo ============================================
echo   ClipBridge CLIENT
echo ============================================
echo El server debe ser la misma version ^(/pull_wait^).
echo Ctrl+C para detener.
echo ============================================
echo.

".venv\Scripts\python.exe" "%~dp0clipbridge.py" --client
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" echo [ERROR] Codigo de salida %RC%
pause
endlocal
exit /b %RC%
