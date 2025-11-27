@echo off
setlocal
set SCRIPT_DIR=%~dp0
set SCRIPT_PATH=%SCRIPT_DIR%main.py

if not exist "%SCRIPT_PATH%" (
    echo No se encontro main.py en %SCRIPT_DIR%
    exit /b 1
)

python "%SCRIPT_PATH%"
