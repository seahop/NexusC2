@echo off
REM Nexus C2 Client Launcher for Windows
REM This script sets up the environment and launches the client

REM Change to the script directory
cd /d "%~dp0"

REM Check if virtual environment exists and activate it
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
    python src\main.py %*
) else (
    REM Try python command (Python 3 on Windows is typically just 'python')
    python src\main.py %*
    if errorlevel 1 (
        REM Fallback to py launcher if python not found
        py -3 src\main.py %*
    )
)
