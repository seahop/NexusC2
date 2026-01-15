# Nexus C2 Client Launcher for Windows (PowerShell)
# This script sets up the environment and launches the client

# Change to the script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# Check if virtual environment exists
$VenvActivate = Join-Path $ScriptDir "venv\Scripts\Activate.ps1"

if (Test-Path $VenvActivate) {
    # Activate virtual environment and run
    & $VenvActivate
    python src\main.py @args
} else {
    # Try to find Python
    $PythonCmd = $null

    # Check for python in PATH
    if (Get-Command python -ErrorAction SilentlyContinue) {
        $PythonCmd = "python"
    }
    # Check for py launcher (Windows Python launcher)
    elseif (Get-Command py -ErrorAction SilentlyContinue) {
        $PythonCmd = "py -3"
    }

    if ($PythonCmd) {
        & $PythonCmd src\main.py @args
    } else {
        Write-Error "Python not found. Please install Python 3 and ensure it's in your PATH."
        Write-Host "Download from: https://www.python.org/downloads/"
        exit 1
    }
}
