param(
    [string]$PythonPath = "python"
)

$ErrorActionPreference = "Stop"

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$MainScript = Join-Path $ScriptRoot "main.py"

if (-not (Test-Path -Path $MainScript)) {
    Write-Error "No se encontró main.py en $ScriptRoot"
}

try {
    $PythonCmd = Get-Command $PythonPath -ErrorAction Stop
} catch {
    Write-Error "Python no está disponible como '$PythonPath'. Actualiza la variable o instala Python."
    exit 1
}

& $PythonCmd.Path $MainScript
