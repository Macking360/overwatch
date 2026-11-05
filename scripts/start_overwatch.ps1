<#
.SYNOPSIS
    Start the OverWatch host-integrity monitor on this Windows machine.

.DESCRIPTION
    Resolves a Python interpreter, ensures dependencies, and launches the web
    server bound to localhost. Reads optional configuration from the
    environment (OVERWATCH_PORT, OVERWATCH_ALERT_WEBHOOK, etc.). OverWatch is
    read-only: it records changes to files, processes, and registry autoruns;
    it never alters the host.

.EXAMPLE
    pwsh -File apps\overwatch\scripts\start_overwatch.ps1 -Install
#>
[CmdletBinding()]
param(
    [switch]$Install,          # install dependencies before launching
    [int]$Port = 0             # override OVERWATCH_PORT
)

$ErrorActionPreference = 'Stop'
$appDir = Split-Path -Parent $PSScriptRoot      # ...\apps\overwatch

function Resolve-Python {
    foreach ($candidate in 'py -3', 'python', 'python3') {
        $parts = $candidate.Split(' ')
        $exe = $parts[0]
        if (Get-Command $exe -ErrorAction SilentlyContinue) {
            return ,$parts
        }
    }
    throw 'No Python interpreter found. Install Python 3.11+ and retry.'
}

$py = Resolve-Python
Write-Host "[overwatch] using interpreter: $($py -join ' ')"

if ($Install) {
    Write-Host '[overwatch] installing dependencies...'
    & $py[0] @($py[1..($py.Count-1)]) -m pip install -r (Join-Path $appDir 'requirements.txt')
}

if ($Port -gt 0) { $env:OVERWATCH_PORT = "$Port" }
$env:PYTHONPATH = $appDir

Write-Host '[overwatch] starting server (Ctrl+C to stop)...'
& $py[0] @($py[1..($py.Count-1)]) -m overwatch run
