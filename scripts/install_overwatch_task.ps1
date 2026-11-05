<#
.SYNOPSIS
    Register OverWatch as a per-user logon scheduled task.

.DESCRIPTION
    Creates a Scheduled Task named "OverWatch Monitor" that launches the
    monitor at user logon, running under the current user (no elevation, no
    SYSTEM). Mirrors the repo's existing *_watcher_task installers. Re-running
    updates the task in place. Use -Remove to delete it.

    This installs a per-user background monitor only; it claims no machine lane
    and changes no security settings.

.EXAMPLE
    pwsh -File apps\overwatch\scripts\install_overwatch_task.ps1
    pwsh -File apps\overwatch\scripts\install_overwatch_task.ps1 -Remove
#>
[CmdletBinding()]
param(
    [string]$TaskName = 'OverWatch Monitor',
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
$appDir   = Split-Path -Parent $PSScriptRoot
$launcher = Join-Path $PSScriptRoot 'start_overwatch.ps1'

if ($Remove) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "[overwatch] removed scheduled task '$TaskName'."
    } else {
        Write-Host "[overwatch] no scheduled task '$TaskName' found."
    }
    return
}

$pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue)?.Source
if (-not $pwsh) { $pwsh = (Get-Command powershell).Source }

$action = New-ScheduledTaskAction -Execute $pwsh `
    -Argument "-NoProfile -WindowStyle Hidden -File `"$launcher`"" `
    -WorkingDirectory $appDir

$trigger  = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal -Force | Out-Null

Write-Host "[overwatch] installed scheduled task '$TaskName' (runs at logon as $env:USERNAME)."
