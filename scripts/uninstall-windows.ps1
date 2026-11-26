#Requires -Version 5.1
<#
.SYNOPSIS
Removes the AGOC login entry, the installed binaries and AGOC's firewall rules.

.DESCRIPTION
Choose "Quit (remove protection)" in the tray first. Run as your normal user:
    powershell -ExecutionPolicy Bypass -File scripts\uninstall-windows.ps1
The removal of binaries and rules asks for UAC consent. The baseline file and
the log directory "%ProgramData%\agoc" are kept.
#>
[CmdletBinding()]
param(
    # Internal: the elevated removal step.
    [switch]$Elevated
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Marker = 'agoc-windows-v1'
$RunKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$Target = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AGOC'

if ($Elevated) {
    $markerFile = Join-Path $Target '.managed'
    if (-not (Test-Path -LiteralPath $markerFile -PathType Leaf) -or
        (Get-Content -LiteralPath $markerFile -TotalCount 1) -ne $Marker) {
        throw "$Target is not an AGOC installation."
    }
    & (Join-Path $Target 'agoc.exe') uninstall --if-present
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Remove-Item -LiteralPath $Target -Recurse -Force
    exit 0
}

if (Get-Process -Name 'agoc', 'agoc-tray' -ErrorAction SilentlyContinue) {
    throw 'AGOC is running. Choose "Quit (remove protection)" in the tray first, then run this again.'
}
Remove-ItemProperty -Path $RunKey -Name 'AGOC' -ErrorAction SilentlyContinue
if (-not (Test-Path -LiteralPath $Target)) {
    Write-Host "Removed the login entry; no installation found in $Target."
    Write-Host 'Remove leftover firewall rules from an elevated terminal: agoc.exe uninstall --if-present'
    exit 0
}

Write-Host "Removing $Target and AGOC's firewall rules (UAC consent required)."
$shell = (Get-Process -Id $PID).Path
$arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath), '-Elevated')
$process = Start-Process -FilePath $shell -Verb RunAs -ArgumentList $arguments -Wait -PassThru
if ($process.ExitCode -ne 0) { throw "The elevated removal step failed (exit code $($process.ExitCode))." }
Write-Host 'AGOC was removed.'
