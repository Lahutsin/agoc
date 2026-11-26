#Requires -Version 5.1
<#
.SYNOPSIS
Installs AGOC for the current Windows user, or updates an existing installation.

.DESCRIPTION
Copies agoc.exe and agoc-tray.exe into "%ProgramFiles%\AGOC" (writable only by
administrators; the copy step asks for UAC consent once) and starts the tray at
login through the per-user Run key. The tray itself runs as your normal user and
asks for UAC consent at every start; no passwordless elevation is installed.

Run it as your normal user, from the repository:
    powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1
To update an existing installation, prefer scripts\update-windows.ps1; re-running
this script also works after "Quit (remove protection)" in the tray.
#>
[CmdletBinding()]
param(
    [string]$BinaryDir = (Join-Path $PSScriptRoot '..\target\release'),
    # Internal: the elevated copy step.
    [switch]$Elevated,
    [string]$Destination
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Binaries = @('agoc.exe', 'agoc-tray.exe')
$Marker = 'agoc-windows-v1'
$RunKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$Target = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AGOC'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ($Elevated) {
    if (-not (Test-Administrator)) { throw 'The copy step must run as Administrator.' }
    if ($Destination -ne $Target) { throw "Unexpected installation path: $Destination" }
    if (Test-Path -LiteralPath $Target) {
        $item = Get-Item -LiteralPath $Target -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "$Target must not be a link."
        }
        $markerFile = Join-Path $Target '.managed'
        if (-not (Test-Path -LiteralPath $markerFile -PathType Leaf) -or
            (Get-Content -LiteralPath $markerFile -TotalCount 1) -ne $Marker) {
            throw "$Target exists but is not an AGOC installation; remove it first."
        }
    } else {
        # Inherits the Program Files permissions: only administrators may write.
        New-Item -ItemType Directory -Path $Target | Out-Null
    }
    foreach ($name in $Binaries) {
        Copy-Item -LiteralPath (Join-Path $BinaryDir $name) -Destination (Join-Path $Target $name) -Force
    }
    Set-Content -LiteralPath (Join-Path $Target '.managed') -Value $Marker -Encoding ASCII
    exit 0
}

if (Test-Administrator) {
    Write-Warning 'Run this script as your normal user; the login entry is created for the current account.'
}
$BinaryDir = (Resolve-Path -LiteralPath $BinaryDir).ProviderPath.TrimEnd('\')
foreach ($name in $Binaries) {
    if (-not (Test-Path -LiteralPath (Join-Path $BinaryDir $name) -PathType Leaf)) {
        throw "Missing $BinaryDir\$name. Build first: cargo build --release --features tray"
    }
}
if (Get-Process -Name 'agoc', 'agoc-tray' -ErrorAction SilentlyContinue) {
    throw 'AGOC is running. Choose "Quit (remove protection)" in the tray first, then run this again.'
}

Write-Host "Installing AGOC into $Target (UAC consent required for this step)."
$shell = (Get-Process -Id $PID).Path
# Windows PowerShell joins -ArgumentList with spaces: quote paths explicitly.
$arguments = @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass',
    '-File', ('"{0}"' -f $PSCommandPath),
    '-Elevated',
    '-BinaryDir', ('"{0}"' -f $BinaryDir),
    '-Destination', ('"{0}"' -f $Target)
)
$process = Start-Process -FilePath $shell -Verb RunAs -ArgumentList $arguments -Wait -PassThru
if ($process.ExitCode -ne 0) { throw "The elevated copy step failed (exit code $($process.ExitCode))." }

$tray = Join-Path $Target 'agoc-tray.exe'
New-ItemProperty -Path $RunKey -Name 'AGOC' -Value ('"{0}"' -f $tray) -PropertyType String -Force | Out-Null

Write-Host ''
Write-Host 'Installed. The tray starts at your next login and asks for UAC consent.'
Write-Host "Start it now: & '$tray'"
