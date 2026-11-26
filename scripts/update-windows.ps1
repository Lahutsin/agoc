#Requires -Version 5.1
<#
.SYNOPSIS
Updates an installed AGOC (see install-windows.ps1) in place.

.DESCRIPTION
Builds the release binaries, stops the installed tray, waits for the elevated
monitor and its guardian to exit, removes AGOC's firewall rules, replaces the
binaries in "%ProgramFiles%\AGOC" (restoring the old ones if that fails) and
starts the tray again. The login entry stays. Protection is removed during the
update; the restarted tray asks for UAC consent again.

Run it as your normal user, from the repository:
    powershell -ExecutionPolicy Bypass -File scripts\update-windows.ps1
#>
[CmdletBinding()]
param(
    # Internal: the elevated replacement step.
    [switch]$Elevated,
    [string]$BinaryDir
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Binaries = @('agoc.exe', 'agoc-tray.exe')
$Marker = 'agoc-windows-v1'
$Target = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AGOC'
$Monitor = Join-Path $Target 'agoc.exe'
$Tray = Join-Path $Target 'agoc-tray.exe'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Installation {
    if (-not (Test-Path -LiteralPath $Target -PathType Container)) {
        throw "AGOC is not installed in $Target; run scripts\install-windows.ps1 first."
    }
    if ((Get-Item -LiteralPath $Target -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "$Target must not be a link."
    }
    $markerFile = Join-Path $Target '.managed'
    if (-not (Test-Path -LiteralPath $markerFile -PathType Leaf) -or
        (Get-Content -LiteralPath $markerFile -TotalCount 1) -ne $Marker) {
        throw "$Target is not an AGOC installation."
    }
}

# Processes started from exactly $Path. Paths of elevated processes are only
# visible to an elevated caller.
function Get-InstalledProcess([string]$Name, [string]$Path) {
    @(Get-Process -Name $Name -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Path })
}

function Wait-NoProcess([string]$Name, [string]$Path, [int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    # @() keeps .Count valid under strict mode for zero or one process.
    while (@(Get-InstalledProcess $Name $Path).Count -gt 0) {
        if ((Get-Date) -gt $deadline) { return $false }
        Start-Sleep -Milliseconds 200
    }
    $true
}

if ($Elevated) {
    if (-not (Test-Administrator)) { throw 'The replacement step must run as Administrator.' }
    Assert-Installation
    foreach ($name in $Binaries) {
        if (-not (Test-Path -LiteralPath (Join-Path $BinaryDir $name) -PathType Leaf)) {
            throw "Missing new binary $BinaryDir\$name."
        }
    }
    # The monitor and its guardian exit on their own once the tray's control
    # connection closes; an in-flight network probe may delay them. The
    # uninstall below needs their AGOC lock to be free.
    Write-Host 'Waiting for the AGOC monitor and its guardian to exit...'
    if (-not (Wait-NoProcess 'agoc' $Monitor 90)) {
        throw 'The AGOC monitor did not stop cleanly. No binaries were replaced.'
    }
    & $Monitor uninstall --if-present
    if ($LASTEXITCODE -ne 0) { throw "Removing AGOC's firewall rules failed. No binaries were replaced." }

    $staging = Join-Path $Target ('.update-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $staging | Out-Null
    $replaced = @()
    try {
        foreach ($name in $Binaries) {
            Copy-Item -LiteralPath (Join-Path $BinaryDir $name) -Destination (Join-Path $staging "$name.new")
        }
        foreach ($name in $Binaries) {
            Move-Item -LiteralPath (Join-Path $Target $name) -Destination (Join-Path $staging "$name.old")
            $replaced += $name
            Move-Item -LiteralPath (Join-Path $staging "$name.new") -Destination (Join-Path $Target $name)
        }
    } catch {
        foreach ($name in $replaced) {
            $current = Join-Path $Target $name
            if (Test-Path -LiteralPath $current) { Remove-Item -LiteralPath $current -Force }
            Move-Item -LiteralPath (Join-Path $staging "$name.old") -Destination $current
        }
        throw
    } finally {
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    }
    exit 0
}

if (Test-Administrator) {
    Write-Warning 'Run this script as your normal user; the tray is restarted with the rights of this shell.'
}
Assert-Installation

$repository = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $cargo) {
    $fallback = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    if (-not (Test-Path -LiteralPath $fallback -PathType Leaf)) {
        throw 'Cargo is not installed or is missing from PATH. Install Rust stable and retry.'
    }
    $cargo = Get-Command $fallback
}

Write-Host 'Building AGOC release binaries...'
Push-Location -LiteralPath $repository
try {
    & $cargo.Source build --locked --release --features tray
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed. Nothing was changed.' }
} finally {
    Pop-Location
}
$newBinaries = Join-Path $repository 'target\release'
foreach ($name in $Binaries) {
    if (-not (Test-Path -LiteralPath (Join-Path $newBinaries $name) -PathType Leaf)) {
        throw "The build did not produce $newBinaries\$name."
    }
}

Write-Host 'Stopping the installed AGOC tray...'
Get-InstalledProcess 'agoc-tray' $Tray | Stop-Process -Force
if (-not (Wait-NoProcess 'agoc-tray' $Tray 30)) {
    throw 'The AGOC tray did not stop. No binaries were replaced; check the tray and retry.'
}

Write-Host "Updating the binaries in $Target (UAC consent required)..."
$shell = (Get-Process -Id $PID).Path
# Windows PowerShell joins -ArgumentList with spaces: quote paths explicitly.
$arguments = @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass',
    '-File', ('"{0}"' -f $PSCommandPath),
    '-Elevated',
    '-BinaryDir', ('"{0}"' -f $newBinaries)
)
$process = Start-Process -FilePath $shell -Verb RunAs -ArgumentList $arguments -Wait -PassThru
if ($process.ExitCode -ne 0) {
    throw "The elevated update step failed (exit code $($process.ExitCode)). Start the tray again: & '$Tray'"
}

Write-Host 'Starting the AGOC tray...'
$started = Start-Process -FilePath $Tray -PassThru
Start-Sleep -Seconds 2
if ($started.HasExited) {
    $log = Join-Path $env:LOCALAPPDATA 'agoc\agoc-tray.log'
    throw "The binaries were updated, but the tray did not stay running. See $log"
}
Write-Host 'AGOC updated and started; confirm the UAC prompt to restore protection.'
