<#
.SYNOPSIS
  Dogfood a local build: stop the GUI + engine service, swap in freshly-built
  release binaries, restart the service, relaunch the GUI. No MSI.

.DESCRIPTION
  Mirrors what the auto-update file-swap does (engine's selfupdate.rs
  `apply_bundle_swap`) but from a local `cargo build --release`, so you can run
  an unreleased build ahead of publishing a release manifest. Touches only the
  two exes in the install directory -- never engine.toml, the service
  registration, or the wireguard-nt DLL -- so none of the MSI major-upgrade
  gotchas apply.

  Privilege split: builds and relaunches the (unprivileged) GUI as the current
  user, and self-elevates ONLY for the stop-service / copy / start-service step,
  so the GUI never ends up running elevated. Whatever version is in the
  workspace Cargo.toml is what the swapped-in engine will report -- bump it
  first if you want the dogfood build to self-identify as the release version.

.PARAMETER SkipBuild
  Swap in whatever is already in target\release without rebuilding.

.PARAMETER SwapOnly
  Internal: the elevated child re-invokes the script with this to perform just
  the privileged swap. Not meant to be passed by hand.

.EXAMPLE
  scripts\dev-install.ps1
  scripts\dev-install.ps1 -SkipBuild
#>
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$SwapOnly
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'UnityLANEngine'
$GuiProcess  = 'unitylan-gui'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
# Shared between the unprivileged parent and the elevated child (whose console
# window closes on exit) so the parent can surface what the swap did. Under the
# repo, not %TEMP% -- the two contexts have different TEMP dirs.
$LogFile = Join-Path $Root 'target\dev-install.log'

function Log($msg) {
    Write-Host $msg -ForegroundColor Cyan
    Add-Content -Path $LogFile -Value $msg -ErrorAction SilentlyContinue
}

function Get-InstallDir {
    $svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if (-not $svc) { throw "service '$ServiceName' not found -- is UnityLAN installed?" }
    # PathName is the full command line: a quoted exe path (possibly) plus args.
    if ($svc.PathName -match '^\s*"([^"]+)"') { $exe = $Matches[1] }
    else { $exe = ($svc.PathName -split '\s+')[0] }
    return (Split-Path -Parent $exe)
}

function Install-Binary($src, $dst) {
    # Rename the target aside before writing the new bytes. Windows permits
    # renaming a still-mapped/locked image even when it forbids overwriting it in
    # place -- the same trick the engine's self_replace path uses -- so this beats
    # `Copy-Item -Force`, which fails outright if a handle is still lingering.
    if (Test-Path $dst) {
        $aside = "$dst.old"
        Remove-Item $aside -Force -ErrorAction SilentlyContinue
        Rename-Item -Path $dst -NewName ([System.IO.Path]::GetFileName($aside)) -Force
    }
    Copy-Item $src $dst -Force
    # Best effort: a still-mapped old image can't be deleted yet, and that's fine.
    Remove-Item "$dst.old" -Force -ErrorAction SilentlyContinue
}

# ---- privileged phase: kill GUI, stop service, copy, restart ----
if ($SwapOnly) {
    Set-Content -Path $LogFile -Value "" -ErrorAction SilentlyContinue
    $installDir = Get-InstallDir
    $engineSrc  = Join-Path $Root 'target\release\unitylan-engine.exe'
    $guiSrc     = Join-Path $Root 'target\release\unitylan-gui.exe'
    foreach ($f in @($engineSrc, $guiSrc)) {
        if (-not (Test-Path $f)) { throw "missing build output: $f (run without -SkipBuild first)" }
    }

    $failed = $false
    try {
        Log ">> stopping GUI"
        $g = Get-Process -Name $GuiProcess -ErrorAction SilentlyContinue
        if ($g) { $g | Stop-Process -Force; $g | ForEach-Object { $_.WaitForExit(5000) | Out-Null } }

        Log ">> stopping service $ServiceName"
        $cim = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
        $svc = Get-Service -Name $ServiceName
        if ($svc.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force
            $svc.WaitForStatus('Stopped', '00:00:30')
        }
        # The SCM can report Stopped a beat before the process releases its image,
        # so wait the old pid all the way out before swapping over its exe.
        if ($cim.ProcessId) {
            $p = Get-Process -Id $cim.ProcessId -ErrorAction SilentlyContinue
            if ($p) { $p.WaitForExit(5000) | Out-Null }
        }

        Log ">> swapping binaries into $installDir"
        Install-Binary $engineSrc (Join-Path $installDir 'unitylan-engine.exe')
        Install-Binary $guiSrc    (Join-Path $installDir 'unitylan-gui.exe')
        # Clear any leftover update artifacts from a prior auto-update so they can't shadow this fresh
        # dev build: `.new.exe` (retired staging name) and `.old.exe` (the engine's renamed-aside image
        # from `promote_gui`), which the GUI's `clean_stale_gui` would otherwise be the one to remove.
        Remove-Item (Join-Path $installDir 'unitylan-gui.new.exe') -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $installDir 'unitylan-gui.old.exe') -Force -ErrorAction SilentlyContinue
    }
    catch {
        Log "!! swap failed: $($_.Exception.Message)"
        $failed = $true
    }
    finally {
        # Always bring the service back -- even if the swap threw, never leave the mesh down.
        try {
            Log ">> starting service $ServiceName"
            Start-Service -Name $ServiceName
            (Get-Service -Name $ServiceName).WaitForStatus('Running', '00:00:30')
        }
        catch {
            Log "!! could not start service: $($_.Exception.Message)"
            $failed = $true
        }
    }

    if ($failed) { exit 1 }
    $ver = (Get-Item (Join-Path $installDir 'unitylan-gui.exe')).VersionInfo.FileVersion
    Log ">> swapped in unitylan-gui $ver (engine service restarted)"
    exit 0
}

# ---- unprivileged phase: build, elevate for the swap, relaunch GUI ----
if (-not $SkipBuild) {
    Write-Host ">> cargo build --release (engine + gui)" -ForegroundColor Cyan
    Push-Location $Root
    try {
        cargo build --release -p unitylan-engine -p unitylan-gui
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    }
    finally { Pop-Location }
}

Write-Host ">> elevating to swap binaries + restart service (accept the UAC prompt)" -ForegroundColor Cyan
$proc = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-SwapOnly'
)
if (Test-Path $LogFile) { Get-Content $LogFile | ForEach-Object { Write-Host "   $_" -ForegroundColor DarkGray } }
if ($proc.ExitCode -ne 0) { throw "elevated swap failed (exit $($proc.ExitCode)) -- see the output above" }

$gui = Join-Path (Get-InstallDir) 'unitylan-gui.exe'
Write-Host ">> relaunching GUI (unprivileged)" -ForegroundColor Cyan
Start-Process -FilePath $gui

Write-Host ">> done" -ForegroundColor Green
