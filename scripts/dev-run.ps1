<#
.SYNOPSIS
  Local dev on Windows: start the engine (elevated — builds the WG interface) + the GUI, sharing
  the control pipe, WITHOUT installing the Windows service. The analogue of scripts/dev-run.sh.

.DESCRIPTION
  Assumes the coordinator is already running and engine.toml points at it. The engine needs
  Administrator rights (wireguard-nt interface, Defender Firewall, NRPT), so this script
  self-elevates via UAC and runs BOTH the engine and GUI elevated. Closing the GUI tears the
  engine down (mirroring dev-run.sh's trap-on-exit).

  Enrollment: if this device isn't bound to your Discord identity yet, use the GUI's
  "Log in with Discord" button, or run:  unitylan-engine login engine.toml

  To instead exercise the real *unprivileged* GUI -> engine split, leave the engine running and
  launch the GUI from a separate, non-elevated shell (same user):
      target\debug\unitylan-gui.exe control.sock
  That connects because the pipe's DACL grants the creating user and the pipe object defaults to
  medium integrity (no write-up barrier).

.PARAMETER Config
  Engine config path (default: engine.toml in the repo root).

.PARAMETER Release
  Use target\release binaries instead of target\debug.

.EXAMPLE
  scripts\dev-run.ps1
  scripts\dev-run.ps1 -Config engine.toml -Release
#>
[CmdletBinding()]
param(
    [string]$Config = 'engine.toml',
    [switch]$Release
)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

# --- self-elevate: the engine needs admin for the WG interface / firewall / NRPT ---
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host 'engine needs Administrator - relaunching elevated (UAC)...' -ForegroundColor Yellow
    $argList = @('-NoExit', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
        '-Config', "`"$Config`"")
    if ($Release) { $argList += '-Release' }
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList
    return
}

Set-Location $Root
$flavor = if ($Release) { 'release' } else { 'debug' }
$bin = Join-Path $Root "target\$flavor"
$ENG = Join-Path $bin 'unitylan-engine.exe'
$GUI = Join-Path $bin 'unitylan-gui.exe'

# --- preflight ---
if (-not (Test-Path $ENG) -or -not (Test-Path $GUI)) {
    Write-Error ("build first:  cargo build{0}" -f $(if ($Release) { ' --release' } else { '' }))
    return
}
if (-not (Test-Path (Join-Path $bin 'wireguard.dll'))) {
    Write-Error ("wireguard.dll (the wireguard-nt runtime) must sit next to the binary at`n" +
        "  $bin\wireguard.dll`n" +
        'Get it from https://download.wireguard.com/wireguard-nt/  (bin\amd64\wireguard.dll).')
    return
}
if (-not (Test-Path $Config)) {
    Write-Error "config not found: $Config  (copy engine.example.toml -> engine.toml, set 'coordinator')"
    return
}

# --- control pipe name: engine serves unitylan-<stem>; stem from control_socket (default 'control') ---
$match = Select-String -Path $Config -Pattern '^\s*control_socket\s*=\s*"?([^"#]+)"?' |
    Select-Object -First 1
if ($match) {
    $sockPath = $match.Matches[0].Groups[1].Value.Trim()
    $stem = [IO.Path]::GetFileNameWithoutExtension($sockPath)
    $guiArg = $sockPath
}
else {
    $stem = 'control'
    $guiArg = 'control.sock'
}
$pipe = "unitylan-$stem"

# --- start the engine (privileged: builds the WG interface). Logs stream to this console. ---
Write-Host "engine:  $ENG run $Config" -ForegroundColor Cyan
$eng = Start-Process -FilePath $ENG -ArgumentList @('run', $Config) -PassThru -NoNewWindow

try {
    # Wait for the control pipe (best-effort; the GUI also retries every 2s).
    $up = $false
    for ($i = 0; $i -lt 40; $i++) {
        if ($eng.HasExited) {
            Write-Error "engine exited early (code $($eng.ExitCode)) - see the log above"
            return
        }
        if ((Get-ChildItem '\\.\pipe\' -ErrorAction SilentlyContinue).Name -contains $pipe) {
            $up = $true; break
        }
        Start-Sleep -Milliseconds 250
    }
    if ($up) {
        Write-Host "engine up (pid $($eng.Id)), control pipe \\.\pipe\$pipe  OK" -ForegroundColor Green
        Write-Host "not enrolled yet?  use the GUI 'Log in with Discord', or: $ENG login $Config" -ForegroundColor DarkGray
    }
    else {
        Write-Host "control pipe \\.\pipe\$pipe not seen yet - launching GUI anyway (it retries)" -ForegroundColor Yellow
    }

    # GUI (viewer/controller). Its arg's file stem selects the same pipe. Foreground: closing it
    # ends the dev session (the finally below stops the engine).
    Write-Host "gui:     $GUI $guiArg" -ForegroundColor Cyan
    $gui = Start-Process -FilePath $GUI -ArgumentList @($guiArg) -PassThru
    $gui.WaitForExit()
}
finally {
    if ($eng -and -not $eng.HasExited) {
        Write-Host "stopping engine (pid $($eng.Id))..." -ForegroundColor Yellow
        Stop-Process -Id $eng.Id -Force -ErrorAction SilentlyContinue
    }
}
