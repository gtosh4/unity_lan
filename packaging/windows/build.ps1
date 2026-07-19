<#
.SYNOPSIS
  Build the UnityLAN Windows installer (.msi).

.DESCRIPTION
  Compiles the release engine + GUI exes, fetches the pinned wireguard-nt runtime DLL (not
  committed — see .gitignore), stages it where the .wxs expects it, and runs `wix build`.

  Prerequisites:
    - Rust (stable) with the x86_64-pc-windows-msvc toolchain.
    - WiX v4/v5 CLI:  dotnet tool install --global wix --version 5.0.2
      (v6+ is gated behind the Open Source Maintenance Fee EULA and errors with WIX7015)

.PARAMETER Version
  MSI ProductVersion (x.y.z). Defaults to the engine crate version.

.PARAMETER Output
  Output .msi path. Defaults to packaging/dist/unitylan-<Version>-x64.msi.

.EXAMPLE
  packaging\windows\build.ps1
  packaging\windows\build.ps1 -Version 0.1.0
#>
[CmdletBinding()]
param(
    [string]$Version,
    [string]$Output
)

$ErrorActionPreference = 'Stop'
$Here = $PSScriptRoot
$Root = (Resolve-Path (Join-Path $Here '..\..')).Path

# wireguard-nt: pinned upstream release. Its zip holds bin\amd64\wireguard.dll.
# Pin the SHA-256 too, not just the version — this DLL ends up inside the signed MSI, so a swapped
# upstream download would otherwise be a silent supply-chain hole. Update both on a version bump
# (get the hash from https://download.wireguard.com/wireguard-nt/ or `sha256sum` of the zip).
$WgNtVersion = '0.10.1'
$WgNtUrl = "https://download.wireguard.com/wireguard-nt/wireguard-nt-$WgNtVersion.zip"
$WgNtSha256 = '772c0b1463d8d2212716f43f06f4594d880dea4f735165bd68e388fc41b81605'

if (-not $Version) {
    $cargo = Get-Content (Join-Path $Root 'crates\engine\Cargo.toml')
    $Version = ($cargo | Select-String '^version\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
}
if (-not $Output) {
    $dist = Join-Path $Root 'packaging\dist'
    New-Item -ItemType Directory -Force -Path $dist | Out-Null
    $Output = Join-Path $dist "unitylan-$Version-x64.msi"
}

Write-Host ">> building release exes (v$Version)" -ForegroundColor Cyan
Push-Location $Root
try {
    cargo build --release -p unitylan-engine -p unitylan-gui
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
}
finally { Pop-Location }

$bin = Join-Path $Root 'target\release'
$engineExe = Join-Path $bin 'unitylan-engine.exe'
$guiExe = Join-Path $bin 'unitylan-gui.exe'
$engineToml = Join-Path $Here 'engine.toml'

# --- fetch + stage the wireguard-nt DLL ---
$wgDll = Join-Path $Root 'resources-windows\binaries\wireguard-amd64.dll'
if (-not (Test-Path $wgDll)) {
    Write-Host ">> fetching wireguard-nt $WgNtVersion" -ForegroundColor Cyan
    $tmp = Join-Path ([IO.Path]::GetTempPath()) "wireguard-nt-$WgNtVersion.zip"
    $extract = Join-Path ([IO.Path]::GetTempPath()) "wireguard-nt-$WgNtVersion"
    Invoke-WebRequest -Uri $WgNtUrl -OutFile $tmp
    $got = (Get-FileHash -Algorithm SHA256 -Path $tmp).Hash.ToLower()
    if ($got -ne $WgNtSha256) {
        throw "wireguard-nt SHA-256 mismatch: expected $WgNtSha256, got $got — refusing to bundle it"
    }
    if (Test-Path $extract) { Remove-Item -Recurse -Force $extract }
    Expand-Archive -Path $tmp -DestinationPath $extract
    New-Item -ItemType Directory -Force -Path (Split-Path $wgDll) | Out-Null
    Copy-Item (Join-Path $extract 'wireguard-nt\bin\amd64\wireguard.dll') $wgDll
    Write-Host "   staged -> $wgDll" -ForegroundColor DarkGray
}

# --- WiX ---
foreach ($f in @($engineExe, $guiExe, $engineToml, $wgDll)) {
    if (-not (Test-Path $f)) { throw "missing input: $f" }
}
Write-Host ">> wix build -> $Output" -ForegroundColor Cyan
wix build (Join-Path $Here 'unitylan.wxs') `
    -d "Version=$Version" `
    -d "EngineExe=$engineExe" `
    -d "GuiExe=$guiExe" `
    -d "WgDll=$wgDll" `
    -d "EngineToml=$engineToml" `
    -o $Output
if ($LASTEXITCODE -ne 0) { throw "wix build failed" }

Write-Host ">> built $Output" -ForegroundColor Green
