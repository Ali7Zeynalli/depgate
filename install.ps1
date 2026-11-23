# DepGate installer for Windows.
#
#   irm https://raw.githubusercontent.com/Ali7Zeynalli/depgate/main/install.ps1 | iex
#
# Downloads the release for this PC from GitHub, checks its SHA-256 against the
# release's checksums.txt, puts depgate.exe in %LOCALAPPDATA%\Programs\DepGate
# and adds that folder to your user PATH. Nothing else is changed.
#
#   $env:DEPGATE_VERSION = "0.21.0"   a given version instead of the latest
$ErrorActionPreference = "Stop"
$repo = "Ali7Zeynalli/depgate"

$version = $env:DEPGATE_VERSION
if (-not $version) {
    $version = (Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest").tag_name
}
$version = $version.TrimStart("v")

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
$file = "depgate_${version}_windows_${arch}.zip"
$base = "https://github.com/$repo/releases/download/v$version"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("depgate-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading DepGate $version (windows/$arch)..."
    Invoke-WebRequest "$base/$file" -OutFile "$tmp\$file" -UseBasicParsing
    Invoke-WebRequest "$base/checksums.txt" -OutFile "$tmp\checksums.txt" -UseBasicParsing

    $line = Get-Content "$tmp\checksums.txt" | Where-Object { $_ -match " $([regex]::Escape($file))$" }
    if (-not $line) { throw "$file is not in checksums.txt" }
    $want = ($line -split " ")[0].ToLower()
    $have = (Get-FileHash "$tmp\$file" -Algorithm SHA256).Hash.ToLower()
    if ($want -ne $have) { throw "checksum mismatch for $file" }

    $dir = Join-Path $env:LOCALAPPDATA "Programs\DepGate"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Expand-Archive "$tmp\$file" -DestinationPath $tmp -Force
    Copy-Item "$tmp\depgate.exe" "$dir\depgate.exe" -Force

    $path = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not (($path -split ";") -contains $dir)) {
        [Environment]::SetEnvironmentVariable("Path", ($path.TrimEnd(";") + ";" + $dir).TrimStart(";"), "User")
        Write-Host "Added $dir to your PATH (open a new terminal)."
    }
    Write-Host "Installed: $dir\depgate.exe"
    Write-Host "Start it: double-click depgate.exe, or run: depgate"
} finally {
    Remove-Item -Recurse -Force $tmp
}
