<#
.SYNOPSIS
  Build, test and (optionally) install att-monitor.
.EXAMPLE
  .\build.ps1                 # vet + test + build bin\att-monitor.exe
  .\build.ps1 -SkipTests      # build only
  .\build.ps1 -Install        # build, then install/upgrade the service (elevated terminal required)
#>
param(
  [switch]$SkipTests,
  [switch]$Install,
  [string]$Version = "1.1.0"
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$commit = (Get-Date -Format "yyyyMMdd-HHmmss")
if (Get-Command git -ErrorAction SilentlyContinue) {
  $c = (git rev-parse --short HEAD 2>$null)
  if ($LASTEXITCODE -eq 0 -and $c) { $commit = $c }
}

Write-Host "== secret scan" -ForegroundColor Cyan
# The gateway access code must only ever live in password.txt (gitignored) and the DPAPI blob.
if (Test-Path .\password.txt) {
  $line = Get-Content .\password.txt | Where-Object { $_ -match '^\s*password\s*:' } | Select-Object -First 1
  if ($line) {
    $code = ($line -split ':', 2)[1].Trim()
    if ($code.Length -ge 4) {
      $hits = Get-ChildItem -Recurse -File -Include *.go,*.md,*.py,*.js,*.html,*.css,*.ps1,*.json,*.txt,*.yaml `
              -Exclude password.txt -Path . -ErrorAction SilentlyContinue |
              Where-Object { $_.FullName -notmatch '\\(bin|evidence|\.git)\\' } |
              Select-String -SimpleMatch -Pattern $code -List
      if ($hits) {
        $hits | ForEach-Object { Write-Host ("  access code found in " + $_.Path) -ForegroundColor Red }
        throw "the gateway access code appears in source files - remove it before building"
      }
    }
  }
}
# Access tokens (GitHub classic and fine-grained) must never be committed either.
$tokens = Get-ChildItem -Recurse -File -Include *.go,*.md,*.py,*.js,*.html,*.css,*.ps1,*.json,*.txt,*.yaml,*.yml,*.cfg,*.env `
          -Path . -ErrorAction SilentlyContinue |
          Where-Object { $_.FullName -notmatch '\\(bin|evidence|reports|\.git)\\' } |
          Select-String -Pattern 'gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}' -List
if ($tokens) {
  $tokens | ForEach-Object { Write-Host ("  access token found in " + $_.Path) -ForegroundColor Red }
  throw "an access token appears in source files - remove it before building"
}

Write-Host "== go vet" -ForegroundColor Cyan
go vet ./...
if ($LASTEXITCODE -ne 0) { throw "go vet failed" }

if (-not $SkipTests) {
  Write-Host "== go test" -ForegroundColor Cyan
  go test ./...
  if ($LASTEXITCODE -ne 0) { throw "tests failed" }
}

Write-Host "== go build ($Version, $commit)" -ForegroundColor Cyan
New-Item -ItemType Directory -Force bin | Out-Null
$env:CGO_ENABLED = "0"
go build -trimpath -ldflags "-s -w -X main.version=$Version -X main.commit=$commit" -o bin\att-monitor.exe ./cmd/att-monitor
if ($LASTEXITCODE -ne 0) { throw "build failed" }
$hash = (Get-FileHash bin\att-monitor.exe -Algorithm SHA256).Hash.ToLower()
Write-Host "bin\att-monitor.exe  sha256 $hash"

if ($Install) {
  $args = @("install")
  if (Test-Path .\password.txt) { $args += @("--access-code-file", (Resolve-Path .\password.txt).Path) }
  if (Test-Path .\evidence\bootstrap) { $args += @("--bootstrap", (Resolve-Path .\evidence\bootstrap).Path) }
  & .\bin\att-monitor.exe @args
  if ($LASTEXITCODE -ne 0) { throw "install failed" }
}
