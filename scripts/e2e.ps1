<#
.SYNOPSIS
  End-to-end smoke test: runs att-monitor in console mode against a throw-away data directory and the
  real network (unauthenticated gateway GETs, pings, DNS/HTTP checks, TSA anchoring), then exercises the
  dashboard API, verify, export, verify-bundle and the Python verifier.
.EXAMPLE
  .\scripts\e2e.ps1 -Seconds 150
#>
param(
  [int]$Seconds = 150,
  [string]$Exe = "$PSScriptRoot\..\bin\att-monitor.exe",
  [int]$Port = 8331
)
$ErrorActionPreference = "Stop"
$Exe = (Resolve-Path $Exe).Path
$data = Join-Path $env:TEMP ("attmon-e2e-" + (Get-Date -Format "yyyyMMddHHmmss"))
New-Item -ItemType Directory -Force $data | Out-Null
Write-Host "data dir: $data"

# Config: non-default port so it never collides with the installed service; anchoring on; the
# MongoDB copy goes to a throw-away database (never the service's "attmonitor": a database belongs
# to the first ledger copied into it).
& $Exe version | Out-Host
$mongoDb = "attmonitor_e2e_" + (Get-Date -Format "yyyyMMddHHmmss")
$cfg = @{ web = @{ listen = "127.0.0.1:$Port" }; bootstrap_dir = (Resolve-Path "$PSScriptRoot\..\evidence\bootstrap").Path
          mongo = @{ enabled = $true; uri = "mongodb://127.0.0.1:27017"; database = $mongoDb; store_blobs = $true; interval = "5s" } } | ConvertTo-Json
Set-Content -Path (Join-Path $data "config.json") -Value $cfg -Encoding UTF8

$log = Join-Path $data "console.out.txt"
$runFor = "{0}s" -f ($Seconds + 45)
$p = Start-Process -FilePath $Exe -ArgumentList @("run", "--data", $data, "--duration", $runFor) -PassThru -NoNewWindow -RedirectStandardError $log
$base = "http://127.0.0.1:$Port"
$hdr = @{ "X-ATT-Monitor" = "1" }
try {
  $ok = $false
  for ($i = 0; $i -lt 30; $i++) { try { Invoke-RestMethod "$base/api/status" | Out-Null; $ok = $true; break } catch { Start-Sleep 1 } }
  if (-not $ok) { throw "dashboard did not come up; see $log" }
  Write-Host "dashboard up; collecting for $Seconds s ..."
  Start-Sleep $Seconds

  $s = Invoke-RestMethod "$base/api/status"
  Write-Host ("state={0} cause={1} attribution={2} head=#{3} anchor={4}" -f $s.verdict.state, $s.verdict.cause, $s.verdict.attribution, $s.ledger.head_seq, $s.ledger.last_anchor_time)
  $s.conditions | ForEach-Object { Write-Host ("condition: [{0}] {1}" -f $_.severity, $_.message) }
  if ($s.mongo) { Write-Host ("mongo: connected={0} db={1} last_seq={2} lag={3} records={4} blobs={5} error={6}" -f $s.mongo.connected, $s.mongo.database, $s.mongo.last_seq, $s.mongo.lag, $s.mongo.records, $s.mongo.blobs, $s.mongo.last_error) }
  $series = Invoke-RestMethod "$base/api/series?range=1h"
  Write-Host ("series points: {0}, optical points: {1}" -f $series.points.Count, $series.optical.Count)
  $recs = Invoke-RestMethod "$base/api/records?from_seq=0&limit=500"
  $recs | Group-Object type | Sort-Object Name | ForEach-Object { Write-Host ("  {0,-18} {1}" -f $_.Name, $_.Count) }

  $note = Invoke-RestMethod -Method Post "$base/api/notes" -Headers $hdr -ContentType "application/json" -Body '{"text":"e2e test note","author":"e2e"}'
  Write-Host "note seq: $($note.seq)"
  $v = Invoke-RestMethod -Method Post "$base/api/verify" -Headers $hdr
  Write-Host ("verify ok={0} records={1} failures={2} anchors={3}" -f $v.ok, $v.records, $v.failures_total, $v.anchors.Count)
  if (-not $v.ok) { throw "verification failed" }

  $from = (Get-Date).ToUniversalTime().AddHours(-1).ToString("yyyy-MM-ddTHH:mm:ssZ")
  $to = (Get-Date).ToUniversalTime().AddMinutes(1).ToString("yyyy-MM-ddTHH:mm:ssZ")
  $exp = Invoke-RestMethod -Method Post "$base/api/exports" -Headers $hdr -ContentType "application/json" -Body (@{ from = $from; to = $to; prepared_by = "e2e"; notes = "smoke test" } | ConvertTo-Json)
  Write-Host "export: $($exp.file_name) sha256 $($exp.sha256)"
  $zip = Join-Path $data "exports\$($exp.file_name)"

  # Negative security checks
  try { Invoke-RestMethod -Method Post "$base/api/notes" -ContentType "application/json" -Body '{"text":"x"}' | Out-Null; throw "POST without header accepted" } catch { if ($_.Exception.Message -like "*accepted*") { throw } ; Write-Host "POST without X-ATT-Monitor rejected: ok" }
  try { Invoke-WebRequest "$base/api/status" -Headers @{ Host = "evil.example" } | Out-Null; throw "foreign Host accepted" } catch { if ($_.Exception.Message -like "*accepted*") { throw }; Write-Host "foreign Host rejected: ok" }
}
finally {
  # The process stops itself gracefully (--duration) so monitor_stop is written.
  if (-not $p.WaitForExit(120000)) { Write-Warning "monitor did not stop in time; killing"; Stop-Process -Id $p.Id -Force }
}

Write-Host "== att-monitor verify"
& $Exe verify --data $data
if ($LASTEXITCODE -ne 0) { throw "verify failed" }
Write-Host "== att-monitor verify-bundle"
& $Exe verify-bundle $zip
if ($LASTEXITCODE -ne 0) { throw "verify-bundle failed" }
Write-Host "== python verifier"
$py = Join-Path $data "pyverify"
Expand-Archive -Path $zip -DestinationPath $py -Force
python (Join-Path $py "tools\verify_bundle.py") $zip
if ($LASTEXITCODE -ne 0) { throw "python verifier failed" }
Write-Host "== att-monitor mongo verify ($mongoDb)"
$mongoUp = Test-NetConnection 127.0.0.1 -Port 27017 -InformationLevel Quiet -WarningAction SilentlyContinue
if ($mongoUp) {
  & $Exe mongo verify --data $data
  if ($LASTEXITCODE -ne 0) { throw "mongo verify failed" }
  # Drop the throw-away database (needs Python with pymongo; otherwise it is left behind).
  python -c "import sys, pymongo; assert sys.argv[1].startswith('attmonitor_e2e_'); pymongo.MongoClient('mongodb://127.0.0.1:27017', serverSelectionTimeoutMS=3000).drop_database(sys.argv[1])" $mongoDb
  if ($LASTEXITCODE -ne 0) { Write-Warning "could not drop the MongoDB database $mongoDb (drop it by hand)" }
} else {
  Write-Host "MongoDB not reachable on 127.0.0.1:27017: skipped"
}
Write-Host "E2E PASSED  (data: $data)" -ForegroundColor Green
