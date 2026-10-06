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
  [int]$Port = 8331,
  [int]$SyslogPort = 5514
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
# Syslog: the receiver listens on a loopback port and accepts this computer as a sender, so the test
# can send datagrams (the installed service listens on UDP 514 for the gateway).
$cfg = @{ web = @{ listen = "127.0.0.1:$Port" }; bootstrap_dir = (Resolve-Path "$PSScriptRoot\..\evidence\bootstrap").Path
          mongo = @{ enabled = $true; uri = "mongodb://127.0.0.1:27017"; database = $mongoDb; store_blobs = $true; interval = "5s" }
          syslog = @{ enabled = $true; listen = "127.0.0.1:$SyslogPort"; port = $SyslogPort; allow = @("127.0.0.1"); flush_interval = "5s"
                      max_per_minute = 2000; keep_mb = 100; keep_days = 0 } } | ConvertTo-Json -Depth 5
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
  $runStart = (Get-Date).ToUniversalTime()

  # Syslog: RFC 3164 and RFC 5424 datagrams, one with bytes that are not UTF-8.
  $udp = New-Object System.Net.Sockets.UdpClient
  $sent = 0
  for ($i = 0; $i -lt 300; $i++) {
    $text = if ($i % 2) { "<30>Oct  5 22:15:{0:D2} BGW320 e2e[42]: test message {1} PON link state check" -f ($i % 60), $i }
            else { "<14>1 2026-10-05T22:15:00.000Z BGW320 e2e - - - test message {0} DHCP renew" -f $i }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    [void]$udp.Send($bytes, $bytes.Length, "127.0.0.1", $SyslogPort); $sent++
  }
  $bin = [byte[]](0x3C, 0x31, 0x33, 0x3E, 0x62, 0x69, 0x6E, 0x20, 0xFF, 0xFE, 0x0A)
  [void]$udp.Send($bin, $bin.Length, "127.0.0.1", $SyslogPort); $sent++
  $udp.Close()
  Write-Host "sent $sent syslog datagrams to 127.0.0.1:$SyslogPort"

  Write-Host "dashboard up; collecting for $Seconds s ..."
  Start-Sleep $Seconds

  $s = Invoke-RestMethod "$base/api/status"
  Write-Host ("state={0} cause={1} attribution={2} head=#{3} anchor={4}" -f $s.verdict.state, $s.verdict.cause, $s.verdict.attribution, $s.ledger.head_seq, $s.ledger.last_anchor_time)
  $s.conditions | ForEach-Object { Write-Host ("condition: [{0}] {1}" -f $_.severity, $_.message) }
  if ($s.mongo) { Write-Host ("mongo: connected={0} db={1} last_seq={2} lag={3} records={4} blobs={5} error={6}" -f $s.mongo.connected, $s.mongo.database, $s.mongo.last_seq, $s.mongo.lag, $s.mongo.records, $s.mongo.blobs, $s.mongo.last_error) }
  $series = Invoke-RestMethod "$base/api/series?range=1h"
  Write-Host ("series points: {0}, optical points: {1}, traffic points: {2}" -f $series.points.Count, $series.optical.Count, $series.traffic.Count)

  # Syslog: what was received, stored and listed.
  $sl = $s.syslog
  if (-not $sl) { throw "no syslog status" }
  Write-Host ("syslog: listening={0} on {1} received={2} recorded={3} dropped={4} rejected={5} store={6} bytes in {7} chunks, keep {8} MiB" -f `
    $sl.listening, $sl.listen, $sl.received, $sl.recorded, $sl.dropped, $sl.rejected, $sl.store.bytes, $sl.store.chunks, $sl.store.keep_mb)
  if (-not $sl.listening) { throw "the syslog receiver is not listening" }
  $list = Invoke-RestMethod ("$base/api/syslog?from={0}&limit=1000" -f [uri]::EscapeDataString($runStart.AddMinutes(-1).ToString("yyyy-MM-ddTHH:mm:ssZ")))
  Write-Host ("/api/syslog: {0} messages, newest: {1}" -f $list.messages.Count, $list.messages[0].raw)
  if ($list.messages.Count -lt $sent) { throw "expected $sent syslog messages, listed $($list.messages.Count)" }
  $f = Invoke-RestMethod ("$base/api/syslog?from={0}&q=DHCP&severity=info&limit=1000" -f [uri]::EscapeDataString($runStart.AddMinutes(-1).ToString("yyyy-MM-ddTHH:mm:ssZ")))
  Write-Host ("/api/syslog q=DHCP severity<=info: {0} messages" -f $f.messages.Count)
  if ($f.messages.Count -ne 150) { throw "expected 150 DHCP messages, got $($f.messages.Count)" }

  # Retention: a change is a config_change; the limit shows in the status.
  $rc = Invoke-RestMethod -Method Post "$base/api/syslog/retention" -Headers $hdr -ContentType "application/json" -Body '{"keep_mb":50,"keep_days":30}'
  Write-Host ("retention change: {0}" -f ($rc | ConvertTo-Json -Compress -Depth 4))
  $s2 = Invoke-RestMethod "$base/api/status"
  if ($s2.syslog.store.keep_mb -ne 50 -or $s2.syslog.store.keep_days -ne 30) { throw "retention not applied: $($s2.syslog.store | ConvertTo-Json -Compress)" }
  try { Invoke-RestMethod -Method Post "$base/api/syslog/retention" -Headers $hdr -ContentType "application/json" -Body '{"keep_mb":0}' | Out-Null; throw "keep_mb 0 accepted" } catch { if ($_.Exception.Message -like "*accepted*") { throw }; Write-Host "keep_mb 0 refused: ok" }

  # Flow meter: one on-demand read of the gateway's counters (unauthenticated).
  $lt = Invoke-RestMethod "$base/api/traffic/live"
  Start-Sleep 6
  $lt = Invoke-RestMethod "$base/api/traffic/live"
  Write-Host ("flow meter: at={0} down={1} Mb/s up={2} Mb/s interval={3}s history={4} error={5}" -f $lt.at, $lt.wan_rx_mbps, $lt.wan_tx_mbps, $lt.interval_s, $lt.history.Count, $lt.error)
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

# The service sealed its open syslog chunk when it stopped: an export made now (the CLI opens the
# store read-only while the service is stopped) carries it, and both verifiers check it.
Write-Host "== att-monitor export after the stop (syslog chunk in the bundle)"
$out2 = Join-Path $data "exports-after-stop"
& $Exe export --from $runStart.AddMinutes(-5).ToString("yyyy-MM-ddTHH:mm:ssZ") --to (Get-Date).ToUniversalTime().AddMinutes(1).ToString("yyyy-MM-ddTHH:mm:ssZ") --prepared-by e2e --out $out2 --data $data
if ($LASTEXITCODE -ne 0) { throw "export after stop failed" }
$zip2 = (Get-ChildItem $out2 -Filter *.zip | Select-Object -First 1).FullName
$vb = & $Exe verify-bundle $zip2 2>&1
$vb | Out-Host
if ($LASTEXITCODE -ne 0) { throw "verify-bundle (with syslog) failed" }
$syslogLine = ($vb | Where-Object { "$_" -like "SYSLOG*" }) -join " "
if ($syslogLine -notmatch "OK") { throw "no SYSLOG OK line: $syslogLine" }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$entries = [System.IO.Compression.ZipFile]::OpenRead($zip2).Entries | Where-Object { $_.FullName -like "syslog/*" }
Write-Host ("syslog chunks in the bundle: {0}" -f @($entries).Count)
if (@($entries).Count -lt 1) { throw "the bundle carries no syslog chunk" }
python (Join-Path $py "tools\verify_bundle.py") $zip2
if ($LASTEXITCODE -ne 0) { throw "python verifier (with syslog) failed" }
& $Exe syslog --data $data --since 1h --limit 3 2>&1 | Out-Host
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
