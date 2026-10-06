<#
.SYNOPSIS
  End-to-end smoke test: runs att-monitor in console mode against a throw-away data directory and the
  real network (unauthenticated gateway GETs, pings, DNS/HTTP checks, TSA anchoring), then exercises the
  dashboard API, the Network page's API, verify, export, verify-bundle and the Python verifier. No
  access code is ever stored, so nothing logs in to the gateway (the NAT table is not read). The
  Network page's Device List sampler reads the real gateway's Device List (no login): the names and
  MAC addresses of the household's devices. The run deletes what it kept of it (connections\) as soon
  as the monitor has stopped, whatever the outcome, and never prints it: the firewall test's LAN
  device has a documentation address (RFC 5737), which no real device has.
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
Add-Type -AssemblyName System.IO.Compression.FileSystem

# The Network page's samples and IP database are not evidence: no bundle may carry them.
function Assert-NoNetworkData([string]$Zip) {
  $archive = [System.IO.Compression.ZipFile]::OpenRead($Zip)
  try {
    $hits = @($archive.Entries | Where-Object { $_.FullName -like "connections/*" -or $_.FullName -like "geo/*" } | ForEach-Object { $_.FullName })
  } finally { $archive.Dispose() }
  if ($hits.Count -gt 0) { throw "the bundle $Zip carries the Network page's data: $($hits -join ', ')" }
}

# Config: non-default port so it never collides with the installed service; anchoring on; the
# MongoDB copy goes to a throw-away database (never the service's "attmonitor": a database belongs
# to the first ledger copied into it).
& $Exe version | Out-Host
$mongoDb = "attmonitor_e2e_" + (Get-Date -Format "yyyyMMddHHmmss")
# Syslog: the receiver listens on a loopback port and accepts this computer as a sender, so the test
# can send datagrams (the installed service listens on UDP 514 for the gateway).
# Network page: the samplers run (the Device List is read without login; the NAT table needs the
# login, and no access code is stored, so it is never read); the IP database is enabled but never
# downloaded (no download in the e2e: organisations and countries stay unknown).
$cfg = @{ web = @{ listen = "127.0.0.1:$Port" }; bootstrap_dir = (Resolve-Path "$PSScriptRoot\..\evidence\bootstrap").Path
          mongo = @{ enabled = $true; uri = "mongodb://127.0.0.1:27017"; database = $mongoDb; store_blobs = $true; interval = "5s" }
          syslog = @{ enabled = $true; listen = "127.0.0.1:$SyslogPort"; port = $SyslogPort; allow = @("127.0.0.1"); flush_interval = "5s"
                      max_per_minute = 2000; keep_mb = 100; keep_days = 0 }
          connections = @{ enabled = $true; interval = "2m"; devices_interval = "5m" }
          geo = @{ enabled = $true; download = $false } } | ConvertTo-Json -Depth 5
# UTF-8 without a byte order mark, in Windows PowerShell 5.1 too (its Set-Content -Encoding UTF8
# writes one).
[System.IO.File]::WriteAllText((Join-Path $data "config.json"), $cfg, (New-Object System.Text.UTF8Encoding $false))
$connDir = Join-Path $data "connections"

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
  # Firewall drops in the BGW320's own format, with documentation addresses only: an inbound probe
  # the gateway dropped, a LAN device's packet dropped on its way out, and syslog-ng's repeat line,
  # which counts 2 more drops like the previous one (the outbound one): 1 inbound, 3 outbound. The
  # view names a LAN device after the Device List read in effect when its packet was received - of
  # the real gateway here - so the LAN device has a documentation address (192.0.2.10), which no
  # real device has: no real device's name or MAC address can come out (the view tells the
  # direction from IN= and OUT=, not SRC=).
  $fwLan = "192.0.2.10"
  $fwLines = @(
    "<12>P0000-00-00T07:48:34.329154 L4 FIREWALL[8512]: nflog_log_fw(), action=DROP reason=POLICY-INPUT-GEN-DISCARD hook=INPUT mark=136314880 IN=veip0.0 OUT= MAC=00:00:5e:00:53:01:00:00:5e:0000:53:02:SRC=203.0.113.66 DST=198.51.100.1 LEN=44 TOS=0x00 PREC=0x00 TTL=55 ID=19286 PROTO=TCP SPT=21110 DPT=8071 SEQ=2082050321 ACK=0 WINDOW=1025 RES=0x00 SYN URGP=0",
    "<12>P0000-00-00T07:50:02.114201 L4 FIREWALL[8512]: nflog_log_fw(), action=DROP reason=POLICY hook=FORWARD mark= IN=br1 OUT=veip0.0 MAC=00:00:5e:00:53:03:00:00:5e:0000:53:04:SRC=$fwLan DST=192.0.2.44 LEN=40 TOS=0x00 PREC=0x00 TTL=127 ID=0 DF PROTO=TCP SPT=51544 DPT=443 WINDOW=0 RES=0x00 ACK RST URGP=0",
    "<12>P0000-00-00T07:53:47.832643 L4 Last message 'FIREWALL[8512]: nflo' repeated 2 times, suppressed by syslog-ng on dsldevice")
  foreach ($line in $fwLines) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($line)
    [void]$udp.Send($bytes, $bytes.Length, "127.0.0.1", $SyslogPort); $sent++
  }
  $udp.Close()
  Write-Host "sent $sent syslog datagrams to 127.0.0.1:$SyslogPort ($($fwLines.Count) of them firewall lines)"

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

  # Network page. No access code is stored, so the NAT sampler never logs in: its rounds (the first
  # a minute after the start, once the startup settings check found nothing to check) say so, and
  # the NAT table is never read. While the gateway is needed for the evidence - an incident, a failed
  # connection check, a gateway that does not answer: the line may be degraded while this runs - a
  # round says that instead, which is fine too as long as nothing is read; the next round (at most
  # an interval, 2 minutes, later) says why again. The wait counts from now: the collection above
  # may have taken longer than the first round.
  if (Test-Path (Join-Path $data "keys\gateway-access-code.dpapi")) { throw "an access code is stored in the e2e data directory" }
  $natReasons = @("*access code*", "skipped during an incident*", "skipped: the latest connection check failed*", "skipped: the gateway did not answer*")
  $natDeadline = (Get-Date).ToUniversalTime().AddSeconds(150)
  do {
    $ns = Invoke-RestMethod "$base/api/network/status"
    if ("$($ns.samplers.nat_problem)" -like "*access code*") { break }
    Start-Sleep 2
  } while ((Get-Date).ToUniversalTime() -lt $natDeadline)
  Write-Host ("/api/network/status: samplers enabled={0} every {1} / {2}; nat_at='{3}' nat_problem='{4}'; devices_at='{5}' devices={6} devices_problem='{7}'" -f `
    $ns.samplers.enabled, $ns.samplers.interval, $ns.samplers.devices_interval, $ns.samplers.nat_at, $ns.samplers.nat_problem, `
    $ns.samplers.devices_at, $ns.samplers.devices, $ns.samplers.devices_problem)
  Write-Host ("  store: {0} bytes in {1} files, keep {2} days / {3} MiB; ip database: enabled={4} download={5} loaded={6} error='{7}'; syslog: {8} messages" -f `
    $ns.store.bytes, $ns.store.files, $ns.store.keep_days, $ns.store.keep_mb, $ns.ipintel.enabled, $ns.ipintel.download, $ns.ipintel.loaded, `
    $ns.ipintel.error, $ns.syslog.messages)
  if (-not $ns.samplers -or -not $ns.store -or -not $ns.ipintel -or -not $ns.syslog) { throw "incomplete network status: $($ns | ConvertTo-Json -Compress -Depth 4)" }
  if (-not $ns.samplers.enabled -or $ns.samplers.interval -ne "2m0s" -or $ns.samplers.devices_interval -ne "5m0s") { throw "samplers not as configured: $($ns.samplers | ConvertTo-Json -Compress)" }
  $natProblem = "$($ns.samplers.nat_problem)"
  $natReason = $natReasons | Where-Object { $natProblem -like $_ } | Select-Object -First 1
  if (-not $natReason) { throw "the NAT sampler does not say why it did not read the NAT table: '$natProblem'" }
  if ($natReason -ne "*access code*") {
    Write-Warning "the NAT rounds left the gateway to the evidence collection ('$natProblem'): that no access code is stored was not seen in this run"
  }
  if ($ns.samplers.nat_at) { throw "the NAT table was read although no access code is stored ($($ns.samplers.nat_at))" }
  if (-not $ns.ipintel.enabled -or $ns.ipintel.download -or $ns.ipintel.loaded) { throw "IP database not as configured (enabled, no download): $($ns.ipintel | ConvertTo-Json -Compress)" }
  # The views' answers may name devices of the real Device List: what is printed of them (here and
  # in the errors below) are counts and the synthetic drops' addresses only.
  $nc = Invoke-RestMethod "$base/api/network/connections?range=1h"
  $ncSummary = "{0} .. {1} samples={2} devices={3} rows={4} rows_total={5}" -f $nc.from, $nc.to, $nc.samples, @($nc.devices).Count, @($nc.rows).Count, $nc.rows_total
  Write-Host "/api/network/connections: $ncSummary"
  if (-not $nc.from -or -not $nc.to -or $nc.samples -ne 0 -or $nc.rows_total -ne 0) { throw "unexpected connections view: $ncSummary" }
  $fw = Invoke-RestMethod "$base/api/network/firewall?range=1h"
  $fwOut = @($fw.outbound_rows)[0]
  $fwSummary = "drops={0} inbound={1} outbound={2} local={3} sources={4} hours={5} outbound_total={6} outbound_devices={7} top source={8}" -f `
    $fw.drops, $fw.inbound, $fw.outbound, $fw.local, $fw.sources, @($fw.hours).Count, $fw.outbound_total, $fw.outbound_devices, @($fw.top_sources)[0].addr
  Write-Host "/api/network/firewall: $fwSummary"
  if ($fw.drops -ne 4 -or $fw.inbound -ne 1 -or $fw.outbound -ne 3 -or $fw.local -ne 0 -or $fw.sources -ne 1 -or @($fw.top_sources)[0].addr -ne "203.0.113.66") {
    throw "the firewall view does not count the synthetic drops (1 inbound, 1 outbound repeated twice): $fwSummary"
  }
  if ($fw.outbound_total -ne 1 -or $fw.outbound_devices -ne 1 -or -not $fwOut -or $fwOut.count -ne 3 -or $fwOut.remote -ne "192.0.2.44" -or
      $fwOut.lan -ne $fwLan -or $fwOut.device -ne "ip:$fwLan" -or $fwOut.name -ne $fwLan -or @($fw.hours).Count -lt 1) {
    # Not the row itself: were it named after a device of the Device List, its name and MAC would show.
    throw ("unexpected outbound rows: {0}; first row: lan={1} remote={2} count={3} named after its address only={4}" -f `
      $fwSummary, $fwOut.lan, $fwOut.remote, $fwOut.count, ($fwOut.device -eq "ip:$fwLan" -and $fwOut.name -eq $fwLan))
  }
  Write-Host "== att-monitor network --firewall --range 1h"
  $netOut = & $Exe network --firewall --range 1h --data $data 2>&1
  $netOut | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "att-monitor network --firewall failed" }
  if (($netOut -join "`n") -notmatch "Dropped:\s+4 packets: 1 inbound") { throw "att-monitor network --firewall does not count the 4 drops" }
  if (($netOut -join "`n") -notmatch ("\n\s+" + [regex]::Escape($fwLan) + "\s+->\s+192\.0\.2\.44\s")) { throw "att-monitor network --firewall does not show the blocked packets of $fwLan" }
  Write-Host "== att-monitor network --range 1h"
  $netOut = & $Exe network --range 1h --data $data 2>&1
  $netOut | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "att-monitor network failed" }
  if (($netOut -join "`n") -notmatch "NAT reads:\s+none in this period") { throw "att-monitor network shows NAT reads, although no access code is stored" }

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
  # Made while connections\ holds the Device List samples (the first read is 30 s after the start).
  Assert-NoNetworkData $zip

  # Negative security checks
  try { Invoke-RestMethod -Method Post "$base/api/notes" -ContentType "application/json" -Body '{"text":"x"}' | Out-Null; throw "POST without header accepted" } catch { if ($_.Exception.Message -like "*accepted*") { throw } ; Write-Host "POST without X-ATT-Monitor rejected: ok" }
  try { Invoke-WebRequest "$base/api/status" -Headers @{ Host = "evil.example" } | Out-Null; throw "foreign Host accepted" } catch { if ($_.Exception.Message -like "*accepted*") { throw }; Write-Host "foreign Host rejected: ok" }
}
finally {
  # The process stops itself gracefully (--duration) so monitor_stop is written.
  if (-not $p.WaitForExit(120000)) { Write-Warning "monitor did not stop in time; killing"; Stop-Process -Id $p.Id -Force; [void]$p.WaitForExit(10000) }
  # connections\ holds what the samplers read of the real gateway: its Device List (devices' names,
  # MAC and IPv6 addresses, the Wi-Fi network's name) and a copy of the page. Nothing after this
  # needs it (the CLI never opens it), and it must not stay behind in %TEMP%, whatever the outcome.
  if (Test-Path -LiteralPath $connDir) {
    try {
      Remove-Item -LiteralPath $connDir -Recurse -Force -ErrorAction Stop
      Write-Host "deleted $connDir (what the samplers read of the real gateway's Device List)"
    } catch {
      Write-Warning "could not delete $connDir, which holds the real gateway's Device List: delete it by hand ($($_.Exception.Message))"
    }
  }
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
$archive = [System.IO.Compression.ZipFile]::OpenRead($zip2)
try { $entries = @($archive.Entries | Where-Object { $_.FullName -like "syslog/*" }) } finally { $archive.Dispose() }
Write-Host ("syslog chunks in the bundle: {0}" -f $entries.Count)
if ($entries.Count -lt 1) { throw "the bundle carries no syslog chunk" }
Assert-NoNetworkData $zip2
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
