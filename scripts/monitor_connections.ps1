[CmdletBinding()]
param(
    [ValidateSet("Start", "Stop", "Status", "RunForeground")]
    [string]$Action = "RunForeground",
    [int]$IntervalSeconds = 30,
    [int]$DurationSeconds = 600,
    [string]$Label = "campus",
    [string]$KgiQuoteHost = "gtsquot.kgieworld.com.tw",
    [string]$KgiTradeHost = "gtstrade.kgieworld.com.tw",
    [int]$KgiPort = 443,
    [string]$ControlHost = "www.microsoft.com",
    [int]$ControlPort = 443,
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Continue"
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ProjectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $ProjectRoot "reports"
}
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

if ($IntervalSeconds -lt 10) {
    $IntervalSeconds = 10
}

$StateFile = Join-Path $OutputDir "monitor_state.json"
$StopFlagFile = Join-Path $OutputDir "monitor_stop.flag"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

if ($Action -eq "Status") {
    if (Test-Path $StateFile) {
        $st = [System.IO.File]::ReadAllText($StateFile, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
        $procAlive = $false
        if ($st.pid) {
            $p = Get-Process -Id ([int]$st.pid) -ErrorAction SilentlyContinue
            if ($p) { $procAlive = $true }
        }
        $statusOut = [ordered]@{
            state_file_found = $true
            process_alive    = $procAlive
            pid              = $st.pid
            label            = $st.label
            started_at       = $st.started_at
            samples_recorded = $st.samples_recorded
            summary_path     = $st.summary_path
            status           = if ($procAlive) { "running" } else { $st.status }
        }
        Write-Output ($statusOut | ConvertTo-Json -Depth 5)
    } else {
        Write-Output ('{"state_file_found": false, "process_alive": false, "status": "idle"}')
    }
    exit 0
}

if ($Action -eq "Stop") {
    [System.IO.File]::WriteAllText($StopFlagFile, (Get-Date).ToString("o"), $Utf8NoBom)
    Start-Sleep -Seconds 2
    Write-Output "OK: Stop signal written to monitor_stop.flag"
    exit 0
}

if ($Action -eq "Start") {
    if (Test-Path $StopFlagFile) { Remove-Item $StopFlagFile -Force -ErrorAction SilentlyContinue }
    $argList = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$PSCommandPath`"",
        "-Action", "RunForeground",
        "-IntervalSeconds", $IntervalSeconds,
        "-DurationSeconds", $DurationSeconds,
        "-Label", $Label,
        "-OutputDir", "`"$OutputDir`""
    )
    $bgProc = Start-Process -FilePath "powershell.exe" -ArgumentList $argList -WindowStyle Hidden -PassThru
    Start-Sleep -Milliseconds 600
    Write-Output ("OK: Background monitor started with PID " + $bgProc.Id + " (Label=" + $Label + ")")
    exit 0
}

# RunForeground Monitoring Loop
if (Test-Path $StopFlagFile) { Remove-Item $StopFlagFile -Force -ErrorAction SilentlyContinue }

function Mask-Mac([string]$Val) {
    if ([string]::IsNullOrWhiteSpace($Val)) { return "" }
    if ($Val.Trim() -match '^([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})([:-][0-9A-Fa-f]{2}){3}$') {
        return ($Matches[1] + ":xx:xx:xx")
    }
    return "xx:xx:xx:xx:xx:xx"
}

function Probe-HostTcp([string]$TargetHost, [int]$Port, [int]$WaitMs = 3000) {
    $dnsSw = [System.Diagnostics.Stopwatch]::StartNew()
    $ip = ""
    $dnsErr = ""
    try {
        $r = Resolve-DnsName -Name $TargetHost -Type A -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1
        $dnsSw.Stop()
        if ($r) { $ip = [string]$r.IPAddress }
    } catch {
        $dnsSw.Stop()
        $dnsErr = $_.Exception.Message
    }
    if ([string]::IsNullOrWhiteSpace($ip)) {
        return @{
            dns_ok = $false; dns_ms = [math]::Round($dnsSw.Elapsed.TotalMilliseconds, 2)
            tcp_ok = $false; tcp_ms = $null; ip = ""; error = ("DNS_FAIL: " + $dnsErr); is_reset = $false
        }
    }

    $tcpSw = [System.Diagnostics.Stopwatch]::StartNew()
    $cli = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $cli.BeginConnect($ip, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($WaitMs, $false)) {
            $tcpSw.Stop()
            $cli.Close()
            return @{
                dns_ok = $true; dns_ms = [math]::Round($dnsSw.Elapsed.TotalMilliseconds, 2)
                tcp_ok = $false; tcp_ms = [math]::Round($tcpSw.Elapsed.TotalMilliseconds, 2)
                ip = $ip; error = "TCP_TIMEOUT"; is_reset = $false
            }
        }
        $cli.EndConnect($iar)
        $tcpSw.Stop()
        $cli.Close()
        return @{
            dns_ok = $true; dns_ms = [math]::Round($dnsSw.Elapsed.TotalMilliseconds, 2)
            tcp_ok = $true; tcp_ms = [math]::Round($tcpSw.Elapsed.TotalMilliseconds, 2)
            ip = $ip; error = ""; is_reset = $false
        }
    } catch {
        $tcpSw.Stop()
        $msg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        try { $cli.Close() } catch {}
        $rst = ($msg -match '(?i)reset|forcibly closed|\u5f37\u5236\u95dc\u9589|10054')
        return @{
            dns_ok = $true; dns_ms = [math]::Round($dnsSw.Elapsed.TotalMilliseconds, 2)
            tcp_ok = $false; tcp_ms = [math]::Round($tcpSw.Elapsed.TotalMilliseconds, 2)
            ip = $ip; error = $msg; is_reset = $rst
        }
    }
}

$SafeLabel = ($Label -replace '[^a-zA-Z0-9_-]', '_')
$Stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$JsonlPath = Join-Path $OutputDir ("monitor_${SafeLabel}_${Stamp}.jsonl")
$CsvPath   = Join-Path $OutputDir ("monitor_${SafeLabel}_${Stamp}.csv")
$SummaryPath = Join-Path $OutputDir ("monitor_${SafeLabel}_latest.json")
$ArchiveSummaryPath = Join-Path $OutputDir ("monitor_${SafeLabel}_${Stamp}_summary.json")

$csvHeader = "timestamp,sample_index,label,net_up,wifi_signal_pct,bssid_roamed,kgi_running,kgi_established_sockets,kgi_reconnect_churn,kgi_quote_dns_ok,kgi_quote_tcp_ok,kgi_quote_tcp_ms,kgi_trade_dns_ok,kgi_trade_tcp_ok,kgi_trade_tcp_ms,control_tcp_ok,control_tcp_ms,system_events_count,outage_active"
[System.IO.File]::WriteAllText($CsvPath, ($csvHeader + "`r`n"), $Utf8NoBom)

$startTime = Get-Date
$lastCheckTime = $startTime.AddSeconds(-1 * $IntervalSeconds)
$prevBssid = ""
$prevSocketSet = New-Object System.Collections.Generic.HashSet[string]
$prevKgiRunning = $false
$prevHadEstablished = $false

$samples = @()
$outageEpisodes = @()
$currentOutageStart = $null
$currentOutageReason = ""

$totalDisconnectCount = 0
$totalReconnectChurn = 0
$totalAppErrorCount = 0
$totalNetAnomalyEvents = 0

$sampleIdx = 0

while ($true) {
    if (Test-Path $StopFlagFile) {
        Remove-Item $StopFlagFile -Force -ErrorAction SilentlyContinue
        break
    }
    $now = Get-Date
    if ($DurationSeconds -gt 0 -and ($now - $startTime).TotalSeconds -ge $DurationSeconds -and $sampleIdx -gt 0) {
        break
    }
    $sampleIdx++

    # 1. Interface & Wi-Fi State
    $netUp = $false
    $ifaceName = ""
    $linkSpd = ""
    try {
        $upCfg = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.NetAdapter.Status -eq "Up" -and $_.IPv4DefaultGateway } | Select-Object -First 1
        if ($upCfg) {
            $netUp = $true
            $ifaceName = [string]$upCfg.InterfaceAlias
            $linkSpd = [string]$upCfg.NetAdapter.LinkSpeed
        }
    } catch {}

    $wifiSig = $null
    $bssidMasked = ""
    $roamed = $false
    try {
        $wOut = (& netsh wlan show interfaces 2>$null) -join "`n"
        if ($wOut) {
            $sm = [regex]::Match($wOut, '(\d{1,3})\s*%')
            if ($sm.Success) { $wifiSig = [int]$sm.Groups[1].Value }
            $bm = [regex]::Match($wOut, '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')
            if ($bm.Success) {
                $rawBssid = $bm.Value.ToLower()
                $bssidMasked = Mask-Mac $rawBssid
                if (-not [string]::IsNullOrWhiteSpace($prevBssid) -and $prevBssid -ne $rawBssid) {
                    $roamed = $true
                    $totalNetAnomalyEvents++
                }
                $prevBssid = $rawBssid
            }
        }
    } catch {}

    # 2. KGI Process & Active Sockets
    $kgiProcs = @(Get-Process -Name "SUPERTSC64", "SuperTSC", "axis", "VELOTRDER64", "TKAP3083" -ErrorAction SilentlyContinue)
    $kgiRunning = ($kgiProcs.Count -gt 0)
    if ($prevKgiRunning -and -not $kgiRunning) {
        $totalAppErrorCount++
    }

    $estCount = 0
    $synCount = 0
    $closeWaitCount = 0
    $curSocketSet = New-Object System.Collections.Generic.HashSet[string]
    if ($kgiRunning) {
        $pids = @($kgiProcs | ForEach-Object { [int]$_.Id })
        $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
            $pids -contains [int]$_.OwningProcess -and $_.RemoteAddress -notin @("0.0.0.0", "::", "127.0.0.1", "::1")
        }
        foreach ($c in $conns) {
            $st = [string]$c.State
            $tup = ("{0}:{1}->{2}:{3}" -f $c.OwningProcess, $c.LocalPort, $c.RemoteAddress, $c.RemotePort)
            if ($st -eq "Established") {
                $estCount++
                [void]$curSocketSet.Add($tup)
            } elseif ($st -eq "SynSent") {
                $synCount++
            } elseif ($st -eq "CloseWait") {
                $closeWaitCount++
            }
        }
    }

    $newSockets = 0
    if ($prevSocketSet.Count -gt 0 -and $curSocketSet.Count -gt 0) {
        foreach ($s in $curSocketSet) {
            if (-not $prevSocketSet.Contains($s)) { $newSockets++ }
        }
    }
    if ($newSockets -gt 0) {
        $totalReconnectChurn += $newSockets
    }

    # 3. Low-load Sequential Probes (Quote, Trade, Control)
    $qProbe = Probe-HostTcp -TargetHost $KgiQuoteHost -Port $KgiPort -WaitMs 3000
    Start-Sleep -Milliseconds 200
    $tProbe = Probe-HostTcp -TargetHost $KgiTradeHost -Port $KgiPort -WaitMs 3000
    Start-Sleep -Milliseconds 200
    $cProbe = Probe-HostTcp -TargetHost $ControlHost -Port $ControlPort -WaitMs 3000

    # 4. System Event Correlation in Window
    $winEvCount = 0
    $winEvTypes = @()
    try {
        $wEvs = Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-WLAN-AutoConfig/Operational"; StartTime = $lastCheckTime } -MaxEvents 5 -ErrorAction SilentlyContinue
        foreach ($e in $wEvs) {
            if ($e.Id -in @(8002, 8003, 11002, 11004, 11006)) {
                $winEvCount++
                $winEvTypes += ("WLAN_" + $e.Id)
            }
        }
    } catch {}
    try {
        $npEvs = Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-NetworkProfile/Operational"; StartTime = $lastCheckTime } -MaxEvents 5 -ErrorAction SilentlyContinue
        foreach ($e in $npEvs) {
            if ($e.Id -eq 10001) {
                $winEvCount++
                $winEvTypes += "NetProfile_Disconnect_10001"
            }
        }
    } catch {}
    try {
        $dEvs = Get-WinEvent -FilterHashtable @{ LogName = "System"; ProviderName = "Microsoft-Windows-DNS-Client"; Id = 1014; StartTime = $lastCheckTime } -MaxEvents 5 -ErrorAction SilentlyContinue
        if ($dEvs) {
            $cnt = @($dEvs).Count
            $winEvCount += $cnt
            $winEvTypes += "DNS_Timeout_1014"
        }
    } catch {}
    if ($winEvCount -gt 0) { $totalNetAnomalyEvents += $winEvCount }

    # 5. Outage / Disconnect State Tracking
    $appDropped = ($prevHadEstablished -and $kgiRunning -and $estCount -eq 0)
    $probeFailed = (-not $qProbe.tcp_ok -or -not $tProbe.tcp_ok)
    $isOutageNow = (-not $netUp -or $appDropped -or $probeFailed)

    if ($isOutageNow -and $null -eq $currentOutageStart) {
        $currentOutageStart = $now
        $totalDisconnectCount++
        $reasons = @()
        if (-not $netUp) { $reasons += "InterfaceDown" }
        if ($appDropped) { $reasons += "KgiSocketsDroppedToZero" }
        if (-not $qProbe.tcp_ok) { $reasons += ("QuoteProbeFail:" + $qProbe.error) }
        if (-not $tProbe.tcp_ok) { $reasons += ("TradeProbeFail:" + $tProbe.error) }
        $currentOutageReason = ($reasons -join "; ")
    } elseif (-not $isOutageNow -and $null -ne $currentOutageStart) {
        $durSec = [math]::Round(($now - $currentOutageStart).TotalSeconds, 1)
        $outageEpisodes += [ordered]@{
            started_at   = $currentOutageStart.ToString("o")
            recovered_at = $now.ToString("o")
            duration_sec = $durSec
            reason       = $currentOutageReason
        }
        $currentOutageStart = $null
        $currentOutageReason = ""
    }

    $prevKgiRunning = $kgiRunning
    if ($estCount -gt 0) { $prevHadEstablished = $true }
    $prevSocketSet = $curSocketSet
    $lastCheckTime = $now

    $sampleObj = [ordered]@{
        timestamp               = $now.ToString("o")
        sample_index            = $sampleIdx
        label                   = $Label
        net_up                  = $netUp
        primary_interface       = $ifaceName
        link_speed              = $linkSpd
        wifi_signal_pct         = $wifiSig
        wifi_bssid_masked       = $bssidMasked
        bssid_roamed            = $roamed
        kgi_running             = $kgiRunning
        kgi_established_sockets = $estCount
        kgi_syn_sent_sockets    = $synCount
        kgi_close_wait_sockets  = $closeWaitCount
        kgi_reconnect_churn     = $newSockets
        kgi_quote_probe         = $qProbe
        kgi_trade_probe         = $tProbe
        control_probe           = $cProbe
        system_events_count     = $winEvCount
        system_event_types      = $winEvTypes
        outage_active           = ($null -ne $currentOutageStart)
    }

    $samples += $sampleObj
    $jsonLine = ($sampleObj | ConvertTo-Json -Compress -Depth 6)
    [System.IO.File]::AppendAllText($JsonlPath, ($jsonLine + "`r`n"), $Utf8NoBom)

    $csvLine = ("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17},{18}" -f `
        $sampleObj.timestamp, $sampleIdx, $Label, $netUp, `
        $(if ($null -ne $wifiSig) { $wifiSig } else { "" }), $roamed, `
        $kgiRunning, $estCount, $newSockets, `
        $qProbe.dns_ok, $qProbe.tcp_ok, $(if ($null -ne $qProbe.tcp_ms) { $qProbe.tcp_ms } else { "" }), `
        $tProbe.dns_ok, $tProbe.tcp_ok, $(if ($null -ne $tProbe.tcp_ms) { $tProbe.tcp_ms } else { "" }), `
        $cProbe.tcp_ok, $(if ($null -ne $cProbe.tcp_ms) { $cProbe.tcp_ms } else { "" }), `
        $winEvCount, ($null -ne $currentOutageStart))
    [System.IO.File]::AppendAllText($CsvPath, ($csvLine + "`r`n"), $Utf8NoBom)

    $stateObj = [ordered]@{
        pid              = $PID
        status           = "running"
        label            = $Label
        started_at       = $startTime.ToString("o")
        updated_at       = $now.ToString("o")
        interval_seconds = $IntervalSeconds
        duration_seconds = $DurationSeconds
        samples_recorded = $sampleIdx
        jsonl_path       = $JsonlPath
        csv_path         = $CsvPath
        summary_path     = $SummaryPath
    }
    [System.IO.File]::WriteAllText($StateFile, ($stateObj | ConvertTo-Json -Depth 4), $Utf8NoBom)

    if ($DurationSeconds -gt 0 -and ((Get-Date) - $startTime).TotalSeconds -ge $DurationSeconds) {
        break
    }

    # Responsive sleep in 1-second chunks so Stop signal takes effect within 1 second
    for ($s = 0; $s -lt $IntervalSeconds; $s++) {
        if (Test-Path $StopFlagFile) { break }
        Start-Sleep -Seconds 1
    }
}

$endTime = Get-Date
if ($null -ne $currentOutageStart) {
    $outageEpisodes += [ordered]@{
        started_at   = $currentOutageStart.ToString("o")
        recovered_at = ""
        duration_sec = [math]::Round(($endTime - $currentOutageStart).TotalSeconds, 1)
        reason       = ($currentOutageReason + " (ongoing at stop)")
    }
}

$totalProbes = $samples.Count * 2
$okTcpProbes = 0
$okDnsProbes = 0
$tcpLatencies = @()
$ctrlOk = 0
foreach ($sm in $samples) {
    if ($sm.kgi_quote_probe.dns_ok) { $okDnsProbes++ }
    if ($sm.kgi_trade_probe.dns_ok) { $okDnsProbes++ }
    if ($sm.kgi_quote_probe.tcp_ok) {
        $okTcpProbes++
        if ($null -ne $sm.kgi_quote_probe.tcp_ms) { $tcpLatencies += [double]$sm.kgi_quote_probe.tcp_ms }
    }
    if ($sm.kgi_trade_probe.tcp_ok) {
        $okTcpProbes++
        if ($null -ne $sm.kgi_trade_probe.tcp_ms) { $tcpLatencies += [double]$sm.kgi_trade_probe.tcp_ms }
    }
    if ($sm.control_probe.tcp_ok) { $ctrlOk++ }
}

$connSuccessRate = if ($totalProbes -gt 0) { [math]::Round(($okTcpProbes * 100.0 / $totalProbes), 2) } else { 0.0 }
$dnsSuccessRate  = if ($totalProbes -gt 0) { [math]::Round(($okDnsProbes * 100.0 / $totalProbes), 2) } else { 0.0 }
$ctrlSuccessRate = if ($samples.Count -gt 0) { [math]::Round(($ctrlOk * 100.0 / $samples.Count), 2) } else { 0.0 }
$avgTcpMs = $null
$maxTcpMs = $null
if ($tcpLatencies.Count -gt 0) {
    $avgTcpMs = [math]::Round((($tcpLatencies | Measure-Object -Average).Average), 2)
    $maxTcpMs = [math]::Round((($tcpLatencies | Measure-Object -Maximum).Maximum), 2)
}

$totalElapsedSec = [math]::Max(1.0, [math]::Round(($endTime - $startTime).TotalSeconds, 1))
$avgConnDurationSec = if ($totalDisconnectCount -gt 0) {
    [math]::Round(($totalElapsedSec / ($totalDisconnectCount + 1)), 1)
} else {
    $totalElapsedSec
}

$summaryObj = [ordered]@{
    schema_version    = "1.0"
    label             = $Label
    started_at        = $startTime.ToString("o")
    ended_at          = $endTime.ToString("o")
    total_duration_sec = $totalElapsedSec
    interval_seconds  = $IntervalSeconds
    sample_count      = $samples.Count
    jsonl_path        = $JsonlPath
    csv_path          = $CsvPath
    metrics           = [ordered]@{
        connection_success_rate_pct = $connSuccessRate
        tcp_connect_avg_ms          = $avgTcpMs
        tcp_connect_max_ms          = $maxTcpMs
        disconnect_count            = $totalDisconnectCount
        avg_connection_duration_sec = $avgConnDurationSec
        dns_success_rate_pct        = $dnsSuccessRate
        reconnect_count             = $totalReconnectChurn
        network_anomaly_events      = $totalNetAnomalyEvents
        app_error_count             = $totalAppErrorCount
        control_success_rate_pct    = $ctrlSuccessRate
    }
    outage_episodes   = $outageEpisodes
    samples           = $samples
}

$sumJson = $summaryObj | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($SummaryPath, $sumJson, $Utf8NoBom)
[System.IO.File]::WriteAllText($ArchiveSummaryPath, $sumJson, $Utf8NoBom)

$finalState = [ordered]@{
    pid              = $PID
    status           = "completed"
    label            = $Label
    started_at       = $startTime.ToString("o")
    ended_at         = $endTime.ToString("o")
    samples_recorded = $samples.Count
    jsonl_path       = $JsonlPath
    csv_path         = $CsvPath
    summary_path     = $SummaryPath
}
[System.IO.File]::WriteAllText($StateFile, ($finalState | ConvertTo-Json -Depth 4), $Utf8NoBom)

Write-Output ("OK: Monitoring completed (" + $samples.Count + " samples). Summary saved to " + $SummaryPath)

