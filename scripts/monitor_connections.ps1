[CmdletBinding()]
param(
    [ValidateSet("Start", "Stop", "Status", "RunForeground")]
    [string]$Action = "RunForeground",
    [string]$RunId = "",
    [int]$PassiveIntervalSeconds = 5,
    [int]$ActiveProbeIntervalSeconds = 30,
    [int]$IntervalSeconds = 0,
    [int]$DurationSeconds = 1800,
    [string]$Label = "campus",
    [string]$KgiQuoteHost = "gtsquot.kgieworld.com.tw",
    [string]$KgiTradeHost = "gtstrade.kgieworld.com.tw",
    [int]$KgiPort = 443,
    [string]$ControlHost = "www.microsoft.com",
    [int]$ControlPort = 443,
    [string]$OutputDir = "",
    [switch]$SpawnedFromStart
)

$ErrorActionPreference = "Continue"
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ProjectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $ProjectRoot "reports\internal\monitor_runtime"
}
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

if ($IntervalSeconds -gt 0 -and $PSBoundParameters.ContainsKey("IntervalSeconds") -and (-not $PSBoundParameters.ContainsKey("ActiveProbeIntervalSeconds"))) {
    $ActiveProbeIntervalSeconds = $IntervalSeconds
}
if ($PassiveIntervalSeconds -lt 2) { $PassiveIntervalSeconds = 2 }
if ($ActiveProbeIntervalSeconds -lt 10) { $ActiveProbeIntervalSeconds = 10 }

$StateFile = Join-Path $OutputDir "monitor_state.json"
$LegacyStopFlagFile = Join-Path $OutputDir "monitor_stop.flag"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$PatKgiName = [regex]::Unescape('(\u65b0\u8d85\u7d1a\u5927\u4e09\u5143|\u8d85\u7d1a\u5927\u4e09\u5143|\u5927\u4e09\u5143|\u51f1\u57fa|KGI)')
$FolderSuper3 = [regex]::Unescape('\u8d85\u7d1a\u5927\u4e09\u5143')

function Write-JsonAtomic([string]$TargetPath, [object]$DataObj, [int]$Depth = 8) {
    $parent = Split-Path -Parent $TargetPath
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $tmpPath = $TargetPath + ".tmp." + $PID + "." + ([guid]::NewGuid().ToString("N").Substring(0, 6))
    $jsonText = $DataObj | ConvertTo-Json -Depth $Depth
    [System.IO.File]::WriteAllText($tmpPath, $jsonText, $Utf8NoBom)
    Move-Item -Path $tmpPath -Destination $TargetPath -Force
}

function Read-JsonSafe([string]$TargetPath) {
    if (-not (Test-Path $TargetPath)) { return $null }
    try {
        return ([System.IO.File]::ReadAllText($TargetPath, [System.Text.Encoding]::UTF8) | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Get-ProcessStartUtc([int]$TargetPid) {
    try {
        $p = Get-Process -Id $TargetPid -ErrorAction SilentlyContinue
        if ($p -and $p.StartTime) {
            return $p.StartTime.ToUniversalTime()
        }
    } catch {}
    return $null
}

function Test-MonitorStateAlive($StateObj) {
    if ($null -eq $StateObj -or -not $StateObj.pid) { return $false }
    $actualStart = Get-ProcessStartUtc -TargetPid ([int]$StateObj.pid)
    if ($null -eq $actualStart) { return $false }

    # Verify process creation time to prevent Windows PID reuse false-positive!
    if ($StateObj.process_start_time_utc) {
        try {
            $recordedStart = [datetime]::Parse([string]$StateObj.process_start_time_utc).ToUniversalTime()
            $diffSec = [math]::Abs(($actualStart - $recordedStart).TotalSeconds)
            if ($diffSec -gt 3.0) {
                return $false
            }
        } catch {
            return $false
        }
    }
    return $true
}

if ($Action -eq "Status") {
    $st = Read-JsonSafe -TargetPath $StateFile
    if ($null -eq $st) {
        Write-Output ('{"state_file_found": false, "process_alive": false, "status": "idle", "run_status": "NOT_TESTED"}')
        exit 0
    }
    $alive = Test-MonitorStateAlive -StateObj $st
    $effectiveStatus = [string]$st.status
    $effectiveRunStatus = [string]$st.run_status
    $exitCode = 0

    if ($st.status -eq "running" -and (-not $alive)) {
        $effectiveStatus = "abnormal_exit"
        $effectiveRunStatus = "FAILED"
        $exitCode = 4
        # Atomically mark state file so dead monitor never stays falsely "running"
        $updatedDeadState = [ordered]@{
            run_id                 = $st.run_id
            pid                    = $st.pid
            process_start_time_utc = $st.process_start_time_utc
            status                 = "abnormal_exit"
            run_status             = "FAILED"
            completion_reason      = "background_process_terminated_unexpectedly"
            label                  = $st.label
            started_at             = $st.started_at
            updated_at             = (Get-Date).ToString("o")
            samples_recorded       = $st.samples_recorded
            jsonl_path             = $st.jsonl_path
            csv_path               = $st.csv_path
            marks_path             = $st.marks_path
            summary_path           = $st.summary_path
        }
        try { Write-JsonAtomic -TargetPath $StateFile -DataObj $updatedDeadState -Depth 5 } catch {}
    }

    $statusOut = [ordered]@{
        state_file_found       = $true
        run_id                 = $st.run_id
        process_alive          = $alive
        pid                    = $st.pid
        process_start_time_utc = $st.process_start_time_utc
        label                  = $st.label
        started_at             = $st.started_at
        samples_recorded       = $st.samples_recorded
        summary_path           = $st.summary_path
        status                 = if ($alive) { "running" } else { $effectiveStatus }
        run_status             = if ($alive) { "RUNNING" } else { $effectiveRunStatus }
    }
    Write-Output ($statusOut | ConvertTo-Json -Depth 5)
    exit $exitCode
}

if ($Action -eq "Stop") {
    $st = Read-JsonSafe -TargetPath $StateFile
    if ($null -eq $st) {
        Write-Output "INFO: No active monitor state found."
        exit 0
    }
    $alive = Test-MonitorStateAlive -StateObj $st
    if (-not $alive) {
        if ($st.status -eq "running") {
            Write-Error ("WARN: Monitor PID " + $st.pid + " (RunId=" + $st.run_id + ") exited abnormally before Stop.")
            exit 4
        }
        Write-Output ("INFO: Monitor RunId=" + $st.run_id + " is already stopped (status=" + $st.status + ").")
        exit 0
    }

    $scopedStopFlag = if ($st.stop_flag_path) { [string]$st.stop_flag_path } else { Join-Path $OutputDir ("stop_" + $st.run_id + ".flag") }
    [System.IO.File]::WriteAllText($scopedStopFlag, (Get-Date).ToString("o"), $Utf8NoBom)

    # Wait up to 12 seconds for graceful flush of final summary & state
    for ($w = 0; $w -lt 24; $w++) {
        Start-Sleep -Milliseconds 500
        if (-not (Test-MonitorStateAlive -StateObj $st)) { break }
    }
    $afterSt = Read-JsonSafe -TargetPath $StateFile
    Write-Output ("OK: Monitor RunId=" + $st.run_id + " stopped gracefully (final_status=" + $afterSt.status + ", samples=" + $afterSt.samples_recorded + ").")
    exit 0
}

# Pre-start duplicate monitor conflict check!
if (-not $SpawnedFromStart) {
    $existingSt = Read-JsonSafe -TargetPath $StateFile
    if ($null -ne $existingSt -and $existingSt.status -eq "running") {
        if (Test-MonitorStateAlive -StateObj $existingSt) {
            Write-Error ("CONFLICT: Another monitor is already running (RunId=" + $existingSt.run_id + ", PID=" + $existingSt.pid + ", Label=" + $existingSt.label + "). Stop it first before starting a new monitor.")
            exit 3
        }
    }
}

if ([string]::IsNullOrWhiteSpace($RunId)) {
    $SafeLblTmp = ($Label -replace '[^a-zA-Z0-9_-]', '_')
    $RunId = "mon_" + $SafeLblTmp + "_" + (Get-Date).ToString("yyyyMMdd_HHmmss") + "_" + ([guid]::NewGuid().ToString("N").Substring(0, 6))
}

# Clean up any legacy or stale stop flags so they NEVER prematurely kill a new monitor!
if (Test-Path $LegacyStopFlagFile) { Remove-Item $LegacyStopFlagFile -Force -ErrorAction SilentlyContinue }
Get-ChildItem -Path $OutputDir -Filter "stop_*.flag" -File -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
}
$ScopedStopFlag = Join-Path $OutputDir ("stop_" + $RunId + ".flag")

if ($Action -eq "Start") {
    $argList = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ".\scripts\monitor_connections.ps1",
        "-Action", "RunForeground",
        "-SpawnedFromStart",
        "-RunId", $RunId,
        "-PassiveIntervalSeconds", $PassiveIntervalSeconds,
        "-ActiveProbeIntervalSeconds", $ActiveProbeIntervalSeconds,
        "-DurationSeconds", $DurationSeconds,
        "-Label", $Label,
        "-KgiQuoteHost", $KgiQuoteHost,
        "-KgiTradeHost", $KgiTradeHost,
        "-KgiPort", $KgiPort,
        "-ControlHost", $ControlHost,
        "-ControlPort", $ControlPort,
        "-OutputDir", "`"$OutputDir`""
    )
    $bgProc = Start-Process -FilePath "powershell.exe" -WorkingDirectory $ProjectRoot -ArgumentList $argList -WindowStyle Hidden -PassThru
    $verifiedStarted = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 250
        $chkSt = Read-JsonSafe -TargetPath $StateFile
        if ($chkSt -and $chkSt.run_id -eq $RunId -and $chkSt.status -eq "running") {
            $verifiedStarted = $true
            break
        }
        if ($bgProc.HasExited) { break }
    }
    if (-not $verifiedStarted) {
        Write-Error ("FAILED: Background monitor process (PID " + $bgProc.Id + ") failed to initialize state.")
        exit 2
    }
    Write-Output ("OK: Background monitor started (RunId=" + $RunId + ", PID=" + $bgProc.Id + ", Label=" + $Label + ", Passive=" + $PassiveIntervalSeconds + "s, Active=" + $ActiveProbeIntervalSeconds + "s)")
    exit 0
}

# RunForeground Dual-Cadence Monitoring Loop (Passive 5s + Active 30s)
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
    if ($TargetHost -match '^\d{1,3}(\.\d{1,3}){3}$') {
        $dnsSw.Stop()
        $ip = $TargetHost
    } else {
        try {
            $r = Resolve-DnsName -Name $TargetHost -Type A -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1
            $dnsSw.Stop()
            if ($r) { $ip = [string]$r.IPAddress }
        } catch {
            $dnsSw.Stop()
            $dnsErr = $_.Exception.Message
        }
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

# Discover KGI install dirs once at monitor startup + cache verified (PID, StartUtc) signatures
$kgiInstallDirs = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
foreach ($drv in @("C:", "D:", "E:")) {
    foreach ($c in @((Join-Path $drv $FolderSuper3), (Join-Path $drv ("KGI\" + $FolderSuper3)))) {
        if (Test-Path $c) { [void]$kgiInstallDirs.Add($c) }
    }
}
$verifiedProcCache = @{}

function Get-VerifiedKgiProcessSnapshot {
    $candidates = @(Get-Process -Name "SUPERTSC64", "SuperTSC", "axis", "VELOTRDER64", "TKAP3083" -ErrorAction SilentlyContinue)
    $verifiedPids = @()
    $summaries = @()
    foreach ($cp in $candidates) {
        $pidVal = [int]$cp.Id
        $stUtcStr = ""
        try { if ($cp.StartTime) { $stUtcStr = $cp.StartTime.ToUniversalTime().ToString("o") } } catch {}
        $cacheKey = ("{0}|{1}" -f $pidVal, $stUtcStr)

        if (-not $verifiedProcCache.ContainsKey($cacheKey)) {
            $exePath = ""
            try { $exePath = [string]$cp.Path } catch {}
            if ([string]::IsNullOrWhiteSpace($exePath)) {
                try {
                    $cimP = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $pidVal) -ErrorAction SilentlyContinue
                    if ($cimP) { $exePath = [string]$cimP.ExecutablePath }
                } catch {}
            }

            $inInstall = $false
            foreach ($idDir in $kgiInstallDirs) {
                if (-not [string]::IsNullOrWhiteSpace($exePath) -and $exePath.StartsWith($idDir, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $inInstall = $true
                    break
                }
            }
            $sigOk = $false
            $sigLabel = "Unchecked"
            if (-not [string]::IsNullOrWhiteSpace($exePath) -and (Test-Path $exePath)) {
                try {
                    $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
                    if ($sig -and $sig.Status -eq "Valid" -and $sig.SignerCertificate.Subject -match '(?i)(KGI Securities|Kway|SysJust)') {
                        $sigOk = $true
                        $sigLabel = "Valid:KGI"
                    } else {
                        $sigLabel = [string]$sig.Status
                    }
                } catch {}
            }
            $verifiedProcCache[$cacheKey] = @{
                is_verified = ($inInstall -or $sigOk)
                summary     = ("{0}.exe(PID={1},Sig={2},Start={3})" -f $cp.ProcessName, $pidVal, $sigLabel, $stUtcStr)
            }
        }

        $entry = $verifiedProcCache[$cacheKey]
        if ($entry.is_verified) {
            $verifiedPids += $pidVal
            $summaries += $entry.summary
        }
    }
    return @{
        is_running = ($verifiedPids.Count -gt 0)
        pids       = $verifiedPids
        summary    = if ($summaries.Count -gt 0) { ($summaries -join ";") } else { "not_running" }
    }
}

$SafeLabel = ($Label -replace '[^a-zA-Z0-9_-]', '_')
$JsonlPath = Join-Path $OutputDir ("monitor_" + $RunId + ".jsonl")
$CsvPath   = Join-Path $OutputDir ("monitor_" + $RunId + ".csv")
$MarksPath = Join-Path $OutputDir ("marks_" + $RunId + ".jsonl")
$SummaryPath = Join-Path $OutputDir ("monitor_" + $SafeLabel + "_latest.json")
$ArchiveSummaryPath = Join-Path $OutputDir ("monitor_" + $RunId + "_summary.json")

$myStartUtc = Get-ProcessStartUtc -TargetPid $PID
$myStartUtcIso = if ($myStartUtc) { $myStartUtc.ToString("o") } else { (Get-Date).ToUniversalTime().ToString("o") }
$startTime = Get-Date
$netProfileDetected = "Detecting"

# Write initial running state IMMEDIATELY before slow CIM/NetTCPIP module loads so parent Start can verify birth promptly
$initState = [ordered]@{
    run_id                        = $RunId
    pid                           = $PID
    process_start_time_utc        = $myStartUtcIso
    status                        = "running"
    run_status                    = "RUNNING"
    label                         = $Label
    network_profile               = $netProfileDetected
    started_at                    = $startTime.ToString("o")
    updated_at                    = $startTime.ToString("o")
    passive_interval_seconds      = $PassiveIntervalSeconds
    active_probe_interval_seconds = $ActiveProbeIntervalSeconds
    duration_seconds              = $DurationSeconds
    samples_recorded              = 0
    stop_flag_path                = $ScopedStopFlag
    jsonl_path                    = $JsonlPath
    csv_path                      = $CsvPath
    marks_path                    = $MarksPath
    summary_path                  = $ArchiveSummaryPath
}
Write-JsonAtomic -TargetPath $StateFile -DataObj $initState -Depth 5

# Detect passive network profile / environment hint
$netProfileDetected = "Unknown"
try {
    $initIpCfg = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.NetAdapter.Status -eq "Up" -and $_.IPv4DefaultGateway } | Select-Object -First 1
    if ($initIpCfg) {
        $aliasStr = [string]$initIpCfg.InterfaceAlias
        $ip4Str = [string]($initIpCfg.IPv4Address | Select-Object -First 1).IPAddress
        if ($ip4Str -match '^(140|163|120)\.') {
            $netProfileDetected = "Campus_TANet_" + $aliasStr
        } elseif ($ip4Str -match '^172\.20\.10\.' -or $aliasStr -match '(?i)wi-fi|wlan') {
            $netProfileDetected = "Wireless_Or_Hotspot_" + $aliasStr
        } else {
            $netProfileDetected = "Private_LAN_" + $aliasStr
        }
    }
} catch {}

$csvHeader = "timestamp,run_id,sample_index,label,net_up,wifi_signal_pct,bssid_roamed,kgi_running,kgi_established_sockets,socket_opened,socket_closed,active_probe_executed,kgi_quote_dns_ok,kgi_quote_tcp_ok,kgi_quote_tcp_ms,kgi_trade_dns_ok,kgi_trade_tcp_ok,kgi_trade_tcp_ms,control_tcp_ok,control_tcp_ms,primary_event_type"
[System.IO.File]::WriteAllText($CsvPath, ($csvHeader + "`r`n"), $Utf8NoBom)

$samples = @()
$eventTimeline = @()
$prevBssid = ""
$prevSocketSet = New-Object System.Collections.Generic.HashSet[string]
$socketBirthMap = @{}
$identifiableDurations = @()
$prevKgiRunning = $false
$prevNetUp = $true

$observedSocketOpenCount = 0
$observedSocketCloseCount = 0
$kgiRunningSampleCount = 0
$maxEstablishedSockets = 0
$totalNetAnomalyEvents = 0

$eventCounts = [ordered]@{
    NETWORK_INTERFACE_DOWN              = 0
    CONTROL_ENDPOINT_FAILURE            = 0
    KGI_PROBE_FAILURE                   = 0
    KGI_SOCKET_DISCONNECTED             = 0
    KGI_PROCESS_EXITED                  = 0
    KGI_APPLICATION_DISCONNECT_REPORTED = 0
    KGI_RECONNECTED                     = 0
    UNKNOWN_EVENT                       = 0
}

$lastActiveProbeTime = $startTime.AddSeconds(-1 * $ActiveProbeIntervalSeconds - 1)
$lastWinEventCheckTime = $startTime.AddSeconds(-1 * $PassiveIntervalSeconds)
$sampleIdx = 0
$completionReason = "duration_reached"
$fatalLoopError = ""

try {
    while ($true) {
        if (((Test-Path $ScopedStopFlag) -or (Test-Path $LegacyStopFlagFile)) -and $sampleIdx -gt 0) {
            Remove-Item $ScopedStopFlag -Force -ErrorAction SilentlyContinue
            Remove-Item $LegacyStopFlagFile -Force -ErrorAction SilentlyContinue
            $completionReason = "manual_stop"
            break
        }
        $now = Get-Date
        if ($DurationSeconds -gt 0 -and ($now - $startTime).TotalSeconds -ge $DurationSeconds -and $sampleIdx -gt 0) {
            $completionReason = "duration_reached"
            break
        }
        $sampleIdx++

        # 1. Passive Interface & Wi-Fi State
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

        # 2. Passive Verified KGI Process & TCP Socket Tracking
        $procSnap = Get-VerifiedKgiProcessSnapshot
        $kgiRunning = [bool]$procSnap.is_running
        $procIdentityStr = [string]$procSnap.summary
        if ($kgiRunning) { $kgiRunningSampleCount++ }

        $estCount = 0
        $synCount = 0
        $closeWaitCount = 0
        $curSocketSet = New-Object System.Collections.Generic.HashSet[string]
        $curSocketArr = @()

        if ($kgiRunning) {
            $vPids = @($procSnap.pids)
            $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
                $vPids -contains [int]$_.OwningProcess -and $_.RemoteAddress -notin @("0.0.0.0", "::", "127.0.0.1", "::1")
            }
            foreach ($c in $conns) {
                $st = [string]$c.State
                $tup = ("{0}:{1}->{2}:{3}" -f $c.OwningProcess, $c.LocalPort, $c.RemoteAddress, $c.RemotePort)
                if ($st -eq "Established") {
                    $estCount++
                    if ($curSocketSet.Add($tup)) { $curSocketArr += $tup }
                } elseif ($st -eq "SynSent") {
                    $synCount++
                } elseif ($st -eq "CloseWait") {
                    $closeWaitCount++
                }
            }
        }
        if ($estCount -gt $maxEstablishedSockets) { $maxEstablishedSockets = $estCount }

        $openedThisTick = 0
        $closedThisTick = 0
        $tickPrimaryEvent = "NONE"

        if (-not $netUp -and ($sampleIdx -eq 1 -or $prevNetUp)) {
            $eventCounts.NETWORK_INTERFACE_DOWN++
            $tickPrimaryEvent = "NETWORK_INTERFACE_DOWN"
        }

        if ($prevKgiRunning -and (-not $kgiRunning)) {
            $eventCounts.KGI_PROCESS_EXITED++
            $tickPrimaryEvent = "KGI_PROCESS_EXITED"
            $socketBirthMap.Clear()
            $prevSocketSet = New-Object System.Collections.Generic.HashSet[string]
        } else {
            if ($sampleIdx -eq 1) {
                $prevSocketSet = $curSocketSet
            } else {
                foreach ($sk in $curSocketSet) {
                    if (-not $prevSocketSet.Contains($sk)) {
                        $openedThisTick++
                        $observedSocketOpenCount++
                        $socketBirthMap[$sk] = $now
                    }
                }
                if ($kgiRunning) {
                    foreach ($oldSk in $prevSocketSet) {
                        if (-not $curSocketSet.Contains($oldSk)) {
                            $closedThisTick++
                            $observedSocketCloseCount++
                            if ($socketBirthMap.ContainsKey($oldSk)) {
                                $durS = [math]::Round(($now - $socketBirthMap[$oldSk]).TotalSeconds, 2)
                                if ($durS -ge 0) { $identifiableDurations += $durS }
                                $socketBirthMap.Remove($oldSk)
                            }
                        }
                    }
                    if ($closedThisTick -gt 0) {
                        $eventCounts.KGI_SOCKET_DISCONNECTED++
                        if ($tickPrimaryEvent -eq "NONE") { $tickPrimaryEvent = "KGI_SOCKET_DISCONNECTED" }
                    }
                }
                $prevSocketSet = $curSocketSet
            }
        }

        # 3. Active Low-Load Probes ONLY when ActiveProbeIntervalSeconds has elapsed!
        $doActiveProbe = (($sampleIdx -eq 1) -or (($now - $lastActiveProbeTime).TotalSeconds -ge $ActiveProbeIntervalSeconds))
        $qProbe = $null
        $tProbe = $null
        $cProbe = $null

        if ($doActiveProbe) {
            $qProbe = Probe-HostTcp -TargetHost $KgiQuoteHost -Port $KgiPort -WaitMs 3000
            Start-Sleep -Milliseconds 150
            $tProbe = Probe-HostTcp -TargetHost $KgiTradeHost -Port $KgiPort -WaitMs 3000
            Start-Sleep -Milliseconds 150
            $cProbe = Probe-HostTcp -TargetHost $ControlHost -Port $ControlPort -WaitMs 3000
            $lastActiveProbeTime = Get-Date

            if ((-not $qProbe.tcp_ok) -or (-not $tProbe.tcp_ok)) {
                $eventCounts.KGI_PROBE_FAILURE++
                if ($tickPrimaryEvent -eq "NONE") { $tickPrimaryEvent = "KGI_PROBE_FAILURE" }
            }
            if (-not $cProbe.tcp_ok) {
                $eventCounts.CONTROL_ENDPOINT_FAILURE++
                if ($tickPrimaryEvent -eq "NONE") { $tickPrimaryEvent = "CONTROL_ENDPOINT_FAILURE" }
            }
        }

        # 4. Windows Network Events in Window
        $winEvCount = 0
        $winEvTypes = @()
        try {
            $npEvs = Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-NetworkProfile/Operational"; StartTime = $lastWinEventCheckTime } -MaxEvents 5 -ErrorAction SilentlyContinue
            foreach ($e in $npEvs) {
                if ($e.Id -eq 10001) {
                    $winEvCount++
                    $winEvTypes += "NetProfile_Disconnect_10001"
                }
            }
        } catch {}
        try {
            $dEvs = Get-WinEvent -FilterHashtable @{ LogName = "System"; ProviderName = "Microsoft-Windows-DNS-Client"; Id = 1014; StartTime = $lastWinEventCheckTime } -MaxEvents 5 -ErrorAction SilentlyContinue
            if ($dEvs) {
                $cnt = @($dEvs).Count
                $winEvCount += $cnt
                $winEvTypes += "DNS_Timeout_1014"
            }
        } catch {}
        if ($winEvCount -gt 0) { $totalNetAnomalyEvents += $winEvCount }

        $prevKgiRunning = $kgiRunning
        $prevNetUp = $netUp
        $lastWinEventCheckTime = $now

        $sampleObj = [ordered]@{
            timestamp                = $now.ToString("o")
            run_id                   = $RunId
            sample_index             = $sampleIdx
            label                    = $Label
            net_up                   = $netUp
            primary_interface        = $ifaceName
            link_speed               = $linkSpd
            wifi_signal_pct          = $wifiSig
            wifi_bssid_masked        = $bssidMasked
            bssid_roamed             = $roamed
            kgi_running              = $kgiRunning
            process_identity_summary = $procIdentityStr
            kgi_established_sockets  = $estCount
            kgi_socket_keys          = $curSocketArr
            kgi_syn_sent_sockets     = $synCount
            kgi_close_wait_sockets   = $closeWaitCount
            socket_opened_count      = $openedThisTick
            socket_closed_count      = $closedThisTick
            active_probe_executed    = $doActiveProbe
            kgi_quote_probe          = $qProbe
            kgi_trade_probe          = $tProbe
            control_probe            = $cProbe
            system_events_count      = $winEvCount
            system_event_types       = $winEvTypes
            primary_event_type       = $tickPrimaryEvent
        }

        $samples += $sampleObj
        $jsonLine = ($sampleObj | ConvertTo-Json -Compress -Depth 6)
        [System.IO.File]::AppendAllText($JsonlPath, ($jsonLine + "`r`n"), $Utf8NoBom)

        $qDns = if ($doActiveProbe) { $qProbe.dns_ok } else { "" }
        $qTcp = if ($doActiveProbe) { $qProbe.tcp_ok } else { "" }
        $qMs  = if ($doActiveProbe -and $null -ne $qProbe.tcp_ms) { $qProbe.tcp_ms } else { "" }
        $tDns = if ($doActiveProbe) { $tProbe.dns_ok } else { "" }
        $tTcp = if ($doActiveProbe) { $tProbe.tcp_ok } else { "" }
        $tMs  = if ($doActiveProbe -and $null -ne $tProbe.tcp_ms) { $tProbe.tcp_ms } else { "" }
        $cTcp = if ($doActiveProbe) { $cProbe.tcp_ok } else { "" }
        $cMs  = if ($doActiveProbe -and $null -ne $cProbe.tcp_ms) { $cProbe.tcp_ms } else { "" }

        $csvLine = ("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17},{18},{19},{20}" -f `
            $sampleObj.timestamp, $RunId, $sampleIdx, $Label, $netUp, `
            $(if ($null -ne $wifiSig) { $wifiSig } else { "" }), $roamed, `
            $kgiRunning, $estCount, $openedThisTick, $closedThisTick, $doActiveProbe, `
            $qDns, $qTcp, $qMs, $tDns, $tTcp, $tMs, $cTcp, $cMs, $tickPrimaryEvent)
        [System.IO.File]::AppendAllText($CsvPath, ($csvLine + "`r`n"), $Utf8NoBom)

        $runningState = [ordered]@{
            run_id                        = $RunId
            pid                           = $PID
            process_start_time_utc        = $myStartUtcIso
            status                        = "running"
            run_status                    = "RUNNING"
            label                         = $Label
            network_profile               = $netProfileDetected
            started_at                    = $startTime.ToString("o")
            updated_at                    = $now.ToString("o")
            passive_interval_seconds      = $PassiveIntervalSeconds
            active_probe_interval_seconds = $ActiveProbeIntervalSeconds
            duration_seconds              = $DurationSeconds
            samples_recorded              = $sampleIdx
            stop_flag_path                = $ScopedStopFlag
            jsonl_path                    = $JsonlPath
            csv_path                      = $CsvPath
            marks_path                    = $MarksPath
            summary_path                  = $ArchiveSummaryPath
        }
        Write-JsonAtomic -TargetPath $StateFile -DataObj $runningState -Depth 5

        if ($DurationSeconds -gt 0 -and ((Get-Date) - $startTime).TotalSeconds -ge $DurationSeconds) {
            $completionReason = "duration_reached"
            break
        }

        for ($s = 0; $s -lt $PassiveIntervalSeconds; $s++) {
            if ((Test-Path $ScopedStopFlag) -or (Test-Path $LegacyStopFlagFile)) { break }
            Start-Sleep -Seconds 1
        }
    }
} catch {
    $fatalLoopError = $_.Exception.Message
    $completionReason = "exception_aborted"
} finally {
    $endTime = Get-Date
    $totalElapsedSec = [math]::Max(1.0, [math]::Round(($endTime - $startTime).TotalSeconds, 1))

    # Count manual marks written during run
    $userDiscMarks = 0
    $userReconnMarks = 0
    if (Test-Path $MarksPath) {
        try {
            $mLines = [System.IO.File]::ReadAllLines($MarksPath, [System.Text.Encoding]::UTF8)
            foreach ($ml in $mLines) {
                if ([string]::IsNullOrWhiteSpace($ml)) { continue }
                $mo = $ml | ConvertFrom-Json
                if ($mo.event -eq "kgi-disconnected") { $userDiscMarks++ }
                elseif ($mo.event -eq "kgi-reconnected") { $userReconnMarks++ }
            }
        } catch {}
    }
    $eventCounts.KGI_APPLICATION_DISCONNECT_REPORTED += $userDiscMarks
    $eventCounts.KGI_RECONNECTED += $userReconnMarks

    $totalKgiProbes = 0
    $okTcpProbes = 0
    $okDnsProbes = 0
    $tcpLatencies = @()
    $totalCtrlProbes = 0
    $okCtrlProbes = 0

    foreach ($sm in $samples) {
        if ($sm.active_probe_executed) {
            if ($null -ne $sm.kgi_quote_probe) {
                $totalKgiProbes++
                if ($sm.kgi_quote_probe.dns_ok) { $okDnsProbes++ }
                if ($sm.kgi_quote_probe.tcp_ok) {
                    $okTcpProbes++
                    if ($null -ne $sm.kgi_quote_probe.tcp_ms) { $tcpLatencies += [double]$sm.kgi_quote_probe.tcp_ms }
                }
            }
            if ($null -ne $sm.kgi_trade_probe) {
                $totalKgiProbes++
                if ($sm.kgi_trade_probe.dns_ok) { $okDnsProbes++ }
                if ($sm.kgi_trade_probe.tcp_ok) {
                    $okTcpProbes++
                    if ($null -ne $sm.kgi_trade_probe.tcp_ms) { $tcpLatencies += [double]$sm.kgi_trade_probe.tcp_ms }
                }
            }
            if ($null -ne $sm.control_probe) {
                $totalCtrlProbes++
                if ($sm.control_probe.tcp_ok) { $okCtrlProbes++ }
            }
        }
    }

    $indepProbeRate = if ($totalKgiProbes -gt 0) { [math]::Round(($okTcpProbes * 100.0 / $totalKgiProbes), 2) } else { $null }
    $indepDnsRate   = if ($totalKgiProbes -gt 0) { [math]::Round(($okDnsProbes * 100.0 / $totalKgiProbes), 2) } else { $null }
    $ctrlProbeRate  = if ($totalCtrlProbes -gt 0) { [math]::Round(($okCtrlProbes * 100.0 / $totalCtrlProbes), 2) } else { $null }
    $avgTcpMs = $null
    $maxTcpMs = $null
    if ($tcpLatencies.Count -gt 0) {
        $avgTcpMs = [math]::Round((($tcpLatencies | Measure-Object -Average).Average), 2)
        $maxTcpMs = [math]::Round((($tcpLatencies | Measure-Object -Maximum).Maximum), 2)
    }

    # NEVER estimate connection duration via totalElapsedSec / (disconnectCount + 1)!
    $avgIdentifiableDur = $null
    $durDisplay = [regex]::Unescape('\u7121\u6cd5\u7cbe\u78ba\u4f30\u8a08')
    if ($identifiableDurations.Count -gt 0) {
        $avgIdentifiableDur = [math]::Round((($identifiableDurations | Measure-Object -Average).Average), 2)
        $durDisplay = ("" + $avgIdentifiableDur + " sec")
    }

    $finalRunStatus = if (-not [string]::IsNullOrWhiteSpace($fatalLoopError) -or $samples.Count -eq 0) { "FAILED" } else { "SUCCESS" }
    $dataCompleteness = if ($finalRunStatus -eq "SUCCESS") { "COMPLETE" } else { "INCOMPLETE" }
    $confirmedDiscCount = [int]$eventCounts.KGI_APPLICATION_DISCONNECT_REPORTED

    $summaryObj = [ordered]@{
        schema_version                = "2.0"
        run_id                        = $RunId
        run_status                    = $finalRunStatus
        completion_reason             = $completionReason
        data_completeness             = $dataCompleteness
        error_message                 = $fatalLoopError
        label                         = $Label
        network_profile               = $netProfileDetected
        started_at                    = $startTime.ToString("o")
        ended_at                      = $endTime.ToString("o")
        total_duration_sec            = $totalElapsedSec
        passive_interval_seconds      = $PassiveIntervalSeconds
        active_probe_interval_seconds = $ActiveProbeIntervalSeconds
        sample_count                  = $samples.Count
        jsonl_path                    = $JsonlPath
        csv_path                      = $CsvPath
        marks_path                    = $MarksPath
        metrics                       = [ordered]@{
            confirmed_trading_disconnect_count        = $confirmedDiscCount
            user_reported_disconnect_count            = $userDiscMarks
            user_reported_reconnect_count             = $userReconnMarks
            observed_socket_open_count                = $observedSocketOpenCount
            observed_socket_close_count               = $observedSocketCloseCount
            identifiable_socket_count                 = $identifiableDurations.Count
            avg_identifiable_socket_duration_sec      = $avgIdentifiableDur
            identifiable_connection_duration_display  = $durDisplay
            independent_kgi_probe_success_rate_pct    = $indepProbeRate
            independent_dns_success_rate_pct          = $indepDnsRate
            independent_control_probe_success_rate_pct = $ctrlProbeRate
            tcp_connect_avg_ms                        = $avgTcpMs
            tcp_connect_max_ms                        = $maxTcpMs
            kgi_running_sample_count                  = $kgiRunningSampleCount
            max_established_sockets                   = $maxEstablishedSockets
            network_anomaly_events                    = $totalNetAnomalyEvents
            event_counts                              = $eventCounts
            unknown_event_count                       = $eventCounts.UNKNOWN_EVENT
            disconnect_count                          = $confirmedDiscCount
            avg_connection_duration_sec               = if ($null -ne $avgIdentifiableDur) { $avgIdentifiableDur } else { $durDisplay }
            connection_success_rate_pct               = $indepProbeRate
            dns_success_rate_pct                      = $indepDnsRate
            control_success_rate_pct                  = $ctrlProbeRate
        }
        samples                       = $samples
    }

    Write-JsonAtomic -TargetPath $ArchiveSummaryPath -DataObj $summaryObj -Depth 8
    Write-JsonAtomic -TargetPath $SummaryPath -DataObj $summaryObj -Depth 8

    $finalState = [ordered]@{
        run_id                 = $RunId
        pid                    = $PID
        process_start_time_utc = $myStartUtcIso
        status                 = if ($finalRunStatus -eq "SUCCESS") { "completed" } else { "failed" }
        run_status             = $finalRunStatus
        completion_reason      = $completionReason
        label                  = $Label
        network_profile        = $netProfileDetected
        started_at             = $startTime.ToString("o")
        ended_at               = $endTime.ToString("o")
        samples_recorded       = $samples.Count
        stop_flag_path         = $ScopedStopFlag
        jsonl_path             = $JsonlPath
        csv_path               = $CsvPath
        marks_path             = $MarksPath
        summary_path           = $ArchiveSummaryPath
    }
    Write-JsonAtomic -TargetPath $StateFile -DataObj $finalState -Depth 5
}

if ($fatalLoopError -or $samples.Count -eq 0) {
    Write-Error ("FAILED: Monitor RunId=" + $RunId + " ended with failure: " + $fatalLoopError)
    exit 2
}
Write-Output ("OK: Monitoring completed (RunId=" + $RunId + ", Samples=" + $samples.Count + ", Summary=" + $ArchiveSummaryPath + ")")
exit 0
