[CmdletBinding()]
param(
    [string]$RunId = "",
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Continue"
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = "kgi_" + (Get-Date).ToString("yyyyMMdd_HHmmss")
}

$ProjectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ProjectRoot ("reports\internal\" + $RunId + "\kgi_inspection.json")
}

$PatKgiName = [regex]::Unescape('(\u65b0\u8d85\u7d1a\u5927\u4e09\u5143|\u8d85\u7d1a\u5927\u4e09\u5143|\u5927\u4e09\u5143|\u51f1\u57fa|KGI)')
$FolderSuper3 = [regex]::Unescape('\u8d85\u7d1a\u5927\u4e09\u5143')

function Mask-UserPath([string]$PathStr) {
    if ([string]::IsNullOrWhiteSpace($PathStr)) { return "" }
    $res = $PathStr -ireplace '([A-Za-z]:\\Users\\)([^\\]+)', '$1<USER>'
    if ($env:USERNAME) {
        $res = $res -ireplace [regex]::Escape($env:USERNAME), "<USER>"
    }
    return $res
}

function Write-JsonAtomic([string]$TargetPath, [object]$DataObj, [int]$Depth = 8) {
    $outDir = Split-Path -Parent $TargetPath
    if (-not [string]::IsNullOrWhiteSpace($outDir) -and -not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    $tmpPath = $TargetPath + ".tmp." + $PID + "." + ([guid]::NewGuid().ToString("N").Substring(0, 6))
    $jsonText = $DataObj | ConvertTo-Json -Depth $Depth
    [System.IO.File]::WriteAllText($tmpPath, $jsonText, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -Path $tmpPath -Destination $TargetPath -Force
}

$installCandidates = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
$registryEntries = @()
$shortcutEntries = @()

# 1A. Registry Uninstall Search (Read-Only)
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
try {
    $items = Get-ItemProperty -Path $regPaths -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -match $PatKgiName -or $_.Publisher -match $PatKgiName
    }
    foreach ($it in $items) {
        $instLoc = [string]$it.InstallLocation
        if ([string]::IsNullOrWhiteSpace($instLoc) -and -not [string]::IsNullOrWhiteSpace($it.UninstallString)) {
            $uClean = ($it.UninstallString -replace '"', '').Trim()
            if (Test-Path $uClean) {
                $instLoc = Split-Path -Parent $uClean
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($instLoc) -and (Test-Path $instLoc)) {
            [void]$installCandidates.Add($instLoc)
        }
        $registryEntries += [ordered]@{
            display_name     = [string]$it.DisplayName
            display_version  = [string]$it.DisplayVersion
            publisher        = [string]$it.Publisher
            install_location = Mask-UserPath $instLoc
        }
    }
} catch {}

# 1B. Shortcuts Search (Desktop & Start Menu)
$scRoots = @(
    [Environment]::GetFolderPath("Desktop"),
    [Environment]::GetFolderPath("CommonDesktopDirectory"),
    [Environment]::GetFolderPath("StartMenu"),
    [Environment]::GetFolderPath("CommonStartMenu")
)
try {
    $wsh = New-Object -ComObject WScript.Shell
    foreach ($root in $scRoots) {
        if (-not [string]::IsNullOrWhiteSpace($root) -and (Test-Path $root)) {
            $lnks = Get-ChildItem -Path $root -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -match $PatKgiName
            }
            foreach ($lnk in $lnks) {
                try {
                    $sc = $wsh.CreateShortcut($lnk.FullName)
                    $tp = [string]$sc.TargetPath
                    if (-not [string]::IsNullOrWhiteSpace($tp) -and (Test-Path $tp)) {
                        $exeDir = Split-Path -Parent $tp
                        $parentDir = Split-Path -Parent $exeDir
                        if ((Split-Path -Leaf $exeDir) -ieq "exe" -and (Test-Path $parentDir)) {
                            [void]$installCandidates.Add($parentDir)
                        } else {
                            [void]$installCandidates.Add($exeDir)
                        }
                    }
                    $shortcutEntries += [ordered]@{
                        shortcut_name      = $lnk.Name
                        target_path        = Mask-UserPath $tp
                        working_directory  = Mask-UserPath ([string]$sc.WorkingDirectory)
                    }
                } catch {}
            }
        }
    }
} catch {}

# 1C. Common Paths Fallback
foreach ($drv in @("C:", "D:", "E:")) {
    $cand1 = Join-Path $drv $FolderSuper3
    $cand2 = Join-Path $drv ("KGI\" + $FolderSuper3)
    foreach ($c in @($cand1, $cand2)) {
        if (Test-Path $c) { [void]$installCandidates.Add($c) }
    }
}

# 2 & 3. Executables, Versions & Authenticode Signatures
$executables = @()
$knownExeNames = @("SUPERTSC64.exe", "SuperTSC.exe", "axis.exe", "AXISVER.EXE", "Patch.exe", "VELOTRDER64.exe", "TKAP3083.EXE", "TKAP3083CHART.EXE")
foreach ($instDir in $installCandidates) {
    $exeFiles = Get-ChildItem -Path $instDir -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue
    foreach ($ef in $exeFiles) {
        $sigStatus = "Unknown"
        $signerSubject = ""
        $signerIssuer = ""
        $certNotAfter = ""
        try {
            $sig = Get-AuthenticodeSignature -FilePath $ef.FullName -ErrorAction SilentlyContinue
            if ($sig) {
                $sigStatus = [string]$sig.Status
                if ($sig.SignerCertificate) {
                    $signerSubject = [string]$sig.SignerCertificate.Subject
                    $signerIssuer = [string]$sig.SignerCertificate.Issuer
                    $certNotAfter = $sig.SignerCertificate.NotAfter.ToString("o")
                }
            }
        } catch {}

        $executables += [ordered]@{
            name             = $ef.Name
            full_path        = Mask-UserPath $ef.FullName
            is_core_binary   = ($ef.Name -in $knownExeNames)
            file_version     = [string]$ef.VersionInfo.FileVersion
            product_version  = [string]$ef.VersionInfo.ProductVersion
            product_name     = [string]$ef.VersionInfo.ProductName
            size_bytes       = [int64]$ef.Length
            last_write_time  = $ef.LastWriteTime.ToString("o")
            signature_status = $sigStatus
            signer_subject   = $signerSubject
            signer_issuer    = $signerIssuer
            cert_not_after   = $certNotAfter
        }
    }
}

# 4. Section 5.1: Multi-Factor Process Identity Verification
# NEVER trust process name (e.g. axis.exe) alone! Must verify path, Authenticode signature, PID, start time, and parent-child relation.
$runningProcesses = @()
$unverifiedSameNameProcesses = @()
$verifiedCorePidSet = New-Object System.Collections.Generic.HashSet[int]
$verifiedChildPidSet = New-Object System.Collections.Generic.HashSet[int]

try {
    $allProcs = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue
    $procByPid = @{}
    foreach ($p in $allProcs) {
        $procByPid[[int]$p.ProcessId] = $p
    }

    foreach ($p in $allProcs) {
        $pidInt = [int]$p.ProcessId
        $pPath = [string]$p.ExecutablePath
        $pName = [string]$p.Name

        $inKgiDir = $false
        foreach ($instDir in $installCandidates) {
            if (-not [string]::IsNullOrWhiteSpace($pPath) -and $pPath.StartsWith($instDir, [System.StringComparison]::OrdinalIgnoreCase)) {
                $inKgiDir = $true
                break
            }
        }

        $isCandidateName = ($pName -match '^(?i)(SUPERTSC64|SuperTSC|axis|VELOTRDER64|TKAP3083)\.exe$')
        if (-not $inKgiDir -and -not $isCandidateName) { continue }

        $sigValidKgi = $false
        $sigSubj = ""
        $sigState = "Unknown"
        if (-not [string]::IsNullOrWhiteSpace($pPath) -and (Test-Path $pPath)) {
            try {
                $psig = Get-AuthenticodeSignature -FilePath $pPath -ErrorAction SilentlyContinue
                if ($psig) {
                    $sigState = [string]$psig.Status
                    if ($psig.SignerCertificate) {
                        $sigSubj = [string]$psig.SignerCertificate.Subject
                    }
                    if ($sigState -eq "Valid" -and ($sigSubj -match '(?i)(KGI Securities|Kway|SysJust)' -or $sigSubj -match $PatKgiName)) {
                        $sigValidKgi = $true
                    }
                }
            } catch {}
        }

        if ($inKgiDir -or $sigValidKgi) {
            [void]$verifiedCorePidSet.Add($pidInt)
        } else {
            # Same-named binary (e.g. another vendor's axis.exe) rejected by multi-factor verification!
            $unverifiedSameNameProcesses += [ordered]@{
                pid              = $pidInt
                name             = $pName
                executable_path  = Mask-UserPath $pPath
                signature_status = $sigState
                signer_subject   = $sigSubj
                rejection_reason = "Process name matched candidate, but neither install path nor KGI Authenticode signature matched"
            }
        }
    }

    # Include child processes spawned by verified KGI core processes
    $addedChild = $true
    while ($addedChild) {
        $addedChild = $false
        foreach ($p in $allProcs) {
            $pidInt = [int]$p.ProcessId
            $ppidInt = [int]$p.ParentProcessId
            if (-not $verifiedCorePidSet.Contains($pidInt) -and -not $verifiedChildPidSet.Contains($pidInt)) {
                if ($verifiedCorePidSet.Contains($ppidInt) -or $verifiedChildPidSet.Contains($ppidInt)) {
                    [void]$verifiedChildPidSet.Add($pidInt)
                    $addedChild = $true
                }
            }
        }
    }

    foreach ($p in $allProcs) {
        $pidInt = [int]$p.ProcessId
        $isCore = $verifiedCorePidSet.Contains($pidInt)
        $isChild = $verifiedChildPidSet.Contains($pidInt)
        if (-not $isCore -and -not $isChild) { continue }

        $startIso = ""
        try {
            $gp = Get-Process -Id $pidInt -ErrorAction SilentlyContinue
            if ($gp -and $gp.StartTime) { $startIso = $gp.StartTime.ToString("o") }
        } catch {}

        $pPath = [string]$p.ExecutablePath
        $sigState = "Unknown"
        $sigSubj = ""
        if (-not [string]::IsNullOrWhiteSpace($pPath) -and (Test-Path $pPath)) {
            try {
                $psig = Get-AuthenticodeSignature -FilePath $pPath -ErrorAction SilentlyContinue
                if ($psig) {
                    $sigState = [string]$psig.Status
                    if ($psig.SignerCertificate) { $sigSubj = [string]$psig.SignerCertificate.Subject }
                }
            } catch {}
        }

        $ppidInt = [int]$p.ParentProcessId
        $parentName = if ($procByPid.ContainsKey($ppidInt)) { [string]$procByPid[$ppidInt].Name } else { "" }

        $runningProcesses += [ordered]@{
            pid                = $pidInt
            parent_pid         = $ppidInt
            parent_name        = $parentName
            name               = [string]$p.Name
            executable_path    = Mask-UserPath $pPath
            start_time         = $startIso
            signature_status   = $sigState
            signer_subject     = $sigSubj
            identity_role      = if ($isCore) { "verified_kgi_core" } else { "verified_child_helper" }
            is_webview_helper  = ([string]$p.Name -match '(?i)webview')
        }
    }
} catch {}

# Static Config Endpoints Discovery (ONLY static package INI files: YELLOWPAGE.INI, AXIS.INI, PLATFORM.INI, HTSWORK.INI)
$configuredEndpoints = @()
$knownKgiIpSet = New-Object System.Collections.Generic.HashSet[string]
$architectureFacts = [ordered]@{
    platform_engine       = ""
    socket_module         = ""
    encryption_module     = ""
    background_jobs       = @()
    reconnect_mechanisms  = @()
    last_log_metadata     = $null
    crashpad_dump_count   = 0
}

try {
    $enc950 = [System.Text.Encoding]::GetEncoding(950)
    foreach ($instDir in $installCandidates) {
        $ypFile = Join-Path $instDir "tab\YELLOWPAGE.INI"
        $portsConfigured = @()
        $hostsMap = @()

        if (Test-Path $ypFile) {
            $lines = [System.IO.File]::ReadAllLines($ypFile, $enc950)
            $sec = ""
            foreach ($ln in $lines) {
                $t = $ln.Trim()
                if ($t -match '^\[(.+)\]$') {
                    $sec = $Matches[1]
                } elseif ($t -match '^([^;=]+)=(.+)$') {
                    $k = $Matches[1].Trim()
                    $v = $Matches[2].Trim()
                    if ($sec -ieq "server_PORT" -and $v -match '^\d+$') {
                        $portsConfigured += [int]$v
                    } elseif ($sec -match 'URL' -and $v -match '^[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,}$') {
                        $hostsMap += [ordered]@{
                            section = $sec
                            key     = $k
                            fqdn    = $v
                        }
                    }
                }
            }
        }

        if ($portsConfigured.Count -eq 0) { $portsConfigured = @(443, 80) }
        foreach ($hm in $hostsMap) {
            $resolvedIps = @()
            try {
                $dnsRecs = Resolve-DnsName -Name $hm.fqdn -Type A -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress }
                foreach ($r in $dnsRecs) {
                    $ipStr = [string]$r.IPAddress
                    $resolvedIps += $ipStr
                    [void]$knownKgiIpSet.Add($ipStr)
                }
            } catch {}
            $configuredEndpoints += [ordered]@{
                endpoint_category = "static_ini_candidate"
                role              = $hm.section
                alias             = $hm.key
                fqdn              = $hm.fqdn
                ports             = $portsConfigured
                resolved_ips      = $resolvedIps
                source            = "static_config:tab/YELLOWPAGE.INI"
            }
        }

        $axisIni = Join-Path $instDir "tab\AXIS.INI"
        if (Test-Path $axisIni) {
            $lines = [System.IO.File]::ReadAllLines($axisIni, $enc950)
            $sec = ""
            foreach ($ln in $lines) {
                $t = $ln.Trim()
                if ($t -match '^\[(.+)\]$') { $sec = $Matches[1] }
                elseif ($sec -ieq "Secure" -and $t -match '^secure=(.+)$') {
                    $architectureFacts.encryption_module = $Matches[1].Trim()
                } elseif ($sec -ieq "BackgroundJob" -and $t -match '^Job\d+=(.+)$') {
                    $jobVal = $Matches[1].Trim()
                    $architectureFacts.background_jobs += $jobVal
                    if ($jobVal -ieq "DISPROXY") {
                        $architectureFacts.reconnect_mechanisms += "BackgroundJob DISPROXY (dispatch/connection proxy monitor)"
                    }
                    if ($jobVal -ieq "RPTORDER") {
                        $architectureFacts.reconnect_mechanisms += "BackgroundJob RPTORDER (real-time order/execution report stream)"
                    }
                }
            }
        }

        $platIni = Join-Path $instDir "tab\PLATFORM.INI"
        if (Test-Path $platIni) {
            $architectureFacts.platform_engine = "Kway HTS (axis.exe + SUPERTSC64.exe launcher)"
            $architectureFacts.socket_module = "axsock.ocx + KGICGCAPIATL2.DLL + LIBWEBVIEW2.dll"
        }

        $htsWorkIni = Join-Path $instDir "tab\HTSWORK.INI"
        if (Test-Path $htsWorkIni) {
            $lines = [System.IO.File]::ReadAllLines($htsWorkIni, $enc950)
            foreach ($ln in $lines) {
                if ($ln -match '^(CountSec|Reopen_Interval)\s*=\s*(\d+)') {
                    $architectureFacts.reconnect_mechanisms += ("HTSWORK.INI FOCLR " + $Matches[1] + "=" + $Matches[2])
                }
            }
        }

        # Metadata-only check on Logs & Crashpad (never decrypting or reading financial logs)
        $logsDir = Join-Path $instDir "Logs"
        if (Test-Path $logsDir) {
            $latestLog = Get-ChildItem -Path $logsDir -File -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($latestLog) {
                $logPidHint = $null
                if ($latestLog.Name -match '-(\d+)\.log$') {
                    $logPidHint = [int]$Matches[1]
                }
                $architectureFacts.last_log_metadata = [ordered]@{
                    file_name       = "HTS_REDACTED.log"
                    size_bytes      = [int64]$latestLog.Length
                    last_write_date = $latestLog.LastWriteTime.ToString("yyyy-MM-dd")
                    pid_in_filename = $logPidHint
                    content_policy  = "Encrypted vendor log; metadata inspected only (no decryption/credential access)"
                }
            }
        }

        $crashDir = Join-Path $instDir "exe\axis.exe.WebView2\EBWebView\Crashpad\reports"
        if (Test-Path $crashDir) {
            $dmpFiles = Get-ChildItem -Path $crashDir -Filter "*.dmp" -File -ErrorAction SilentlyContinue
            $architectureFacts.crashpad_dump_count += @($dmpFiles).Count
        }
    }
} catch {}

# 5, 6, 7. Active TCP Connections separated into observed_active_endpoints vs unverified_remote_endpoints
$activeConnections = @()
$observedActiveEndpoints = @()
$unverifiedRemoteEndpoints = @()

if ($verifiedCorePidSet.Count -gt 0 -or $verifiedChildPidSet.Count -gt 0) {
    $dnsCacheMap = @{}
    try {
        $cacheEntries = Get-DnsClientCache -ErrorAction SilentlyContinue
        foreach ($ce in $cacheEntries) {
            if ($ce.Data -and $ce.Entry) {
                $dnsCacheMap[[string]$ce.Data] = [string]$ce.Entry
            }
        }
    } catch {}

    foreach ($ep in $configuredEndpoints) {
        foreach ($rip in $ep.resolved_ips) {
            $dnsCacheMap[$rip] = $ep.fqdn
        }
    }

    try {
        $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
            $verifiedCorePidSet.Contains([int]$_.OwningProcess) -or $verifiedChildPidSet.Contains([int]$_.OwningProcess)
        }
        foreach ($c in $conns) {
            $remAddr = [string]$c.RemoteAddress
            if ($remAddr -in @("0.0.0.0", "::", "127.0.0.1", "::1")) { continue }

            $ownerPid = [int]$c.OwningProcess
            $isCoreOwner = $verifiedCorePidSet.Contains($ownerPid)
            $hostHint = ""
            if ($dnsCacheMap.ContainsKey($remAddr)) {
                $hostHint = $dnsCacheMap[$remAddr]
            } else {
                try {
                    $ptr = Resolve-DnsName -Name $remAddr -Type PTR -DnsOnly -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($ptr -and $ptr.NameHost) { $hostHint = [string]$ptr.NameHost }
                } catch {}
            }

            $isKnownKgiEndpoint = (
                $knownKgiIpSet.Contains($remAddr) -or
                ($hostHint -match '(?i)(kgi\.com\.tw|kgieworld\.com\.tw|kgif\.com\.tw)')
            )
            $epCategory = if ($isCoreOwner -or $isKnownKgiEndpoint) { "observed_active" } else { "unverified_remote" }

            $procObj = $runningProcesses | Where-Object { $_.pid -eq $ownerPid } | Select-Object -First 1
            $connEntry = [ordered]@{
                endpoint_category = $epCategory
                pid               = $ownerPid
                process_name      = if ($procObj) { $procObj.name } else { "" }
                identity_role     = if ($procObj) { $procObj.identity_role } else { "" }
                local_port        = [int]$c.LocalPort
                remote_address    = $remAddr
                remote_port       = [int]$c.RemotePort
                state             = [string]$c.State
                verified_fqdn     = $hostHint
            }
            $activeConnections += $connEntry
            if ($epCategory -eq "observed_active") {
                $observedActiveEndpoints += $connEntry
            } else {
                $unverifiedRemoteEndpoints += $connEntry
            }
        }
    } catch {}
}

$installRootList = @()
foreach ($d in $installCandidates) { $installRootList += (Mask-UserPath $d) }

$supertscRunning = @($runningProcesses | Where-Object { $_.name -match '^(?i)(SUPERTSC64|SuperTSC)\.exe$' }).Count -gt 0
$axisRunning = @($runningProcesses | Where-Object { $_.name -ieq 'axis.exe' }).Count -gt 0

$estCount = @($activeConnections | Where-Object { $_.state -ieq 'Established' }).Count
$synSentCount = @($activeConnections | Where-Object { $_.state -ieq 'SynSent' -or $_.state -ieq 'SYN_SENT' }).Count
$closeWaitCount = @($activeConnections | Where-Object { $_.state -ieq 'CloseWait' -or $_.state -ieq 'CLOSE_WAIT' }).Count
$timeWaitCount = @($activeConnections | Where-Object { $_.state -ieq 'TimeWait' -or $_.state -ieq 'TIME_WAIT' }).Count
$abnormalStates = @($activeConnections | Where-Object { $_.state -notmatch '^(?i)(Established|Listen)$' } | ForEach-Object { ($_.remote_address + ":" + $_.remote_port + "(" + $_.state + ")") })

$matchedStaticCount = 0
$unlistedActualCount = 0
foreach ($obs in $observedActiveEndpoints) {
    if ($knownKgiIpSet.Contains([string]$obs.remote_address)) {
        $matchedStaticCount++
    } else {
        $unlistedActualCount++
    }
}

$consistencyStatus = "NO_ACTIVE_CONNECTIONS"
$consistencyDetail = "No active KGI TCP connections observed yet; static INI endpoints cannot be treated as active connections."
if ($observedActiveEndpoints.Count -gt 0) {
    if ($matchedStaticCount -gt 0 -and $unlistedActualCount -eq 0) {
        $consistencyStatus = "CONSISTENT_WITH_STATIC_INI"
        $consistencyDetail = "All observed active KGI endpoints match static YELLOWPAGE.INI resolved server IPs."
    } elseif ($matchedStaticCount -gt 0 -and $unlistedActualCount -gt 0) {
        $consistencyStatus = "PARTIAL_MATCH_WITH_DYNAMIC_DISPATCH"
        $consistencyDetail = "Observed both static YELLOWPAGE.INI endpoints and additional dynamically dispatched remote IPs."
    } else {
        $consistencyStatus = "DYNAMIC_ENDPOINTS_DIFFER_FROM_STATIC_INI"
        $consistencyDetail = "Observed active connections use remote IPs not listed in static YELLOWPAGE.INI DNS resolution."
    }
}

$verificationStatus = "VERIFIED_ACTIVE_TRADING_CONNECTIONS"
$verificationReason = "Verified KGI process is running with Established TCP connections."
if (-not ($verifiedCorePidSet.Count -gt 0)) {
    $verificationStatus = "NOT_VERIFIED_PROCESS_NOT_RUNNING"
    $verificationReason = "KGI trading software (SUPERTSC64.exe / axis.exe) is not currently running."
} elseif ($estCount -eq 0) {
    $verificationStatus = "NOT_VERIFIED_NO_ESTABLISHED_SOCKET"
    $verificationReason = "KGI process is running, but 0 Established remote TCP sockets were observed (may not be logged in yet or already disconnected)."
}

$outputObj = [ordered]@{
    schema_version                         = "2.0"
    run_id                                 = $RunId
    run_status                             = "SUCCESS"
    inspected_at                           = (Get-Date).ToString("o")
    is_installed                           = ($installRootList.Count -gt 0)
    is_currently_running                   = ($verifiedCorePidSet.Count -gt 0)
    supertsc64_running                     = $supertscRunning
    axis_running                           = $axisRunning
    trading_connection_verification_status = $verificationStatus
    trading_connection_verification_reason = $verificationReason
    install_directories                    = $installRootList
    registry_entries                       = $registryEntries
    shortcuts                              = $shortcutEntries
    executables                            = $executables
    running_processes                      = $runningProcesses
    rejected_same_name_processes           = $unverifiedSameNameProcesses
    active_tcp_connections                 = $activeConnections
    tcp_state_summary                      = [ordered]@{
        total_connections        = $activeConnections.Count
        established_count        = $estCount
        syn_sent_count           = $synSentCount
        close_wait_count         = $closeWaitCount
        time_wait_count          = $timeWaitCount
        has_abnormal_tcp_states  = ($synSentCount -gt 0 -or $closeWaitCount -gt 0 -or $abnormalStates.Count -gt 0)
        abnormal_endpoints       = $abnormalStates
    }
    static_vs_actual_comparison            = [ordered]@{
        has_active_connections          = ($observedActiveEndpoints.Count -gt 0)
        matched_static_endpoints_count  = $matchedStaticCount
        unlisted_actual_endpoints_count = $unlistedActualCount
        consistency_status              = $consistencyStatus
        detail                          = $consistencyDetail
    }
    observed_active_endpoints              = $observedActiveEndpoints
    configured_endpoints                   = $configuredEndpoints
    unverified_remote_endpoints            = $unverifiedRemoteEndpoints
    architecture_and_reconnect             = $architectureFacts
}

try {
    Write-JsonAtomic -TargetPath $OutputPath -DataObj $outputObj -Depth 8
    Write-Output ("OK: KGI inspection saved to " + $OutputPath + " (RunId=" + $RunId + ")")
    exit 0
} catch {
    Write-Error ("FAILED: Unable to write KGI inspection JSON: " + $_.Exception.Message)
    exit 2
}
