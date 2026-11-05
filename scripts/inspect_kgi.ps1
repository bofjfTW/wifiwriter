[CmdletBinding()]
param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Continue"
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ProjectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ProjectRoot "reports\kgi_inspection.json"
}

$PatKgiName = [regex]::Unescape('(\u65b0\u8d85\u7d1a\u5927\u4e09\u5143|\u8d85\u7d1a\u5927\u4e09\u5143|\u5927\u4e09\u5143|\u51f1\u57fa|KGI)')
$FolderSuper3 = [regex]::Unescape('\u8d85\u7d1a\u5927\u4e09\u5143')

function Mask-UserPath([string]$PathStr) {
    if ([string]::IsNullOrWhiteSpace($PathStr)) { return "" }
    if ($env:USERNAME) {
        return ($PathStr -ireplace [regex]::Escape($env:USERNAME), "<USER>")
    }
    return $PathStr
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
            raw_dir          = $instDir
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

# 4. Running Processes & Child Processes
$runningProcesses = @()
$kgiPidSet = New-Object System.Collections.Generic.HashSet[int]
try {
    $allProcs = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue
    foreach ($p in $allProcs) {
        $pPath = [string]$p.ExecutablePath
        $pName = [string]$p.Name
        $matchedInstall = $false
        foreach ($instDir in $installCandidates) {
            if (-not [string]::IsNullOrWhiteSpace($pPath) -and $pPath.StartsWith($instDir, [System.StringComparison]::OrdinalIgnoreCase)) {
                $matchedInstall = $true
                break
            }
        }
        if ($matchedInstall -or $pName -match '^(SUPERTSC64|SuperTSC|VELOTRDER64|TKAP3083)\.exe$') {
            [void]$kgiPidSet.Add([int]$p.ProcessId)
        }
    }

    # Include child processes (e.g. msedgewebview2.exe spawned by axis.exe)
    $addedChild = $true
    while ($addedChild) {
        $addedChild = $false
        foreach ($p in $allProcs) {
            $pidInt = [int]$p.ProcessId
            $ppidInt = [int]$p.ParentProcessId
            if (-not $kgiPidSet.Contains($pidInt) -and $kgiPidSet.Contains($ppidInt)) {
                [void]$kgiPidSet.Add($pidInt)
                $addedChild = $true
            }
        }
    }

    foreach ($p in $allProcs) {
        $pidInt = [int]$p.ProcessId
        if ($kgiPidSet.Contains($pidInt)) {
            $startIso = ""
            try {
                $gp = Get-Process -Id $pidInt -ErrorAction SilentlyContinue
                if ($gp -and $gp.StartTime) { $startIso = $gp.StartTime.ToString("o") }
            } catch {}
            $runningProcesses += [ordered]@{
                pid               = $pidInt
                parent_pid        = [int]$p.ParentProcessId
                name              = [string]$p.Name
                executable_path   = Mask-UserPath ([string]$p.ExecutablePath)
                start_time        = $startIso
                is_webview_helper = ([string]$p.Name -match '(?i)webview')
            }
        }
    }
} catch {}

# Static Config Endpoints Discovery (ONLY static package INI files: YELLOWPAGE.INI, LINK.INI, AXIS.INI, HTSWORK.INI; NEVER user files)
$configuredEndpoints = @()
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
                foreach ($r in $dnsRecs) { $resolvedIps += [string]$r.IPAddress }
            } catch {}
            $configuredEndpoints += [ordered]@{
                role         = $hm.section
                alias        = $hm.key
                fqdn         = $hm.fqdn
                ports        = $portsConfigured
                resolved_ips = $resolvedIps
                source       = "static_config:tab/YELLOWPAGE.INI"
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
                # Extract PID hint from filename pattern HTSyyyyMMdd-HHmm-PID.log
                $logPidHint = $null
                if ($latestLog.Name -match '-(\d+)\.log$') {
                    $logPidHint = [int]$Matches[1]
                }
                $architectureFacts.last_log_metadata = [ordered]@{
                    file_name       = $latestLog.Name
                    size_bytes      = [int64]$latestLog.Length
                    last_write_time = $latestLog.LastWriteTime.ToString("o")
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

# 5, 6, 7. Active TCP Connections for KGI Processes + Reverse Hostname Mapping
$activeConnections = @()
if ($kgiPidSet.Count -gt 0) {
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
            $kgiPidSet.Contains([int]$_.OwningProcess)
        }
        foreach ($c in $conns) {
            $remAddr = [string]$c.RemoteAddress
            if ($remAddr -in @("0.0.0.0", "::", "127.0.0.1", "::1")) { continue }

            $hostHint = ""
            if ($dnsCacheMap.ContainsKey($remAddr)) {
                $hostHint = $dnsCacheMap[$remAddr]
            } else {
                try {
                    $ptr = Resolve-DnsName -Name $remAddr -Type PTR -DnsOnly -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($ptr -and $ptr.NameHost) { $hostHint = [string]$ptr.NameHost }
                } catch {}
            }

            $procObj = $runningProcesses | Where-Object { $_.pid -eq [int]$c.OwningProcess } | Select-Object -First 1
            $activeConnections += [ordered]@{
                pid            = [int]$c.OwningProcess
                process_name   = if ($procObj) { $procObj.name } else { "" }
                local_port     = [int]$c.LocalPort
                remote_address = $remAddr
                remote_port    = [int]$c.RemotePort
                state          = [string]$c.State
                verified_fqdn  = $hostHint
            }
        }
    } catch {}
}

$installRootList = @()
foreach ($d in $installCandidates) { $installRootList += (Mask-UserPath $d) }

$outputObj = [ordered]@{
    schema_version         = "1.0"
    inspected_at           = (Get-Date).ToString("o")
    is_installed           = ($installRootList.Count -gt 0)
    is_currently_running   = ($runningProcesses.Count -gt 0)
    install_directories    = $installRootList
    registry_entries       = $registryEntries
    shortcuts              = $shortcutEntries
    executables            = $executables
    running_processes      = $runningProcesses
    active_tcp_connections = $activeConnections
    configured_endpoints   = $configuredEndpoints
    architecture_and_reconnect = $architectureFacts
}

$outDir = Split-Path -Parent $OutputPath
if (-not [string]::IsNullOrWhiteSpace($outDir) -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$jsonText = $outputObj | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($OutputPath, $jsonText, (New-Object System.Text.UTF8Encoding($false)))

Write-Output ("OK: KGI inspection saved to " + $OutputPath)

