[CmdletBinding()]
param(
    [string]$TargetsPath = "",
    [string]$OutputPath = "",
    [int]$TimeoutMs = 5000
)

$ErrorActionPreference = "Continue"
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ProjectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($TargetsPath)) {
    $customTargets = Join-Path $ProjectRoot "config\targets.json"
    if (Test-Path $customTargets) {
        $TargetsPath = $customTargets
    } else {
        $TargetsPath = Join-Path $ProjectRoot "config\targets.example.json"
    }
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ProjectRoot "reports\restrictions_check_ps.json"
}

$CAT_OK          = [regex]::Unescape('\u6b63\u5e38')
$CAT_FAIL        = [regex]::Unescape('\u9023\u7dda\u5931\u6557')
$CAT_RESTRICTED  = [regex]::Unescape('\u53ef\u80fd\u53d7\u5230\u9650\u5236')
$CAT_BLOCKED     = [regex]::Unescape('\u78ba\u8a8d\u6709\u660e\u78ba\u5c01\u9396\u56de\u61c9')
$CAT_INSUFF      = [regex]::Unescape('\u8b49\u64da\u4e0d\u8db3')

function Test-TcpPortTimed([string]$HostOrIp, [int]$Port, [int]$WaitMs) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($HostOrIp, $Port, $null, $null)
        $signaled = $iar.AsyncWaitHandle.WaitOne($WaitMs, $false)
        if (-not $signaled) {
            $sw.Stop()
            $client.Close()
            return @{ ok = $false; rtt_ms = $sw.Elapsed.TotalMilliseconds; error = "Timeout" }
        }
        $client.EndConnect($iar)
        $sw.Stop()
        $client.Close()
        return @{ ok = $true; rtt_ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 2); error = "" }
    } catch {
        $sw.Stop()
        $errMsg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        try { $client.Close() } catch {}
        return @{ ok = $false; rtt_ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 2); error = $errMsg }
    }
}

function Test-TlsInspection([string]$TargetHost, [int]$Port, [int]$WaitMs) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($WaitMs, $false)) {
            $client.Close()
            return @{ ok = $false; error = "TCP Timeout before TLS"; issuer = ""; subject = ""; protocol = ""; chain_valid = $false }
        }
        $client.EndConnect($iar)
        $client.ReceiveTimeout = $WaitMs
        $client.SendTimeout = $WaitMs

        $script:tlsPolicyErrors = "None"
        $cb = [System.Net.Security.RemoteCertificateValidationCallback]{
            param($sender, $cert, $chain, $errors)
            $script:tlsPolicyErrors = [string]$errors
            return $true
        }
        $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false, $cb)
        $ssl.AuthenticateAsClient($TargetHost)
        $remoteCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $res = @{
            ok           = ($script:tlsPolicyErrors -eq "None")
            policy_error = $script:tlsPolicyErrors
            protocol     = [string]$ssl.SslProtocol
            subject      = [string]$remoteCert.Subject
            issuer       = [string]$remoteCert.Issuer
            not_after    = $remoteCert.NotAfter.ToString("o")
            error        = if ($script:tlsPolicyErrors -eq "None") { "" } else { "CertPolicyError: " + $script:tlsPolicyErrors }
        }
        $ssl.Close()
        $client.Close()
        return $res
    } catch {
        $errMsg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        try { $client.Close() } catch {}
        return @{ ok = $false; error = $errMsg; issuer = ""; subject = ""; protocol = ""; policy_error = "HandshakeFailed" }
    }
}

function Invoke-SafeHttpCheck([string]$Url, [string]$Method, [int]$WaitMs) {
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
    } catch {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = $Method
        $req.Timeout = $WaitMs
        $req.ReadWriteTimeout = $WaitMs
        $req.AllowAutoRedirect = $false
        $req.UserAgent = "CampusNetDiag/1.0 (Windows NT; ReadOnly-LowLoad)"
        $resp = [System.Net.HttpWebResponse]$req.GetResponse()
        $sw.Stop()
        $code = [int]$resp.StatusCode
        $loc = [string]$resp.Headers["Location"]
        $via = [string]$resp.Headers["Via"]
        $srv = [string]$resp.Headers["Server"]
        $ctype = [string]$resp.ContentType
        $clen = [int64]$resp.ContentLength
        $resp.Close()
        return @{
            ok = $true; status_code = $code; latency_ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            location = $loc; via = $via; server = $srv; content_type = $ctype; content_length = $clen; error = ""
        }
    } catch [System.Net.WebException] {
        $sw.Stop()
        $wresp = $_.Exception.Response
        if ($wresp -is [System.Net.HttpWebResponse]) {
            $code = [int]$wresp.StatusCode
            $loc = [string]$wresp.Headers["Location"]
            $via = [string]$wresp.Headers["Via"]
            $srv = [string]$wresp.Headers["Server"]
            $ctype = [string]$wresp.ContentType
            $wresp.Close()
            return @{
                ok = $false; status_code = $code; latency_ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
                location = $loc; via = $via; server = $srv; content_type = $ctype; content_length = -1; error = $_.Exception.Message
            }
        }
        return @{
            ok = $false; status_code = 0; latency_ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            location = ""; via = ""; server = ""; content_type = ""; content_length = -1; error = $_.Exception.Message
        }
    } catch {
        $sw.Stop()
        return @{
            ok = $false; status_code = 0; latency_ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            location = ""; via = ""; server = ""; content_type = ""; content_length = -1; error = $_.Exception.Message
        }
    }
}

$rawCfg = [System.IO.File]::ReadAllText($TargetsPath, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
$probeCount = 3
if ($rawCfg.metadata -and $rawCfg.metadata.low_load_policy -and $rawCfg.metadata.low_load_policy.tcp_probe_count) {
    $probeCount = [int]$rawCfg.metadata.low_load_policy.tcp_probe_count
}

# A. Website Checks
$websiteResults = @()
foreach ($w in $rawCfg.websites) {
    $uri = [System.Uri]$w.url
    $hostName = $uri.Host
    $port = if ($w.port) { [int]$w.port } elseif ($uri.Port -gt 0) { $uri.Port } else { 443 }

    # 1. DNS
    $dnsSw = [System.Diagnostics.Stopwatch]::StartNew()
    $dnsOk = $false
    $ips = @()
    $dnsErr = ""
    try {
        $recs = Resolve-DnsName -Name $hostName -Type A -ErrorAction Stop | Where-Object { $_.IPAddress }
        $dnsSw.Stop()
        foreach ($r in $recs) { $ips += [string]$r.IPAddress }
        $dnsOk = ($ips.Count -gt 0)
    } catch {
        $dnsSw.Stop()
        $dnsErr = $_.Exception.Message
    }

    # 2. TCP (multiple low-rate probes)
    $tcpSamples = @()
    $tcpSuccess = 0
    if ($dnsOk) {
        for ($i = 0; $i -lt $probeCount; $i++) {
            $t = Test-TcpPortTimed -HostOrIp $ips[0] -Port $port -WaitMs $TimeoutMs
            $tcpSamples += $t
            if ($t.ok) { $tcpSuccess++ }
            if ($i -lt ($probeCount - 1)) { Start-Sleep -Milliseconds 350 }
        }
    }
    $intermittent = ($tcpSuccess -gt 0 -and $tcpSuccess -lt $probeCount)
    $avgTcpMs = $null
    $okRtts = @($tcpSamples | Where-Object { $_.ok } | ForEach-Object { $_.rtt_ms })
    if ($okRtts.Count -gt 0) {
        $avgTcpMs = [math]::Round((($okRtts | Measure-Object -Average).Average), 2)
    }

    # 3. TLS
    $tlsInfo = @{ ok = $false; error = "Skipped"; issuer = ""; subject = ""; protocol = "" }
    if ($tcpSuccess -gt 0 -and $uri.Scheme -ieq "https") {
        $tlsInfo = Test-TlsInspection -TargetHost $hostName -Port $port -WaitMs $TimeoutMs
    }

    # 4. HTTP
    $httpInfo = @{ ok = $false; status_code = 0; error = "Skipped" }
    if ($tcpSuccess -gt 0) {
        $httpInfo = Invoke-SafeHttpCheck -Url $w.url -Method "HEAD" -WaitMs $TimeoutMs
        if ($httpInfo.status_code -in @(403, 405) -or $httpInfo.status_code -eq 0) {
            Start-Sleep -Milliseconds 200
            $httpGet = Invoke-SafeHttpCheck -Url $w.url -Method "GET" -WaitMs $TimeoutMs
            if ($httpGet.status_code -gt 0) { $httpInfo = $httpGet }
        }
    }

    # Evidence-based classification
    $classification = $CAT_INSUFF
    $reason = ""
    $mitmSuspected = ($tlsInfo.issuer -match '(?i)(Fortinet|FortiGate|Palo Alto|Zscaler|SonicWall|Sophos|Sangfor|Check Point|BlueCoat|Untrusted)')
    $explicitBlockRedirect = ($httpInfo.location -match '(?i)(block|fortiguard|captive|portal|auth|deny)')

    if (-not $dnsOk) {
        $classification = $CAT_FAIL
        $reason = "DNS resolution failed: " + $dnsErr
    } elseif ($tcpSuccess -eq 0) {
        $classification = $CAT_FAIL
        $reason = "TCP connection failed across all probes"
    } elseif ($httpInfo.status_code -eq 451 -or $explicitBlockRedirect -or $mitmSuspected) {
        $classification = $CAT_BLOCKED
        $reason = "Explicit policy block / SSL inspection / captive redirect indicator detected"
    } elseif ($intermittent -or (-not $tlsInfo.ok -and $uri.Scheme -ieq "https")) {
        $classification = $CAT_RESTRICTED
        $reason = "Intermittent TCP loss or TLS validation anomaly requiring verification"
    } elseif ($httpInfo.status_code -ge 200 -and $httpInfo.status_code -lt 400) {
        $classification = $CAT_OK
        $reason = "DNS, TCP, TLS, and HTTP status normal"
    } elseif ($httpInfo.status_code -eq 403) {
        $classification = $CAT_INSUFF
        $reason = "HTTP 403 returned (may be WAF/User-Agent policy rather than campus block)"
    } else {
        $classification = $CAT_INSUFF
        $reason = "HTTP status " + $httpInfo.status_code + "; insufficient evidence for block"
    }

    $websiteResults += [ordered]@{
        id               = $w.id
        name             = $w.name
        url              = $w.url
        dns_ok           = $dnsOk
        dns_latency_ms   = [math]::Round($dnsSw.Elapsed.TotalMilliseconds, 2)
        resolved_ips     = $ips
        tcp_success_rate = if ($dnsOk) { "$tcpSuccess/$probeCount" } else { "0/0" }
        tcp_avg_rtt_ms   = $avgTcpMs
        intermittent     = $intermittent
        tls              = $tlsInfo
        http             = $httpInfo
        classification   = $classification
        evidence_summary = $reason
    }
}

# B. Application Checks
$appResults = @()
$fwRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
$allFwValues = @()
if (Test-Path $fwRegPath) {
    $props = (Get-Item -Path $fwRegPath -ErrorAction SilentlyContinue).Property
    foreach ($p in $props) {
        $allFwValues += [string](Get-ItemPropertyValue -Path $fwRegPath -Name $p -ErrorAction SilentlyContinue)
    }
}

foreach ($app in $rawCfg.applications) {
    $foundExe = ""
    foreach ($h in $app.exe_hints) {
        if (Test-Path $h) { $foundExe = $h; break }
    }

    $runProcs = @()
    foreach ($pn in $app.process_names) {
        $ps = Get-Process -Name $pn -ErrorAction SilentlyContinue
        foreach ($pr in $ps) {
            $runProcs += $pr
            if ([string]::IsNullOrWhiteSpace($foundExe) -and $pr.Path) { $foundExe = $pr.Path }
        }
    }

    $installed = (-not [string]::IsNullOrWhiteSpace($foundExe) -and (Test-Path $foundExe))
    $fileVer = ""
    $sigStat = "NotChecked"
    $signer = ""
    if ($installed) {
        $fi = Get-Item $foundExe
        $fileVer = [string]$fi.VersionInfo.FileVersion
        $sig = Get-AuthenticodeSignature -FilePath $foundExe -ErrorAction SilentlyContinue
        if ($sig) {
            $sigStat = [string]$sig.Status
            if ($sig.SignerCertificate) { $signer = [string]$sig.SignerCertificate.Subject }
        }
    }

    $fwAllow = 0
    $fwBlock = 0
    if ($installed) {
        $escapedExe = [regex]::Escape($foundExe)
        foreach ($fv in $allFwValues) {
            if ($fv -match $escapedExe) {
                if ($fv -match 'Action=Block' -and $fv -match 'Active=TRUE') { $fwBlock++ }
                elseif ($fv -match 'Action=Allow' -and $fv -match 'Active=TRUE') { $fwAllow++ }
            }
        }
    }

    $activeTcpCount = 0
    if ($runProcs.Count -gt 0) {
        $pids = @($runProcs | ForEach-Object { [int]$_.Id })
        $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
            $pids -contains [int]$_.OwningProcess -and $_.RemoteAddress -notin @("0.0.0.0", "::", "127.0.0.1", "::1")
        }
        $activeTcpCount = @($conns).Count
    }

    $appClass = $CAT_INSUFF
    $appNote = ""
    if (-not $installed) {
        $appClass = $CAT_INSUFF
        $appNote = "Executable not found on local disk"
    } elseif ($fwBlock -gt 0) {
        $appClass = $CAT_BLOCKED
        $appNote = "Active Windows Firewall Block rule found targeting executable"
    } elseif ($runProcs.Count -eq 0) {
        # Rule: Do NOT classify non-running applications as restricted
        $appClass = $CAT_INSUFF
        $appNote = "Application installed and signed, but currently NOT running; cannot classify live connectivity as restricted"
    } elseif ($activeTcpCount -gt 0) {
        $appClass = $CAT_OK
        $appNote = "Application running with active external TCP connections"
    } else {
        $appClass = $CAT_INSUFF
        $appNote = "Application process running without current external TCP sockets (may be at login screen)"
    }

    $appResults += [ordered]@{
        id                  = $app.id
        name                = $app.name
        installed           = $installed
        executable_path     = $foundExe
        file_version        = $fileVer
        signature_status    = $sigStat
        signer              = $signer
        is_running          = ($runProcs.Count -gt 0)
        running_pids        = @($runProcs | ForEach-Object { [int]$_.Id })
        firewall_allow_rules = $fwAllow
        firewall_block_rules = $fwBlock
        active_tcp_count    = $activeTcpCount
        classification      = $appClass
        evidence_summary    = $appNote
    }
}

# C. Download Restriction Checks (HEAD only, zero payload download)
$downloadResults = @()
foreach ($dl in $rawCfg.downloads) {
    $baseResp = Invoke-SafeHttpCheck -Url $dl.base_site_url -Method "HEAD" -WaitMs $TimeoutMs
    if ($baseResp.status_code -eq 405 -or $baseResp.status_code -eq 0) {
        $baseResp = Invoke-SafeHttpCheck -Url $dl.base_site_url -Method "GET" -WaitMs $TimeoutMs
    }
    $dlResp = Invoke-SafeHttpCheck -Url $dl.url -Method "HEAD" -WaitMs $TimeoutMs

    $dlClass = $CAT_INSUFF
    $dlReason = ""
    $isBlockRedirect = ($dlResp.location -match '(?i)(block|fortiguard|captive|deny|virus|filter)')

    if ($dlResp.status_code -eq 451 -or $isBlockRedirect) {
        $dlClass = $CAT_BLOCKED
        $dlReason = "Explicit HTTP 451 or firewall block redirect on download URL"
    } elseif ($dlResp.status_code -ge 200 -and $dlResp.status_code -lt 400) {
        $dlClass = $CAT_OK
        $dlReason = "HEAD request succeeded without file-type blocking"
    } elseif ($baseResp.status_code -ge 200 -and $baseResp.status_code -lt 400 -and $dlResp.status_code -eq 0) {
        $dlClass = $CAT_RESTRICTED
        $dlReason = "Base site reachable, but download endpoint connection dropped/timed out"
    } elseif ($dlResp.status_code -eq 403) {
        $dlClass = $CAT_INSUFF
        $dlReason = "HTTP 403 on HEAD (could be origin server ACL or file filter; requires header/body verification)"
    } elseif ($dlResp.status_code -eq 404) {
        $dlClass = $CAT_INSUFF
        $dlReason = "HTTP 404 from origin server (server reachable, file path not present)"
    } else {
        $dlClass = $CAT_FAIL
        $dlReason = "Both base site and download endpoint failed: " + $dlResp.error
    }

    $downloadResults += [ordered]@{
        id                  = $dl.id
        name                = $dl.name
        url                 = $dl.url
        file_type           = $dl.file_type
        method_used         = "HEAD"
        base_site_status    = $baseResp.status_code
        download_status     = $dlResp.status_code
        latency_ms          = $dlResp.latency_ms
        redirect_location   = $dlResp.location
        content_type        = $dlResp.content_type
        content_length      = $dlResp.content_length
        via_header          = $dlResp.via
        classification      = $dlClass
        evidence_summary    = $dlReason
    }
}

$maskedTargetsSource = $TargetsPath
if ($env:USERNAME) {
    $maskedTargetsSource = $maskedTargetsSource -ireplace [regex]::Escape($env:USERNAME), "<USER>"
}

$finalOut = [ordered]@{
    schema_version = "1.0"
    checked_at     = (Get-Date).ToString("o")
    targets_source = $maskedTargetsSource
    websites       = $websiteResults
    applications   = $appResults
    downloads      = $downloadResults
}

$outDir = Split-Path -Parent $OutputPath
if (-not [string]::IsNullOrWhiteSpace($outDir) -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
$jsonText = $finalOut | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($OutputPath, $jsonText, (New-Object System.Text.UTF8Encoding($false)))

Write-Output ("OK: Restriction check saved to " + $OutputPath)

