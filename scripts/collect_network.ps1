[CmdletBinding()]
param(
    [string]$OutputPath = "",
    [string]$MarkdownPath = "",
    [int]$EventLookbackHours = 24
)

$ErrorActionPreference = "Continue"
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ProjectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ProjectRoot "reports\network_environment.json"
}
if ([string]::IsNullOrWhiteSpace($MarkdownPath)) {
    $MarkdownPath = Join-Path $ProjectRoot "reports\network_environment.md"
}

$WellKnownPublicIps = @(
    "8.8.8.8", "8.8.4.4",
    "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112",
    "168.95.1.1", "168.95.192.1",
    "208.67.222.222", "208.67.220.220"
)

function Mask-Username([string]$Val) {
    if ([string]::IsNullOrWhiteSpace($Val)) { return "" }
    if ($Val.Length -le 2) { return "user_***" }
    return ($Val.Substring(0, 1) + "***" + $Val.Substring($Val.Length - 1, 1))
}

function Mask-Hostname([string]$Val) {
    if ([string]::IsNullOrWhiteSpace($Val)) { return "" }
    if ($Val.Length -le 4) { return "HOST-***" }
    return ($Val.Substring(0, 3) + "***" + $Val.Substring($Val.Length - 2, 2))
}

function Mask-Mac([string]$Val) {
    if ([string]::IsNullOrWhiteSpace($Val)) { return "" }
    $clean = $Val.Trim()
    if ($clean -match '^([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})([:-][0-9A-Fa-f]{2}){3}$') {
        $sep = if ($clean.Contains(":")) { ":" } else { "-" }
        return ($Matches[1] + $sep + "xx" + $sep + "xx" + $sep + "xx")
    }
    return "xx:xx:xx:xx:xx:xx"
}

function Classify-IPv4([string]$Ip) {
    if ([string]::IsNullOrWhiteSpace($Ip)) { return "Unknown" }
    if ($Ip -in $WellKnownPublicIps) { return "Public_WellKnown_DNS" }
    if ($Ip -match '^127\.') { return "Loopback" }
    if ($Ip -match '^169\.254\.') { return "APIPA_LinkLocal" }
    if ($Ip -match '^10\.') { return "Private_RFC1918_ClassA" }
    if ($Ip -match '^192\.168\.') { return "Private_RFC1918_ClassC" }
    if ($Ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') {
        if ($Ip -match '^172\.20\.10\.') { return "Private_Hotspot_iOS_Candidate" }
        return "Private_RFC1918_ClassB"
    }
    if ($Ip -match '^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.') { return "CGNAT_RFC6598_Carrier_Or_Campus" }
    if ($Ip -match '^140\.(109|11[0-9]|12[0-9]|13[0-8])\.' -or
        $Ip -match '^163\.(1[3-9]|2[0-9]|3[0-2])\.' -or
        $Ip -match '^120\.(9[6-9]|1[0-1][0-9]|12[0-7])\.') {
        return "TANet_Taiwan_Academic_IPv4"
    }
    return "Public_IPv4"
}

function Mask-Ip([string]$Ip, [bool]$AllowWellKnown = $true) {
    if ([string]::IsNullOrWhiteSpace($Ip)) { return "" }
    $trimIp = $Ip.Trim()
    if ($AllowWellKnown -and ($trimIp -in $WellKnownPublicIps)) {
        return $trimIp
    }
    if ($trimIp -eq "0.0.0.0" -or $trimIp -eq "::" -or $trimIp -eq "255.255.255.255") {
        return $trimIp
    }
    if ($trimIp -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(/\d+)?$') {
        $o1 = $Matches[1]
        $o2 = $Matches[2]
        $cidr = if ($Matches[5]) { $Matches[5] } else { "" }
        return "$o1.$o2.xxx.xxx$cidr"
    }
    if ($trimIp.Contains(":")) {
        $parts = $trimIp.Split(":")
        if ($parts.Count -ge 2) {
            return ($parts[0] + ":" + $parts[1] + ":xxxx:xxxx::xxxx")
        }
        return "xxxx:xxxx::xxxx"
    }
    return $trimIp
}

function Mask-Ssid([string]$Ssid) {
    if ([string]::IsNullOrWhiteSpace($Ssid)) { return "" }
    $s = $Ssid.Trim()
    if ($s.Length -le 3) { return ($s.Substring(0, 1) + "***") }
    return ($s.Substring(0, 3) + "***")
}

function Mask-FreeText([string]$Text) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
    $res = $Text
    if ($env:USERNAME) {
        $res = $res -ireplace [regex]::Escape($env:USERNAME), "<USER>"
    }
    if ($env:COMPUTERNAME) {
        $res = $res -ireplace [regex]::Escape($env:COMPUTERNAME), "<HOST>"
    }
    $res = [regex]::Replace($res, '\b(?!0\.0\.0\.0|255\.255\.255\.0|127\.0\.0\.1)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b', {
        param($m)
        $full = $m.Value
        if ($full -in $WellKnownPublicIps) { return $full }
        return ($m.Groups[1].Value + "." + $m.Groups[2].Value + ".xxx.xxx")
    })
    $res = [regex]::Replace($res, '\b([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})([:-][0-9A-Fa-f]{2}){3}\b', '$1:xx:xx:xx')
    return $res
}

function Prefix-ToSubnetMask([int]$PrefixLength) {
    if ($PrefixLength -lt 0 -or $PrefixLength -gt 32) { return "" }
    if ($PrefixLength -eq 0) { return "0.0.0.0" }
    $maskLong = ([int64]4294967295 -shl (32 - $PrefixLength)) -band [int64]4294967295
    $b1 = ($maskLong -shr 24) -band 255
    $b2 = ($maskLong -shr 16) -band 255
    $b3 = ($maskLong -shr 8) -band 255
    $b4 = $maskLong -band 255
    return "$b1.$b2.$b3.$b4"
}

$isElevated = $false
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}

# 1. OS & System Info
$osInfo = @{}
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $cv = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
    $powerScheme = ""
    try {
        $pOut = & powercfg /getactivescheme 2>$null
        if ($pOut) { $powerScheme = ($pOut -join " ").Trim() }
    } catch {}
    $osInfo = [ordered]@{
        caption          = [string]$os.Caption
        version          = [string]$os.Version
        display_version  = [string]$cv.DisplayVersion
        build_number     = [string]$os.BuildNumber
        ubr              = $cv.UBR
        architecture     = [string]$os.OSArchitecture
        last_boot_time   = if ($os.LastBootUpTime) { $os.LastBootUpTime.ToString("o") } else { "" }
        masked_hostname  = Mask-Hostname $env:COMPUTERNAME
        masked_username  = Mask-Username $env:USERNAME
        is_elevated      = $isElevated
        active_power_plan = Mask-FreeText $powerScheme
    }
} catch {
    $osInfo = [ordered]@{ error = $_.Exception.Message; is_elevated = $isElevated }
}

# 2-5. Network Adapters, IP Configuration, Gateways, DNS
$adaptersList = @()
$ipConfigsList = @()
$dnsServersSummary = @()
$primaryConnectionType = "Disconnected"
$primaryInterfaceAlias = ""
$primaryInterfaceIndex = -1

try {
    $netAdapters = Get-NetAdapter -ErrorAction SilentlyContinue
    $powerMgmtMap = @{}
    try {
        $pmSettings = Get-CimInstance -Namespace "root/StandardCimv2" -ClassName "MSFT_NetAdapterPowerManagementSettingData" -ErrorAction SilentlyContinue
        foreach ($pm in $pmSettings) {
            $powerMgmtMap[$pm.Name] = [ordered]@{
                allow_computer_to_turn_off = $pm.AllowComputerToTurnOffDevice
                wake_on_magic_packet       = $pm.WakeOnMagicPacket
            }
        }
    } catch {}

    foreach ($na in $netAdapters) {
        $drvDate = ""
        if ($na.DriverDate) { $drvDate = [string]$na.DriverDate }
        $adaptersList += [ordered]@{
            name                = [string]$na.Name
            interface_index     = [int]$na.InterfaceIndex
            description         = [string]$na.InterfaceDescription
            status              = [string]$na.Status
            link_speed          = [string]$na.LinkSpeed
            media_type          = [string]$na.MediaType
            physical_media_type = [string]$na.PhysicalMediaType
            driver_version      = [string]$na.DriverVersionString
            driver_date         = $drvDate
            mac_address_masked  = Mask-Mac ([string]$na.MacAddress)
            is_virtual          = [bool]$na.Virtual
            power_management    = if ($powerMgmtMap.ContainsKey($na.Name)) { $powerMgmtMap[$na.Name] } else { $null }
        }
    }

    $netConfigs = Get-NetIPConfiguration -ErrorAction SilentlyContinue
    $bestMetric = 999999
    foreach ($cfg in $netConfigs) {
        if ($null -eq $cfg.NetAdapter -or $cfg.NetAdapter.Status -ne "Up") { continue }

        $ipv4List = @()
        foreach ($ip4 in $cfg.IPv4Address) {
            $ipv4List += [ordered]@{
                ip_masked      = Mask-Ip $ip4.IPAddress $false
                ip_class       = Classify-IPv4 $ip4.IPAddress
                prefix_length  = [int]$ip4.PrefixLength
                subnet_mask    = Prefix-ToSubnetMask ([int]$ip4.PrefixLength)
            }
        }

        $ipv6Count = 0
        if ($cfg.IPv6Address) { $ipv6Count = @($cfg.IPv6Address).Count }

        $gw4 = @()
        $ifaceMetric = 999999
        foreach ($g in $cfg.IPv4DefaultGateway) {
            if ($g.NextHop) {
                $gw4 += [ordered]@{
                    next_hop_masked = Mask-Ip $g.NextHop $false
                    next_hop_class  = Classify-IPv4 $g.NextHop
                    route_metric    = $g.RouteMetric
                }
                $m = [int]$g.RouteMetric + [int]$cfg.NetIPv4Interface.InterfaceMetric
                if ($m -lt $ifaceMetric) { $ifaceMetric = $m }
            }
        }

        $dnsEntries = @()
        foreach ($d in $cfg.DnsServer) {
            foreach ($addr in $d.ServerAddresses) {
                $isPublicDns = $addr -in $WellKnownPublicIps
                $dnsEntries += [ordered]@{
                    address_masked = Mask-Ip $addr $true
                    address_class  = Classify-IPv4 $addr
                    is_public_well_known = $isPublicDns
                    address_family = [string]$d.AddressFamily
                }
                $dnsServersSummary += [ordered]@{
                    interface_alias = [string]$cfg.InterfaceAlias
                    address_masked  = Mask-Ip $addr $true
                    address_class   = Classify-IPv4 $addr
                    is_public_well_known = $isPublicDns
                }
            }
        }

        $pmType = [string]$cfg.NetAdapter.PhysicalMediaType
        $mType = [string]$cfg.NetAdapter.MediaType
        $desc = [string]$cfg.InterfaceDescription
        $alias = [string]$cfg.InterfaceAlias
        $connMedium = "Other"
        if ($pmType -match '802\.11|Wireless|Native 802\.11' -or $mType -match '802\.11' -or $alias -match 'Wi-Fi|WLAN') {
            $connMedium = "Wi-Fi"
        } elseif ($desc -match 'Remote NDIS|Apple Mobile|Android|WWAN|Cellular') {
            $connMedium = "Mobile_Tethering_USB_Or_WWAN"
        } elseif ($pmType -match '802\.3' -or $mType -match '802\.3' -or $alias -match 'Ethernet|\u4e59\u592a\u7db2\u8def') {
            $connMedium = "Ethernet"
        }

        if ($gw4.Count -gt 0 -and $ifaceMetric -lt $bestMetric) {
            $bestMetric = $ifaceMetric
            $primaryConnectionType = $connMedium
            $primaryInterfaceAlias = $alias
            $primaryInterfaceIndex = [int]$cfg.InterfaceIndex
        }

        $ipConfigsList += [ordered]@{
            interface_alias       = $alias
            interface_index       = [int]$cfg.InterfaceIndex
            interface_description = $desc
            connection_medium     = $connMedium
            net_profile_category  = if ($cfg.NetProfile) { [string]$cfg.NetProfile.NetworkCategory } else { "Unknown" }
            ipv4_addresses        = $ipv4List
            ipv6_address_count    = $ipv6Count
            ipv4_gateways         = $gw4
            dns_servers           = $dnsEntries
        }
    }
} catch {}

# 9A. Wi-Fi Signal & Interface details via netsh wlan
$wifiInfo = [ordered]@{
    applicable = ($primaryConnectionType -eq "Wi-Fi")
    connected  = $false
    details    = @{}
}
try {
    $wlanLines = & netsh wlan show interfaces 2>$null
    if ($wlanLines) {
        $rawText = $wlanLines -join "`n"
        $signalMatch = [regex]::Match($rawText, '(\d{1,3})\s*%')
        $bssidMatch = [regex]::Match($rawText, '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')
        $radioMatch = [regex]::Match($rawText, '802\.11[a-zA-Z0-9/]+')
        $authMatch = [regex]::Match($rawText, '(WPA3-[^\r\n]+|WPA2-[^\r\n]+|WPA-[^\r\n]+|802\.1[xX][^\r\n]*|Open|\u958b\u653e\u5f0f)')

        $ssidVal = ""
        $channelVal = ""
        $rxRate = ""
        $txRate = ""
        foreach ($ln in $wlanLines) {
            if ($ln -match '^\s*SSID\s*:\s*(.+)$') {
                $ssidVal = $Matches[1].Trim()
            } elseif ($ln -match '(?i)(Channel|\u983b\u9053)\s*:\s*(\d+)') {
                $channelVal = $Matches[2].Trim()
            } elseif ($ln -match '(?i)(Receive rate|\u63a5\u6536\u901f\u7387)[^:]*:\s*([\d\.]+)') {
                $rxRate = $Matches[2].Trim()
            } elseif ($ln -match '(?i)(Transmit rate|\u50b3\u8f38\u901f\u7387)[^:]*:\s*([\d\.]+)') {
                $txRate = $Matches[2].Trim()
            }
        }

        if ($signalMatch.Success -or -not [string]::IsNullOrWhiteSpace($ssidVal)) {
            $wifiInfo.applicable = $true
            $wifiInfo.connected = $true
            $sigPct = if ($signalMatch.Success) { [int]$signalMatch.Groups[1].Value } else { $null }
            $authStr = if ($authMatch.Success) { $authMatch.Groups[1].Value.Trim() } else { "Unknown" }
            $isEnterprise8021x = ($authStr -match '(?i)Enterprise|\u4f01\u696d|802\.1x')
            $wifiInfo.details = [ordered]@{
                ssid_masked        = Mask-Ssid $ssidVal
                bssid_masked       = if ($bssidMatch.Success) { Mask-Mac $bssidMatch.Value } else { "" }
                signal_percent     = $sigPct
                radio_type         = if ($radioMatch.Success) { $radioMatch.Value } else { "" }
                channel            = $channelVal
                rx_rate_mbps       = $rxRate
                tx_rate_mbps       = $txRate
                authentication     = $authStr
                is_8021x_enterprise = $isEnterprise8021x
            }
        }
    }
} catch {}

# 6. Windows Firewall Status & KGI-related Rules (Read-Only, fast registry + profile lookup)
$firewallInfo = [ordered]@{
    profiles               = @()
    outbound_block_count   = 0
    kgi_related_rules      = @()
}
try {
    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    foreach ($p in $profiles) {
        $firewallInfo.profiles += [ordered]@{
            name                    = [string]$p.Name
            enabled                 = [bool]$p.Enabled
            default_inbound_action  = [string]$p.DefaultInboundAction
            default_outbound_action = [string]$p.DefaultOutboundAction
        }
    }

    $kgiPat = [regex]::Unescape('(SUPERTSC|axis\.exe|VELOTRDER|TKAP3083|\bKGI\b|kgieworld|\u8d85\u7d1a\u5927\u4e09\u5143|\u51f1\u57fa)')
    $fwRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
    if (Test-Path $fwRegPath) {
        $regProps = (Get-Item -Path $fwRegPath -ErrorAction SilentlyContinue).Property
        $outBlockCnt = 0
        $matchedRules = @()
        foreach ($propName in $regProps) {
            $val = [string](Get-ItemPropertyValue -Path $fwRegPath -Name $propName -ErrorAction SilentlyContinue)
            if ($val -match 'Dir=Out' -and $val -match 'Action=Block' -and $val -match 'Active=TRUE') {
                $outBlockCnt++
            }
            if ($val -match $kgiPat) {
                $matchedRules += [ordered]@{
                    rule_id = $propName
                    raw_summary = Mask-FreeText $val
                }
            }
        }
        $firewallInfo.outbound_block_count = $outBlockCnt
        $firewallInfo.kgi_related_rules = $matchedRules
    }
} catch {}

# 7. Proxy Settings (WinINET, WinHTTP, PAC, Env Vars)
$proxyInfo = [ordered]@{
    wininet_proxy_enabled = $false
    wininet_proxy_server  = ""
    wininet_pac_url       = ""
    wininet_auto_detect   = $false
    winhttp_raw           = ""
    winhttp_direct_access = $true
    env_proxies           = @{}
}
try {
    $ieKey = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
    if ($ieKey) {
        $proxyInfo.wininet_proxy_enabled = ([int]$ieKey.ProxyEnable -eq 1)
        $proxyInfo.wininet_proxy_server = Mask-FreeText ([string]$ieKey.ProxyServer)
        $proxyInfo.wininet_pac_url = Mask-FreeText ([string]$ieKey.AutoConfigURL)
        if ($null -ne $ieKey.AutoDetect) {
            $proxyInfo.wininet_auto_detect = ([int]$ieKey.AutoDetect -eq 1)
        }
    }
    $winhttpOut = (& netsh winhttp show proxy 2>$null) -join " "
    $proxyInfo.winhttp_raw = Mask-FreeText ($winhttpOut.Trim())
    $proxyInfo.winhttp_direct_access = ($winhttpOut -match '(?i)Direct access|\u76f4\u63a5\u5b58\u53d6')

    $envMap = @{}
    foreach ($ev in @("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy")) {
        $v = [Environment]::GetEnvironmentVariable($ev)
        if (-not [string]::IsNullOrWhiteSpace($v)) {
            $envMap[$ev] = Mask-FreeText $v
        }
    }
    $proxyInfo.env_proxies = $envMap
} catch {}

# 8. Routing Table & Target Route Verification
$routingInfo = [ordered]@{
    default_routes = @()
    target_route_checks = @()
}
try {
    $defRoutes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Sort-Object RouteMetric
    foreach ($r in $defRoutes) {
        $routingInfo.default_routes += [ordered]@{
            interface_alias  = [string]$r.InterfaceAlias
            interface_index  = [int]$r.InterfaceIndex
            destination      = [string]$r.DestinationPrefix
            next_hop_masked  = Mask-Ip $r.NextHop $false
            route_metric     = [int]$r.RouteMetric
            interface_metric = [int]$r.InterfaceMetric
        }
    }

    $probeTargets = @(
        @{ label = "Public_DNS_8.8.8.8"; host = "8.8.8.8"; ip = "8.8.8.8" },
        @{ label = "KGI_Quote_gtsquot.kgieworld.com.tw"; host = "gtsquot.kgieworld.com.tw"; ip = "" },
        @{ label = "KGI_Trade_gtstrade.kgieworld.com.tw"; host = "gtstrade.kgieworld.com.tw"; ip = "" }
    )
    foreach ($pt in $probeTargets) {
        $targetIp = $pt.ip
        if ([string]::IsNullOrWhiteSpace($targetIp)) {
            try {
                $dnsRes = Resolve-DnsName -Name $pt.host -Type A -DnsOnly -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1
                if ($dnsRes) { $targetIp = [string]$dnsRes.IPAddress }
            } catch {}
        }
        if (-not [string]::IsNullOrWhiteSpace($targetIp)) {
            try {
                $frAll = @(Find-NetRoute -RemoteIPAddress $targetIp -ErrorAction Stop)
                $frIpObj = $frAll | Where-Object { $_.IPAddress } | Select-Object -First 1
                $frRouteObj = $frAll | Where-Object { $_.NextHop } | Select-Object -First 1
                $ifaceAlias = if ($frRouteObj -and $frRouteObj.InterfaceAlias) { [string]$frRouteObj.InterfaceAlias } elseif ($frIpObj) { [string]$frIpObj.InterfaceAlias } else { "" }
                $routingInfo.target_route_checks += [ordered]@{
                    label            = $pt.label
                    target_host      = $pt.host
                    resolved_ip      = $targetIp
                    interface_alias  = $ifaceAlias
                    next_hop_masked  = if ($frRouteObj) { Mask-Ip ([string]$frRouteObj.NextHop) $false } else { "" }
                    local_ip_masked  = if ($frIpObj) { Mask-Ip ([string]$frIpObj.IPAddress) $false } else { "" }
                }
            } catch {
                $routingInfo.target_route_checks += [ordered]@{
                    label       = $pt.label
                    target_host = $pt.host
                    resolved_ip = $targetIp
                    error       = $_.Exception.Message
                }
            }
        } else {
            $routingInfo.target_route_checks += [ordered]@{
                label       = $pt.label
                target_host = $pt.host
                resolved_ip = ""
                error       = "DNS resolution unavailable during route check"
            }
        }
    }
} catch {}

# 9B. System Network / Wi-Fi / Sleep Event Logs (Last N Hours, Read-Only)
$cutoffTime = (Get-Date).AddHours(-1 * $EventLookbackHours)
$recentEvents = [ordered]@{
    lookback_hours        = $EventLookbackHours
    wlan_events           = @()
    network_profile_events = @()
    dns_client_timeouts   = @()
    power_sleep_events    = @()
}

try {
    $wlanEvs = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-WLAN-AutoConfig/Operational"
        StartTime = $cutoffTime
    } -MaxEvents 25 -ErrorAction SilentlyContinue
    foreach ($ev in $wlanEvs) {
        if ($ev.Id -in @(8001, 8002, 8003, 11000, 11001, 11002, 11004, 11005, 11006, 11010)) {
            $recentEvents.wlan_events += [ordered]@{
                time    = $ev.TimeCreated.ToString("o")
                id      = [int]$ev.Id
                level   = [string]$ev.LevelDisplayName
                message = Mask-FreeText (($ev.Message -split "`r?`n")[0])
            }
        }
    }
} catch {}

try {
    $npEvs = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-NetworkProfile/Operational"
        StartTime = $cutoffTime
    } -MaxEvents 20 -ErrorAction SilentlyContinue
    foreach ($ev in $npEvs) {
        if ($ev.Id -in @(10000, 10001)) {
            $recentEvents.network_profile_events += [ordered]@{
                time    = $ev.TimeCreated.ToString("o")
                id      = [int]$ev.Id
                type    = if ($ev.Id -eq 10000) { "Network_Connected" } else { "Network_Disconnected" }
                message = Mask-FreeText (($ev.Message -split "`r?`n")[0])
            }
        }
    }
} catch {}

try {
    $dnsEvs = Get-WinEvent -FilterHashtable @{
        LogName      = "System"
        ProviderName = "Microsoft-Windows-DNS-Client"
        Id           = 1014
        StartTime    = $cutoffTime
    } -MaxEvents 15 -ErrorAction SilentlyContinue
    foreach ($ev in $dnsEvs) {
        $recentEvents.dns_client_timeouts += [ordered]@{
            time    = $ev.TimeCreated.ToString("o")
            id      = [int]$ev.Id
            message = Mask-FreeText (($ev.Message -split "`r?`n")[0])
        }
    }
} catch {}

try {
    $pwrEvs = Get-WinEvent -FilterHashtable @{
        LogName      = "System"
        ProviderName = "Microsoft-Windows-Kernel-Power"
        StartTime    = $cutoffTime
    } -MaxEvents 15 -ErrorAction SilentlyContinue
    foreach ($ev in $pwrEvs) {
        if ($ev.Id -in @(42, 107, 506, 507)) {
            $recentEvents.power_sleep_events += [ordered]@{
                time    = $ev.TimeCreated.ToString("o")
                id      = [int]$ev.Id
                message = Mask-FreeText (($ev.Message -split "`r?`n")[0])
            }
        }
    }
} catch {}

# 10. VPN, Campus Auth, Endpoint Security
$vpnAndAuth = [ordered]@{
    configured_vpn_profiles = @()
    virtual_vpn_adapters    = @()
    running_vpn_or_proxy_processes = @()
    wired_8021x_service_running = $false
    ncsi_active_probing_enabled = $true
    security_products       = @()
    environment_inference   = ""
}
try {
    $vpns = Get-VpnConnection -ErrorAction SilentlyContinue
    foreach ($v in $vpns) {
        $vpnAndAuth.configured_vpn_profiles += [ordered]@{
            name              = Mask-FreeText ([string]$v.Name)
            connection_status = [string]$v.ConnectionStatus
            tunnel_type       = [string]$v.TunnelType
            split_tunneling   = [bool]$v.SplitTunneling
        }
    }

    foreach ($ad in $adaptersList) {
        if ($ad.description -match '(?i)(VPN|TAP|TUN|WireGuard|Tailscale|ZeroTier|Cisco AnyConnect|Fortinet|PangP|GlobalProtect|Juniper|Pulse|Wintun)' -or
            $ad.name -match '(?i)(VPN|WireGuard|Tailscale|ZeroTier)') {
            $vpnAndAuth.virtual_vpn_adapters += [ordered]@{
                name        = $ad.name
                description = $ad.description
                status      = $ad.status
            }
        }
    }

    $vpnProcRegex = '^(clash|mihomo|v2ray|xray|sing-box|tailscaled|wireguard|openvpn|vpnui|FortiClient|FortiTray|PanGPA|Pulse|zerotier)'
    $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match $vpnProcRegex }
    foreach ($pr in $procs) {
        $vpnAndAuth.running_vpn_or_proxy_processes += [string]$pr.ProcessName
    }

    $dot3 = Get-Service -Name "dot3svc" -ErrorAction SilentlyContinue
    if ($dot3 -and $dot3.Status -eq "Running") {
        $vpnAndAuth.wired_8021x_service_running = $true
    }

    $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" -ErrorAction SilentlyContinue
    if ($nla -and $null -ne $nla.EnableActiveProbing) {
        $vpnAndAuth.ncsi_active_probing_enabled = ([int]$nla.EnableActiveProbing -eq 1)
    }

    $avs = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction SilentlyContinue
    foreach ($av in $avs) {
        $vpnAndAuth.security_products += [ordered]@{
            type         = "AntiVirus"
            display_name = [string]$av.displayName
            product_state = $av.productState
        }
    }
    $fws = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "FirewallProduct" -ErrorAction SilentlyContinue
    foreach ($fw in $fws) {
        $vpnAndAuth.security_products += [ordered]@{
            type         = "ThirdPartyFirewall"
            display_name = [string]$fw.displayName
            product_state = $fw.productState
        }
    }

    # Passive local network environment inference (no subnet scanning)
    $hasTanetIp = ($ipConfigsList | ForEach-Object { $_.ipv4_addresses } | Where-Object { $_.ip_class -eq "TANet_Taiwan_Academic_IPv4" })
    $hasTanetDns = ($dnsServersSummary | Where-Object { $_.address_class -eq "TANet_Taiwan_Academic_IPv4" })
    $hasHotspotHint = ($ipConfigsList | ForEach-Object { $_.ipv4_addresses } | Where-Object { $_.ip_class -eq "Private_Hotspot_iOS_Candidate" }) -or ($primaryConnectionType -eq "Mobile_Tethering_USB_Or_WWAN")
    if ($hasTanetIp -or $hasTanetDns -or $wifiInfo.details.is_8021x_enterprise) {
        $vpnAndAuth.environment_inference = "Campus_TANet_Or_Enterprise_Network"
    } elseif ($hasHotspotHint) {
        $vpnAndAuth.environment_inference = "Mobile_Hotspot_Candidate"
    } elseif ($primaryConnectionType -ne "Disconnected") {
        $vpnAndAuth.environment_inference = "NAT_Private_Or_Campus_LAN"
    } else {
        $vpnAndAuth.environment_inference = "Disconnected"
    }
} catch {}

$result = [ordered]@{
    schema_version           = "1.0"
    collected_at             = (Get-Date).ToString("o")
    mode                     = "read_only_local_inspection"
    os_and_system            = $osInfo
    primary_connection       = [ordered]@{
        connection_type      = $primaryConnectionType
        interface_alias      = $primaryInterfaceAlias
        interface_index      = $primaryInterfaceIndex
        environment_hint     = $vpnAndAuth.environment_inference
    }
    active_ip_configurations = $ipConfigsList
    dns_servers              = $dnsServersSummary
    network_adapters         = $adaptersList
    windows_firewall         = $firewallInfo
    proxy_settings           = $proxyInfo
    routing                  = $routingInfo
    wifi_diagnostics         = $wifiInfo
    recent_network_events    = $recentEvents
    vpn_auth_and_security    = $vpnAndAuth
}

$outDir = Split-Path -Parent $OutputPath
if (-not [string]::IsNullOrWhiteSpace($outDir) -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$jsonText = $result | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($OutputPath, $jsonText, (New-Object System.Text.UTF8Encoding($false)))

Write-Output ("OK: Network environment saved to " + $OutputPath)
