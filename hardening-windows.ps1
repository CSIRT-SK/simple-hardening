# Helper functions
# -----------------------------------------------------------------------------

function Write-Host-Nice(
    [String] $text, 
    [String] $hlineSeed = "-"
) {
    $hline = $hlineSeed * $text.length
    Write-Host $text
    Write-Host $hline $outputFilePrefix
}

function Read-User-Decision(
    [String] $question

) {
    $decision = Read-Host $question
    $decision
}

function Invoke-Named-Operation(
    [String] $operationInfo,
    [scriptblock] $operation
) {
    Write-Host $operationInfo
    $operation.Invoke()
}

function Invoke-User-Decision(
    [String] $question,
    [scriptblock] $onYes,
    [scriptblock] $onNo = $null
) {
    $decision = 'yes'
    $correctDecision = $true
    do {

        $decision = Read-User-Decision "$($question) (Yes (default)/No)"
        if ($null -eq $decision) {
            $decision = 'yes'
            break
        }
        $decision = $decision.toLower()
        $correctDecision = ($decision -eq 'yes' -or $decision -eq 'y' -or $decision -eq 'no' -or $decision -eq 'no')
        if (-Not $correctDecision) {
            Write-Host 'Incorect option passed, repeat your decision'   
        }
    } while ($decision -ne 'yes' -and $decision -ne 'y' -and $decision -ne 'no' -and $decision -ne 'n')

    If ($decision -eq 'y' -Or $decision -eq 'yes') {
        $onYes.Invoke()
    }
    Else {
        If ($null -ne $onNo) {
            $onNo.Invoke()
        }
    }    
    
}

# Program functions
# -----------------------------------------------------------------------------

function Set-Maximum-UAC {
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $Name = "ConsentPromptBehaviorAdmin"
    $value = "2"

    IF (!(Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name $name -Value $value `
            -PropertyType DWORD -Force | Out-Null
    }
    ELSE {
        New-ItemProperty -Path $registryPath -Name $name -Value $value `
            -PropertyType DWORD -Force | Out-Null
    }

    $Name = "PromptOnSecureDesktop"
    $value = "1"

    IF (!(Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name $name -Value $value `
            -PropertyType DWORD -Force | Out-Null
    }
    ELSE {
        New-ItemProperty -Path $registryPath -Name $name -Value $value `
            -PropertyType DWORD -Force | Out-Null
    }
}

function Set-Up-Firewall-Profile {
    Get-NetConnectionProfile -NetworkCategory Private | Set-NetConnectionProfile -NetworkCategory
}

function Disable-Non-Essential-Network-Protocols {
    $netAdapters = Get-NetAdapter | Select-Object -ExpandProperty "InterfaceAlias"
    for ($i = 0; $i -lt $netAdapters.Length; $i++) {
        Disable-NetAdapterBinding -Name $netAdapters[$i] -ComponentID ms_rspndr
        Disable-NetAdapterBinding -Name $netAdapters[$i] -ComponentID ms_implat
        Disable-NetAdapterBinding -Name $netAdapters[$i] -ComponentID ms_lldp
        Disable-NetAdapterBinding -Name $netAdapters[$i] -ComponentID ms_tcpip6
        Disable-NetAdapterBinding -Name $netAdapters[$i] -ComponentID ms_lltdio
        Disable-NetAdapterBinding -Name $netAdapters[$i] -ComponentID ms_pacer
        Disable-NetAdapterBinding -Name $netAdapters[$i] -ComponentID ms_msclient
    }
    
    $adapter = (Get-WmiObject -computer $env:computername win32_networkadapterconfiguration)
    for ($i = 0; $i -lt $adapter.Length; $i++) {
        $adapter[$i].settcpipnetbios(2)
    }

    Get-NetAdapter | Set-DNSClient –RegisterThisConnectionsAddress $False
}

function Disable-Network-Printer-Protocols {
    $netAdapters = Get-NetAdapter | Select-Object -ExpandProperty "InterfaceAlias"
    for ($i = 0; $i -lt $netAdapters.Length; $i++) {
        Disable-NetAdapterBinding -Name $netAdapters[$i] -ComponentID ms_server
    }
    
    $adapter = (Get-WmiObject -computer $env:computername win32_networkadapterconfiguration)
    for ($i = 0; $i -lt $adapter.Length; $i++) {
        $adapter[$i].settcpipnetbios(2)
    }

    Get-NetAdapter | Set-DNSClient –RegisterThisConnectionsAddress $False
}

function Disable-IPv6 {
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    $Name = "DisabledComponents"
    $value = "255"

    IF (!(Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name $name -Value $value `
            -PropertyType DWORD -Force | Out-Null
    }
    ELSE {
        New-ItemProperty -Path $registryPath -Name $name -Value $value `
            -PropertyType DWORD -Force | Out-Null
    }
}

function Disable-Unused-Network-Devices {
    # Disable 'remote Desktop Device Redirector Bus'
    $RDDRB = (Get-CimInstance Win32_PNPEntity | Where-Object caption -match 'Remote Desktop Device Redirector Bus').PNPDeviceID 
    $ppid = "{0}{1}" -f '@', $RDDRB

    try {
        $Disable | Where-Object { $_ -match "Disabled" } 
        Write-Warning "Device 'remote Desktop Device Redirector Bus' has been disabled via current script" 
    } 
    Catch {
        Write-Warning -Message $_.Exception.message 
    }

    # Disable 'Microsoft Kernel Debug Network Adapter'
    $MKDNA = (Get-CimInstance Win32_PNPEntity | Where-Object caption -match 'Microsoft Kernel Debug Network Adapter').PNPDeviceID
    $ppid2 = "{0}{1}" -f '@', $MKDNA

    try {
        $Disable2 | Where-Object { $_ -match "Disabled" } 
        Write-Warning "Device 'Microsoft Kernel Debug Network Adapter' has been disabled via current script" 
    } 
    Catch {
        Write-Warning -Message $_.Exception.message 
    }
}

function Disable-IGMP {
    Netsh interface ipv4 set global mldlevel=none
}

function Disable-UPnP {
    $registryPath = "HKLM:\Software\Microsoft\DirectplayNATHelp\DPNHUPnP"
    $Name = "UPnPMode"
    $value = "2"

    IF (!(Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name $name -Value $value `
            -PropertyType DWORD -Force | Out-Null
    }
    ELSE {
        New-ItemProperty -Path $registryPath -Name $name -Value $value `
            -PropertyType DWORD -Force | Out-Null
    }
}

function Disable-SMBv1 {
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
}

function Disable-Remote-Assistance {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 1
}

function Expand-Windows-Logs {
    Limit-EventLog -LogName Application -MaximumSize 1000000KB
    Limit-EventLog -LogName Security -MaximumSize 1000000KB
    Limit-EventLog -LogName System -MaximumSize 1000000KB
}

function Disable-Non-Essential-Services {
    $services = @(
        # Services Considered To Have Spying Capabilities
        "DcpSvc"                                   # Data Collection and Publishing Service
        "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
        "DiagTrack"                                # Diagnostics Tracking Service
        "SensrSvc"                                 # Monitors Various Sensors
        "dmwappushservice"                         # WAP Push Message Routing Service
        "lfsvc"                                    # Geolocation Service
        "MapsBroker"                               # Downloaded Maps Manager
        "NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
        "RemoteAccess"                             # Routing and Remote Access
        "RemoteRegistry"                           # Remote Registry
        "SharedAccess"                             # Internet Connection Sharing (ICS)
        "TrkWks"                                   # Distributed Link Tracking Client
        "WbioSrvc"                                 # Windows Biometric Service
        "WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
        "WSearch"                                  # Windows Search
        # Gaming Based Services
        "XblAuthManager"                           # Xbox Live Auth Manager
        "XblGameSave"                              # Xbox Live Game Save Service
        "XboxNetApiSvc"                            # Xbox Live Networking Service
        # Windows HomeGroup Services
        "HomeGroupListener"                        # HomeGroup Listener
        "HomeGroupProvider"                        # HomeGroup Provider
        # Other Optional
        #"bthserv"                                 # Bluetooth Support Service
        #"wscsvc"                                  # Security Center Service
        #"WlanSvc"                                 # WLAN AutoConfig
        "OneSyncSvc"                               # Sync Host Service
        "AeLookupSvc"                              # Application Experience Service
        "PcaSvc"                                   # Program Compatibility Assistant
        "WinHttpAutoProxySvc"                      # WinHTTP Web Proxy Auto-Discovery
        "UPNPHOST"                                 # Universal Plug & Play Host
        "ERSVC"                                    # Error Reporting Service
        "WERSVC"                                   # Windows Error Reporting Service
        "SSDPSRV"                                  # SSDP Discovery Service
        "CDPSvc"                                   # Connected Devices Platform Service
        "DsSvc"                                    # Data Sharing Service
        "DcpSvc"                                   # Data Collection and Publishing Service
        "lfsvc"                                    # Geolocation service
    )

    foreach ($service in $services) {
        if ( Get-Service "$service*" -Include $service ) {
            Write-Output " Disabling Service $service ..."
            Get-Service -Name $service | Stop-Service -Force
            Get-Service -Name $service | Set-Service -StartupType Disabled
        }
    } 
}

function Disable-Qos-Packet-Scheduler {
    try {
        if (Get-NetAdapterBinding -name "Ethernet*" -DisplayName "QoS Packet Scheduler" -OutVariable LANConnection) {
            Disable-NetAdapterBinding -name $LANConnection.name -DisplayName $LANConnection.displayname
            Write-Warning "$($LANConnection.displayname) was set to disabled on Network Adapter $($LANConnection.name)" 
        }
        Else 
        { Write-Warning "Cannot find Ethernet Adapter" }
    }
    catch {  
        Write-Warning -Message $_.Exception.message
    }
}

# Main entry
# -----------------------------------------------------------------------------

#(Get-Item "${function:OnYes}").ScriptBlock.StartPosition


# Every invocation of Invoke-User-Decision will ask the user if (s)he wants to perform it
Invoke-User-Decision 'Set UAC to maximum?' ${function:Set-Maximum-UAC}
Invoke-User-Decision 'Set up firewall profile?' ${function:Set-Up-Firewall-Profile}
Invoke-User-Decision 'Disable non essential network protocols?' ${function:Disable-Non-Essential-Network-Protocols}
Invoke-User-Decision 'Disable network printers?' ${function:Disable-Network-Printer-Protocols}
Invoke-User-Decision 'Disable IPv6?' ${function:Disable-IPv6}
Invoke-User-Decision 'Disable unused network devices?' ${function:Disable-Unused-Network-Devices}
Invoke-User-Decision 'Disable IGMP?' ${function:Disable-IGMP}
Invoke-User-Decision 'Disable UPnP?' ${function:Disable-UPnP}
Invoke-User-Decision 'Disable SMBv1?' ${function:Disable-SMBv1}
Invoke-User-Decision 'Disable Remote Assistance?' ${function:Disable-Remote-Assistance}
Invoke-User-Decision 'Expand Windows logs?' ${function:Expand-Windows-Logs}
Invoke-User-Decision 'Disable non essential system services?' ${function:Disable-Non-Essential-Services}
Invoke-User-Decision 'Disable Qos packet scheduler' ${function:Disable-Qos-Packet-Scheduler}
