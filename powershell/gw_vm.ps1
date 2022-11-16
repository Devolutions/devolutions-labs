. .\common.ps1

$VMAlias = "GW"
$VMNumber = 7
$VMName = $LabPrefix, $VMAlias -Join "-"
$IpAddress = Get-DLabIpAddress $LabNetworkBase $VMNumber

New-DLabVM $VMName -Password $LocalPassword -OSVersion $OSVersion -Force
Start-DLabVM $VMName

Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $LocalUserName -Password $LocalPassword
$VMSession = New-DLabVMSession $VMName -UserName $LocalUserName -Password $LocalPassword

Set-DLabVMNetAdapter $VMName -VMSession $VMSession `
    -SwitchName $SwitchName -NetAdapterName $NetAdapterName `
    -IPAddress $IPAddress -DefaultGateway $DefaultGateway `
    -DnsServerAddress $DnsServerAddress

Write-Host "Joining domain"

Add-DLabVMToDomain $VMName -VMSession $VMSession `
    -DomainName $DomainName -DomainController $DCHostName `
    -UserName $DomainUserName -Password $DomainPassword

# Wait for virtual machine to reboot after domain join operation

Wait-DLabVM $VMName 'Reboot' -Timeout 120
Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $DomainUserName -Password $DomainPassword

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

Write-Host "Requesting RDP server certificate"

Request-DLabRdpCertificate $VMName -VMSession $VMSession `
    -CAHostName $CAHostName -CACommonName $CACommonName

Write-Host "Initializing PSRemoting"

Initialize-DLabPSRemoting $VMName -VMSession $VMSession

Write-Host "Initializing VNC server"

Initialize-DLabVncServer $VMName -VMSession $VMSession

# Install Remote Desktop Gateway

Write-Host "Installing RD Gateway, RD Web Access and RD Connection Broker"

Invoke-Command -ScriptBlock {
    @('RDS-Gateway',
    'RDS-Web-Access',
    'RDS-Licensing',
    'RDS-Licensing-UI',
    'RDS-Connection-Broker',
    'RSAT-RDS-Tools',
    'RSAT-RDS-Gateway'
    ) | ForEach-Object { Install-WindowsFeature -Name $_ | Out-Null }
} -Session $VMSession

Write-Host "Creating default RD CAP and RD RAP"

Invoke-Command -ScriptBlock {
    Import-Module RemoteDesktopServices
    $UserGroups = @("Administrators@BUILTIN", "Remote Desktop Users@BUILTIN")
    New-Item -Path RDS:\GatewayServer\CAP -Name "RD-CAP" -UserGroups $UserGroups -AuthMethod 1
    New-Item -Path RDS:\GatewayServer\RAP -Name "RD-RAP" -UserGroups $UserGroups -ComputerGroupType 2
} -Session $VMSession

$DnsName = "rdg"
$RdgHostName = "$DnsName.$DomainName"
$CertificateFile = "~\Documents\rdg-cert.pfx"
$CertificatePassword = "cert123!"

Write-Host "Creating new DNS record for RD Gateway"

Invoke-Command -ScriptBlock { Param($DnsName, $DnsZoneName, $IPAddress, $DnsServer)
    Install-WindowsFeature RSAT-DNS-Server | Out-Null
    Add-DnsServerResourceRecordA -Name $DnsName -ZoneName $DnsZoneName -IPv4Address $IPAddress -AllowUpdateAny -ComputerName $DnsServer
} -Session $VMSession -ArgumentList @($DnsName, $DomainName, $IPAddress, $DCHostName)

Write-Host "Requesting new certificate for RD Gateway"

Request-DLabCertificate $VMName -VMSession $VMSession `
    -CommonName $RdgHostName `
    -CAHostName $CAHostName -CACommonName $CACommonName `
    -CertificateFile $CertificateFile -Password $CertificatePassword

Write-Host "Installing RD Session Host"

Invoke-Command -ScriptBlock {
    Install-WindowsFeature -Name RDS-RD-Server | Out-Null
    Restart-Computer -Force
} -Session $VMSession

Write-Host "Rebooting VM"

Wait-DLabVM $VMName 'Reboot' -Timeout 120
Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $DomainUserName -Password $DomainPassword
$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

# Create new RD session deployment

$GWMachineName = "$VMName.$DomainName"
$ConnectionBroker = $GWMachineName
$SessionHost = $GWMachineName
$WebAccessServer = $GWMachineName
$GatewayExternalFQDN = $RdgHostName

Invoke-Command -ScriptBlock { Param($ConnectionBroker, $SessionHost, $WebAccessServer, $GatewayExternalFQDN)
    $Params = @{
        ConnectionBroker = $ConnectionBroker;
        SessionHost = $SessionHost;
        WebAccessServer = $WebAccessServer;
    }
    New-RDSessionDeployment @Params

    Add-RDServer -Server $ConnectionBroker -Role RDS-Licensing `
        -ConnectionBroker $ConnectionBroker

    Add-RDServer -Server $WebAccessServer -Role RDS-Gateway `
        -ConnectionBroker $ConnectionBroker -GatewayExternalFqdn $GatewayExternalFQDN
} -Session $VMSession -ArgumentList @($ConnectionBroker, $SessionHost, $WebAccessServer, $GatewayExternalFQDN)

Write-Host "Configuring RD Gateway certificate"

Invoke-Command -ScriptBlock { Param($CertificateFile, $CertificatePassword)
    Import-Module RemoteDesktopServices
    $CertificatePassword = ConvertTo-SecureString $CertificatePassword -AsPlainText -Force
    $Params = @{
        FilePath          = $CertificateFile;
        CertStoreLocation = "cert:\LocalMachine\My";
        Password          = $CertificatePassword;
        Exportable        = $true;
    }
    $Certificate = Import-PfxCertificate @Params
    Set-Item "RDS:\GatewayServer\SSLCertificate\Thumbprint" -Value $Certificate.Thumbprint
    Restart-Service TSGateway
} -Session $VMSession -ArgumentList @($CertificateFile, $CertificatePassword)

Write-Host "Creating RD session collection"

$CollectionName = "Session Collection"
$CollectionDescription = "Default Session Collection"

Invoke-Command -ScriptBlock { Param($ConnectionBroker, $SessionHost, $CollectionName, $CollectionDescription)
    $Params = @{
        CollectionName = $CollectionName;
        CollectionDescription = $CollectionDescription;
        SessionHost = @($SessionHost);
        ConnectionBroker = $ConnectionBroker;
    }
    New-RDSessionCollection @Params

    $Params = @{
        DisplayName    = "Notepad";
        FilePath       = "C:\Windows\System32\Notepad.exe";
        CollectionName = $CollectionName;
    }
    New-RDRemoteApp @Params

    $Params = @{
        DisplayName    = "Windows Explorer";
        FilePath       = "C:\Windows\explorer.exe";
        CollectionName = $CollectionName;
    }
    New-RDRemoteApp @Params

    $Params = @{
        DisplayName    = "Windows PowerShell";
        FilePath       = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        CollectionName = $CollectionName;
    }
    New-RDRemoteApp @Params

    $Params = @{
        DisplayName    = "PowerShell 7";
        FilePath       = "C:\Program Files\PowerShell\7\pwsh.exe";
        CollectionName = $CollectionName;
    }
    New-RDRemoteApp @Params

    $CAMachineName = $Env:ComputerName -Replace "-GW", "-DC"
    $Params = @{
        DisplayName    = "DNS Manager";
        FilePath       = "C:\Windows\System32\dnsmgmt.msc";
        IconPath       = "C:\Windows\System32\dnsmgr.dll";
        CommandLineSetting = "Allow";
        RequiredCommandLine = "/ComputerName $CAMachineName";
        CollectionName = $CollectionName;
    }
    New-RDRemoteApp @Params

    $CollectionName = "Session Collection"
    $TransformedName = $CollectionName -Replace " ", "_"
    $FarmsRegPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\CentralPublishedResources\PublishedFarms"
    $FarmRegName = Get-ChildItem $FarmsRegPath |
        Where-Object { $TransformedName.StartsWith($_.PSChildName) } |
        Select-Object -ExpandProperty PSChildName

    Set-ItemProperty -Path "$FarmsRegPath\$FarmRegName\RemoteDesktops\$FarmRegName" -Name "Name" -Value "Remote Desktop"
    Set-ItemProperty -Path "$FarmsRegPath\$FarmRegName\RemoteDesktops\$FarmRegName" -Name "ShowInPortal" -Value 1 -Type DWORD

} -Session $VMSession -ArgumentList @($ConnectionBroker, $SessionHost, $CollectionName, $CollectionDescription)

Write-Host "Installing RD Web Client"

Invoke-Command -ScriptBlock { Param($ConnectionBroker, $CertificateFile, $CertificatePassword)
    Import-Module RemoteDesktopServices
    $Thumbprint = $(Get-Item "RDS:\GatewayServer\SSLCertificate\Thumbprint").CurrentValue
    @('RDGateway', 'RDWebAccess', 'RDPublishing', 'RDRedirector') | ForEach-Object {
        Set-RDCertificate -Role $_ -Thumbprint $Thumbprint `
            -ConnectionBroker $ConnectionBroker -Force
    }
    Install-Module RDWebClientManagement -Force -AcceptLicense
    Install-RDWebClientPackage
    $CertificateFile = Resolve-Path $CertificateFile
    $CertificatePassword = ConvertTo-SecureString $CertificatePassword -AsPlainText -Force
    Import-RDWebClientBrokerCert -Path $CertificateFile -Password $CertificatePassword
    Publish-RDWebClientPackage -Type Production -Latest
} -Session $VMSession -ArgumentList @($ConnectionBroker, $CertificateFile, $CertificatePassword)

Write-Host "Creating DNS record for Devolutions Gateway"

$DnsName = "gateway"
$DGatewayFQDN = "$DnsName.$DomainName"
$CertificateFile = "~\Documents\gateway-cert.pfx"
$CertificatePassword = "cert123!"

Invoke-Command -ScriptBlock { Param($DnsName, $DnsZoneName, $IPAddress, $DnsServer)
    Add-DnsServerResourceRecordA -Name $DnsName -ZoneName $DnsZoneName -IPv4Address $IPAddress -AllowUpdateAny -ComputerName $DnsServer
} -Session $VMSession -ArgumentList @($DnsName, $DomainName, $IPAddress, $DCHostName)

Write-Host "Requesting certificate for Devolutions Gateway"

Request-DLabCertificate $VMName -VMSession $VMSession `
    -CommonName $DGatewayFQDN `
    -CAHostName $CAHostName -CACommonName $CACommonName `
    -CertificateFile $CertificateFile -Password $CertificatePassword

Write-Host "Installing Devolutions Gateway"

Invoke-Command -ScriptBlock {
    Install-Module -Name DevolutionsGateway -Force
    Import-Module DevolutionsGateway
    Install-DGatewayPackage
} -Session $VMSession

Write-Host "Configuring Devolutions Gateway"

Invoke-Command -ScriptBlock { Param($DGatewayFQDN, $CertificateFile, $CertificatePassword)
    Import-Module DevolutionsGateway
    Import-DGatewayCertificate -CertificateFile $CertificateFile -Password $CertificatePassword
    Set-DGatewayHostname $DGatewayFQDN

    Set-DGatewayListeners @(
        $(New-DGatewayListener 'https://*:7171' 'https://*:7171'),
        $(New-DGatewayListener 'tcp://*:8181' 'tcp://*:8181'))

    Set-Service 'DevolutionsGateway' -StartupType 'Automatic'
    Start-Service 'DevolutionsGateway'
} -Session $VMSession -ArgumentList @($DGatewayFQDN, $CertificateFile, $CertificatePassword)

Write-Host "Creating DNS record for KDC Proxy"

$DnsName = "kdc"
$KdcPort = "4343"
$KdcFQDN = "$DnsName.$DomainName"
$CertificateFile = "~\Documents\kdc-cert.pfx"
$CertificatePassword = "cert123!"

Invoke-Command -ScriptBlock { Param($DnsName, $DnsZoneName, $IPAddress, $DnsServer)
    Add-DnsServerResourceRecordA -Name $DnsName -ZoneName $DnsZoneName -IPv4Address $IPAddress -AllowUpdateAny -ComputerName $DnsServer
} -Session $VMSession -ArgumentList @($DnsName, $DomainName, $IPAddress, $DCHostName)

Write-Host "Requesting certificate for KDC Proxy"

Request-DLabCertificate $VMName -VMSession $VMSession `
    -CommonName $KdcFQDN `
    -CAHostName $CAHostName -CACommonName $CACommonName `
    -CertificateFile $CertificateFile -Password $CertificatePassword

Write-Host "Importing certificate for KDC Proxy"

Invoke-Command -ScriptBlock { Param($CertificateFile, $CertificatePassword)
    $CertificatePassword = ConvertTo-SecureString $CertificatePassword -AsPlainText -Force
    $Params = @{
        FilePath          = $CertificateFile;
        CertStoreLocation = "cert:\LocalMachine\My";
        Password          = $CertificatePassword;
        Exportable        = $true;
    }
    $Certificate = Import-PfxCertificate @Params
} -Session $VMSession -ArgumentList @($CertificateFile, $CertificatePassword)

Write-Host "Configuring KDC Proxy"

Invoke-Command -ScriptBlock { Param($KdcFQDN, $KdcPort)
    $Certificate = Get-ChildItem -Path "cert:\LocalMachine\My" | `
        Where-Object { $_.Subject -Like "*$KdcFQDN*" } | Select-Object -First 1

    $CertHash = $Certificate.Thumbprint
    $AppId = [Guid]::NewGuid().ToString("B")
    
    & "netsh" "http" "add" "urlacl" "url=https://+:$KdcPort/KdcProxy" 'user="NT AUTHORITY\Network Service"'
    & "netsh" "http" "add" "sslcert" "hostnameport=$KdcFQDN`:$KdcPort" "certhash=$CertHash" "appid=$AppId" "certstorename=MY"

    $KpsSvcSettingsReg = "HKLM:\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings"
    New-ItemProperty -Path $KpsSvcSettingsReg -Name "HttpsClientAuth" -Type DWORD -Value 0 -Force
    New-ItemProperty -Path $KpsSvcSettingsReg -Name "DisallowUnprotectedPasswordAuth" -Type DWORD -Value 0 -Force
    New-ItemProperty -Path $KpsSvcSettingsReg -Name "HttpsUrlGroup" -Type MultiString -Value "+`:$KdcPort" -Force

    Set-Service -Name KPSSVC -StartupType Automatic
    Start-Service -Name KPSSVC

    New-NetFirewallRule -DisplayName "Allow KDCProxy TCP $KdcPort" -Direction Inbound -Protocol TCP -LocalPort $KdcPort
} -Session $VMSession -ArgumentList @($KdcFQDN, $KdcPort)
