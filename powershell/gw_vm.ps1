
. .\common.ps1

$VMAlias = "GW"
$VMNumber = 7
$VMName = $LabPrefix, $VMAlias -Join "-"
$IpAddress = Get-DLabIpAddress $LabNetworkBase $VMNumber

New-DLabVM $VMName -Password $Password -Force
Start-DLabVM $VMName

Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $UserName -Password $Password
$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Set-DLabVMNetAdapter $VMName -VMSession $VMSession `
    -SwitchName $SwitchName -NetAdapterName $NetAdapterName `
    -IPAddress $IPAddress -DefaultGateway $DefaultGateway `
    -DnsServerAddress $DnsServerAddress

# Join virtual machine to domain

Add-DLabVMToDomain $VMName -VMSession $VMSession `
    -DomainName $DomainName -DomainController $DCHostName `
    -UserName $DomainUserName -Password $DomainPassword

# Wait for virtual machine to reboot after domain join operation

Wait-DLabVM $VMName 'Reboot' -Timeout 120
Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $DomainUserName -Password $DomainPassword

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

# Install Remote Desktop Gateway

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

Invoke-Command -ScriptBlock {
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

# Install RD Session Host (should normally be on a different machine)

Invoke-Command -ScriptBlock {
    Install-WindowsFeature -Name RDS-RD-Server | Out-Null
    Restart-Computer -Force
} -Session $VMSession

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
        $WebAccessServer = $WebAccessServer;
    }
    New-RDSessionDeployment @Params

    Add-RDServer -Server $SessionHost -Role RDS-RD-SERVER `
        -ConnectionBroker $ConnectionBroker
 
    Add-RDServer -Server $ConnectionBroker -Role RDS-Licensing `
        -ConnectionBroker $ConnectionBroker
    
    Add-RDServer -Server $WebAccessServer -Role RDS-Gateway `
        -ConnectionBroker $ConnectionBroker -GatewayExternalFqdn $GatewayExternalFQDN
} -Session $VMSession -ArgumentList @($ConnectionBroker, $SessionHost, $WebAccessServer, $GatewayExternalFQDN)

Write-Host "Configure RD Gateway certificate"

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

# Create new RD Session Collection

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

} -Session $VMSession -ArgumentList @($ConnectionBroker, $SessionHost, $CollectionName, $CollectionDescription)

# Install RD Web Client (HTML5)

Invoke-Command -ScriptBlock {
    Install-Module -Name RDWebClientManagement -Force
    Install-RDWebClientPackage
} -Session $VMSession
