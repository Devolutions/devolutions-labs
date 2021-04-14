
Import-Module .\DevolutionsLabs.psm1 -Force

# common variable definitions

$UserName = "Administrator"
$Password = "yolo123!"

$SwitchName = "LAN Switch"
$NetAdapterName = "vEthernet (LAN)"
$DefaultGateway = "10.10.0.1"

$WaykRealm = "it-yolo.ninja"
$DomainName = "ad.it-yolo.ninja"
$DomainNetbiosName = "IT-YOLO"
$SafeModeAdministratorPassword = "SafeMode123!"

$DomainUserName = "$DomainNetbiosName\Administrator"
$DomainPassword = $Password

# IT-YOLO-DC

$VMName = "IT-YOLO-DC"
$IPAddress = "10.10.0.110"

$DnsServerAddress = $IPAddress
$DnsServerForwarder = "1.1.1.1"

New-DLabVM $VMName -Password $Password -Force
Start-VM $VMName
Wait-VM $VMName -For IPAddress -Timeout 60

$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Set-DLabVMNetAdapter $VMName -VMSession $VMSession `
    -SwitchName $SwitchName -NetAdapterName $NetAdapterName `
    -IPAddress $IPAddress -DefaultGateway $DefaultGateway `
    -DnsServerAddress $DnsServerForwarder

Invoke-Command -ScriptBlock { Param($DomainName, $DomainNetbiosName, $SafeModeAdministratorPassword)
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    $SafeModeAdministratorPassword = ConvertTo-SecureString $SafeModeAdministratorPassword -AsPlainText -Force
    Install-ADDSForest -DomainName $DomainName -DomainNetbiosName $DomainNetbiosName -InstallDNS `
        -SafeModeAdministratorPassword $SafeModeAdministratorPassword -Force
} -Session $VMSession -ArgumentList @($DomainName, $DomainNetbiosName, $SafeModeAdministratorPassword)

# wait a good 5-10 minutes for the domain controller promotion to complete

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

# IT-YOLO-CA

$VMName = "IT-YOLO-CA"
$IPAddress = "10.10.0.111"

New-DLabVM $VMName -Password $Password -Force
Start-VM $VMName
Wait-VM $VMName -For IPAddress -Timeout 60

$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Set-DLabVMNetAdapter $VMName -VMSession $VMSession `
    -SwitchName $SwitchName -NetAdapterName $NetAdapterName `
    -IPAddress $IPAddress -DefaultGateway $DefaultGateway `
    -DnsServerAddress $DnsServerAddress

# Join virtual machine to domain

Add-DLabVMToDomain $VMName -VMSession $VMSession `
    -DomainName $DomainName -UserName $DomainUserName -Password $DomainPassword

# Wait for virtual machine to reboot after domain join operation

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

# Install Active Directory Certificate Services

Invoke-Command -ScriptBlock { Param($DomainName, $UserName, $Password)
    $ConfirmPreference = "High"
    Install-WindowsFeature -Name AD-Certificate -IncludeManagementTools
    $Params = @{
        CAType = "EnterpriseRootCa";
        CryptoProviderName = "RSA#Microsoft Software Key Storage Provider";
        HashAlgorithmName = "SHA256";
        KeyLength = 2048;
    }
    Install-AdcsCertificationAuthority @Params -Force
} -Session $VMSession -ArgumentList @($DomainName, $DomainUserName, $DomainPassword)

# IT-YOLO-WAYK

$VMName = "IT-YOLO-WAYK"
$IPAddress = "10.10.0.112"

New-DLabVM $VMName -Password $Password -Force
Start-VM $VMName
Wait-VM $VMName -For IPAddress -Timeout 60

$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Set-DLabVMNetAdapter $VMName -VMSession $VMSession `
    -SwitchName $SwitchName -NetAdapterName $NetAdapterName `
    -IPAddress $IPAddress -DefaultGateway $DefaultGateway `
    -DnsServerAddress $DnsServerAddress

Add-DLabVMToDomain $VMName -VMSession $VMSession `
    -DomainName $DomainName -UserName $DomainUserName -Password $DomainPassword

# Wait for virtual machine to reboot after domain join operation

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

Invoke-Command -ScriptBlock {
    Install-WindowsFeature -Name Containers
    Install-Module -Name DockerMsftProvider -Force
    Install-Package -Name docker -ProviderName DockerMsftProvider -Force
} -Session $VMSession

Restart-VM $VMName -Force

Invoke-Command -ScriptBlock {
    choco install -y mongodb
    choco install -y mongodb-compass
    choco install -y mongodb-database-tools
} -Session $VMSession

Invoke-Command -ScriptBlock { Param($WaykRealm)
    Install-Module WaykBastion -Scope AllUsers -Force
    Import-Module -Name WaykBastion
    $Params = @{
        Realm = $WaykRealm;
        ListenerUrl = "http://localhost:4000";
        ExternalUrl = "http://localhost:4000";
    }
    New-WaykBastionConfig @Params
} -Session $VMSession -ArgumentList @($WaykRealm)

# prefetch Windows container images (takes a while)

Invoke-Command -ScriptBlock {
    Import-Module -Name WaykBastion
    Update-WaykBastionImage
} -Session $VMSession

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

# IT-YOLO-DVLS

$VMName = "IT-YOLO-DVLS"
$IPAddress = "10.10.0.113"

New-DLabVM $VMName -Password $Password -Force
Start-VM $VMName
Wait-VM $VMName -For IPAddress -Timeout 60

$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Set-DLabVMNetAdapter $VMName -VMSession $VMSession `
    -SwitchName $SwitchName -NetAdapterName $NetAdapterName `
    -IPAddress $IPAddress -DefaultGateway $DefaultGateway `
    -DnsServerAddress $DnsServerAddress

Add-DLabVMToDomain $VMName -VMSession $VMSession `
    -DomainName $DomainName -UserName $DomainUserName -Password $DomainPassword

# Wait for virtual machine to reboot after domain join operation

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

Invoke-Command -ScriptBlock {
    @('Web-Server',
    'Web-Http-Errors',
    'Web-Http-Logging',
    'Web-Static-Content',
    'Web-Default-Doc',
    'Web-Dir-Browsing',
    'Web-AppInit',
    'Web-Net-Ext45',
    'Web-Asp-Net45',
    'Web-ISAPI-Ext',
    'Web-ISAPI-Filter',
    'Web-Basic-Auth',
    'Web-Digest-Auth',
    'Web-Stat-Compression',
    'Web-Windows-Auth',
    'Web-Mgmt-Tools'
    ) | Foreach-Object { Install-WindowsFeature -Name $_ | Out-Null }
} -Session $VMSession

Invoke-Command -ScriptBlock {
    choco install -y urlrewrite
    choco install -y iis-arr --ignore-checksums
} -Session $VMSession

Invoke-Command -ScriptBlock {
    & "$Env:WinDir\system32\inetsrv\appcmd.exe" set config `
        -section:system.webServer/proxy -preserveHostHeader:true /commit:apphost

    & "$Env:WinDir\system32\inetsrv\appcmd.exe" set config `
        -section:system.WebServer/rewrite/globalRules -useOriginalURLEncoding:false /commit:apphost
} -Session $VMSession
