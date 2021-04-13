
Import-Module .\DevolutionsLabs.psm1 -Force

# common variable definitions

$UserName = "Administrator"
$Password = "yolo123!"

$SwitchName = "LAN Switch"
$NetAdapterName = "vEthernet (LAN)"

$DomainName = "ad.it-yolo.ninja"
$DomainNetbiosName = "IT-YOLO"
$SafeModeAdministratorPassword = "SafeMode123!"

$DomainUserName = "$DomainNetbiosName\Administrator"
$DomainPassword = $Password

# IT-YOLO-DC

$VMName = "IT-YOLO-DC"
$IPAddress = "10.10.0.110"
$DnsServerAddress = $IPAddress

New-DLabVM $VMName -Password $Password -Force
Start-VM $VMName
Wait-VM $VMName -For IPAddress -Timeout 60

$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Set-DLabVMNetAdapter $VMName -VMSession $VMSession `
    -SwitchName $SwitchName -NetAdapterName $NetAdapterName `
    -IPAddress $IPAddress -DnsServerAddress $DnsServerAddress

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
    -IPAddress $IPAddress -DnsServerAddress $DnsServerAddress

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
    -IPAddress $IPAddress -DnsServerAddress $DnsServerAddress

Add-DLabVMToDomain $VMName -VMSession $VMSession `
    -DomainName $DomainName -UserName $DomainUserName -Password $DomainPassword

# Wait for virtual machine to reboot after domain join operation

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
    -IPAddress $IPAddress -DnsServerAddress $DnsServerAddress

Add-DLabVMToDomain $VMName -VMSession $VMSession `
    -DomainName $DomainName -UserName $DomainUserName -Password $DomainPassword

# Wait for virtual machine to reboot after domain join operation

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword
