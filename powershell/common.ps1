# common variable definitions

Import-Module .\DevolutionsLabs.psm1 -Force

$licensing = Get-Content -Path "$PSScriptRoot\licensing.json" -Raw | ConvertFrom-Json

$OSVersion = "2022"
$LabPrefix = "IT-HELP"
$LabDnsTld = ".ninja"
$LabCompanyName = "IT Help Ninja"
$LabName = $LabPrefix.ToLower() + $LabDnsTld

$LocalUserName = "Administrator"
$LocalPassword = "Local123!"

$WanSwitchName = "NAT Switch"
$LanSwitchName = "LAN Switch"
$SwitchName = $LanSwitchName
$NetAdapterName = "vEthernet (LAN)"
$LabNetworkBase = "10.10.0.0"

$RTRVMNumber = 2
$RTRIpAddress = Get-DLabIpAddress $LabNetworkBase $RTRVMNumber
$DefaultGateway = $RTRIpAddress

$DomainName = "ad.$LabName"
$DnsZoneName = $DomainName
$DomainDnsName = $DomainName
$DomainNetbiosName = $LabPrefix
$SafeModeAdministratorPassword = "SafeMode123!"

$DCVMNumber = 3
$DCMachineName = $LabPrefix, "DC" -Join "-"
$DomainController = $DCMachineName
$DCHostName = "$DCMachineName.$DomainName"
$DCIpAddress = Get-DLabIpAddress $LabNetworkBase $DCVMNumber

$CAMachineName = $LabPrefix, "DC" -Join "-"
$CACommonName = $CAMachineName
$CAHostName = "$CAMachineName.$DomainName"

$DomainUserName = "$DomainNetbiosName\Administrator"
$DomainPassword = "DevoLabs123!"

$DnsServerForwarder = "1.1.1.1"
$DnsServerAddress = $DCIpAddress
