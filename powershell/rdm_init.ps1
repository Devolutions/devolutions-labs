
. .\common.ps1

Import-Module RemoteDesktopManager

$LabName = "$LabPrefix-LAB"
$VMAliases = @("DC", "CA", "DVLS", "GW")

$Refresh = $true

$LabDataSourceName = $LabName
if (-Not (Get-RDMDataSource | Select-Object -ExpandProperty Name).Contains($LabDataSourceName)) {
    $DBFileName = ($LabDataSourceName -Replace ' ', '') + ".db"
    $Params = @{
        Name = $LabDataSourceName;
        SQLite = $true;
        Database = "$Env:LocalAppData\Devolutions\RemoteDesktopManager\$DBFileName.db";
    }
    $DataSource = New-RDMDataSource @Params
    Set-RDMDataSource -DataSource $DataSource
}

$LabDataSource = Get-RDMDataSource -Name $LabDataSourceName
Set-RDMCurrentDataSource -DataSource $LabDataSource

# Lab Folder
$LabFolderName = $LabCompanyName
$LabFolder = New-RDMSession -Type "Group" -Name $LabFolderName
$LabFolder.Group = $LabFolderName
Set-RDMSession -Session $LabFolder -Refresh:$Refresh

# Active Directory Folder
$ADFolderName = "Active Directory"
$ADFolder = New-RDMSession -Type "Group" -Name $ADFolderName
$ADFolder.Group = "$LabFolderName\$ADFolderName"
Set-RDMSession -Session $ADFolder -Refresh:$Refresh

# LAN Folder
$LANFolderName = "Local Network"
$LANFolder = New-RDMSession -Type "Group" -Name $LANFolderName
$LANFolder.Group = "$LabFolderName\$LANFolderName"
Set-RDMSession -Session $LANFolder -Refresh:$Refresh

# WAN Folder
$RDGFolderName = "RD Gateway"
$RDGFolder = New-RDMSession -Type "Group" -Name $RDGFolderName
$RDGFolder.Group = "$LabFolderName\$RDGFolderName"
Set-RDMSession -Session $RDGFolder -Refresh:$Refresh

# Hyper-V Folder
$HVFolderName = "Hyper-V Host"
$HVFolder = New-RDMSession -Type "Group" -Name $HVFolderName
$HVFolder.Group = "$LabFolderName\$HVFolderName"
Set-RDMSession -Session $HVFolder -Refresh:$Refresh

# Domain Administrator

$DomainAdminUPN = "Administrator@$DomainDnsName"

$Params = @{
    Name = $DomainAdminUPN
    Type = "Credential";
}

$Session = New-RDMSession @Params
$Session.Group = "$LabFolderName\$ADFolderName"
$Session.MetaInformation.UPN = $DomainAdminUPN
Set-RDMSession -Session $Session -Refresh:$Refresh

Set-RDMSessionUsername -ID $Session.ID "Administrator"
Set-RDMSessionDomain -ID $Session.ID $DomainDnsName
$Password = ConvertTo-SecureString $DomainPassword -AsPlainText -Force
Set-RDMSessionPassword -ID $Session.ID -Password $Password

$DomainAdminEntry = Get-RDMSession -GroupName "$LabFolderName\$ADFolderName" -Name $DomainAdminUPN
$DomainAdminId = $DomainAdminEntry.ID

# RD Gateway

$RDGatewayFQDN = "rdg.$DnsZoneName"

$Params = @{
    Name = $RDGatewayFQDN
    Host = $RDGatewayFQDN
    Type = "Gateway";
}

$Session = New-RDMSession @Params
$Session.Group = "$LabFolderName\$RDGFolderName"
$Session.CredentialConnectionID = $DomainAdminId
$Session.RDP.GatewayCredentialsSource = "UserPassword"
$Session.RDP.GatewayProfileUsageMethod = "Explicit"
$Session.RDP.GatewaySelection = "SpecificGateway"
$Session.RDP.GatewayUsageMethod = "ModeDirect"
Set-RDMSession -Session $Session -Refresh:$Refresh

$RDGatewayEntry = Get-RDMSession -GroupName "$LabFolderName\$RDGFolderName" -Name $RDGatewayFQDN | Select-Object -First 1

# RDP (Regular)

$VMAliases | ForEach-Object {
    $VMAlias = $_
    $VMName = $LabPrefix, $VMAlias -Join "-"

    $MachineName = $VMName
    $MachineFQDN = "$MachineName.$DnsZoneName"

    $Params = @{
        Name = "$MachineName";
        Host = $MachineFQDN;
        Type = "RDPConfigured";
    }

    $Session = New-RDMSession @Params
    $Session.Group = "$LabFolderName\$LANFolderName"
    $Session.CredentialConnectionID = $DomainAdminId
    Set-RDMSession -Session $Session -Refresh:$Refresh
}

# RDP (Hyper-V)

$VMAliases | ForEach-Object {
    $VMAlias = $_
    $VMName = $LabPrefix, $VMAlias -Join "-"

    $VMId = $(Get-VM $VMName).Id
    $VMHost = "localhost"

    $Params = @{
        Name = "$VMName";
        Host = $VMHost;
        Type = "RDPConfigured";
    }

    $Session = New-RDMSession @Params
    $Session.Group = "$LabFolderName\$HVFolderName"
    $Session.RDP.RDPType = "HyperV"
    $Session.RDP.HyperVInstanceID = $VMId
    $Session.RDP.FrameBufferRedirection = $false
    $Session.RDP.UseEnhancedSessionMode = $true
    if ($($Session.RDP | Get-Member -Name 'VMConnectImplicitCredentials')) {
        $Session.RDP.VMConnectImplicitCredentials = $true # added in 2021.1.27
    }
    Set-RDMSession -Session $Session -Refresh:$Refresh
}

# RDP (RD Gateway)

$VMAliases | ForEach-Object {
    $VMAlias = $_
    $VMName = $LabPrefix, $VMAlias -Join "-"

    $MachineName = $VMName
    $MachineFQDN = "$MachineName.$DnsZoneName"

    $Params = @{
        Name = "$MachineName";
        Host = $MachineFQDN;
        Type = "RDPConfigured";
    }

    $Session = New-RDMSession @Params
    $Session.Group = "$LabFolderName\$RDGFolderName"
    $Session.CredentialConnectionID = $DomainAdminId
    $Session.VPN.Application = "Gateway"
    $Session.VPN.Enabled = $true
    $Session.VPN.Mode = "AlwaysConnect"
    $Session.VPN.ExistingGatewayID = $RDGatewayEntry.ID
    Set-RDMSession -Session $Session -Refresh:$Refresh
}

# PowerShell (Hyper-V)

$VMAliases | ForEach-Object {
    $VMAlias = $_
    $VMName = $LabPrefix, $VMAlias -Join "-"

    $Params = @{
        Name = "$VMName";
        Host = $VMName;
        Type = "PowerShellRemoteConsole";
    }

    $Session = New-RDMSession @Params
    $Session.Group = "$LabFolderName\$HVFolderName"
    $Session.CredentialConnectionID = $DomainAdminId
    $Session.PowerShell.RemoteConsoleConnectionMode = "VMName"
    $Session.PowerShell.Run64BitsMode = $true
    Set-RDMSession -Session $Session -Refresh:$Refresh
}

# PowerShell (WinRM)

$VMAliases | ForEach-Object {
    $VMAlias = $_
    $VMName = $LabPrefix, $VMAlias -Join "-"

    $MachineName = $VMName
    $MachineFQDN = "$MachineName.$DnsZoneName"

    $Params = @{
        Name = "$MachineName";
        Host = $MachineFQDN;
        Type = "PowerShellRemoteConsole";
    }

    $Session = New-RDMSession @Params
    $Session.Group = "$LabFolderName\$LANFolderName"
    $Session.CredentialConnectionID = $DomainAdminId
    $Session.PowerShell.RemoteConsoleConnectionMode = "ComputerName"
    $Session.PowerShell.Run64BitsMode = $true
    Set-RDMSession -Session $Session -Refresh:$Refresh
}

# Active Directory Accounts

if (Test-Path -Path "ADAccounts.json" -PathType 'Leaf') {
    $ADAccounts = $(Get-Content -Path "ADAccounts.json") | ConvertFrom-Json

    $ADAccounts | ForEach-Object {
        $Username = $_.Identity
        $Password = $_.Password
        $AccountUPN = "$Username@$DomainDnsName"

        $Params = @{
            Name = $AccountUPN;
            Type = "Credential";
        }

        $Session = New-RDMSession @Params
        $Session.Group = "$LabFolderName\$ADFolderName"
        $Session.MetaInformation.UPN = $AccountUPN
        Set-RDMSession -Session $Session -Refresh:$Refresh

        Set-RDMSessionUsername -ID $Session.ID "$Username"
        Set-RDMSessionDomain -ID $Session.ID $DomainDnsName
        $Password = ConvertTo-SecureString $Password -AsPlainText -Force
        Set-RDMSessionPassword -ID $Session.ID -Password $Password
    }
}
