
. .\common.ps1

Import-RdmModule

$VMAliases = @("DC", "CA", "WAYK", "DVLS", "GW")

# Lab Folder

$LabFolderName = "$LabPrefix-LAB"
$LabFolder = New-RDMSession -Type "Group" -Name $LabFolderName
$LabFolder.Group = $LabFolderName
Set-RDMSession -Session $LabFolder -Refresh

# Domain Administrator

$DomainAdminUPN = "Administrator@$DomainDnsName"

$Params = @{
    Name = $DomainAdminUPN
    Type = "Credential";
}

$Session = New-RDMSession @Params
$Session.Group = $LabFolderName
Set-RDMSession -Session $Session -Refresh
Update-RDMUI

$Session.MetaInformation.UPN = $DomainAdminUPN
Set-RDMSession -Session $Session -Refresh
Update-RDMUI

Set-RDMSessionUsername -ID $Session.ID "Administrator"
Set-RDMSessionDomain -ID $Session.ID $DomainDnsName
$Password = ConvertTo-SecureString $DomainPassword -AsPlainText -Force
Set-RDMSessionPassword -ID $Session.ID -Password $Password

$DomainAdminEntry = Get-RDMSession -GroupName $LabFolderName -Name $DomainAdminUPN
$DomainAdminId = $DomainAdminEntry.ID

# Wayk Bastion Admin

$WaykBastionUser = "wayk-admin"

$Params = @{
    Name = "$WaykBastionUser (bastion)"
    Type = "Credential";
}

$Session = New-RDMSession @Params
$Session.Group = $LabFolderName
Set-RDMSession -Session $Session -Refresh
Update-RDMUI

Set-RDMSessionUsername -ID $Session.ID $WaykBastionUser
$Password = ConvertTo-SecureString "WaykBastion123!" -AsPlainText -Force
Set-RDMSessionPassword -ID $Session.ID -Password $Password

# Wayk Bastion Technician

$WaykBastionUser = "technician"

$Params = @{
    Name = "$WaykBastionUser (bastion)"
    Type = "Credential";
}

$Session = New-RDMSession @Params
$Session.Group = $LabFolderName
Set-RDMSession -Session $Session -Refresh
Update-RDMUI

Set-RDMSessionUsername -ID $Session.ID $WaykBastionUser
$Password = ConvertTo-SecureString "Technician123!" -AsPlainText -Force
Set-RDMSessionPassword -ID $Session.ID -Password $Password

# Wayk Bastion

$BastionFQDN = "bastion.$DnsZoneName"
$BastionURL = "https://$BastionFQDN"

$Params = @{
    Name = $BastionFQDN;
    Host = $BastionURL;
    Type = "WaykDenConsole";
}

$Session = New-RDMSession @Params
$Session.Group = $LabFolderName
Set-RDMSession -Session $Session -Refresh
Update-RDMUI

$WaykBastionEntry = Get-RDMSession -GroupName $LabFolderName -Name $BastionFQDN | Select-Object -First 1

# RD Gateway

$RDGatewayFQDN = "rdg.$DnsZoneName"

$Params = @{
    Name = $RDGatewayFQDN
    Host = $RDGatewayFQDN
    Type = "Gateway";
}

$Session = New-RDMSession @Params
$Session.Group = $LabFolderName
$Session.CredentialConnectionID = $DomainAdminId
$Session.RDP.GatewayCredentialsSource = "UserPassword"
$Session.RDP.GatewayProfileUsageMethod = "Explicit"
$Session.RDP.GatewaySelection = "SpecificGateway"
$Session.RDP.GatewayUsageMethod = "ModeDirect"
Set-RDMSession -Session $Session -Refresh
Update-RDMUI

$RDGatewayEntry = Get-RDMSession -GroupName $LabFolderName -Name $RDGatewayFQDN | Select-Object -First 1

# RDP (Regular)

$VMAliases | ForEach-Object {
    $VMAlias = $_
    $VMName = $LabPrefix, $VMAlias -Join "-"

    $MachineName = $VMName
    $MachineFQDN = "$MachineName.$DnsZoneName"

    $Params = @{
        Name = "$MachineName (RDP)";
        Host = $MachineFQDN;
        Type = "RDPConfigured";
    }

    $Session = New-RDMSession @Params
    $Session.Group = $LabFolderName
    $Session.CredentialConnectionID = $DomainAdminId
    Set-RDMSession -Session $Session -Refresh
    Update-RDMUI
}

# RDP (Hyper-V)

$VMAliases | ForEach-Object {
    $VMAlias = $_
    $VMName = $LabPrefix, $VMAlias -Join "-"

    $VMId = $(Get-VM $VMName).Id
    $VMHost = "localhost"

    $Params = @{
        Name = "$VMName (Hyper-V)";
        Host = $VMHost;
        Type = "RDPConfigured";
    }

    $Session = New-RDMSession @Params
    $Session.Group = $LabFolderName
    $Session.RDP.RDPType = "HyperV"
    $Session.RDP.HyperVInstanceID = $VMId
    $Session.RDP.FrameBufferRedirection = $false
    $Session.RDP.UseEnhancedSessionMode = $true
    if ($($Session.RDP | Get-Member -Name 'VMConnectImplicitCredentials')) {
        $Session.RDP.VMConnectImplicitCredentials = $true # added in 2021.1.27
    }
    Set-RDMSession -Session $Session -Refresh
    Update-RDMUI
}

# RDP (RD Gateway)

$VMAliases | ForEach-Object {
    $VMAlias = $_
    $VMName = $LabPrefix, $VMAlias -Join "-"

    $MachineName = $VMName
    $MachineFQDN = "$MachineName.$DnsZoneName"

    $Params = @{
        Name = "$MachineName (RD Gateway)";
        Host = $MachineFQDN;
        Type = "RDPConfigured";
    }

    $Session = New-RDMSession @Params
    $Session.Group = $LabFolderName
    $Session.CredentialConnectionID = $DomainAdminId
    $Session.VPN.Application = "Gateway"
    $Session.VPN.Enabled = $true
    $Session.VPN.Mode = "AlwaysConnect"
    $Session.VPN.ExistingGatewayID = $RDGatewayEntry.ID
    Set-RDMSession -Session $Session -Refresh
    Update-RDMUI
}

# PowerShell (Hyper-V)

$VMAliases | ForEach-Object {
    $VMAlias = $_
    $VMName = $LabPrefix, $VMAlias -Join "-"

    $Params = @{
        Name = "$VMName (Hyper-V)";
        Host = $VMName;
        Type = "PowerShellRemoteConsole";
    }

    $Session = New-RDMSession @Params
    $Session.Group = $LabFolderName
    $Session.CredentialConnectionID = $DomainAdminId
    $Session.PowerShell.RemoteConsoleConnectionMode = "VMName"
    Set-RDMSession -Session $Session -Refresh
    Update-RDMUI
}

# PowerShell (WinRM)

$VMAliases | ForEach-Object {
    $VMAlias = $_
    $VMName = $LabPrefix, $VMAlias -Join "-"

    $MachineName = $VMName
    $MachineFQDN = "$MachineName.$DnsZoneName"

    $Params = @{
        Name = "$MachineName (WinRM)";
        Host = $MachineFQDN;
        Type = "PowerShellRemoteConsole";
    }

    $Session = New-RDMSession @Params
    $Session.Group = $LabFolderName
    $Session.CredentialConnectionID = $DomainAdminId
    $Session.PowerShell.RemoteConsoleConnectionMode = "ComputerName"
    Set-RDMSession -Session $Session -Refresh
    Update-RDMUI
}

# Wayk Remote Desktop

$VMAliases | ForEach-Object {
    $VMAlias = $_
    $VMName = $LabPrefix, $VMAlias -Join "-"

    $MachineName = $VMName
    $MachineFQDN = "$MachineName.$DnsZoneName"

    $Params = @{
        Name = "$MachineName (Wayk)";
        Host = $MachineFQDN;
        Type = "Wayk";
    }

    $Session = New-RDMSession @Params
    $Session.Group = $LabFolderName
    $Session.CredentialConnectionID = $DomainAdminId
    $Session.UserNameFormat = "UserAtDomain"
    $Session.Wayk.WaykDenConnectionID = $WaykBastionEntry.ID
    $Session.Wayk.PreferredAuthType = "SecureRemoteDelegation"
    Set-RDMSession -Session $Session -Refresh
    Update-RDMUI
}

# Wayk RDP

$VMAliases | ForEach-Object {
    $VMAlias = $_
    $VMName = $LabPrefix, $VMAlias -Join "-"

    $MachineName = $VMName
    $MachineFQDN = "$MachineName.$DnsZoneName"

    $Params = @{
        Name = "$MachineName (Wayk RDP)";
        Host = $MachineFQDN;
        Type = "RDPConfigured";
    }

    $Session = New-RDMSession @Params
    $Session.Group = $LabFolderName
    $Session.CredentialConnectionID = $DomainAdminId
    $Session.UserNameFormat = "UserAtDomain"
    $Session.VPN.Application = "WaykBastion"
    $Session.VPN.Enabled = $true
    $Session.VPN.Mode = "AlwaysConnect"
    $Session.VPN.WaykBastionID = $WaykBastionEntry.ID
    Set-RDMSession -Session $Session -Refresh
    Update-RDMUI
}

# Wayk PowerShell Remoting

$VMAliases | ForEach-Object {
    $VMAlias = $_
    $VMName = $LabPrefix, $VMAlias -Join "-"

    $Params = @{
        Name = "$VMName (Wayk)";
        Host = $VMName;
        Type = "PowerShellRemoteConsole";
    }

    $Session = New-RDMSession @Params
    $Session.Group = $LabFolderName
    $Session.CredentialConnectionID = $DomainAdminId
    $Session.UserNameFormat = "UserAtDomain"
    $Session.PowerShell.RemoteConsoleConnectionMode = "Wayk"
    $Session.PowerShell.Version = "PowerShell7"
    $Session.VPN.Application = "WaykBastion"
    $Session.VPN.Enabled = $true
    $Session.VPN.Mode = "AlwaysConnect"
    $Session.VPN.WaykBastionID = $WaykBastionEntry.ID
    Set-RDMSession -Session $Session -Refresh
    Update-RDMUI
}
