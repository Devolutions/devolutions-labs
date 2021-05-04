
. .\common.ps1

$VMAliases = @("DC", "CA", "WAYK", "DVLS", "GW")

Import-RdmModule

$LabFolderName = "$LabPrefix-LAB"
$LabFolder = New-RDMSession -Type "Group" -Name $LabFolderName
$LabFolder.Group = $LabFolderName
Set-RDMSession -Session $LabFolder -Refresh

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

# RDP

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
    Set-RDMSession -Session $Session -Refresh
    Update-RDMUI

    Set-RDMSessionUsername -ID $Session.ID "Administrator"
    Set-RDMSessionDomain -ID $Session.ID $DomainName
    $Password = ConvertTo-SecureString $DomainPassword -AsPlainText -Force
    Set-RDMSessionPassword -ID $Session.ID -Password $Password
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
    Set-RDMSession -Session $Session -Refresh
    Update-RDMUI

    $Session.PowerShell.RemoteConsoleConnectionMode = "VMName"

    Set-RDMSessionUsername -ID $Session.ID "Administrator"
    Set-RDMSessionDomain -ID $Session.ID $DomainName
    $Password = ConvertTo-SecureString $DomainPassword -AsPlainText -Force
    Set-RDMSessionPassword -ID $Session.ID -Password $Password
}

# PowerShell (WinRM)

$VMAliases | ForEach-Object {
    $VMAlias = $_
    $VMName = $LabPrefix, $VMAlias -Join "-"

    $Params = @{
        Name = "$VMName (WinRM)";
        Host = $VMName;
        Type = "PowerShellRemoteConsole";
    }

    $Session = New-RDMSession @Params
    $Session.Group = $LabFolderName
    Set-RDMSession -Session $Session -Refresh
    Update-RDMUI

    $Session.PowerShell.RemoteConsoleConnectionMode = "ComputerName"

    Set-RDMSessionUsername -ID $Session.ID "Administrator"
    Set-RDMSessionDomain -ID $Session.ID $DomainName
    $Password = ConvertTo-SecureString $DomainPassword -AsPlainText -Force
    Set-RDMSessionPassword -ID $Session.ID -Password $Password
}

# PowerShell (Wayk)

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
    Set-RDMSession -Session $Session -Refresh
    Update-RDMUI

    $Session.PowerShell.RemoteConsoleConnectionMode = "Wayk"
    $Session.PowerShell.Version = "PowerShell7"

    Set-RDMSessionUsername -ID $Session.ID "Administrator"
    Set-RDMSessionDomain -ID $Session.ID $DomainName
    $Password = ConvertTo-SecureString $DomainPassword -AsPlainText -Force
    Set-RDMSessionPassword -ID $Session.ID -Password $Password
}
