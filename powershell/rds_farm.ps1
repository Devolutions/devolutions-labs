. .\common.ps1

$FarmSize = 3

foreach ($FarmIndex in 1..$FarmSize) {
    $VMAlias = "RDSH" + $FarmIndex
    $VMNumber = 10 + $FarmIndex
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

    Write-Host "Installing RD Session Host"

    Invoke-Command -ScriptBlock {
        Install-WindowsFeature -Name RDS-RD-Server
        Restart-Computer -Force
    } -Session $VMSession

    Write-Host "Rebooting VM"

    Wait-DLabVM $VMName 'Reboot' -Timeout 120
    Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $DomainUserName -Password $DomainPassword
    $VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword
}

# IT-HELP-GW

$VMAlias = "GW"
$VMNumber = 7
$VMName = $LabPrefix, $VMAlias -Join "-"
$IpAddress = Get-DLabIpAddress $LabNetworkBase $VMNumber

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

$SessionHosts = @()
foreach ($FarmIndex in 1..$FarmSize) {
    $SessionHost = $LabPrefix + "-RDSH" + $FarmIndex + "." + $DomainName
    $SessionHosts += $SessionHost
}

Write-Host "Create new RD session collection"

$ConnectionBroker = "$VMName.$DomainName"

Invoke-Command -ScriptBlock { Param($ConnectionBroker, $SessionHosts)
    $SessionHosts | ForEach-Object {
        Add-RDServer -Server $_ -Role RDS-RD-SERVER
    }

    $CollectionName = "IT-HELP-FARM"
    $CollectionDescription = "IT Help RDS Farm"

    $Params = @{
        CollectionName = "IT-HELP-FARM";
        CollectionDescription = "IT Help RDS Farm";
        SessionHost = $SessionHosts;
        ConnectionBroker = $ConnectionBroker;
    }
    New-RDSessionCollection @Params
} -Session $VMSession -ArgumentList @($ConnectionBroker, $SessionHosts)
