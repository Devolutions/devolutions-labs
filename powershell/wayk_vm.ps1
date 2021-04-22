
. .\common.ps1

$VMAlias = "WAYK"
$VMNumber = 5
$VMName = $LabPrefix, $VMAlias -Join "-"
$IpAddress = Get-DLabIpAddress $LabNetworkBase $VMNumber

New-DLabVM $VMName -Password $Password -Force
Start-DLabVM $VMName

Wait-DLabVM $VMName 'Heartbeat' -Timeout 120 -UserName $UserName -Password $Password
$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Set-DLabVMNetAdapter $VMName -VMSession $VMSession `
    -SwitchName $SwitchName -NetAdapterName $NetAdapterName `
    -IPAddress $IPAddress -DefaultGateway $DefaultGateway `
    -DnsServerAddress $DnsServerAddress

Add-DLabVMToDomain $VMName -VMSession $VMSession `
    -DomainName $DomainName -DomainController $DomainController `
    -UserName $DomainUserName -Password $DomainPassword

# Wait for virtual machine to reboot after domain join operation

Wait-DLabVM $VMName 'Reboot' -Timeout 120
Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $DomainUserName -Password $DomainPassword

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

Invoke-Command -ScriptBlock {
    Install-WindowsFeature -Name Containers
    Install-Module -Name DockerMsftProvider -Force
    Install-Package -Name docker -ProviderName DockerMsftProvider -Force
} -Session $VMSession

$OldUptime = Get-DLabVMUptime $VMName
Restart-VM $VMName -Force
Wait-DLabVM $VMName 'Reboot' -Timeout 120 -OldUptime $OldUptime

Wait-DLabVM $VMName 'Heartbeat' -Timeout 120
$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

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

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

$BastionHostName = "bastion.$DomainName"
$CertificateFile = "~\Documents\cert.pfx"
$CertificatePassword = "cert123!"

Invoke-Command -ScriptBlock { Param($DnsName, $DnsZoneName, $IPAddress, $DnsServer)
    Install-WindowsFeature RSAT-DNS-Server
    Add-DnsServerResourceRecordA -Name $DnsName -ZoneName $DnsZoneName -IPv4Address $IPAddress -AllowUpdateAny -ComputerName $DnsServer
} -Session $VMSession -ArgumentList @("bastion", $DomainName, $IPAddress, $DCHostName)

Request-DLabCertificate $VMName -VMSession $VMSession `
    -CommonName $BastionHostName `
    -CAHostName $CAHostName -CACommonName $CACommonName `
    -CertificateFile $CertificateFile -Password $CertificatePassword

Invoke-Command -ScriptBlock { Param($ExternalHost, $CertificateFile, $CertificatePassword)
    Import-Module -Name WaykBastion
    Import-WaykBastionCertificate -CertificateFile $CertificateFile -Password $CertificatePassword
    $Params = @{
        ListenerUrl = "https://localhost:443";
        ExternalUrl = "https://${ExternalHost}`:443";
    }
    Set-WaykBastionConfig @Params
} -Session $VMSession -ArgumentList @($BastionHostName, $CertificateFile, $CertificatePassword)

# prefetch Windows container images (takes a while)

Invoke-Command -ScriptBlock {
    Import-Module -Name WaykBastion
    Update-WaykBastionImage
} -Session $VMSession
