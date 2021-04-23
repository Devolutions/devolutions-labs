
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

Write-Host "Joining domain"

Add-DLabVMToDomain $VMName -VMSession $VMSession `
    -DomainName $DomainName -DomainController $DomainController `
    -UserName $DomainUserName -Password $DomainPassword

# Wait for virtual machine to reboot after domain join operation

Wait-DLabVM $VMName 'Reboot' -Timeout 120
Wait-DLabVM $VMName 'PSDirect' -Timeout 600 -UserName $DomainUserName -Password $DomainPassword
$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

Write-Host "Installing containers feature"

Invoke-Command -ScriptBlock {
    Install-WindowsFeature -Name Containers -Restart
} -Session $VMSession

Write-Host "Rebooting"

$OldUptime = Get-DLabVMUptime $VMName
Restart-VM $VMName -Force
Wait-DLabVM $VMName 'Reboot' -Timeout 120 -OldUptime $OldUptime

Wait-DLabVM $VMName 'PSDirect' -Timeout 600 -UserName $DomainUserName -Password $DomainPassword
$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

Write-Host "Installing Docker"

Invoke-Command -ScriptBlock {
    Install-Module -Name DockerMsftProvider -Repository PSGallery -Force
    Install-Package -Name docker -ProviderName DockerMsftProvider -Force
    Start-Service -Name docker
} -Session $VMSession

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

Write-Host "Installing MongoDB"

Invoke-Command -ScriptBlock {
    choco install -y --no-progress mongodb
    choco install -y --no-progress mongodb-compass
    choco install -y --no-progress mongodb-database-tools
} -Session $VMSession

Write-Host "Installing Wayk Bastion"

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

Write-Host "Creating new DNS record for Wayk Bastion"

Invoke-Command -ScriptBlock { Param($DnsName, $DnsZoneName, $IPAddress, $DnsServer)
    Install-WindowsFeature RSAT-DNS-Server
    Add-DnsServerResourceRecordA -Name $DnsName -ZoneName $DnsZoneName -IPv4Address $IPAddress -AllowUpdateAny -ComputerName $DnsServer
} -Session $VMSession -ArgumentList @("bastion", $DomainName, $IPAddress, $DCHostName)

Write-Host "Requesting new certificate for Wayk Bastion"

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

Write-Host "Prefetching Windows container images"

Invoke-Command -ScriptBlock {
    Import-Module -Name WaykBastion
    Update-WaykBastionImage
} -Session $VMSession

Write-Host "Registering Wayk Bastion service"

Invoke-Command -ScriptBlock {
    Import-Module -Name WaykBastion
    Register-WaykBastionService
    Start-Service WaykBastion
} -Session $VMSession
