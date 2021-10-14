
. .\common.ps1

$VMAlias = "DVLS"
$VMNumber = 6
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
Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $DomainUserName -Password $DomainPassword

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

Write-Host "Installing IIS features"

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

Write-Host "Installing IIS extensions"

Invoke-Command -ScriptBlock {
    choco install -y urlrewrite
    choco install -y iis-arr --ignore-checksums
} -Session $VMSession

Write-Host "Changing IIS default rules"

Invoke-Command -ScriptBlock {
    & "$Env:WinDir\system32\inetsrv\appcmd.exe" set config `
        -section:system.webServer/proxy -preserveHostHeader:true /commit:apphost

    & "$Env:WinDir\system32\inetsrv\appcmd.exe" set config `
        -section:system.WebServer/rewrite/globalRules -useOriginalURLEncoding:false /commit:apphost
} -Session $VMSession

Write-Host "Installing SQL Server Express"

Invoke-Command -ScriptBlock {
    choco install -y --no-progress sql-server-express
    choco install -y --no-progress sql-server-management-studio
} -Session $VMSession

Write-Host "Creating SQL database for DVLS"

$DatabaseName = "dvls"
$SqlInstance = "localhost\SQLEXPRESS"

Invoke-Command -ScriptBlock { Param($DatabaseName, $SqlInstance)
    Install-Module -Name SqlServer -Scope AllUsers -AllowClobber
    Import-Module SqlServer
    $SqlServer = New-Object Microsoft.SqlServer.Management.Smo.Server($SqlInstance)
    $Database = New-Object Microsoft.SqlServer.Management.Smo.Database($SqlServer, $DatabaseName)
    $Database.Create()
} -Session $VMSession

<#
# https://www.fosstechnix.com/how-to-enable-sa-account-in-sql-server/
$SqlUsername = "dvls"
$SqlPassword = "dvls123!"
$SecurePassword = ConvertTo-SecureString $SqlPassword -AsPlainText -Force
$SqlCredential = New-Object System.Management.Automation.PSCredential @($SqlUsername, $SecurePassword)
Add-SqlLogin -ServerInstance $SqlInstance -LoginPSCredential $SqlCredential -LoginType SqlLogin
#>

$DvlsHostName = "dvls.$DomainName"
$CertificateFile = "~\Documents\cert.pfx"
$CertificatePassword = "cert123!"

Write-Host "Creating new DNS record for Devolutions Server"

Invoke-Command -ScriptBlock { Param($DnsName, $DnsZoneName, $IPAddress, $DnsServer)
    Install-WindowsFeature RSAT-DNS-Server
    Add-DnsServerResourceRecordA -Name $DnsName -ZoneName $DnsZoneName -IPv4Address $IPAddress -AllowUpdateAny -ComputerName $DnsServer
} -Session $VMSession -ArgumentList @("dvls", $DomainName, $IPAddress, $DCHostName)

Write-Host "Requesting new certificate for Devolutions Server"

Request-DLabCertificate $VMName -VMSession $VMSession `
    -CommonName $DvlsHostName `
    -CAHostName $CAHostName -CACommonName $CACommonName `
    -CertificateFile $CertificateFile -Password $CertificatePassword
