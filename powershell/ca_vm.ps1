. .\common.ps1

$VMAlias = "CA"
$VMNumber = 4
$VMName = $LabPrefix, $VMAlias -Join "-"
$IpAddress = Get-DLabIpAddress $LabNetworkBase $VMNumber

New-DLabVM $VMName -Password $Password -Force
Start-DLabVM $VMName

Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $UserName -Password $Password
$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Set-DLabVMNetAdapter $VMName -VMSession $VMSession `
    -SwitchName $SwitchName -NetAdapterName $NetAdapterName `
    -IPAddress $IPAddress -DefaultGateway $DefaultGateway `
    -DnsServerAddress $DnsServerAddress

# Join virtual machine to domain

Add-DLabVMToDomain $VMName -VMSession $VMSession `
    -DomainName $DomainName -DomainController $DCHostName `
    -UserName $DomainUserName -Password $DomainPassword

# Wait for virtual machine to reboot after domain join operation

Wait-DLabVM $VMName 'Reboot' -Timeout 120
Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $DomainUserName -Password $DomainPassword

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

# Install Active Directory Certificate Services

Invoke-Command -ScriptBlock { Param($DomainName, $UserName, $Password, $CACommonName)
    $ConfirmPreference = "High"
    Install-WindowsFeature -Name AD-Certificate -IncludeManagementTools
    $Params = @{
        CAType = "EnterpriseRootCa";
        CryptoProviderName = "RSA#Microsoft Software Key Storage Provider";
        HashAlgorithmName = "SHA256";
        KeyLength = 2048;
        CACommonName = $CACommonName;
    }
    Install-AdcsCertificationAuthority @Params -Force
} -Session $VMSession -ArgumentList @($DomainName, $DomainUserName, $DomainPassword, $CACommonName)

# Install IIS + Publish CRL over HTTP

Invoke-Command -ScriptBlock { Param($CAHostName, $CACommonName)
    Install-WindowsFeature -Name 'Web-Server' | Out-Null
    Remove-IISSite -Name "Default Web Site" -Confirm:$false
    $CertSrvPath = "${Env:WinDir}\System32\CertSrv"
    New-IISSite -Name 'CertSrv' -PhysicalPath $CertSrvPath -BindingInformation "*:80:"
    & "$Env:WinDir\system32\inetsrv\appcmd.exe" set config `
        -section:system.webServer/security/requestFiltering -allowDoubleEscaping:True /commit:apphost
    Start-IISSite -Name 'CertSrv'
    $HttpCrlDP = Get-CACrlDistributionPoint | Where-Object { $_.Uri -Like "http://*/CertEnroll/*" }
    Remove-CACrlDistributionPoint -Uri $HttpCrlDP.Uri -Force
    Add-CACrlDistributionPoint -Uri $HttpCrlDP.URI -AddToCertificateCdp -AddToFreshestCrl -Force
    Restart-Service CertSvc
    Start-Sleep -Seconds 2 # Wait for CertSvc
    $CAConfigName = "$CAHostName\$CACommonName"
    $CertAdmin = New-Object -COM "CertificateAuthority.Admin"
    # PublishCRLs flags: RePublish = 0x10 (16), BaseCRL = 1, DeltaCRL = 2
    $CertAdmin.PublishCRLs($CAConfigName, $([DateTime]::UtcNow), 17)
    Get-ChildItem "$CertSrvPath\CertEnroll\*.crl" | ForEach-Object { certutil.exe -f -dspublish $_.FullName }
} -Session $VMSession -ArgumentList @($CAHostName, $CACommonName)
