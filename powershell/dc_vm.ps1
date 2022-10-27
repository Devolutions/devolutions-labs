. .\common.ps1

$VMAlias = "DC"
$VMNumber = $DCVMNumber
$VMName = $LabPrefix, $VMAlias -Join "-"
$IpAddress = Get-DLabIpAddress $LabNetworkBase $VMNumber

New-DLabVM $VMName -Password $DomainPassword -MemoryBytes 2GB -ProcessorCount 2 -Force
Start-DLabVM $VMName

Wait-DLabVM $VMName 'PSDirect' -Timeout 600 -UserName $LocalUserName -Password $DomainPassword
$VMSession = New-DLabVMSession $VMName -UserName $LocalUserName -Password $DomainPassword

Set-DLabVMNetAdapter $VMName -VMSession $VMSession `
    -SwitchName $SwitchName -NetAdapterName $NetAdapterName `
    -IPAddress $IPAddress -DefaultGateway $DefaultGateway `
    -DnsServerAddress $DnsServerForwarder

Write-Host "Test Internet connectivity"

$ConnectionTest = Invoke-Command -ScriptBlock {
    1..10 | ForEach-Object {
        Start-Sleep -Seconds 1;
        Resolve-DnsName -Name "www.google.com" -Type 'A' -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
    } | Where-Object { $_ -ne $null } | Select-Object -First 1
} -Session $VMSession

if (-Not $ConnectionTest) {
    throw "virtual machine doesn't have Internet access - fail early"
}

Write-Host "Promote Windows Server to domain controller"

Invoke-Command -ScriptBlock { Param($DomainName, $DomainNetbiosName, $SafeModeAdministratorPassword)
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    $SafeModeAdministratorPassword = ConvertTo-SecureString $SafeModeAdministratorPassword -AsPlainText -Force
    $Params = @{
        DomainName = $DomainName;
        DomainNetbiosName = $DomainNetbiosName;
        SafeModeAdministratorPassword = $SafeModeAdministratorPassword;
        InstallDNS = $true;
        SkipPreChecks = $true;
    }
    Install-ADDSForest @Params -Force
} -Session $VMSession -ArgumentList @($DomainName, $DomainNetbiosName, $SafeModeAdministratorPassword)

Wait-DLabVM $VMName 'Reboot' -Timeout 120
$BootTime = Get-Date

Wait-DLabVM $VMName 'PSDirect' -Timeout 600 -UserName $DomainUserName -Password $DomainPassword
$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

Write-Host "Wait for domain controller promotion to complete (about 10 minutes)"

# wait a good 5-10 minutes for the domain controller promotion to complete after reboot

Invoke-Command -ScriptBlock { Param($BootTime)
    while (-Not [bool]$(Get-EventLog -LogName "System" `
        -Source "Microsoft-Windows-GroupPolicy" -InstanceId 1502 `
        -After $BootTime -ErrorAction SilentlyContinue)) {
            Start-Sleep 10
    }
} -Session $VMSession -ArgumentList @($BootTime)

Write-Host "Create read-only network share"

Invoke-Command -ScriptBlock {
    New-Item "C:\Shared" -ItemType "Directory" | Out-Null
    New-SmbShare -Name "Shared" -Path "C:\Shared" -FullAccess 'ANONYMOUS LOGON','Everyone'
} -Session $VMSession

Write-Host "Disable Active Directory default password expiration policy"

Invoke-Command -ScriptBlock {
    Get-ADDefaultDomainPasswordPolicy -Current LoggedOnUser | Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 00.00:00:00
} -Session $VMSession

Write-Host "Create ProtectedUser test account in Protected Users group"

$ProtectedUserName = "ProtectedUser"
$ProtectedUserPassword = "Protected123!"

Invoke-Command -ScriptBlock { Param($ProtectedUserName, $ProtectedUserPassword)
    $SafeProtectedUserPassword = ConvertTo-SecureString $ProtectedUserPassword -AsPlainText -Force
    $DomainDnsName = $Env:UserDnsDomain.ToLower()
    
    $Params = @{
        Name = $ProtectedUserName;
        GivenName = "Protected";
        Surname = "User";
        SamAccountName = "ProtectedUser";
        UserPrincipalName = "ProtectedUser@$DomainDnsName";
        AccountPassword = $SafeProtectedUserPassword;
        PasswordNeverExpires = $true;
        Description = "User member of the Protected Users group";
        Enabled = $true;
    }
    $ProtectedUser = New-ADUser @Params -PassThru
    
    Add-ADGroupMember -Identity "Protected Users" -Members @($ProtectedUser)
    Add-ADGroupMember -Identity "Domain Admins" -Members @($ProtectedUser)
} -Session $VMSession -ArgumentList @($ProtectedUserName, $ProtectedUserPassword)

Write-Host "Install Active Directory Certificate Services"

Invoke-Command -ScriptBlock { Param($DomainName, $UserName, $Password, $CACommonName)
    $ConfirmPreference = "High"
    Install-WindowsFeature -Name AD-Certificate -IncludeManagementTools
    Install-WindowsFeature -Name ADCS-Online-Cert
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
    $LdapCrlDP = Get-CACrlDistributionPoint | Where-Object { $_.Uri -Like "ldap://*" }
    Remove-CACrlDistributionPoint -Uri $LdapCrlDP.Uri -Force
    $HttpCrlDP = Get-CACrlDistributionPoint | Where-Object { $_.Uri -Like "http://*/CertEnroll/*" }
    Remove-CACrlDistributionPoint -Uri $HttpCrlDP.Uri -Force
    Add-CACrlDistributionPoint -Uri $HttpCrlDP.URI -AddToCertificateCdp -AddToFreshestCrl -Force
    $LdapAIA = Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -Like "ldap://*" }
    Remove-CAAuthorityInformationAccess -Uri $LdapAIA.Uri -Force
    Restart-Service CertSvc
    Start-Sleep -Seconds 10 # Wait for CertSvc
    $CAConfigName = "$CAHostName\$CACommonName"
    $CertAdmin = New-Object -COM "CertificateAuthority.Admin"
    # PublishCRLs flags: RePublish = 0x10 (16), BaseCRL = 1, DeltaCRL = 2
    $CertAdmin.PublishCRLs($CAConfigName, $([DateTime]::UtcNow), 17)
    Get-ChildItem "$CertSrvPath\CertEnroll\*.crl" | ForEach-Object { certutil.exe -f -dspublish $_.FullName }
} -Session $VMSession -ArgumentList @($CAHostName, $CACommonName)

Write-Host "Requesting RDP server certificate"

Request-DLabRdpCertificate $VMName -VMSession $VMSession `
    -CAHostName $CAHostName -CACommonName $CACommonName

Write-Host "Initializing PSRemoting"

Initialize-DLabPSRemoting $VMName -VMSession $VMSession

Write-Host "Initializing VNC server"

Initialize-DLabVncServer $VMName -VMSession $VMSession

Write-Host "Configuring LDAPS certificate"

Invoke-Command -ScriptBlock {
    $FullComputerName = [System.Net.DNS]::GetHostByName($Env:ComputerName).HostName
    $Certificate = Get-ChildItem "cert:\LocalMachine\My" | Where-Object {
        ($_.Subject -eq "CN=$FullComputerName") -and ($_.Issuer -ne $_.Subject)
    } | Select-Object -First 1
    $CertificateThumbprint = $Certificate.Thumbprint
    
    $LocalCertStore = 'HKLM:/Software/Microsoft/SystemCertificates/My/Certificates'
    $NtdsCertStore = 'HKLM:/Software/Microsoft/Cryptography/Services/NTDS/SystemCertificates/My/Certificates'
    if (-Not (Test-Path $NtdsCertStore)) {
        New-Item $NtdsCertStore -Force
    }
    Copy-Item -Path "$LocalCertStore/$CertificateThumbprint" -Destination $NtdsCertStore

    $dse = [adsi]'LDAP://localhost/rootDSE'
    [void]$dse.Properties['renewServerCertificate'].Add(1)
    $dse.CommitChanges()
} -Session $VMSession
