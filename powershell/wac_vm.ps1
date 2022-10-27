. .\common.ps1

$VMAlias = "WAC"
$VMNumber = 8
$VMName = $LabPrefix, $VMAlias -Join "-"
$IpAddress = Get-DLabIpAddress $LabNetworkBase $VMNumber

New-DLabVM $VMName -Password $LocalPassword -Force
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

Write-Host "Creating DNS record for Windows Admin Center"

$DnsName = "wac"
$WacFQDN = "$DnsName.$DomainName"
$CertificateFile = "~\Documents\cert.pfx"
$CertificatePassword = "cert123!"

Invoke-Command -ScriptBlock { Param($DnsName, $DnsZoneName, $IPAddress, $DnsServer)
    Add-DnsServerResourceRecordA -Name $DnsName -ZoneName $DnsZoneName -IPv4Address $IPAddress -AllowUpdateAny -ComputerName $DnsServer
} -Session $VMSession -ArgumentList @($DnsName, $DomainName, $IPAddress, $DCHostName)

Write-Host "Creating SPN for Windows Admin Center DNS name"

$SpnAccountName = "$DomainNetbiosName\$VMName"

Invoke-Command -ScriptBlock { Param($WacFQDN, $SpnAccountName)
    & "setspn" "-A" "HTTP/$WacFQDN" $SpnAccountName
} -Session $VMSession -ArgumentList @($WacFQDN, $SpnAccountName)

Write-Host "Requesting certificate for Windows Admin Center"

Request-DLabCertificate $VMName -VMSession $VMSession `
    -CommonName $WacFQDN `
    -CAHostName $CAHostName -CACommonName $CACommonName `
    -CertificateFile $CertificateFile -Password $CertificatePassword

Write-Host "Adding Windows Admin Center firewall exceptions"

Invoke-Command -ScriptBlock {
    $Params = @{
        Profile = "Any";
        LocalPort = 6516;
        Protocol = "TCP";
        Action = "Allow";
        DisplayName = "Windows Admin Center";
    }
    New-NetFirewallRule -Direction Outbound @Params | Out-Null
    New-NetFirewallRule -Direction Inbound @Params | Out-Null
} -Session $VMSession

Write-Host "Installing Windows Admin Center"

# https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/deploy/install

Invoke-Command -ScriptBlock { Param($WacFQDN, $CertificateFile, $CertificatePassword)
    $ProgressPreference = 'SilentlyContinue'
    $WacMsi = "$(Resolve-Path ~)\Documents\WAC.msi"
    Invoke-WebRequest 'https://aka.ms/WACDownload' -OutFile $WacMsi
    $CertificatePassword = ConvertTo-SecureString $CertificatePassword -AsPlainText -Force
    $Params = @{
        FilePath          = $CertificateFile;
        CertStoreLocation = "cert:\LocalMachine\My";
        Password          = $CertificatePassword;
        Exportable        = $true;
    }
    $Certificate = Import-PfxCertificate @Params
    $Thumbprint = $Certificate.Thumbprint
    $MsiArgs = @("/i", $WacMsi, "/qn", "/L*v", "log.txt",
        "SME_PORT=6516", "SME_THUMBPRINT=$Thumbprint", "SSL_CERTIFICATE_OPTION=installed")
    Start-Process msiexec.exe -Wait -ArgumentList $MsiArgs
} -Session $VMSession -ArgumentList @($WacFQDN, $CertificateFile, $CertificatePassword)
