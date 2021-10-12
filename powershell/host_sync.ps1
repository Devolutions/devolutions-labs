
. .\common.ps1

$VMAlias = "DC"
$VMName = $LabPrefix, $VMAlias -Join "-"

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

# Synchronize DNS records with hosts file

$IpFilter = $LabNetworkBase -Replace "^(\d+)\.(\d+)\.(\d+).(\d+)$", "`$1.`$2.`$3.`*"

$HostEntries = Invoke-Command -ScriptBlock { Param($DnsZoneName, $IpFilter)
    Get-DnsServerResourceRecord -ZoneName $DnsZoneName -RRType 'A' | `
    Where-Object { ($_.RecordData.IPv4Address -Like $IpFilter) `
        -and ($_.HostName -ne '@') -and ($_.HostName -NotLike '*DnsZones') } | `
    ForEach-Object {
        [PSCustomObject]@{
            HostName = $_.HostName;
            Address = $_.RecordData.IPv4Address.ToString();
        }
    }
} -Session $VMSession -ArgumentList @($DnsZoneName, $IpFilter)

$HostEntries | Where-Object { $_.HostName -Like "$LabPrefix-*" } | ForEach-Object {
    $MachineName = $_.HostName.ToUpper()
    $MachineFQDN = "$MachineName.$DnsZoneName"
    Set-HostEntry -Name $MachineName -Address $_.Address -Force
    Set-HostEntry -Name $MachineFQDN -Address $_.Address -Force
}

$HostEntries | Where-Object { $_.HostName -NotLike "$LabPrefix-*" } | ForEach-Object {
    $HostFQDN = "$($_.HostName).$DnsZoneName"
    Set-HostEntry -Name $HostFQDN -Address $_.Address -Force
}

# Synchronize trusted root CAs

$VMAlias = "CA"
$VMName = $LabPrefix, $VMAlias -Join "-"

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

$CertSubject = (@("CN=$CAMachineName") + @($DnsZoneName -Split '\.' | ForEach-Object { "DC=$_" })) -Join ", "

[byte[]] $CACert = Invoke-Command -ScriptBlock { Param($CertSubject)
    $MyCert = Get-ChildItem "cert:\LocalMachine\My" | Where-Object { $_.Subject -Like $CertSubject }
    $RootCert = Get-ChildItem "cert:\LocalMachine\Root" | Where-Object {
        $_.Subject -Like $CertSubject -and $_.Thumbprint -eq $MyCert.Thumbprint } | Select-Object -First 1
    $RootCert.GetRawCertData()
} -Session $VMSession -ArgumentList @($CertSubject)

$CACertPath = "~\ca-cert.cer"
$AsByteStream = if ($PSEdition -eq 'Core') { @{AsByteStream = $true} } else { @{'Encoding' = 'Byte'} }
Set-Content -Value $CACert -Path $CACertPath @AsByteStream -Force

$CertificateFile = Resolve-Path $CACertPath
$Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificateFile)

if (-Not (Get-ChildItem "Cert:\LocalMachine\Root" |
        Where-Object { $_.Thumbprint -eq $Certificate.Thumbprint })) {
    Import-Certificate -FilePath $CACertPath -CertStoreLocation "Cert:\LocalMachine\Root"
}

# Synchronize WinRM client trusted hosts

$LabTrustedHost = "*.$DnsZoneName"
$TrustedHostsValue = $(Get-Item "WSMan:localhost\Client\TrustedHosts").Value
if ($TrustedHostsValue -ne '*') {
    [string[]]$TrustedHosts = $TrustedHostsValue -Split ',' | ForEach-Object { $_.Trim() }
    if (-Not $TrustedHosts.Contains($LabTrustedHost)) {
        $TrustedHosts += @($LabTrustedHost)
    }
    $TrustedHostsValue = $TrustedHosts -Join ','
    Set-Item "WSMan:localhost\Client\TrustedHosts" -Value $TrustedHostsValue -Force
}
