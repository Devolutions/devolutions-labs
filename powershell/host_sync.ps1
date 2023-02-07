#Requires -RunAsAdministrator
#Requires -PSEdition Core

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

function Set-HostEntrySafe
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Name,
        [Parameter(Mandatory=$true,Position=1)]
        [string] $Address,
        [switch] $Force
    )

    $success = $false
    while (-Not $success) {
        try {
            Set-HostEntry -Name $Name -Address $Address -Force:$Force
            $success = $true
        } catch [System.IO.IOException] {
            # The process cannot access the file because it is being used by another process.
            Start-Sleep 1
        } catch {
            throw $_.Exception
        }
    }
}

$HostEntries | Where-Object { $_.HostName -Like "$LabPrefix-*" } | ForEach-Object {
    $MachineName = $_.HostName.ToUpper()
    $MachineFQDN = "$MachineName.$DnsZoneName"
    Set-HostEntrySafe -Name $MachineName -Address $_.Address -Force
    Set-HostEntrySafe -Name $MachineFQDN -Address $_.Address -Force
}

$HostEntries | Where-Object { $_.HostName -NotLike "$LabPrefix-*" } | ForEach-Object {
    $HostFQDN = "$($_.HostName).$DnsZoneName"
    Set-HostEntrySafe -Name $HostFQDN -Address $_.Address -Force
}

# Add DNS client rule for lab DNS suffix

Get-DnsClientNrptRule | Where-Object { $_.Namespace -eq ".$DnsZoneName" } | Remove-DnsClientNrptRule -Force
Add-DnsClientNrptRule -Namespace ".$DnsZoneName" -NameServers @($DnsServerAddress)

# Synchronize trusted root CAs

$VMAlias = "DC"
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

# Flush CRL cache

& certutil.exe "-urlcache" "crl" "delete"
& certutil.exe "-setreg" "chain\ChainCacheResyncFiletime" "@now"

# Synchronize WinRM client trusted hosts

$LabTrustedHost = "*.$DnsZoneName"
$TrustedHostsValue = $(Get-Item "WSMan:localhost\Client\TrustedHosts").Value
if ($TrustedHostsValue -ne '*') {
    if ([string]::IsNullOrEmpty($TrustedHostsValue)) {
        $TrustedHostsValue = $LabTrustedHost
    } else {
        $TrustedHosts = $TrustedHostsValue -Split ',' | ForEach-Object { $_.Trim() }
        if (-Not $TrustedHosts.Contains($LabTrustedHost)) {
            $TrustedHosts += @($LabTrustedHost)
        }
        $TrustedHostsValue = $TrustedHosts -Join ','
    }
    Set-Item "WSMan:localhost\Client\TrustedHosts" -Value $TrustedHostsValue -Force
}
