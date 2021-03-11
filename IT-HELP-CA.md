# IT-HELP-CA VM

## Creating Certificate Authority

Rename the computer and join it to the domain:

```powershell
Add-Computer -DomainName "ad.it-help.ninja" -NewName "IT-HELP-CA" -Restart
```

Install Active Directory Certificate Services (AD CS):

```powershell
Install-WindowsFeature -Name AD-Certificate -IncludeManagementTools
```

```powershell
Install-AdcsCertificationAuthority -CAType EnterpriseRootCa `
    -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
    -KeyLength 2048 -HashAlgorithmName SHA256
```

Force a group policy update to update the trusted root CA certificates in Active Directory:

```powershell
gpupdate /force
```

Firefox does not trust the system trusted root CA certificates by default and [needs to be configured to trust them](https://support.mozilla.org/en-US/kb/setting-certificate-authorities-firefox).

## Requesting Wayk Bastion Certificate

Request a new certificate from Active Directory Certificate Services. Start by creating a new file called "cert.inf":

```
[NewRequest] 
Subject = "CN=bastion.ad.it-help.ninja" 
Exportable = TRUE
KeyLength = 2048
KeySpec = 1 ; Key Exchange – Required for encryption
KeyUsage = 0xA0 ; Digital Signature, Key Encipherment
MachineKeySet = TRUE 

[RequestAttributes]
CertificateTemplate="WebServer"

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.1 ; Server Authentication
OID=1.3.6.1.5.5.7.3.2 ; Client Authentication

[Extensions]
2.5.29.17 = "{text}" ; SAN - Subject Alternative Name
_continue_ = "dns=bastion.ad.it-help.ninja&"
```

Convert the certificate request config file into a certificate signing request (CSR):

```powershell
certreq.exe -new cert.inf cert.csr
```

Submit the certificate signing request and obtain the certificate without the private key:

```powershell
certreq.exe -submit cert.csr cert.cer
```

Accept the certificate signing request and import private key into certificate store:

```powershell
certreq.exe -accept cert.cer
```

Export the new certificate including the private key in .pfx format:

```powershell
$Certificate = Get-ChildItem "cert:\LocalMachine\My" | `
    Where-Object { $_.Subject -eq "CN=bastion.ad.it-help.ninja" } | Select-Object -First 1
$Password = ConvertTo-SecureString -String "cert123!" -Force -AsPlainText
Export-PfxCertificate -Cert $Certificate -ChainOption BuildChain -FilePath ".\cert.pfx" -Password $Password
```

Once the certificate is exported, it can be removed from the certificate store:

```powershell
Get-ChildItem "cert:\LocalMachine\My" | `
    Where-Object { $_.Subject -eq "CN=bastion.ad.it-help.ninja" } | `
    Remove-Item
```
