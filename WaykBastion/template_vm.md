
# Wayk Bastion Lab

Azure Lab Services virtual machine base image:

 * Windows Server 2019 Datacenter
 * Windows 10 Enterprise, Version 20H2
 * Large (Nested virtualization) | 8 cores | 32GB RAM

In Server Manager, go to "Local Server" to change to following properties:

 * IE Enhanced Security Configuration: Off
 * Time zone: Eastern Time (US & Canada)

In the "Manage" menu, click "Server Manager Properties", then check "Do not start Server Manager automatically at logon".

Open elevated Windows PowerShell prompt.

Disable PowerShell console quick edit mode:

```powershell
Set-ItemProperty -Path "HKCU:\Console" -Name QuickEdit –Value 0
```

Update PowerShell default configuration and packages:

```powershell
Set-ExecutionPolicy Unrestricted -Force
Install-PackageProvider Nuget -Force
Install-Module -Name PowerShellGet -Force
Set-PSRepository -Name "PSGallery" -InstallationPolicy "Trusted"
```

Install chocolatey:

```powershell
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

Install chocolatey packages:

```powershell
choco install -y git
choco install -y vlc
choco install -y 7zip
choco install -y gsudo
choco install -y firefox
choco install -y vscode
choco install -y openssl
choco install -y kdiff3
choco install -y filezilla
choco install -y wireshark
choco install -y sysinternals
choco install -y sublimetext3
choco install -y notepadplusplus
```

Install Windows Terminal (Windows 10 only):

```powershell
choco install -y microsoft-windows-terminal
```

Install PowerShell modules:

```powershell
Install-Module RdmHelper -Scope AllUsers
Install-Module WaykClient -Scope AllUsers
Install-Module WaykBastion -Scope AllUsers
Install-Module DevolutionsGateway -Scope AllUsers
Install-Module Posh-ACME -Scope AllUsers
Install-Module PsHosts -Scope AllUsers
```

Install Remote Desktop Manager:

```powershell
Install-RdmPackage -Edition 'Free'
```

## Docker + Hyper-V (Windows 10)

```powershell
choco install -y docker-desktop
```

Download and install the [latest WSL2 Linux kernel](https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi).

Install the containers and Hyper-V Windows features:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName $("Microsoft-Hyper-V", "Containers") -All
```

## Docker + Hyper-V (Windows Server)

```powershell
Install-WindowsFeature -Name Containers
Install-Module -Name DockerMsftProvider -Force
Install-Package -Name docker -ProviderName DockerMsftProvider -Force
```

Install Hyper-V with management tools:

```powershell
Install-WindowsFeature -Name Hyper-V -IncludeManagementTools
```

Install OpenSSH client and server:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

Install PowerShell 7:

```powershell
iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"
```

Reboot (required for Docker, Hyper-V, OpenSSH, IIS):

```powershell
Restart-Computer
```

## IIS (Windows Server)

Open an elevated Windows PowerShell prompt:

Install IIS features:

```powershell
$Features = @(
    'Web-Server',
    'Web-WebSockets',
    'Web-Mgmt-Tools')

foreach ($Feature in $Features) {
    Install-WindowsFeature -Name $Feature
}
```

Install IIS URL Rewrite and Application Request Routing (ARR) modules:

```powershell
choco install -y urlrewrite
choco install -y iis-arr
```

Change default IIS configuration settings:

```powershell
& "$Env:WinDir\system32\inetsrv\appcmd.exe" set config `
    -section:system.webServer/proxy -preserveHostHeader:true /commit:apphost

& "$Env:WinDir\system32\inetsrv\appcmd.exe" set config `
    -section:system.WebServer/rewrite/globalRules -useOriginalURLEncoding:false /commit:apphost
```

Open an elevated PowerShell 7 prompt:

Enable PowerShell remoting over SSH:

```powershell
Install-Module -Name Microsoft.PowerShell.RemotingTools -Scope AllUsers
Set-Service -Name sshd -StartupType 'Automatic'
Start-Service sshd
Enable-SSHRemoting -Force
Restart-Service sshd
```

Prepare a new Wayk Bastion configuration:

```powershell
Add-HostEntry bastion.ad.it-help.ninja 127.0.0.1
New-WaykBastionConfig -Realm "it-help.ninja" -ExternalUrl "http://bastion.ad.it-help.ninja:4000"
Enter-WaykBastionConfig -ChangeDirectory
Update-WaykBastionImage
Start-WaykBastion
```

Open "http://bastion.ad.it-help.ninja:4000" in firefox.

For the initial login, use "wayk-admin" as the username, and "wayk-admin" as the password. You will be asked to change the password, simply use the same one as the host machine for the lab.

Stop Wayk Bastion, then register the system service wrapper:

```powershell
Stop-WaykBastion
Register-WaykBastionService
```

## Hyper-V Lab Environment

### Golden Image Creation

Create a Windows Server 2019 and Windows 10 virtual, customize them, run Windows updates, [then call sysprep to generalize them](https://www.altaro.com/hyper-v/templating-virtual-machines-with-hyper-v-manager/).

Download and transfer the latest Windows .iso files:

 * Windows Server 2019 (en_windows_server_2019_updated_jan_2021_x64_dvd_5ef22372.iso)
 * Windows 10 Enterprise (en_windows_10_business_editions_version_20h2_updated_jan_2021_x64_dvd_533a330d.iso)

Always check to see if a newer version of the .iso files updated with the latest patches is available, as it will save time for the post-install updating process.

Install Windows using the .iso files, then customize and install additional software (make heavy use of chocolatey to automate the process). Run Windows Update until the operating system is fully up-to-date.

Cleanup the Windows Update files to reduce the image size:

```powershell
dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase
```

Disable Windows updates:

```powershell
Stop-service wuauserv | Set-Service -StartupType Disabled
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 1 -Type DWORD
```

As the last step, launch [sysprep](https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/sysprep-process-overview) to generalize the image:

```powershell
& "$Env:WinDir\System32\Sysprep\sysprep.exe" /oobe /generalize /shutdown /mode:vm
```

The VM will shutdown automatically, after which the VHDX contains a clean Windows image in a "factory reset" state. *Do not start* the virtual machine attached to the clean disk. You can delete the virtual machine and keep only the VHDX file.

[Shrink the VHDX file](https://www.nakivo.com/blog/shrink-compact-virtual-hard-disks-hyper-v/) to reduce its total size and remove empty segments of data. Save the resulting VHDX files for later, they are the golden images upon which all virtual machines will be created.

### Hyper-V Virtual Disks

For each VM, create [Hyper-V differencing disks](https://www.altaro.com/hyper-v/hyper-v-differencing-disks-explained/) linked to the parent golden images.

 * Disk format: VHDX
 * Disk type: Differencing
 * Name: use virtual machine name + .vhdx
 * Location: use default virtual hard disk path
 * Parent Location: path to parent VHDX file (golden image)

It is important to understand that the golden image *cannot* be changed once a differencing disk has been created to use it. The new child VHDX file will only contain the bytes that have changed, making it easier to fit a large number of VMs inside constrained storage space.

### Hyper-V Virtual Switch

In the Hyper-V virtual switch manager, create a new switch called "Internal Switch" using the "Internal Network" connection type. This switch will be used by the Hyper-V host and all the virtual machine guests. For all new virtual machines, click "Add Hardware" and add the internal switch, leaving the default switch for internet access.

### Hyper-V Hardware Configuration

Assign 4GB of RAM to all VMs, or enable dynamic memory with range between 2GB and 6GB of RAM. If you enable dynamic memory, use a higher memory weight for the domain controller VM.

Assign 4 virtual processors to all VMs. One virtual processor (the default) is usually never enough to get decent performance in the VM.

### Hyper-V Management Configuration

[Disable checkpoints by default](https://www.nakivo.com/hyper-v-backup/need-know-hyper-v-checkpoints/). If you have existing checkpoints, [delete them correctly](https://support.hostway.com/hc/en-us/articles/360001685039-How-to-delete-checkpoints-using-Hyper-V).

Checkpoints are very useful and enable restoring a virtual machine in a previous state, but they take a lot of disk space. It is recommended to create manual checkpoints on the domain controller VM before important operations that are hard to revert.

Change the [Automatic Stop Action](https://petri.com/hyper-v-automatic-start-and-stop) to "Shut down the guest operating system" instead of "Save the virtual machine state".

Saving the virtual machine state is also a useful feature in production, but it preallocates disk space equal to the amount of RAM allocated to the VM. It is not needed for testing, so disable it to save space.

### Hyper-V Network Configuration

Create a Hyper-V internal adapter that will be used for the LAN between the Hyper-V host and the lab VMs:

```powershell
New-VMSwitch –SwitchName "LAN Switch" –SwitchType Internal –Verbose
```

[Set up a NAT network](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/setup-nat-network). Create a new Hyper-V switch for localhost NAT:

```powershell
New-VMSwitch –SwitchName "NAT Switch" –SwitchType Internal –Verbose
$NetAdapter = Get-NetAdapter | Where-Object { $_.Name -Like "*(NAT Switch)" }
New-NetIPAddress -IPAddress 10.9.0.1 -PrefixLength 24 -InterfaceIndex $NetAdapter.IfIndex
New-NetNat –Name NatNetwork –InternalIPInterfaceAddressPrefix 10.9.0.0/24
```

Download [pfSense Community Edition](https://www.pfsense.org/download/) and extract the .iso file it contains.

Create a new pfSense virtual machine with 2GB of RAM, 2 vCPUs and a 32GB virtual hard disk. Create two network adapters attached (in order) to the NAT switch and the LAN switch that were just created. The NAT switch will be used for the WAN side, and the LAN switch will be used for LAN side in the new router VM.

At the pfSense prompt, select 1 to assign interfaces:

```bash
Valid interfaces are:

hn0     00:15:5d:19:7f:09    (up) Hyper-V Network Interface
hn1     00:15:5d:19:7f:0a    (up) Hyper-V Network Interface

Do VLANs need to be set up first?
If VLANs will not be used, or only for optional interfaces, it is typical to say no here and use the webConfigurator to configure VLANs later, if required.

Should VLANs be set up now [y|n]? n

If the names of the interfaces are not known, auto-detection can be used instead. To use auto-detection, please disconnect all interfaces before pressing 'a' to begin the process.

Enter the WAN interface name or 'a' for auto-detection
(hn0 hn1 or a): hn0

Enter the LAN interface name or 'a' for auto-detection
NOTE: this enables full Firewalling/NAT mode.
(hn1 a or nothing if finished): hn1

The interfaces will be assigned as follows:

WAN  -> hn0
LAN  -> hn1

Do you want to proceed [y|n]? y

Writing configuration... done.
One moment while the settings are reloading... done!
```

At the pfSense prompt, select 2 to configure the WAN interface:

```bash
Available interfaces:

1 - WAN (hn0 - static)
2 - LAN (hn1 - static)

Enter the number of the interface you wish to configure: 1

Configure IPv4 address WAN interface via DHCP? (y/n) n

Enter the new WAN IPv4 address. Press <ENTER> for none:
> 10.9.0.2

Subnet masks are entered as bit counts (as in CIDR notation) in pfSense.
e.g. 255.255.255.0 = 24
     255.255.0.0   = 16
     255.0.0.0     = 8

Enter the new WAN IPv4 subnet bit count (1 to 31):
> 24

For a WAN, enter the new WAN IPv4 upstream gateway address.
For a LAN, press <ENTER> for none:
> 10.9.0.1

Configure IPv6 address WAN interface via DHCP6? (y/n) n

Enter the new WAN IPv6 address. Press <ENTER> for none:
> 

Please wait while the changes are saved to WAN...

The IPv4 WAN address has been set to 10.9.0.2/24

Press <ENTER> to continue.
```

At the pfSense prompt, select 2 to configure the LAN interface:

```bash
Available interfaces:

1 - WAN (hn0 - static)
2 - LAN (hn1 - static)

Enter the number of the interface you wish to configure: 2

Enter the new LAN IPv4 address. Press <ENTER> for none:
> 10.10.0.1

Subnet masks are entered as bit counts (as in CIDR notation) in pfSense.
e.g. 255.255.255.0 = 24
     255.255.0.0   = 16
     255.0.0.0     = 8

Enter the new WAN IPv4 subnet bit count (1 to 31):
> 24

For a WAN, enter the new WAN IPv4 upstream gateway address.
For a LAN, press <ENTER> for none:
> 

Enter the new LAN IPv6 address. Press <ENTER> for none:
>

Do you want to enable the DHCP server on LAN? (y/n) y
Enter the start address of the IPv4 client address range: 10.10.0.100
Enter the end address of the IPv4 client address range: 10.10.0.199

Please wait while the changes are saved to LAN...

The IPv4 LAN address has been set to 10.10.0.1/24
You can now access the webConfigurator by opening the following URL in your web browser:
        http://10.10.0.1/

Press <ENTER> to continue.
```

At the pfSense prompt, select 14 to enable the secure shell (sshd):

```bash
SSHD is currently disabled. Would you like to enable it? [y/n] y

Writing configuration... done.

Enabling SSHD...
Reloading firewall rules. done.
```

Extract the list of MAC addresses for all the VMs to create DHCP reservations in pfSense:

```powershell
Get-VMNetworkAdapter -VMName IT-HELP-* | `
	Where-Object { $_.SwitchName -eq "LAN Switch" } | `
	ForEach-Object { [PSCustomObject]@{ VMName = $_.VMName
	MacAddress = $_.MacAddress -Split '(.{2})' -Match '.' -Join ':' } }

VMName       MacAddress
------       ----------
IT-HELP-WAYK 00:15:5D:19:7F:07
IT-HELP-DC   00:15:5D:19:7F:05
IT-HELP-DVLS 00:15:5D:19:7F:0B
```

Open the pfSense web interface (http://10.10.0.1/) and login with the default user "admin" and password "pfsense". Change the default password with a generated one and save it.

In the pfSense menu, select **Services**, go to **DHCP Server**. Make sure that **Enable DHCP server on LAN interface** is checked, and review the following under **General Options**:

 * **Subnet**: 10.10.0.0
 * **Subnet mask**: 255.255.255.0
 * **Available range**: 10.10.0.1 - 10.10.0.254
 * **Range**: from 10.10.0.100 to 10.10.0.199

Under **Server**, set the following DNS servers: 1.1.1.1, 1.0.0.1. This list of DNS servers will be pushed through DHCP automatically.

At the bottom of the page, under **DHCP Static Mappings**, create entries using the MAC addresses extracted earlier:

|MAC Address      |IP Address  |Hostname    |
|-----------------|------------|------------|
|00:15:5D:19:7F:05|10.10.0.10  |IT-HELP-DC  |
|00:15:5D:19:7F:0B|10.10.0.21  |IT-HELP-DVLS|
|00:15:5D:19:7F:07|10.10.0.22  |IT-HELP-WAYK|

Click **Save**. With the DHCP server configured, there should be no need for static IP configurations in each VM.

In the pfSense menu, select **Services**, go to **Interfaces** then select **WAN**. Review the **Static IPv4 Configuration**:

 * **IPv4 Address**: 10.9.0.2 /24
 * **IPv4 Upstream gateway**: WANGW - 10.9.0.1

In the pfSense menu, select **Status** then **Gateways**. Make sure that "WANGW" is marked as the default gateway, with IP address 10.9.0.1 and that the status is **Online**. This is very important, otherwise the router VM will not provide internet access in the local network.

In the pfSense menu, select **Services**, go to **Interfaces** then select **LAN**. Review the **Static IPv4 Configuration**:

 * **IPv4 Address**: 10.10.0.1 /24
 * **IPv4 Upstream gateway**: None

There should be no gateway configuration on the LAN interface, so remove it if you configured one by mistake.

Allow ICMP echo reply (ping) on all VMs and the host:

```powershell
New-NetFirewallRule -Name 'ICMPv4' -DisplayName 'ICMPv4' `
    -Description 'Allow ICMPv4' -Profile Any -Direction Inbound -Action Allow `
    -Protocol ICMPv4 -Program Any -LocalAddress Any -RemoteAddress Any
```

Enable RDP for all VMs so you can connect without using the IP address instead of the Hyper-V manager:

```powershell
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

Connect to the domain controller VM (IT-HELP-DC) and make sure that it correctly obtained its IP address through DHCP (10.10.0.10) and that DNS can resolve google.com (nslookup google.com).

Install the Active Directory Domain Services feature including the management tools:

```powershell
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
```

Create the new Active Directory forest. This a point of no return, so creating a manual Hyper-V checkpoint is recommended. Make sure that the computer name ($Env:ComputerName) is set to "IT-HELP-DC" because it cannot be changed later. Generate a password for the Active Directory safe administrator and use it when prompted by the `Install-ADDSForest` command.

```powershell
Install-ADDSForest -DomainName "ad.it-help.ninja" -DomainNetbiosName "IT-HELP" -InstallDNS
```

The IT-HELP-DC will reboot to complete the domain controller promotion. The process can take at least 5 minutes to complete, so be patient. The domain controller VM should now become the DNS server used by all other VMs inside the local network, so the pfSense DHCP Server and DNS Resolver configuration need to be updated.

In the pfSense menu, select **Services**, then **DNS Resolver**. Make sure that **Enable DNS Resolver** is unchecked, because pfSense should **not** act as the DNS server.

In the pfSense menu, select **Services**, then **DHCP Server**. In the **Servers** section, remove the previous list of DNS servers (1.1.1.1, 1.0.0.1) and enter the IP address of the domain controller VM (10.10.0.10 for IT-HELP-DC). All other VMs in the local network will now automatically point to the correct DNS server required for Active Directory to work.

## Certificate Authority

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
PS > $Certificate = Get-ChildItem "cert:\LocalMachine\My" | `
    Where-Object { $_.Subject -eq "CN=bastion.ad.it-help.ninja" } | Select-Object -First 1
PS > $Password = ConvertTo-SecureString -String "cert123!" -Force -AsPlainText
PS > Export-PfxCertificate -Cert $Certificate -ChainOption BuildChain -FilePath ".\cert.pfx" -Password $Password
```

Once the certificate is exported, it can be removed from the certificate store:

```powershell
Get-ChildItem "cert:\LocalMachine\My" | `
    Where-Object { $_.Subject -eq "CN=bastion.ad.it-help.ninja" } | `
    Remove-Item
```
