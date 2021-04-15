
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

Make firefox accept enterprise root CAs:

```powershell
$RegPath = "HKLM:\Software\Policies\Mozilla\Firefox\Certificates"
New-Item -Path $RegPath -Force | Out-Null
New-ItemProperty -Path $RegPath -Name ImportEnterpriseRoots -Value 1 -Force | Out-Null
```

Install PowerShell modules:

```powershell
Install-Module Microsoft.PowerShell.SecretManagement -Scope AllUsers
Install-Module Microsoft.PowerShell.SecretStore -Scope AllUsers
```

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

You can also create the differencing disks in bulk with PowerShell:

```powershell
$ParentDiskPath = "C:\Hyper-V\Golden Images\Windows Server 2019 Standard.vhdx"
$VirtualHardDisks = "C:\Hyper-V\Virtual Hard Disks"
$VMNames = @('IT-HELP-DC', 'IT-HELP-CA', 'IT-HELP-WAYK', 'IT-HELP-DVLS')
foreach ($VMName in $VMNames) {
    New-VHD -Path "$VirtualHardDisks\$VMName.vhdx" -ParentPath $ParentDiskPath
}
```

Create the VMs:

```powershell
foreach ($VMName in $VMNames) {
    New-VM -Name $VMName -MemoryStartupBytes 4GB `
        -VHDPath "$VirtualHardDisks\$VMName.vhdx" `
        -SwitchName "LAN Switch"
    
    Set-VM -Name $VMName `
        -ProcessorCount 4 `
        -AutomaticStopAction Shutdown `
        -CheckpointType Disabled
}
```

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

Configure [pfSense router VM](pfSense.md) for the lab network environment.

Configure the [IT-HELP-DC domain controller VM](IT-HELP-DC.md) before going any further.

Start the other VMs, rename them using `Rename-Computer`, then join them to the new domain. You will be prompted for the domain admin credentials:

```powershell
Add-Computer -DomainName "ad.it-help.ninja" -NewName "IT-HELP-CA" -Restart
```

Configure the [IT-HELP-CA certificate authority VM](IT-HELP-CA.md).

Configure the [IT-HELP-WAYK Wayk Bastion VM](IT-HELP-WAYK.md).
