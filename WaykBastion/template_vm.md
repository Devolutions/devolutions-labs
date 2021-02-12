
# Wayk Bastion Lab

Azure Lab Services virtual machine base image:

 * Windows Server 2019 Datacenter
 * Large (Nested virtualization) | 8 cores | 32GB RAM

In Server Manager, go to "Local Server" to change to following properties:

 * IE Enhanced Security Configuration: Off
 * Time zone: Eastern Time (US & Canada)

In the "Manage" menu, click "Server Manager Properties", then check "Do not start Server Manager automatically at logon".

Open elevated Windows PowerShell prompt.

Update PowerShell default configuration and packages:

```powershell
Install-PackageProvider Nuget -Force
Install-Module -Name PowerShellGet -Force
Set-PSRepository -Name "PSGallery" -InstallationPolicy "Trusted"
```

Install chocolatey:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

Install chocolatey packages:

```powershell
choco install -y git
choco install -y vlc
choco install -y 7zip
choco install -y firefox
choco install -y vscode
choco install -y openssl
choco install -y kdiff3
choco install -y wireshark
choco install -y sysinternals
choco install -y sublimetext3
choco install -y notepadplusplus
choco install -y paint.net
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

Install Docker for Windows:

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

Install PowerShell 7:

```powershell
iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"
```

Reboot (required for Docker, Hyper-V, OpenSSH, IIS):

```powershell
Restart-Computer
```

Open an elevated Windows PowerShell prompt:

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
Add-HostEntry bastion.it-help.loco 127.0.0.1
New-WaykBastionConfig -Realm "it-help.loco" -ExternalUrl "http://bastion.it-help.loco:4000"
Enter-WaykBastionConfig -ChangeDirectory
Update-WaykBastionImage
Start-WaykBastion
```

Open "http://bastion.it-help.loco:4000" in firefox.

For the initial login, use "wayk-admin" as the username, and "wayk-admin" as the password. You will be asked to change the password, simply use the same one as the host machine for the lab.

Stop Wayk Bastion, then register the system service wrapper:

```powershell
Stop-WaykBastion
Register-WaykBastionService
```

Install [AutomatedLab](https://automatedlab.org/) PowerShell module:

```powershell
Install-Module AutomatedLab -AllowClobber -Scope AllUsers
```

Initialize the lab sources folder:

```powershell
New-LabSourcesFolder -Drive C
```

Transfer ISO files to C:\LabSources\ISOs:

 * Windows Server 2019 (en_windows_server_2019_updated_jan_2021_x64_dvd_5ef22372.iso)
 * Windows 10 (en_windows_10_business_editions_version_20h2_updated_jan_2021_x64_dvd_533a330d.iso)

Make sure that the ISOs can be found by AutomatedLab:

```powershell
Get-LabAvailableOperatingSystem
```

Create a new lab:

```powershell
New-LabDefinition -Name "ItHelpLab" `
    -DefaultVirtualizationEngine HyperV

Add-LabVirtualNetworkDefinition -Name "ItHelpNetwork" `
    -AddressSpace "192.168.1.0/24" `
    -HyperVProperties @{ SwitchType = "Internal" }

Add-LabMachineDefinition -Name "IT-HELP-DC" `
    -OperatingSystem "Windows Server 2019 Standard" `
    -UserLocale "en-CA" -TimeZone "Eastern Standard Time" `
    -Memory 2GB -Processors 2 `
    -DomainName "it-help.loco" `
    -Network "ItHelpNetwork" `
    -IpAddress "192.168.1.5" `
    -Roles RootDC

Add-LabMachineDefinition -Name "IT-HELP-SRV1" `
    -OperatingSystem "Windows Server 2019 Standard (Desktop Experience)" `
    -UserLocale "en-CA" -TimeZone "Eastern Standard Time" `
    -Memory 4GB -MinMemory 2GB -MaxMemory 4GB -Processors 4 `
    -DomainName "it-help.loco" `
    -IpAddress "192.168.1.11" `
    -Network "ItHelpNetwork"

Add-LabMachineDefinition -Name "IT-HELP-SRV2" `
    -OperatingSystem "Windows Server 2019 Standard (Desktop Experience)" `
    -UserLocale "en-CA" -TimeZone "Eastern Standard Time" `
    -Memory 4GB -MinMemory 2GB -MaxMemory 4GB -Processors 4 `
    -DomainName "it-help.loco" `
    -IpAddress "192.168.1.12" `
    -Network "ItHelpNetwork"

Add-LabMachineDefinition -Name "IT-HELP-101" `
    -OperatingSystem 'Windows 10 Enterprise' `
    -UserLocale "en-CA" -TimeZone "Eastern Standard Time" `
    -Memory 4GB -MinMemory 2GB -MaxMemory 4GB -Processors 4 `
    -DomainName "it-help.loco" `
    -IpAddress "192.168.1.101" `
    -Network "ItHelpNetwork"

Add-LabMachineDefinition -Name "IT-HELP-102" `
    -OperatingSystem 'Windows 10 Pro' `
    -UserLocale "en-CA" -TimeZone "Eastern Standard Time" `
    -Memory 4GB -MinMemory 2GB -MaxMemory 4GB -Processors 4 `
    -DomainName "it-help.loco" `
    -IpAddress "192.168.1.102" `
    -Network "ItHelpNetwork"

Install-Lab

Show-LabDeploymentSummary -Detailed
```
