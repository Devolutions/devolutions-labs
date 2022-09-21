
# Devolutions Labs

## Prerequisites

This Hyper-V lab is designed to work properly on a Windows host with 32GB of RAM, alongside common development tools, and with minimal disk usage.

If you have never set up PowerShell, use the following to change the default execution policy and update it from an elevated shell:

```powershell
Set-ExecutionPolicy Unrestricted -Force
Install-PackageProvider Nuget -Force
Install-Module -Name PowerShellGet -Force
```

If you do not have the chocolatey package manager already, use the following code snippet to install it:

```powershell
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

You can now install Hyper-V including the management tools (very important!). Manually reboot once this is done:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName @("Microsoft-Hyper-V") -All -NoRestart
```

In order to use Hyper-V from an unelevated shell, add yourself to the local Hyper-V Administrators group:

```powershell
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
if (-Not (Get-LocalGroupMember -Group "Hyper-V Administrators" -Member $CurrentUser -ErrorAction SilentlyContinue)) {
	Add-LocalGroupMember -Group "Hyper-V Administrators" -Member @($CurrentUser)
}
```

Disable the Windows console host QuickEdit mode that freezes terminal output when you click anywhere in it until you press Enter. While this feature simplifies copy/pasting in the old terminal, too many hours have been wasted by unsuspecting users waiting on a terminal that had stopped executing:

```powershell
Set-ItemProperty -Path "HKCU:\Console" -Name QuickEdit -Value 0
```

While optional, it is highly recommended to use Windows Terminal instead of the old Windows console host. Install it quickly using chocolatey:

```powershell
choco install -y --no-progress microsoft-windows-terminal
```

Last but not least, install PowerShell 7 using an elevated Windows PowerShell terminal:

```powershell
&([ScriptBlock]::Create((irm "https://aka.ms/install-powershell.ps1"))) -UseMSI -Quiet
```

At this point, it is advised to reboot.

From this point forward, always use PowerShell 7, as Windows PowerShell compatibility is not guaranteed.

## Host Initialization

Open elevated Windows PowerShell prompt, and move to the "powershell" directory of this repository containing all the scripts.

Run the host_init.ps1 script to initialize the host environment:

```powershell
.\host_init.ps1
```

By default, the host initialization script installs the bare minimum required for the lab, but it can be used to bootstrap a new environment with default PowerShell settings and optional tools that can be useful:

```powershell
.\host_init.ps1 -Bootstrap -IncludeOptional
```

You may need to reboot the host for the Hyper-V feature installation to complete.

## Golden Image

Download the latest Windows Server .iso file (en_windows_server_2019_updated_jun_2021_x64_dvd_a2a2f782.iso). This is the regular Windows Server ISO which is only available to those with the right Visual Studio (MSDN) subscription, not the evaluation ISO available publicly. Ask someone on your team for a download link (hint: the person maintaining these scripts). Copy the iso file to "C:\Hyper-V\ISOs", then create the golden virtual machine image:

```powershell
.\golden.ps1
```

The process takes about an hour to complete, and creates a clean virtual hard disk image containing everything we need for all the virtual machines in the lab.

## Virtual Machines

Launch the script to build the isolated lab of virtual machines:

```powershell
.\build.ps1
```

All virtual machines are created in order using the golden image. The entire process takes about an hour to complete.

## Host Synchronization

Last but not least, run the host synchronization script to make it possible to reach the virtual machines with the proper hostnames. The script also imports the root certificate authority from the lab, such that HTTPS will work properly inside the browser of the host.

```powershell
.\host_sync.ps1
```

## Remote Desktop Manager

Launch Remote Desktop Manager, then run the rdm_init.ps1 script to create and initialize a new data source called "IT-HELP-LAB"

```powershell
.\rdm_init.ps1
```

You will need to restart Remote Desktop Manager after running the script to see the new data source in the list. This part usually doesn't work well, so if "IT-HELP-LAB" is missing from the list, simply create an SQLite data source of the same name using "%LocalAppData%\Devolutions\RemoteDesktopManager\IT-HELP-LAB.db" as database file.

## Azure Lab Services

Use this section to build the lab in Azure Lab Services, otherwise skip it.

Azure Lab Services virtual machine base image:

 * Windows Server 2019 Datacenter
 * Windows 10 Enterprise, Version 20H2
 * Large (Nested virtualization) | 8 cores | 32GB RAM

Change the default time zone:

```powershell
Set-TimeZone -Id 'Eastern Standard Time' -PassThru
```

Disable the server manager automatic start at logon:

```powershell
Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask
```

Disable IE Enhanced Security Configuration:

```powershell
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
```
