
# Devolutions Labs

## Azure Lab Services

Use this section to create an Azure Lab Services template virtual machine, otherwise skip to the next step.

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

## Host environment

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

Download the latest Windows Server .iso file (en_windows_server_2019_updated_jun_2021_x64_dvd_a2a2f782.iso) and copy it to "C:\Hyper-V\ISOs", then create the golden virtual machine image:

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
