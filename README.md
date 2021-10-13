
# Wayk Bastion Lab

Azure Lab Services virtual machine base image:

 * Windows Server 2019 Datacenter
 * Windows 10 Enterprise, Version 20H2
 * Large (Nested virtualization) | 8 cores | 32GB RAM

In Server Manager, go to "Local Server" to change to following properties:

 * IE Enhanced Security Configuration: Off
 * Time zone: Eastern Time (US & Canada)

In the "Manage" menu, click "Server Manager Properties", then check "Do not start Server Manager automatically at logon".

Open elevated Windows PowerShell prompt, and initialize the host environment. To install just the bare minimum required, simply call the host_init.ps1 script without any parameters:

```powershell
.\host_init.ps1 -Bootstrap -IncludeOptional
```

You may need to reboot the host for the Hyper-V feature installation to complete.

Download the latest Windows Server .iso file (en_windows_server_2019_updated_jun_2021_x64_dvd_a2a2f782.iso) and copy it to "C:\Hyper-V\ISOs", then create the golden virtual machine image:

```powershell
.\golden.ps1
```

The process takes about an hour to complete, and creates a clean virtual hard disk image containing everything we need for all the virtual machines in the lab.

Launch the script to build the isolated lab of virtual machines:

```powershell
.\build.ps1
```

All virtual machines are created in order using the golden image. The entire process takes about an hour to complete.
