# DVLS Linux Dev VM (Hyper-V)

This script provisions a Gen 2 Ubuntu 22.04 VM pre-configured for DVLS development on Linux. It uses cloud-init to automate the full setup on first boot, including .NET, PowerShell, the `dvls` service user, and the systemd service.

## Prerequisites

Download the Ubuntu 22.04 generic cloud image and copy it to `C:\Hyper-V\ISOs\ubuntu-22.04-server-cloudimg-amd64.img`.

WSL is required for seed ISO creation and VHDX conversion. Install it from an elevated PowerShell prompt if not already done:

```powershell
wsl --install
```

Hyper-V must be enabled with an internal switch named `LAN Switch`. Run the following to check available switches and update `$SwitchName` in the script if needed:

```powershell
Get-VMSwitch | Select-Object Name
```

The router VM must be running before provisioning, as the script checks reachability of `10.10.0.2`:

```powershell
Start-VM -Name 'IT-HELP-RTR'
```

## Usage

Run from an elevated PowerShell prompt inside the `powershell` directory:

```powershell
.\dev_dvls_linux_vm.ps1
```

The script provisions the VM and waits for SSH to be ready (~5-10 min for packages and .NET). Once done, connect with:

```powershell
ssh devuser@10.10.0.10
```

## Verify Installation

cloud-init writes a verification log on first boot. Check it with:

```bash
cat /var/log/cloud-init-verify.log
```

Or verify each package manually over SSH:

```bash
dotnet --info
pwsh --version
git --version
curl --version
wget --version
openssl version
id dvls
ls /opt/devolutions/dvls
systemctl status dvls
```
