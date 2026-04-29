# DVLS Linux Dev VM (Hyper-V)

This script provisions a Gen 2 Ubuntu 22.04 VM pre-configured for DVLS development on Linux. It uses the Ubuntu Server installer ISO for unattended installation, then provisions the VM over SSH.

## Prerequisites

### qemu-img

`qemu-img` is required to create the VHDX disk image. Install it via Chocolatey:

```powershell
choco install qemu -y
```

Then ensure `qemu-img` is available in your `PATH`:

```powershell
qemu-img --version
```

### Ubuntu 22.04 Server ISO

Download the Ubuntu 22.04 Server ISO and copy it to `C:\Hyper-V\ISOs\ubuntu-22.04.5-live-server-amd64.iso`:

```
https://releases.ubuntu.com/22.04/ubuntu-22.04.5-live-server-amd64.iso
```

### Hyper-V

Hyper-V must be enabled with an internal switch named `LAN Switch`. Run the following to check available switches and update `$SwitchName` in the script if needed:

```powershell
Get-VMSwitch | Select-Object Name
```

### Router VM

The router VM must be running before provisioning, as the script checks reachability of `10.10.0.2`:

```powershell
Start-VM -Name 'IT-HELP-RTR'
```

## How It Works

1. A blank VHDX is created and the Ubuntu installer ISO + seed ISO are attached as DVD drives.
2. The VM boots from the installer ISO (VHDX is blank, UEFI falls through to the DVD).
3. The installer picks up the autoinstall config from the seed ISO (labeled `cidata`) and installs Ubuntu unattended (~10-15 min).
4. After reboot, the script waits for SSH to become available.
5. A provisioning script is uploaded via SCP and executed over SSH, installing .NET, PowerShell, and setting up the DVLS service account.

## Usage

Run from an elevated PowerShell prompt inside the `powershell` directory:

```powershell
.\dev_dvls_linux_vm.ps1
```

Once done, connect with:

```powershell
ssh devuser@10.10.0.10
```

## Verify Installation

The provisioning script writes logs on the VM:

```bash
# Full provisioning output
cat /var/log/provision.log

# Verification summary
cat /var/log/provision-verify.log
```

Or verify each component manually:

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
