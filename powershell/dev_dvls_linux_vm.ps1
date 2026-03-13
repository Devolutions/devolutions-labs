#Requires -RunAsAdministrator
#Requires -Modules Hyper-V

. .\common.ps1

<#
.SYNOPSIS
    Creates a Hyper-V Ubuntu 22.04 VM pre-configured for DVLS Linux development.

.DESCRIPTION
    Provisions a Gen 2 Ubuntu 22.04 VM using the generic Ubuntu cloud image with:
      - Static IP
      - SSH server + key-based auth
      - .NET ASP.NET Core Runtime 10.0
      - PowerShell 7
      - rsync, openssl, curl, wget, git

    Prerequisites:
      - Ubuntu 22.04 generic cloud image at $CloudImagePath
        Download: https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img
        Copy to: C:\Hyper-V\ISOs\ubuntu-22.04-server-cloudimg-amd64.img
        Note: Uses NoCloud datasource natively — no image patching needed.
      - Hyper-V enabled with a LAN switch (internal)
      - WSL (for cloud-localds seed ISO creation)
      - Internet access via LAN switch NAT (no external/WiFi bridge needed)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================
# CONFIGURATION — edit before running
# ============================================================
$VMName         = $LabPrefix, "LINUX-DEBUG" -Join "-"
$VMPath         = "C:\Hyper-V\VMs"
$CloudImagePath = "C:\Hyper-V\ISOs\ubuntu-22.04-server-cloudimg-amd64.img"

$VHDXSizeGB    = 40
$MemoryGB      = 4
$CPUCount      = 2

$VMIPAddress      = "10.10.0.10"   # Static IP on the lab LAN
$VMSubnet         = "24"           # CIDR prefix length
$VMGateway        = $DefaultGateway
$VMDNS            = $RTRIpAddress

$VMUsername   = "devuser"
$VMPassword   = "changeme123!"     # Change this! Pre-generated hash below must match.
$SSHKeyPath    = "$env:USERPROFILE\.ssh\id_ed25519"
if (-not (Test-Path "$SSHKeyPath.pub")) {
    Write-Info "No SSH key found — generating id_ed25519..."
    ssh-keygen -t ed25519 -f $SSHKeyPath -N '""' -q
    Write-Ok "SSH key generated: $SSHKeyPath"
}
$SSHPublicKey = (Get-Content "$SSHKeyPath.pub" -Raw).Trim()

# SHA-512 crypt hash of $VMPassword ("changeme123!").
# Regenerate with: wsl openssl passwd -6 'yournewpassword'
$VMPasswordHash = '$6$GJpgtdnTyoj8HZ5w$t0hV74DHPOKm0sPJJWXm46/CBg3Cj7uVCTSUMySj.oAX5G9KAkHq6tLhp8Lw4LNU88hFsxf2OLB7kM4dEOVuE0'
# ============================================================

$VHDXPath    = "$VMPath\$VMName\$VMName.vhdx"
$SeedISOPath = "$VMPath\$VMName\seed.iso"
$SeedDir     = "$VMPath\$VMName\cloud-init"

function Write-Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Write-Ok([string]$Message) {
    Write-Host "   [OK] $Message" -ForegroundColor Green
}

function Write-Info([string]$Message) {
    Write-Host "   $Message"
}


function ConvertTo-WslPath([string]$WindowsPath) {
    if ($WindowsPath -match '^([A-Za-z]):\\(.*)$') {
        $drive = $Matches[1].ToLower()
        $rest  = $Matches[2] -replace '\\', '/'
        return "/mnt/$drive/$rest"
    }
    return $WindowsPath -replace '\\', '/'
}

function New-SeedISO([string]$SourceDir, [string]$OutputISO) {
    Write-Info "Using WSL cloud-localds..."

    $wslOut        = ConvertTo-WslPath $OutputISO
    $wslUserData   = ConvertTo-WslPath "$SourceDir\user-data"
    $wslMetaData   = ConvertTo-WslPath "$SourceDir\meta-data"
    $wslNetworkCfg = ConvertTo-WslPath "$SourceDir\network-config"

    $cmd = "DEBIAN_FRONTEND=noninteractive apt-get install -y cloud-utils -q && cloud-localds --network-config='$wslNetworkCfg' '$wslOut' '$wslUserData' '$wslMetaData'"
    $output = wsl -u root -e bash -c $cmd 2>&1
    if ($LASTEXITCODE -ne 0) { throw "cloud-localds failed (exit $LASTEXITCODE):`n$output" }
}

# --- Validate ---
Write-Step "Validating prerequisites"

Write-Info "Checking cloud image: $CloudImagePath"
if (-not (Test-Path $CloudImagePath)) {
    throw "Cloud image not found: $CloudImagePath`nDownload: https://cloud-images.ubuntu.com/releases/22.04/release/`nFile: ubuntu-22.04-server-cloudimg-amd64-azure.vhd.tar.gz`nExtract: wsl tar xzf ubuntu-22.04-server-cloudimg-amd64-azure.vhd.tar.gz -C 'C:\Hyper-V\ISOs\'"
}
Write-Ok "Cloud image found."

Write-Info "Checking virtual switch: $SwitchName"
if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
    $available = (Get-VMSwitch | Select-Object -ExpandProperty Name) -join ", "
    throw "Virtual switch '$SwitchName' not found.`nAvailable: $available`nUpdate `$SwitchName."
}
Write-Ok "Switch found."

Write-Info "Checking router VM is reachable ($VMGateway)..."
if (-not (Test-NetConnection -ComputerName $VMGateway -Port 53 -WarningAction SilentlyContinue -InformationLevel Quiet)) {
    throw "Router at $VMGateway is not reachable. Start IT-HELP-RTR first: Start-VM -Name 'IT-HELP-RTR'"
}
Write-Ok "Router reachable."

Write-Info "Checking for existing VM: $VMName"
if (Get-VM -Name $VMName -ErrorAction SilentlyContinue) {
    throw "VM '$VMName' already exists. Remove it first or change `$VMName."
}
Write-Ok "No conflict."

Write-Host ""
Write-Info "VM name  : $VMName"
Write-Info "RAM      : $MemoryGB GB  |  CPUs: $CPUCount  |  Disk: $VHDXSizeGB GB"
Write-Info "Switch   : $SwitchName"
Write-Info "IP       : $VMIPAddress/$VMSubnet"
Write-Info "Username : $VMUsername"
Write-Info "SSH key  : $(if ($SSHPublicKey) { 'yes' } else { 'none' })"

# --- Directories ---
Write-Step "Creating directories"
New-Item -ItemType Directory -Force -Path "$VMPath\$VMName" | Out-Null
New-Item -ItemType Directory -Force -Path $SeedDir | Out-Null
Write-Ok $SeedDir

# --- cloud-init user-data ---
Write-Step "Writing cloud-init config"

$sshKeysBlock = if ($SSHPublicKey) { "`n    ssh_authorized_keys:`n      - $SSHPublicKey" } else { "" }

$userData = @"
#cloud-config
hostname: $VMName

output:
  all: '| tee -a /dev/console /var/log/cloud-init-output.log'

package_upgrade: true

power_state:
  mode: reboot
  message: "Rebooting after cloud-init setup"
  condition: true

users:
  - name: $VMUsername
    groups: sudo
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    passwd: '$VMPasswordHash'$sshKeysBlock

ssh_pwauth: true

write_files:
  - path: /etc/systemd/system/dvls.service
    content: |
      [Unit]
      Description=Devolutions Server
      After=network.target

      [Service]
      Type=notify
      User=dvls
      WorkingDirectory=/opt/devolutions/dvls
      ExecStart=/usr/local/bin/dotnet /opt/devolutions/dvls/Devolutions.Server.dll
      Restart=always
      RestartSec=5

      [Install]
      WantedBy=multi-user.target

runcmd:
  - sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="[^"]*/& systemd.networkd.wait_online.timeout=10/' /etc/default/grub
  - update-grub
  - apt-get update -qq
  - apt-get install -y openssl curl wget git vim
  - |
    for i in 1 2 3; do
      curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh && break
      echo "dotnet-install.sh download attempt $i failed, retrying in 10s..."
      sleep 10
    done
    bash /tmp/dotnet-install.sh --channel 10.0 --runtime aspnetcore --install-dir /usr/share/dotnet
    ln -sf /usr/share/dotnet/dotnet /usr/local/bin/dotnet
    dotnet --info || echo "ERROR: dotnet install failed" >> /var/log/cloud-init-verify.log
  - snap install powershell --classic
  - useradd -r -s /bin/false dvls
  - mkdir -p /opt/devolutions/dvls
  - chown -R dvls:dvls /opt/devolutions/dvls
  - systemctl daemon-reload
  - usermod -U root
  - mkdir -p /root/.ssh
  - chmod 700 /root/.ssh
  - echo '$($SSHPublicKey)' >> /root/.ssh/authorized_keys
  - chmod 600 /root/.ssh/authorized_keys
  - echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
  - systemctl restart ssh
  - |
    echo "=== Verification ===" >> /var/log/cloud-init-verify.log
    dotnet --info >> /var/log/cloud-init-verify.log 2>&1 && echo "dotnet: OK" || echo "dotnet: MISSING" >> /var/log/cloud-init-verify.log
    pwsh --version >> /var/log/cloud-init-verify.log 2>&1 && echo "pwsh: OK" || echo "pwsh: MISSING" >> /var/log/cloud-init-verify.log
    for pkg in git curl wget openssl vim; do
      dpkg -l `$pkg 2>/dev/null | grep -q '^ii' && echo "`$pkg: OK" || echo "`$pkg: MISSING"
    done >> /var/log/cloud-init-verify.log
    id dvls >> /var/log/cloud-init-verify.log 2>&1 && echo "dvls user: OK" || echo "dvls user: MISSING" >> /var/log/cloud-init-verify.log
    test -d /opt/devolutions/dvls && echo "dvls dir: OK" >> /var/log/cloud-init-verify.log || echo "dvls dir: MISSING" >> /var/log/cloud-init-verify.log
    test -f /etc/systemd/system/dvls.service && echo "dvls.service: OK" >> /var/log/cloud-init-verify.log || echo "dvls.service: MISSING" >> /var/log/cloud-init-verify.log
    passwd -S root >> /var/log/cloud-init-verify.log 2>&1
    echo "=== Done ===" >> /var/log/cloud-init-verify.log
"@

$metaData = @"
instance-id: $VMName
local-hostname: $VMName
"@

$networkConfig = @"
version: 2
ethernets:
  eth0:
    match:
      name: "eth0"
    addresses:
      - ${VMIPAddress}/${VMSubnet}
    gateway4: ${VMGateway}
    nameservers:
      addresses:
        - ${VMDNS}
"@

Set-Content -Path "$SeedDir\user-data"      -Value $userData      -Encoding UTF8
Set-Content -Path "$SeedDir\meta-data"      -Value $metaData      -Encoding UTF8
Set-Content -Path "$SeedDir\network-config" -Value $networkConfig  -Encoding UTF8
Write-Ok "user-data, meta-data and network-config written."

# --- Seed ISO ---
Write-Step "Building seed ISO (cloud-init)"
New-SeedISO -SourceDir $SeedDir -OutputISO $SeedISOPath
Write-Ok $SeedISOPath

# --- VHDX from cloud image ---
Write-Step "Preparing VHDX from cloud image"
if (Test-Path $VHDXPath) {
    Write-Info "Removing existing VHDX..."
    try {
        Remove-Item -Force $VHDXPath
    } catch {
        Write-Info "VHDX locked — restarting Hyper-V services to release handle..."
        Restart-Service vmcompute -Force -ErrorAction SilentlyContinue
        Restart-Service vmms -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        Remove-Item -Force $VHDXPath
    }
}
Write-Info "Converting to VHDX using qemu-img..."
$wslImg  = ConvertTo-WslPath $CloudImagePath
$wslVhdx = ConvertTo-WslPath $VHDXPath
$output = wsl -u root -e bash -c "apt-get install -y qemu-utils -qq && qemu-img convert -f qcow2 -O vhdx -o subformat=dynamic '$wslImg' '$wslVhdx'" 2>&1
Write-Host $output
if ($LASTEXITCODE -ne 0) { throw "qemu-img conversion failed." }
Write-Info "Resizing to $VHDXSizeGB GB..."
Resize-VHD -Path $VHDXPath -SizeBytes ($VHDXSizeGB * 1GB)
Write-Ok $VHDXPath

# --- VM ---
Write-Step "Creating VM: $VMName"

New-VM -Name $VMName `
       -MemoryStartupBytes ($MemoryGB * 1GB) `
       -Generation 2 `
       -VHDPath $VHDXPath `
       -SwitchName $SwitchName `
       -Path $VMPath | Out-Null
Write-Ok "VM created (Gen 2)."


Set-VM -Name $VMName `
       -ProcessorCount $CPUCount `
       -StaticMemory `
       -MemoryStartupBytes ($MemoryGB * 1GB) `
       -AutomaticCheckpointsEnabled $false
Write-Ok "$CPUCount vCPUs, $MemoryGB GB RAM (static)."

Set-VMFirmware -VMName $VMName -EnableSecureBoot Off
Write-Ok "Secure Boot: disabled (Azure cloud image deadlocks with Hyper-V Secure Boot)."

Set-VMComPort -VMName $VMName -Number 1 -Path "\\.\pipe\$VMName-com1"
Write-Ok "COM1 port added (workaround for initramfs-tools boot stall on Hyper-V)."

Add-VMDvdDrive -VMName $VMName -Path $SeedISOPath
$dvd = Get-VMDvdDrive      -VMName $VMName | Select-Object -First 1
$vhd = Get-VMHardDiskDrive -VMName $VMName | Select-Object -First 1
Set-VMFirmware -VMName $VMName -BootOrder @($vhd, $dvd)
Write-Ok "Boot order: VHDX -> seed ISO."

# --- Start ---
Write-Step "Starting VM"
Start-VM -Name $VMName
Write-Ok "VM started."

Write-Host ""
Write-Info "Connect to watch: vmconnect.exe localhost '$VMName'"
Write-Info "cloud-init configures the VM on first boot (~5-10 min for packages + .NET)"

# --- Wait for SSH ---
Write-Step "Waiting for VM to be ready (polling SSH every 30s)"
Write-Host "   Press Ctrl+C to stop waiting."
Write-Host ""

$timeoutMinutes = 20
$elapsed        = 0
$ready          = $false

while ($elapsed -lt ($timeoutMinutes * 2)) {
    $tcp = Test-NetConnection -ComputerName $VMIPAddress -Port 22 -WarningAction SilentlyContinue -InformationLevel Quiet
    if ($tcp) {
        $ready = $true
        break
    }

    $elapsed++
    Write-Host "   [$([math]::Round($elapsed * 0.5, 1)) min] Waiting for SSH..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 30
}

if ($ready) {
    Write-Step "VM is ready"

    Write-Info "Removing seed ISO..."
    Get-VMDvdDrive -VMName $VMName | Remove-VMDvdDrive
    Write-Ok "Seed ISO removed."

    Write-Host @"

[OK] VM '$VMName' is ready.

  SSH : ssh $VMUsername@$VMIPAddress
  Pass: $VMPassword

  Note: .NET and PowerShell may still be installing in the background.
        Run 'cloud-init status --wait' to confirm completion.
"@ -ForegroundColor Green
} else {
    Write-Host @"

[TIMEOUT] SSH did not respond after $timeoutMinutes minutes.
  Check the console: vmconnect.exe localhost '$VMName'
  SSH in once ready: ssh $VMUsername@$VMIPAddress
"@ -ForegroundColor Yellow
}
