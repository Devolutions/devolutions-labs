
Set-ExecutionPolicy Unrestricted -Force
Install-PackageProvider Nuget -Force
Install-Module -Name PowerShellGet -Force
Set-PSRepository -Name "PSGallery" -InstallationPolicy "Trusted"

iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

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

if ([System.Environment]::OSVersion.Version.Build -ge 18362) {
    choco install -y microsoft-windows-terminal
}

$RegPath = "HKLM:\Software\Policies\Mozilla\Firefox\Certificates"
New-Item -Path $RegPath -Force | Out-Null
New-ItemProperty -Path $RegPath -Name ImportEnterpriseRoots -Value 1 -Force | Out-Null

Install-Module Microsoft.PowerShell.SecretManagement -Scope AllUsers
Install-Module Microsoft.PowerShell.SecretStore -Scope AllUsers

Install-Module RdmHelper -Scope AllUsers
Install-Module WaykClient -Scope AllUsers
Install-Module WaykBastion -Scope AllUsers
Install-Module DevolutionsGateway -Scope AllUsers
Install-Module Posh-ACME -Scope AllUsers
Install-Module PsHosts -Scope AllUsers

Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"

Install-Module -Name Microsoft.PowerShell.RemotingTools -Scope AllUsers
Set-Service -Name sshd -StartupType 'Automatic'
Start-Service sshd

& "${Env:ProgramFiles}\PowerShell\7\pwsh.exe" -NoLogo -Command "Enable-SSHRemoting -Force"
Restart-Service sshd

New-NetFirewallRule -Name 'ICMPv4' -DisplayName 'ICMPv4' `
    -Description 'Allow ICMPv4' -Profile Any -Direction Inbound -Action Allow `
    -Protocol ICMPv4 -Program Any -LocalAddress Any -RemoteAddress Any

& netsh advfirewall firewall set rule group="Network Discovery" new enable=yes
& netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=yes

$HyperVPath = "C:\Hyper-V"
New-Item -ItemType Directory -Path $HyperVPath -ErrorAction SilentlyContinue | Out-Null

@('ISOs','IMGs','VHDs','VFDs') | ForEach-Object {
    New-Item -ItemType Directory -Path $(Join-Path $HyperVPath $_) -ErrorAction SilentlyContinue | Out-Null
}

# Download Windows Server 2019 ISO with the latest Windows updates and place it in C:\Hyper-V\ISOs
# To avoid logging in to the Visual Studio subscriber download portal inside the VM, one trick
# is to start the download from another computer and then grab the short-lived download URL.

# en_windows_server_2019_updated_april_2021_x64_dvd_ef6373f0.iso

# Download latest Alpine Linux "virtual" edition (https://www.alpinelinux.org/downloads/)

$AlpineVersion = "3.13.5"
$AlpineRelease = $AlpineVersion -Replace "^(\d+)\.(\d+)\.(\d+)$", "v`$1.`$2"
$AlpineIsoFileName = "alpine-virt-${AlpineVersion}-x86_64.iso"
$AlpineIsoDownloadUrl = "https://dl-cdn.alpinelinux.org/alpine/${AlpineRelease}/releases/x86_64/$AlpineIsoFileName"
$AlpineIsoDownloadPath = Join-Path "$HyperVPath\ISOs" $AlpineIsoFileName

if (-Not $(Test-Path -Path $AlpineIsoDownloadPath -PathType 'Leaf')) {
    Write-Host "Downloading $AlpineIsoDownloadUrl"
    curl.exe $AlpineIsoDownloadUrl -o $AlpineIsoDownloadPath
}

# Create LAN switch for the host and VMs
New-VMSwitch –SwitchName "LAN Switch" –SwitchType Internal –Verbose
$NetAdapter = Get-NetAdapter | Where-Object { $_.Name -Like "*(LAN Switch)" }
New-NetIPAddress -InterfaceIndex $NetAdapter.IfIndex -IPAddress 10.10.0.1 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceIndex $NetAdapter.IfIndex -ServerAddresses @()

# Create NAT switch for the router VM WAN
New-VMSwitch –SwitchName "NAT Switch" –SwitchType Internal –Verbose
$NetAdapter = Get-NetAdapter | Where-Object { $_.Name -Like "*(NAT Switch)" }
New-NetIPAddress -InterfaceIndex $NetAdapter.IfIndex -IPAddress 10.9.0.1 -PrefixLength 24
New-NetNat –Name NatNetwork –InternalIPInterfaceAddressPrefix 10.9.0.0/24

# Requires a boot (do it at the end)
Enable-WindowsOptionalFeature -Online -FeatureName $("Microsoft-Hyper-V", "Containers") -All
