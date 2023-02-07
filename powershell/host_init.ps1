#Requires -RunAsAdministrator
#Requires -PSEdition Core

function Invoke-HostInit {
    param(
    )

    $IsChocoPresent = [bool](Get-Command -Name choco -CommandType Application -ErrorAction SilentlyContinue)
    $IsWingetPresent = [bool](Get-Command -Name winget -CommandType Application -ErrorAction SilentlyContinue)

    if (-Not (Get-Command -Name 7z -CommandType Application -ErrorAction SilentlyContinue)) {
        if ($IsWingetPresent) {
            winget install 7zip.7zip
        } elseif ($IsChocoPresent) {
            choco install -y --no-progress 7zip
        } else {
            Write-Warning "7z.exe cannot be found or installed automatically"
        }
    }

    $RegPath = "HKLM:\Software\Policies\Mozilla\Firefox\Certificates"
    New-Item -Path $RegPath -Force | Out-Null
    New-ItemProperty -Path $RegPath -Name ImportEnterpriseRoots -Value 1 -Force | Out-Null

    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Credssp" `
        -Name UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors -Value 1 -Force | Out-Null

    if ($(Get-WindowsCapability -Online -Name "OpenSSH.Client~~~~0.0.1.0").State -ne "Installed") {
        Add-WindowsCapability -Online -Name "OpenSSH.Client~~~~0.0.1.0"
    }

    if (-Not (Get-InstalledModule PsHosts -ErrorAction SilentlyContinue)) {
        Install-Module PsHosts -Scope AllUsers -Force
    }

    if (-Not (Get-InstalledModule RemoteDesktopManager -ErrorAction SilentlyContinue)) {
        Install-Module RemoteDesktopManager -Scope AllUsers -Force
    }

    # Enable WinRM client

    Set-Service 'WinRM' -StartupType 'Automatic'
    Start-Service 'WinRM'

    # Create Hyper-V directory structure

    $HyperVPath = if (Test-Path Env:DLAB_HOME) { $Env:DLAB_HOME } else { "C:\Hyper-V" }
    New-Item -ItemType Directory -Path $HyperVPath -ErrorAction SilentlyContinue | Out-Null

    @('ISOs','IMGs','VHDs') | ForEach-Object {
        New-Item -ItemType Directory -Path $(Join-Path $HyperVPath $_) -ErrorAction SilentlyContinue | Out-Null
    }

    # Download Windows Server 2022 ISO with the latest Windows updates and place it in C:\Hyper-V\ISOs
    # To avoid logging in to the Visual Studio subscriber download portal inside the VM, one trick
    # is to start the download from another computer and then grab the short-lived download URL.

    # The .iso file name needs to include "windows_server_2022", like this:
    # en-us_windows_server_2022_updated_jan_2023_x64_dvd_2897e63d.iso

    # Download latest Alpine Linux "virtual" edition (https://www.alpinelinux.org/downloads/)

    $AlpineVersion = "3.15.0"
    $AlpineRelease = $AlpineVersion -Replace "^(\d+)\.(\d+)\.(\d+)$", "v`$1.`$2"
    $AlpineIsoFileName = "alpine-virt-${AlpineVersion}-x86_64.iso"
    $AlpineIsoDownloadUrl = "https://dl-cdn.alpinelinux.org/alpine/${AlpineRelease}/releases/x86_64/$AlpineIsoFileName"
    $AlpineIsoDownloadPath = Join-Path "$HyperVPath\ISOs" $AlpineIsoFileName

    if (-Not $(Test-Path -Path $AlpineIsoDownloadPath -PathType 'Leaf')) {
        Write-Host "Downloading $AlpineIsoDownloadUrl"
        curl.exe $AlpineIsoDownloadUrl -o $AlpineIsoDownloadPath
    }

    # Enable Hyper-V (requires a reboot)
    if ($(Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V").State -ne 'Enabled') {
        Enable-WindowsOptionalFeature -Online -FeatureName @("Microsoft-Hyper-V") -All -NoRestart
    }

    # Create LAN switch for the host and VMs

    $SwitchName = "LAN Switch"
    $IPAddress = "10.10.0.1"
    if (-Not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
        New-VMSwitch -SwitchName $SwitchName -SwitchType Internal -Verbose
    }
    $NetAdapter = Get-NetAdapter | Where-Object { $_.Name -Like "*($SwitchName)" }
    if ($(Get-NetIpAddress -InterfaceIndex $NetAdapter.IfIndex).IPAddress -ne $IPAddress) {
        Remove-NetIPAddress -InterfaceIndex $NetAdapter.IfIndex -Confirm:$false
        New-NetIPAddress -InterfaceIndex $NetAdapter.IfIndex -IPAddress $IPAddress -PrefixLength 24
        Set-DnsClientServerAddress -InterfaceIndex $NetAdapter.IfIndex -ServerAddresses @()
    }

    # Create NAT switch for the router VM WAN

    $SwitchName = "NAT Switch"
    $IPAddress = "10.9.0.1"
    $NatName = "NatNetwork"
    $NatPrefix = "10.9.0.0/24"
    if (-Not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
        New-VMSwitch -SwitchName $SwitchName -SwitchType Internal -Verbose
    }
    $NetAdapter = Get-NetAdapter | Where-Object { $_.Name -Like "*($SwitchName)" }
    if ($(Get-NetIpAddress -InterfaceIndex $NetAdapter.IfIndex).IPAddress -ne $IPAddress) {
        Remove-NetIPAddress -InterfaceIndex $NetAdapter.IfIndex -Confirm:$false
        New-NetIPAddress -InterfaceIndex $NetAdapter.IfIndex -IPAddress $IPAddress -PrefixLength 24
    }
    if (-Not (Get-NetNat -Name $NatName -ErrorAction SilentlyContinue)) {
        New-NetNat -Name $NatName -InternalIPInterfaceAddressPrefix $NatPrefix
    }
}

Invoke-HostInit @args
