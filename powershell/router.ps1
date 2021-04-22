
Import-Module .\DevolutionsLabs.psm1 -Force

$WanSwitchName = "NAT Switch"
$LanSwitchName = "LAN Switch"

$VMName = "IT-YOLO-RTR"

$NetworkInterfaces = @"
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
        address 10.9.0.3
        netmask 255.255.255.0
        gateway 10.9.0.1

auto eth1
iface eth1 inet static
        address 10.10.0.50
        netmask 255.255.255.0
"@

New-DLabRouterVM $VMName `
    -WanSwitchName $WanSwitchName `
    -LanSwitchName $LanSwitchName `
    -NetworkInterfaces $NetworkInterfaces `
    -Force

Start-DLabVM $VMName

Wait-DLabVM $VMName 'Shutdown' -Timeout 600

$DiskPath = Join-Path $(Get-DLabPath "ChildDisks") $($VMName, 'vhdx' -Join '.')

$AlpineDisk = Mount-VHD -Path $DiskPath -PassThru

$Volumes = $AlpineDisk | Get-Partition | Get-Volume | `
    Sort-Object -Property Size -Descending
$Volume = $Volumes[0]

$MountPath = "$($Volume.DriveLetter)`:"
Remove-Item "$MountPath\unattend.sh" -ErrorAction SilentlyContinue | Out-Null

Dismount-VHD $DiskPath
