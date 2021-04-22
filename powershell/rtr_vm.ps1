
. .\common.ps1

$VMAlias = "RTR"
$VMName = $LabPrefix, $VMAlias -Join "-"

$NetworkInterfaces = @"
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
        address 10.9.0.2
        netmask 255.255.255.0
        gateway 10.9.0.1

auto eth1
iface eth1 inet static
        address $DefaultGateway
        netmask 255.255.255.0
"@

New-DLabRouterVM $VMName `
    -WanSwitchName $WanSwitchName `
    -LanSwitchName $LanSwitchName `
    -NetworkInterfaces $NetworkInterfaces `
    -Force

Start-DLabVM $VMName

Wait-DLabVM $VMName 'Shutdown' -Timeout 600

$DiskPath = Join-Path $(Get-DLabPath "VHDs") $($VMName, 'vhdx' -Join '.')

$AlpineDisk = Mount-VHD -Path $DiskPath -PassThru

$Volumes = $AlpineDisk | Get-Partition | Get-Volume | `
    Sort-Object -Property Size -Descending
$Volume = $Volumes[0]

$MountPath = "$($Volume.DriveLetter)`:"
Remove-Item "$MountPath\unattend.sh" -ErrorAction SilentlyContinue | Out-Null

Dismount-VHD $DiskPath

Start-DLabVM $VMName
