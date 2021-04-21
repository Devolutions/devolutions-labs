
Import-Module .\DevolutionsLabs.psm1 -Force

$WanSwitchName = "NAT Switch"
$LanSwitchName = "LAN Switch"

$VMName = "IT-ROUTER"

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
