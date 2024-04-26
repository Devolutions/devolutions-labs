. .\common.ps1

$VMAlias = "RTR"
$VMName = $LabPrefix, $VMAlias -Join "-"

$NatHostIpAddress = "10.9.0.1"
$NatGuestIpAddress = "10.9.0.2"

$NetworkInterfaces = @"
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
        address $NatGuestIpAddress
        netmask 255.255.255.0
        gateway $NatHostIpAddress

auto eth1
iface eth1 inet static
        address $DefaultGateway
        netmask 255.255.255.0
"@

$DnsMasqConf = @"
interface=eth1
dhcp-range=$DhcpRangeStart,$DhcpRangeEnd,255.255.255.0,12h
"@

New-DLabRouterVM $VMName `
    -WanSwitchName $WanSwitchName `
    -LanSwitchName $LanSwitchName `
    -NetworkInterfaces $NetworkInterfaces `
    -DnsMasqConf $DnsMasqConf `
    -Force

Start-DLabVM $VMName

Wait-DLabVM $VMName 'Shutdown' -Timeout 600

Start-DLabVM $VMName
