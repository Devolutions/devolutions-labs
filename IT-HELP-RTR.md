# IT-HELP-RTR VM

Create a Hyper-V internal switch that will be used for the LAN between the Hyper-V host and the lab VMs:

```powershell
New-VMSwitch –SwitchName "LAN Switch" –SwitchType Internal –Verbose
$NetAdapter = Get-NetAdapter | Where-Object { $_.Name -Like "*(LAN Switch)" }
New-NetIPAddress -InterfaceIndex $NetAdapter.IfIndex -IPAddress 10.10.0.5 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceIndex $NetAdapter.IfIndex -ServerAddresses @()
```

It is very important to avoid using DHCP for the network adapter attached to the LAN switch on the host to avoid using the DNS server from the domain controller VM. If DNS resolution becomes suspiciously slow on the host, make sure that the DNS server published through DHCP on this interface is ignored.

[Set up a NAT network](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/setup-nat-network). Create a new Hyper-V switch for localhost NAT:

```powershell
New-VMSwitch –SwitchName "NAT Switch" –SwitchType Internal –Verbose
$NetAdapter = Get-NetAdapter | Where-Object { $_.Name -Like "*(NAT Switch)" }
New-NetIPAddress -InterfaceIndex $NetAdapter.IfIndex -IPAddress 10.9.0.1 -PrefixLength 24
New-NetNat –Name NatNetwork –InternalIPInterfaceAddressPrefix 10.9.0.0/24
```

Download the latest [Alpine Linux](https://www.alpinelinux.org/downloads/) release. The "virtual" build is preferred because it is optimized for virtual machines, otherwise the "standard" build will work just fine. Move the .iso file to a known location (C:\Hyper-V\ISOs) once downloaded.
