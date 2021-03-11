# pfSense VM

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

Download [pfSense Community Edition](https://www.pfsense.org/download/) and extract the .iso file it contains.

Create a new pfSense virtual machine with 2GB of RAM, 2 vCPUs and a 32GB virtual hard disk. Create two network adapters attached (in order) to the NAT switch and the LAN switch that were just created. The NAT switch will be used for the WAN side, and the LAN switch will be used for LAN side in the new router VM.

At the pfSense prompt, select 1 to assign interfaces:

```bash
Valid interfaces are:

hn0     00:15:5d:19:7f:09    (up) Hyper-V Network Interface
hn1     00:15:5d:19:7f:0a    (up) Hyper-V Network Interface

Do VLANs need to be set up first?
If VLANs will not be used, or only for optional interfaces, it is typical to say no here and use the webConfigurator to configure VLANs later, if required.

Should VLANs be set up now [y|n]? n

If the names of the interfaces are not known, auto-detection can be used instead. To use auto-detection, please disconnect all interfaces before pressing 'a' to begin the process.

Enter the WAN interface name or 'a' for auto-detection
(hn0 hn1 or a): hn0

Enter the LAN interface name or 'a' for auto-detection
NOTE: this enables full Firewalling/NAT mode.
(hn1 a or nothing if finished): hn1

The interfaces will be assigned as follows:

WAN  -> hn0
LAN  -> hn1

Do you want to proceed [y|n]? y

Writing configuration... done.
One moment while the settings are reloading... done!
```

At the pfSense prompt, select 2 to configure the WAN interface:

```bash
Available interfaces:

1 - WAN (hn0 - static)
2 - LAN (hn1 - static)

Enter the number of the interface you wish to configure: 1

Configure IPv4 address WAN interface via DHCP? (y/n) n

Enter the new WAN IPv4 address. Press <ENTER> for none:
> 10.9.0.2

Subnet masks are entered as bit counts (as in CIDR notation) in pfSense.
e.g. 255.255.255.0 = 24
     255.255.0.0   = 16
     255.0.0.0     = 8

Enter the new WAN IPv4 subnet bit count (1 to 31):
> 24

For a WAN, enter the new WAN IPv4 upstream gateway address.
For a LAN, press <ENTER> for none:
> 10.9.0.1

Configure IPv6 address WAN interface via DHCP6? (y/n) n

Enter the new WAN IPv6 address. Press <ENTER> for none:
> 

Please wait while the changes are saved to WAN...

The IPv4 WAN address has been set to 10.9.0.2/24

Press <ENTER> to continue.
```

At the pfSense prompt, select 2 to configure the LAN interface:

```bash
Available interfaces:

1 - WAN (hn0 - static)
2 - LAN (hn1 - static)

Enter the number of the interface you wish to configure: 2

Enter the new LAN IPv4 address. Press <ENTER> for none:
> 10.10.0.1

Subnet masks are entered as bit counts (as in CIDR notation) in pfSense.
e.g. 255.255.255.0 = 24
     255.255.0.0   = 16
     255.0.0.0     = 8

Enter the new WAN IPv4 subnet bit count (1 to 31):
> 24

For a WAN, enter the new WAN IPv4 upstream gateway address.
For a LAN, press <ENTER> for none:
> 

Enter the new LAN IPv6 address. Press <ENTER> for none:
>

Do you want to enable the DHCP server on LAN? (y/n) y
Enter the start address of the IPv4 client address range: 10.10.0.100
Enter the end address of the IPv4 client address range: 10.10.0.199

Please wait while the changes are saved to LAN...

The IPv4 LAN address has been set to 10.10.0.1/24
You can now access the webConfigurator by opening the following URL in your web browser:
        http://10.10.0.1/

Press <ENTER> to continue.
```

At the pfSense prompt, select 14 to enable the secure shell (sshd):

```bash
SSHD is currently disabled. Would you like to enable it? [y/n] y

Writing configuration... done.

Enabling SSHD...
Reloading firewall rules. done.
```

Extract the list of MAC addresses for all the VMs to create DHCP reservations in pfSense:

```powershell
Get-VMNetworkAdapter -VMName IT-HELP-* | `
	Where-Object { $_.SwitchName -eq "LAN Switch" } | `
	ForEach-Object { [PSCustomObject]@{ VMName = $_.VMName
	MacAddress = $_.MacAddress -Split '(.{2})' -Match '.' -Join ':' } }

VMName       MacAddress
------       ----------
IT-HELP-CA   00:15:5D:19:7F:11
IT-HELP-SRV2 00:15:5D:19:7F:10
IT-HELP-SRV1 00:15:5D:19:7F:0F
IT-HELP-WAYK 00:15:5D:19:7F:07
IT-HELP-DC   00:15:5D:19:7F:05
IT-HELP-DVLS 00:15:5D:19:7F:0B
```

Open the pfSense web interface (http://10.10.0.1/) and login with the default user "admin" and password "pfsense". Change the default password with a generated one and save it.

In the pfSense menu, select **Services**, go to **DHCP Server**. Make sure that **Enable DHCP server on LAN interface** is checked, and review the following under **General Options**:

 * **Subnet**: 10.10.0.0
 * **Subnet mask**: 255.255.255.0
 * **Available range**: 10.10.0.1 - 10.10.0.254
 * **Range**: from 10.10.0.100 to 10.10.0.199

Under **Server**, set the following DNS servers: 1.1.1.1, 1.0.0.1. This list of DNS servers will be pushed through DHCP automatically.

At the bottom of the page, under **DHCP Static Mappings**, create entries using the MAC addresses extracted earlier:

|MAC Address      |IP Address  |Hostname    |
|-----------------|------------|------------|
|00:15:5D:19:7F:05|10.10.0.10  |IT-HELP-DC  |
|00:15:5D:19:7F:11|10.10.0.11  |IT-HELP-CA  |
|00:15:5D:19:7F:0B|10.10.0.21  |IT-HELP-DVLS|
|00:15:5D:19:7F:07|10.10.0.22  |IT-HELP-WAYK|
|00:15:5D:19:7F:0F|10.10.0.31  |IT-HELP-SRV1|
|00:15:5D:19:7F:10|10.10.0.32  |IT-HELP-SRV2|

Click **Save**. With the DHCP server configured, there should be no need for static IP configurations in each VM.

In the pfSense menu, select **Services**, go to **Interfaces** then select **WAN**. Review the **Static IPv4 Configuration**:

 * **IPv4 Address**: 10.9.0.2 /24
 * **IPv4 Upstream gateway**: WANGW - 10.9.0.1

In the pfSense menu, select **Status** then **Gateways**. Make sure that "WANGW" is marked as the default gateway, with IP address 10.9.0.1 and that the status is **Online**. This is very important, otherwise the router VM will not provide internet access in the local network.

In the pfSense menu, select **Services**, go to **Interfaces** then select **LAN**. Review the **Static IPv4 Configuration**:

 * **IPv4 Address**: 10.10.0.1 /24
 * **IPv4 Upstream gateway**: None

There should be no gateway configuration on the LAN interface, so remove it if you configured one by mistake.
