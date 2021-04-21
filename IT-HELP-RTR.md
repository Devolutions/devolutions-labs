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

```bash
mkfs.vfat /dev/sda1
mount -t vfat /dev/sda1 /media/usb
grep /dev/sda1 /proc/mounts >> /etc/fstab
```

Run `setup-alpine`:

```text
Select keyboard layout: [none] us
Select variant (or 'abort') us
Enter system hostname (short form, e.g. 'foo') [localhost] alpine
Available interfaces are: eth0
Enter '?' for help on bridges, bonding and vlans.
Which one do you want to initialize? (or '?' or 'done') [eth0]
Ip address for eth0? (or 'dhcp', 'none', '?') [dhcp]
Do you want to do any manual network configuration? (y/n) [n]
Changing password for root
New password: alpine123!
Retype password: alpine123!
password: password for root changed by root
Which timezone are you in? ('?' for list) [UTC] America/Toronto
HTTP/FTP proxy URL? (e.g. 'http://proxy:8080', or 'none') [none]
Which NTP client to run? ('busybox', 'openntpd', 'chrony', or 'none') [chrony]
Enter mirror number (1-60) or URL to add (or r/f/e/done) [1] 1
Which SSH server? ('openssh', 'dropbear', or 'none') [openssh]
No available disks found. Unmount /media/cdrom and retry? (y/n) [n]
Enter where to store configs ('floppy', 'usb', or 'none') [usb]
Enter apk cache directory (or '?' or 'none') [/media/usb/cache]
```

Save the modifications to the external USB, then shutdown the VM:

```bash
lbu ci usb
poweroff
```

Create and edit the "/etc/network/interfaces":

```text
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
        address 10.9.0.3/24
        netmask 255.255.255.0
        gateway 10.9.0.1

auto eth1
iface eth1 inet static
        address 10.10.0.51/24
        netmask 255.255.255.0
```

Restart networking:

```bash
/etc/init.d/networking restart
```

At this point, you should be able to ping www.google.com and access the internet from the VM.

Create iptables configuration:

```powershell
apk add iptables
rc-update add iptables

echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i eth1 -j ACCEPT
/etc/init.d/iptables save
/etc/init.d/iptables restart
```

Install a few basic tools:

```bash
apk add nano
apk add sudo
```

Install [Hyper-V guest services](https://wiki.alpinelinux.org/wiki/Hyper-V_guest_services):

```bash
apk add hvtools
rc-update add hv_fcopy_daemon
rc-update add hv_kvp_daemon
rc-update add hv_vss_daemon
```

Install [OpenSSH server](https://wiki.alpinelinux.org/wiki/Setting_up_a_ssh-server)

```bash
apk add openssh
rc-update add sshd
/etc/init.d/sshd start
```

Edit "/etc/ssh/sshd_config" and add the following lines:

```text
PermitRootLogin yes
Subsystem       powershell      /opt/microsoft/powershell/7/pwsh -sshs -NoLogo
```

Reboot Alpine Linux, then connect to the VM from the host:

```bash
hvc.exe ssh root@IT-HELP-RTR
```

Install [PowerShell 7](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux) for Alpine Linux:

```bash
apk add --no-cache ca-certificates less \
    ncurses-terminfo-base krb5-libs \
    libgcc libintl libssl1.1 libstdc++ \
    tzdata userspace-rcu zlib icu-libs curl

apk -X https://dl-cdn.alpinelinux.org/alpine/edge/main add --no-cache lttng-ust

curl -L https://github.com/PowerShell/PowerShell/releases/download/v7.1.3/powershell-7.1.3-linux-alpine-x64.tar.gz -o /tmp/powershell.tar.gz

mkdir -p /opt/microsoft/powershell/7
tar zxf /tmp/powershell.tar.gz -C /opt/microsoft/powershell/7
chmod +x /opt/microsoft/powershell/7/pwsh
ln -s /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh
```
