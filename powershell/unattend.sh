#!/bin/sh

# Setup apk cache on USB drive
mount -o remount,rw /media/sda1
mkdir /media/sda1/cache
setup-apkcache /media/sda1/cache

# Install iptables
apk add iptables
rc-update add iptables

# Configure routing
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i eth1 -j ACCEPT
/etc/init.d/iptables save
/etc/init.d/iptables restart

# Install DHCP server
apk add dnsmasq
rc-update add dnsmasq default

# Install common tools
apk add nano
apk add sudo

# Install Hyper-V extensions
apk add hvtools
rc-update add hv_fcopy_daemon
rc-update add hv_kvp_daemon
rc-update add hv_vss_daemon

# Install OpenSSH
apk add openssh
rc-update add sshd

# fix key permissions
find /etc/ssh/*_key -type f -exec chmod 600 {} \;;

# Enable SSH root login
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# Install PowerShell 7

apk add --no-cache ca-certificates less \
    ncurses-terminfo-base krb5-libs \
    libgcc libintl libssl1.1 libstdc++ \
    tzdata userspace-rcu zlib icu-libs curl

apk -X https://dl-cdn.alpinelinux.org/alpine/edge/main add --no-cache lttng-ust

curl -L https://github.com/PowerShell/PowerShell/releases/download/v7.3.12/powershell-7.3.12-linux-alpine-x64.tar.gz -o /tmp/powershell.tar.gz

mkdir -p /opt/microsoft/powershell/7
tar zxf /tmp/powershell.tar.gz -C /opt/microsoft/powershell/7
chmod +x /opt/microsoft/powershell/7/pwsh
ln -s /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh

# Enable PowerShell Remoting
echo "Subsystem powershell /opt/microsoft/powershell/7/pwsh -sshs -NoLogo" >> /etc/ssh/sshd_config

# commit overlay changes
lbu ci

# disable run-once script
mv /media/sda1/unattend.sh /media/sda1/unattend.old

# shutdown, we're done!
poweroff
