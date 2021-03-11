# IT-HELP-DC VM

Connect to the domain controller VM (IT-HELP-DC) and make sure that it correctly obtained its IP address through DHCP (10.10.0.10) and that DNS can resolve google.com (nslookup google.com).

Rename the computer to IT-HELP-DC:

```powershell
Rename-Computer -NewName "IT-HELP-DC"
```

Install the Active Directory Domain Services feature including the management tools:

```powershell
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
```

Create the new Active Directory forest. This a point of no return, so creating a manual Hyper-V checkpoint is recommended. Make sure that the computer name ($Env:ComputerName) is set to "IT-HELP-DC" because it cannot be changed later. Generate a password for the Active Directory safe administrator and use it when prompted by the `Install-ADDSForest` command.

```powershell
Install-ADDSForest -DomainName "ad.it-help.ninja" -DomainNetbiosName "IT-HELP" -InstallDNS
```

The IT-HELP-DC will reboot to complete the domain controller promotion. The process can take at least 5 minutes to complete, so be patient. The domain controller VM should now become the DNS server used by all other VMs inside the local network, so the pfSense DHCP Server and DNS Resolver configuration need to be updated.

In the pfSense menu, select **Services**, then **DNS Resolver**. Make sure that **Enable DNS Resolver** is unchecked, because pfSense should **not** act as the DNS server.

In the pfSense menu, select **Services**, then **DHCP Server**. In the **Servers** section, remove the previous list of DNS servers (1.1.1.1, 1.0.0.1) and enter the IP address of the domain controller VM (10.10.0.10 for IT-HELP-DC), then click **Save**. All VMs in the local network will now automatically point to the correct DNS server required for Active Directory to work.
