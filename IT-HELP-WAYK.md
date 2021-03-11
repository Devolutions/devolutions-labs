# IT-HELP-WAYK VM

```powershell
Add-Computer -DomainName "ad.it-help.ninja" -NewName "IT-HELP-WAYK" -Restart
```

## Prerequisites

Install Docker for Windows:

```powershell
Install-WindowsFeature -Name Containers
Install-Module -Name DockerMsftProvider -Force
Install-Package -Name docker -ProviderName DockerMsftProvider -Force
```

To complete the Docker installation, restart the computer:

```powershell
Restart-Computer
```

The `docker` command should now be available:

```powershell
PS > docker --version
Docker version 19.03.14, build e820475
```

To confirm that Docker is working correctly, you can run the "hello-world" container:

```powershell
PS > docker run hello-world

Hello from Docker!
This message shows that your installation appears to be working correctly.

To generate this message, Docker took the following steps:
 1. The Docker client contacted the Docker daemon.
 2. The Docker daemon pulled the "hello-world" image from the Docker Hub.
    (windows-amd64, nanoserver-1809)
 3. The Docker daemon created a new container from that image which runs the
    executable that produces the output you are currently reading.
 4. The Docker daemon streamed that output to the Docker client, which sent it
    to your terminal.

To try something more ambitious, you can run a Windows Server container with:
 PS C:\> docker run -it mcr.microsoft.com/windows/servercore:ltsc2019 powershell

Share images, automate workflows, and more with a free Docker ID:
 https://hub.docker.com/

For more examples and ideas, visit:
 https://docs.docker.com/get-started/
```

## Initial Configuration

Install the **WaykBastion** PowerShell module for all users:

```powershell
Install-Module WaykBastion -Scope AllUsers
Import-Module -Name WaykBastion
```

Create a new Wayk Bastion configuration:

```powershell
New-WaykBastionConfig -Realm "it-help.ninja" -ListenerUrl "http://localhost:4000" -ExternalUrl "http://localhost:4000"
```

You can now inspect the new Wayk Bastion configuration that was just created:

```powershell
PS > Get-WaykBastionPath
C:\ProgramData\Devolutions\Wayk Bastion
PS > Enter-WaykBastionConfig -ChangeDirectory
PS > Get-WaykBastionConfig -NonDefault
Realm       : it-help.ninja
ExternalUrl : http://localhost:4000
ListenerUrl : http://localhost:4000
```

You can now pull the container images used in Wayk Bastion using the **Update-WaykBastionImage** command. This step is done automatically when launching Wayk Bastion, but since the Windows container images are quite large, it is good to prefetch them:

```powershell
PS > Update-WaykBastionImage
docker pull library/mongo:4.2-windowsservercore-1809
docker pull devolutions/picky:4.8.0-servercore-ltsc2019
docker pull devolutions/den-lucid:3.9.4-servercore-ltsc2019
docker pull devolutions/den-server:3.3.0-servercore-ltsc2019
docker pull library/traefik:1.7-windowsservercore-1809
docker pull devolutions/devolutions-gateway:0.14.0-servercore-ltsc2019
```

This operation should take a while for the first containers, and will complete much faster for the rest. You can now launch Wayk Bastion for the first time:

```powershell
Start-WaykBastion -Verbose
```

The **-Verbose** parameter is not required, but it is useful to see the complete Docker commands that are executed under the hood to launch the multiple containers that Wayk Bastion is comprised of. Don't bother trying to understand it too much, just know that it is there for reference.

Once started, open [http://localhost:4000](http://localhost:4000) in your browser to proceed with the Wayk Bastion initial setup. Enter the default username ("wayk-admin") and password ("wayk-admin"), after which you will need to create the admin account. Enter the admin username ("wayk-admin") and a strong generated password to complete the process.

Congratulations, you now have access to the Wayk Bastion management interface! We now need to configure secure external access and deploy Wayk Agent to multiple machines before making the first connection using Wayk Client.

## Secure External Access

Add a new DNS 'A' record in Active Directory for "bastion" pointing to the machine hosting Wayk Bastion (IT-HELP-WAYK):

```powershell
Add-DnsServerResourceRecordA -Name "bastion" -ZoneName "ad.it-help.ninja" -AllowUpdateAny -IPv4Address "10.10.0.22"
```

Import a certificate emitted by a trusted certificate authority (use Active Directory Certificate Services) for "bastion.ad.it-help.ninja". Follow the instructions from the [IT-HELP-CA](IT-HELP-CA.md) certificate authority VM to generate the certificate.

```powershell
Import-WaykBastionCertificate -CertificateFile ".\bastion.ad.it-help.ninja.pfx" -Password "cert123!"
```

Reconfigure the Wayk Bastion listener and external URLs:

```powershell
Set-WaykBastionConfig -ListenerUrl "https://localhost:443" -ExternalUrl "https://bastion.ad.it-help.ninja"
```

The **-ListenerUrl** parameter becomes "https://localhost:443", which means "listen in HTTPS on port 443". Importing a certificate does not automatically enable HTTPS, so make sure to use "https://" instead of "http://" if the intent is to listen in HTTPS.

The **-ExternalUrl** parameter becomes "https://bastion.ad.it-help.ninja". It is *very* important to access Wayk Bastion through this URL only: using the IP address or a different hostname will result in a broken page that loads partially.

Restart Wayk Bastion to apply the configuration changes:

```powershell
Restart-WaykBastion
```

Open "https://bastion.ad.it-help.ninja" in a browser from one of the domain-joined VMs. The Wayk Bastion web interface should load without warnings over HTTPS. Automatic certificate validation is mandatory for Wayk Client and Wayk Agent. If certificate validation fails, review the instructions from the [IT-HELP-CA certificate authority VM](IT-HELP-CA.md).

## Wayk Agent Deployment

In Wayk Bastion, under **Settings** go to **Machine Registration**. Click on the "+" button at the top right of the screen, then click **Generate** to generate a new token. The new token id can be used to register machines automatically to Wayk Bastion.

Run the following commands on the **IT-HELP-GW** and **IT-HELP-WEB** virtual machines to:
 * Install the **WaykAgent** PowerShell module
 * Install quietly Wayk Agent unattended
 * Register Wayk Agent with Wayk Bastion

```powershell
Install-Module -Name WaykAgent -Force
Import-Module -Name WaykAgent
Install-WaykAgent -Quiet
$TokenId = "9390e88d-d9df-46ed-a821-4ddef1de0d70"
$BastionUrl = "https://bastion.ad.it-help.ninja"
Register-WaykAgent -DenUrl $BastionUrl -TokenId $TokenId
```

The new machines managed by Wayk Agent and registered in Wayk Bastion should now be visible in the **Machines** section of the web interface. For advanced deployment options (.msi installer, custom executable) [refer to the documentation](https://docs.devolutions.net/wayk/bastion/deployment-automation.html).

## Wayk Client Connection

In Wayk Bastion, [add a new license and assign it to a user](https://docs.devolutions.net/wayk/bastion/license-management.html).

On **IT-HELP-WAYK**, install Wayk Client and configure it to use the correct Wayk Bastion URL:

```powershell
Install-Module -Name WaykClient -Force
Import-Module -Name WaykClient
Install-WaykClient -Quiet
Set-WaykClientConfig -DenUrl "https://bastion.ad.it-help.ninja"
```

Launch Wayk Client, then go in **File**, then **Options**. In the **Connectivity** tab, make sure that the Wayk Bastion URL is set to "https://bastion.ad.it-help.ninja", then click **Login**. The Wayk Bastion login page will be opened with the default system browser, login using the technician user with an assigned license.

In the Wayk Bastion web interface, go to the **Machines** section and select the **IT-HELP-GW** virtual machine. At the top right of the screen, click the **Connect** button, then select **Desktop Client**.

When prompted to open wayk:// links using Wayk Client, simply accept. The Wayk Client program should now initiate the connection to **IT-HELP-GW** and prompt for a system username and password. Use the previously configured Administrator account for now to connect.

Voila! You just made your first connection using Wayk Bastion.
