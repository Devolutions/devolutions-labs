
# IT-HELP-WAYK VM

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

## Wayk Agent Deployment

## Wayk Client Connection

