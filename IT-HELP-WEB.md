# IT-HELP-WEB VM

Rename the computer and join it to the domain:

```powershell
Add-Computer -DomainName "ad.it-help.ninja" -NewName "IT-HELP-WEB" -Restart
```

Install IIS features:

```powershell
$Features = @(
    'Web-Server',
    'Web-WebSockets',
    'Web-Mgmt-Tools')

foreach ($Feature in $Features) {
    Install-WindowsFeature -Name $Feature
}
```

Install IIS URL Rewrite and Application Request Routing (ARR) modules:

```powershell
choco install -y urlrewrite
choco install -y iis-arr
```

Change default IIS configuration settings:

```powershell
& "$Env:WinDir\system32\inetsrv\appcmd.exe" set config `
    -section:system.webServer/proxy -preserveHostHeader:true /commit:apphost

& "$Env:WinDir\system32\inetsrv\appcmd.exe" set config `
    -section:system.WebServer/rewrite/globalRules -useOriginalURLEncoding:false /commit:apphost
```
