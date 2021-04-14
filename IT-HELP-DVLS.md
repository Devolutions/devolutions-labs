# IT-HELP-WEB VM

Rename the computer and join it to the domain:

```powershell
Add-Computer -DomainName "ad.it-help.ninja" -NewName "IT-HELP-WEB" -Restart
```

Install IIS features:

```powershell
@('Web-Server',
    'Web-Http-Errors',
    'Web-Http-Logging',
    'Web-Static-Content',
    'Web-Default-Doc',
    'Web-Dir-Browsing',
    'Web-AppInit',
    'Web-Net-Ext45',
    'Web-Asp-Net45',
    'Web-ISAPI-Ext',
    'Web-ISAPI-Filter',
    'Web-Basic-Auth',
    'Web-Digest-Auth',
    'Web-Stat-Compression',
    'Web-Windows-Auth',
    'Web-Mgmt-Tools'
    ) | Foreach-Object { Install-WindowsFeature -Name $_ | Out-Null }
```

Install IIS URL Rewrite and Application Request Routing (ARR) modules:

```powershell
choco install -y urlrewrite
choco install -y iis-arr --ignore-checksums
```

Change default IIS configuration settings:

```powershell
& "$Env:WinDir\system32\inetsrv\appcmd.exe" set config `
    -section:system.webServer/proxy -preserveHostHeader:true /commit:apphost

& "$Env:WinDir\system32\inetsrv\appcmd.exe" set config `
    -section:system.WebServer/rewrite/globalRules -useOriginalURLEncoding:false /commit:apphost
```
