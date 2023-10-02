. .\common.ps1

$VMAlias = "DVLS"
$VMNumber = 6
$VMName = $LabPrefix, $VMAlias -Join "-"
$IpAddress = Get-DLabIpAddress $LabNetworkBase $VMNumber

New-DLabVM $VMName -Password $LocalPassword -OSVersion $OSVersion -Force
Start-DLabVM $VMName

Wait-DLabVM $VMName 'Heartbeat' -Timeout 120 -UserName $LocalUserName -Password $LocalPassword
$VMSession = New-DLabVMSession $VMName -UserName $LocalUserName -Password $LocalPassword

Set-DLabVMNetAdapter $VMName -VMSession $VMSession `
    -SwitchName $SwitchName -NetAdapterName $NetAdapterName `
    -IPAddress $IPAddress -DefaultGateway $DefaultGateway `
    -DnsServerAddress $DnsServerAddress

Write-Host "Joining domain"

Add-DLabVMToDomain $VMName -VMSession $VMSession `
    -DomainName $DomainName -DomainController $DomainController `
    -UserName $DomainUserName -Password $DomainPassword

# Wait for virtual machine to reboot after domain join operation

Wait-DLabVM $VMName 'Reboot' -Timeout 120
Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $DomainUserName -Password $DomainPassword

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

Write-Host "Requesting RDP server certificate"

Request-DLabRdpCertificate $VMName -VMSession $VMSession `
    -CAHostName $CAHostName -CACommonName $CACommonName

Write-Host "Initializing PSRemoting"

Initialize-DLabPSRemoting $VMName -VMSession $VMSession

Write-Host "Initializing VNC server"

Initialize-DLabVncServer $VMName -VMSession $VMSession

Write-Host "Installing IIS features"

Invoke-Command -ScriptBlock {
    @('Web-Server',
    'Web-Http-Errors',
    'Web-Http-Logging',
    'Web-Http-Tracing',
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
    'Web-Mgmt-Tools',
    'Web-WebSockets'
    ) | Foreach-Object { Install-WindowsFeature -Name $_ | Out-Null }
} -Session $VMSession

Write-Host "Installing IIS ASP.NET Core Module (ANCM)"

Invoke-Command -ScriptBlock {
    # https://docs.microsoft.com/en-us/aspnet/core/host-and-deploy/iis/?view=aspnetcore-6.0
    # https://docs.microsoft.com/en-us/aspnet/core/host-and-deploy/iis/hosting-bundle?view=aspnetcore-6.0
    $DotNetHostingFileName = "dotnet-hosting-6.0.16-win.exe"
    $DotNetHostingFileUrl = "https://download.visualstudio.microsoft.com/download/pr/7ab0bc25-5b00-42c3-b7cc-bb8e08f05135/91528a790a28c1f0fe39845decf40e10/$DotNetHostingFileName"
    $DotNetHostingFileSHA512 = '5fafc4170dce11f52d970d14e737f5b85491b5257bb7eb5b3c5e9bd275469ac2482185e3d3464a18cb522dfb7f582287451e2f24f86cdaaa3de017e1c8300711'
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest $DotNetHostingFileUrl -OutFile "${Env:TEMP}\$DotNetHostingFileName"
    $FileHash = (Get-FileHash -Algorithm SHA512 "${Env:TEMP}\$DotNetHostingFileName").Hash
    if ($DotNetHostingFileSHA512 -ine $FileHash) { throw "unexpected SHA512 file hash for $DotNetHostingFileName`: $DotNetHostingFileSHA512" }
    Start-Process -FilePath "${Env:TEMP}\$DotNetHostingFileName" -ArgumentList @('/install', '/quiet', '/norestart', 'OPT_NO_X86=1') -Wait -NoNewWindow
    Remove-Item "${Env:TEMP}\$DotNetHostingFileName" -Force | Out-Null
} -Session $VMSession

Write-Host "Installing IIS extensions"

Invoke-Command -ScriptBlock {
    choco install -y --no-progress urlrewrite
    choco install -y --no-progress --ignore-checksums iis-arr
} -Session $VMSession

Write-Host "Increase http.sys UrlSegmentMaxLength"

Invoke-Command -ScriptBlock {
    # https://learn.microsoft.com/en-US/troubleshoot/developer/webapps/iis/iisadmin-service-inetinfo/httpsys-registry-windows
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters' -Name 'UrlSegmentMaxLength' -Value 8192 -Type DWORD
} -Session $VMSession

Write-Host "Changing IIS default rules"

Invoke-Command -ScriptBlock {
    & "$Env:WinDir\system32\inetsrv\appcmd.exe" set config `
        -section:system.webServer/proxy -enabled:true /commit:apphost

    & "$Env:WinDir\system32\inetsrv\appcmd.exe" set config `
        -section:system.webServer/proxy -preserveHostHeader:true /commit:apphost

    & "$Env:WinDir\system32\inetsrv\appcmd.exe" set config `
        -section:system.webServer/rewrite/globalRules -useOriginalURLEncoding:false /commit:apphost
} -Session $VMSession

Write-Host "Installing WebView2 Runtime"

Invoke-Command -ScriptBlock {
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest "https://go.microsoft.com/fwlink/p/?LinkId=2124703" -OutFile 'MicrosoftEdgeWebview2Setup.exe'
    Start-Process -FilePath '.\MicrosoftEdgeWebview2Setup.exe' -ArgumentList @('/silent', '/install') -Wait
    Remove-Item 'MicrosoftEdgeWebview2Setup.exe' -Force | Out-Null
} -Session $VMSession

Write-Host "Installing SQL Server Express"

Invoke-Command -ScriptBlock {
    choco install -y --no-progress sql-server-express
    #choco install -y --no-progress sql-server-management-studio
    Install-Module -Name SqlServer -Scope AllUsers -AllowClobber -Force
} -Session $VMSession

Write-Host "Creating SQL database for DVLS"

$DatabaseName = "dvls"
$SqlInstance = "localhost\SQLEXPRESS"

$SqlUsername = "dvls"
$SqlPassword = "sql123!"

Invoke-Command -ScriptBlock { Param($DatabaseName, $SqlInstance)
    Import-Module SqlServer -Force
    $SqlServer = New-Object Microsoft.SqlServer.Management.Smo.Server($SqlInstance)
    $SqlServer.Settings.LoginMode = [Microsoft.SqlServer.Management.SMO.ServerLoginMode]::Mixed
    $SqlServer.Alter()
    $Database = New-Object Microsoft.SqlServer.Management.Smo.Database($SqlServer, $DatabaseName)
    $Database.Create()
    $Database.RecoveryModel = "simple"
    $Database.Alter()
    Get-Service -Name 'MSSQL$SQLEXPRESS' | Restart-Service
    Start-Sleep -Seconds 2
} -Session $VMSession -ArgumentList @($DatabaseName, $SqlInstance)

Write-Host "Creating SQL user for DVLS"

Invoke-Command -ScriptBlock { Param($DatabaseName, $SqlInstance, $SqlUsername, $SqlPassword)
    Import-Module SqlServer -Force
    $SecurePassword = ConvertTo-SecureString $SqlPassword -AsPlainText -Force
    $SqlCredential = New-Object System.Management.Automation.PSCredential @($SqlUsername, $SecurePassword)
    $Params = @{
        ServerInstance = $SqlInstance;
        LoginPSCredential = $SqlCredential;
        LoginType = "SqlLogin";
        GrantConnectSql = $true;
        Enable = $true;
    }
    Add-SqlLogin @Params
    $SqlServer = New-Object Microsoft.SqlServer.Management.Smo.Server($SqlInstance)
    $Database = $SqlServer.Databases[$DatabaseName]
    $Database.SetOwner('sa')
    $Database.Alter()
    $User = New-Object Microsoft.SqlServer.Management.Smo.User($Database, $SqlUsername)
    $User.Login = $SqlUsername
    $User.Create()
    $Role = $Database.Roles['db_owner']
    $Role.AddMember($SqlUsername)
} -Session $VMSession -ArgumentList @($DatabaseName, $SqlInstance, $SqlUsername, $SqlPassword)

$DvlsVersion = "2023.2.9.0"
$GatewayVersion = "2023.2.3.0"
$DvlsSiteName = "DVLS"
$DvlsPath = "C:\inetpub\dvlsroot"
$DvlsAdminUsername = "dvls-admin"
$DvlsAdminPassword = "dvls-admin123!"
$DvlsAdminEmail = "admin@ad.it-help.ninja"
$DvlsLicense = $licensing.DVLS

$DvlsHostName = "dvls.$DomainName"
$DvlsAccessUri = "https://$DvlsHostName"
$CertificateFile = "~\Documents\cert.pfx"
$CertificatePassword = "cert123!"

Write-Host "Creating new DNS record for Devolutions Server"

Invoke-Command -ScriptBlock { Param($DnsName, $DnsZoneName, $IPAddress, $DnsServer)
    Install-WindowsFeature RSAT-DNS-Server
    $Params = @{
        Name = $DnsName;
        ZoneName = $DnsZoneName;
        IPv4Address = $IPAddress;
        ComputerName = $DnsServer;
        AllowUpdateAny = $true;
    }
    Add-DnsServerResourceRecordA @Params
} -Session $VMSession -ArgumentList @("dvls", $DomainName, $IPAddress, $DCHostName)

Write-Host "Requesting new certificate for Devolutions Server"

Request-DLabCertificate $VMName -VMSession $VMSession `
    -CommonName $DvlsHostName `
    -CAHostName $CAHostName -CACommonName $CACommonName `
    -CertificateFile $CertificateFile -Password $CertificatePassword

Write-Host "Creating Devolutions Server IIS site"

Invoke-Command -ScriptBlock { Param($DvlsHostName, $DvlsSiteName, $DvlsPath, $CertificateFile, $CertificatePassword)
    $DvlsPort = 443;
    New-Item -Path $DvlsPath -ItemType 'Directory' -ErrorAction SilentlyContinue | Out-Null
    $CertificatePassword = ConvertTo-SecureString $CertificatePassword -AsPlainText -Force
    $Params = @{
        FilePath          = $CertificateFile;
        CertStoreLocation = "cert:\LocalMachine\My";
        Password          = $CertificatePassword;
        Exportable        = $true;
    }
    $Certificate = Import-PfxCertificate @Params
    $CertificateThumbprint = $Certificate.Thumbprint
    $BindingInformation = '*:' + $DvlsPort + ':' + $DvlsHostName
    $Params = @{
        Name = $DvlsSiteName;
        Protocol = "https";
        SslFlag = "Sni";
        PhysicalPath = $DvlsPath;
        BindingInformation = $BindingInformation;
        CertStoreLocation = "cert:\LocalMachine\My";
        CertificateThumbprint = $CertificateThumbprint;
    }
    New-IISSite @Params
} -Session $VMSession -ArgumentList @($DvlsHostName, $DvlsSiteName, $DvlsPath, $CertificateFile, $CertificatePassword)

Write-Host "Installing Devolutions Console"

Invoke-Command -ScriptBlock { Param($DvlsVersion)
    $ProgressPreference = 'SilentlyContinue'
    $DownloadBaseUrl = "https://cdn.devolutions.net/download"
    $DvlsConsoleExe = "$(Resolve-Path ~)\Documents\Setup.DVLS.Console.exe"
    Invoke-WebRequest "$DownloadBaseUrl/Setup.DVLS.Console.${DvlsVersion}.exe" -OutFile $DvlsConsoleExe
    Start-Process -FilePath $DvlsConsoleExe -ArgumentList @('/qn') -Wait
} -Session $VMSession -ArgumentList @($DvlsVersion)

Write-Host "Installing Devolutions Server"

Invoke-Command -ScriptBlock { Param($DvlsVersion, $GatewayVersion,
    $DvlsPath, $DvlsSiteName, $DvlsAccessUri, $DatabaseName,
    $SqlInstance, $SqlUsername, $SqlPassword,
    $DvlsAdminUsername, $DvlsAdminPassword,
    $DvlsAdminEmail, $DvlsLicense)

    $ProgressPreference = 'SilentlyContinue'
    $DownloadBaseUrl = "https://cdn.devolutions.net/download"

    Write-Host "Downloading Devolutions Server version $DvlsVersion"
    $DvlsWebAppZip = "$(Resolve-Path ~)\Documents\DVLS.${DvlsVersion}.zip"
    if (-Not $(Test-Path -Path $DvlsWebAppZip -PathType 'Leaf')) {
        Invoke-WebRequest "$DownloadBaseUrl/RDMS/DVLS.${DvlsVersion}.zip" -OutFile $DvlsWebAppZip
    }

    Write-Host "Downloading Devolutions Gateway version $GatewayVersion"
    $GatewayMsi = "$(Resolve-Path ~)\Documents\DevolutionsGateway.msi"
    if (-Not $(Test-Path -Path $GatewayMsi -PathType 'Leaf')) {
        Invoke-WebRequest "$DownloadBaseUrl/DevolutionsGateway-x86_64-${GatewayVersion}.msi" -OutFile $GatewayMsi
    }

    $BackupKeysPassword = "DvlsBackupKeys123!"
    $BackupKeysPath = "$(Resolve-Path ~)\Documents\DvlsBackupKeys"
    New-Item -Path $BackupKeysPath -ItemType 'Directory' -ErrorAction SilentlyContinue | Out-Null

    $DvlsConsoleArgs = @(
        "server", "install",
        "-v", "--acceptEula", "-q",
        "--adminUsername=$DvlsAdminUsername",
        "--adminPassword=$DvlsAdminPassword",
        "--adminEmail=$DvlsAdminEmail",
        "--installZip=$DvlsWebAppZip",
        "--dps-path=$DvlsPath",
        "--dps-website-name=$DvlsSiteName",
        "--web-application-name=/",
        "--access-uri=$DvlsAccessUri",
        "--backupKeysPath=$BackupKeysPath",
        "--backupKeysPassword=$BackupKeysPassword",
        "--databaseHost=$SqlInstance",
        "--databaseName=$DatabaseName",
        "--db-username=$SqlUsername",
        "--db-password=$SqlPassword",
        "--install-devolutions-gateway",
        "--gateway-msi=$GatewayMsi",
        "--disableEncryptConfig",
        "--disablePassword")

    if ($DvlsAccessUri.StartsWith("http://")) {
        $DvlsConsoleArgs += @("--disable-https")
    }

    if (-Not [string]::IsNullOrEmpty($DvlsLicense)) {
        $DvlsConsoleArgs += @('--serial', $DvlsLicense)
    }

    $DvlsConsoleCli = "${Env:ProgramFiles(x86)}\Devolutions\Devolutions Server Console\DPS.Console.CLI.exe"

    Write-Host "& '$DvlsConsoleCli' $($DvlsConsoleArgs -Join ' ')"

    & $DvlsConsoleCli @DvlsConsoleArgs

} -Session $VMSession -ArgumentList @($DvlsVersion, $GatewayVersion,
    $DvlsPath, $DvlsSiteName, $DvlsAccessUri, $DatabaseName,
    $SqlInstance, $SqlUsername, $SqlPassword,
    $DvlsAdminUsername, $DvlsAdminPassword,
    $DvlsAdminEmail, $DvlsLicense)
