. .\common.ps1

$VMAlias = "DVLS"
$VMNumber = 6
$VMName = $LabPrefix, $VMAlias -Join "-"
$IpAddress = Get-DLabIpAddress $LabNetworkBase $VMNumber

New-DLabVM $VMName -Password $Password -Force
Start-DLabVM $VMName

Wait-DLabVM $VMName 'Heartbeat' -Timeout 120 -UserName $UserName -Password $Password
$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

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

Write-Host "Installing IIS features"

Invoke-Command -ScriptBlock {
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
} -Session $VMSession

Write-Host "Installing IIS extensions"

Invoke-Command -ScriptBlock {
    choco install -y urlrewrite
    choco install -y iis-arr --ignore-checksums
} -Session $VMSession

Write-Host "Changing IIS default rules"

Invoke-Command -ScriptBlock {
    & "$Env:WinDir\system32\inetsrv\appcmd.exe" set config `
        -section:system.webServer/proxy -preserveHostHeader:true /commit:apphost

    & "$Env:WinDir\system32\inetsrv\appcmd.exe" set config `
        -section:system.WebServer/rewrite/globalRules -useOriginalURLEncoding:false /commit:apphost
} -Session $VMSession

Write-Host "Installing SQL Server Express"

Invoke-Command -ScriptBlock {
    choco install -y --no-progress sql-server-express
    choco install -y --no-progress sql-server-management-studio
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

$DvlsVersion = "2022.1.9.0"
$DvlsPath = "C:\inetpub\dvlsroot"
$DvlsAdminUsername = "dvls-admin"
$DvlsAdminPassword = "dvls-admin123!"
$DvlsAdminEmail = "admin@ad.it-help.ninja"

$DvlsHostName = "dvls.$DomainName"
$DvlsAccessUri = "https://$DvlsHostName"
$CertificateFile = "~\Documents\cert.pfx"
$CertificatePassword = "cert123!"

Write-Host "Creating new DNS record for Devolutions Server"

Invoke-Command -ScriptBlock { Param($DnsName, $DnsZoneName, $IPAddress, $DnsServer)
    Install-WindowsFeature RSAT-DNS-Server
    Add-DnsServerResourceRecordA -Name $DnsName -ZoneName $DnsZoneName -IPv4Address $IPAddress -AllowUpdateAny -ComputerName $DnsServer
} -Session $VMSession -ArgumentList @("dvls", $DomainName, $IPAddress, $DCHostName)

Write-Host "Requesting new certificate for Devolutions Server"

Request-DLabCertificate $VMName -VMSession $VMSession `
    -CommonName $DvlsHostName `
    -CAHostName $CAHostName -CACommonName $CACommonName `
    -CertificateFile $CertificateFile -Password $CertificatePassword

Write-Host "Creating Devolutions Server IIS site"

Invoke-Command -ScriptBlock { Param($DvlsHostName, $DvlsPath, $CertificateFile, $CertificatePassword)
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
        Name = "DVLS";
        Protocol = "https";
        SslFlag = "Sni";
        PhysicalPath = $DvlsPath;
        BindingInformation = $BindingInformation;
        CertStoreLocation = "cert:\LocalMachine\My";
        CertificateThumbprint = $CertificateThumbprint;
    }
    New-IISSite @Params
} -Session $VMSession -ArgumentList @($DvlsHostName, $DvlsPath, $CertificateFile, $CertificatePassword)

Write-Host "Installing Devolutions Console"

Invoke-Command -ScriptBlock { Param($DvlsVersion)
    $ProgressPreference = 'SilentlyContinue'
    $DownloadBaseUrl = "https://cdn.devolutions.net/download"
    $DvlsConsoleExe = "$(Resolve-Path ~)\Documents\Setup.DVLS.Console.exe"
    Invoke-WebRequest "$DownloadBaseUrl/Setup.DVLS.Console.${DvlsVersion}.exe" -OutFile $DvlsConsoleExe
    Start-Process -FilePath $DvlsConsoleExe -ArgumentList @('/qn') -Wait
} -Session $VMSession -ArgumentList @($DvlsVersion)

Write-Host "Install Devolutions Server"

Invoke-Command -ScriptBlock { Param($DvlsVersion, $DvlsPath, $DvlsAccessUri,
    $SqlInstance, $SqlUsername, $SqlPassword,
    $DvlsAdminUsername, $DvlsAdminPassword, $DvlsAdminEmail)

    $ProgressPreference = 'SilentlyContinue'
    $DownloadBaseUrl = "https://cdn.devolutions.net/download"
    $DvlsWebAppZip = "$(Resolve-Path ~)\Documents\DVLS.${DvlsVersion}.zip"

    if (-Not $(Test-Path -Path $DvlsWebAppZip -PathType 'Leaf')) {
        Invoke-WebRequest "$DownloadBaseUrl/RDMS/DVLS.${DvlsVersion}.zip" -OutFile $DvlsWebAppZip
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
        "--installZip=`"$DvlsWebAppZip`"",
        "--dps-path=`"$DvlsPath`""
        "--website=`"DVLS`"",
        "--access-uri=`"$DvlsAccessUri`"",
        "--serverName=`"Devolutions Server`"",
        "--backupKeysPath=`"$BackupKeysPath`"",
        "--backupKeysPassword=$BackupKeysPassword",
        "--databaseHost=$SqlInstance",
        "--databaseName=`"dvls`"",
        "--db-username=$SqlUsername",
        "--db-password=$SqlPassword",
        "--disableEncryptConfig",
        "--disablePassword")

    $DvlsConsoleCli = "${Env:ProgramFiles(x86)}\Devolutions\Devolutions Server Console\DPS.Console.CLI.exe"

    & $DvlsConsoleCli @DvlsConsoleArgs

} -Session $VMSession -ArgumentList @($DvlsVersion, $DvlsPath, $DvlsAccessUri,
    $SqlInstance, $SqlUsername, $SqlPassword,
    $DvlsAdminUsername, $DvlsAdminPassword, $DvlsAdminEmail)
