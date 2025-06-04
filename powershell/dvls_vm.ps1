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
    # https://dotnet.microsoft.com/permalink/dotnetcore-current-windows-runtime-bundle-installer
    $DotNetHostingFileName = "dotnet-hosting-9.0.4-win.exe"
    $DotNetHostingFileUrl = "https://builds.dotnet.microsoft.com/dotnet/aspnetcore/Runtime/9.0.4/$DotNetHostingFileName"
    $DotNetHostingFileSHA512 = 'e02d6e48361bc09f84aefef0653bd1eaa1324795d120758115818d77f1ba0bca751dcc7e7c143293c7831fd72ff566d7c2248d1cb795f8d251c04631bc4459ea'
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
    choco install -y --no-progress sql-server-management-studio
    Install-Module -Name SqlServer -Scope AllUsers -AllowClobber -Force
} -Session $VMSession

Write-Host "Creating SQL database for RDM"

$SqlInstance = "localhost\SQLEXPRESS"
$RdmDatabaseName = "rdm"
$RdmSqlUsername = "rdm"
$RdmSqlPassword = "sql123!"

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
} -Session $VMSession -ArgumentList @($RdmDatabaseName, $SqlInstance)

Write-Host "Creating SQL user for RDM"

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
} -Session $VMSession -ArgumentList @($RdmDatabaseName, $SqlInstance, $RdmSqlUsername, $RdmSqlPassword)

Write-Host "Creating SQL database for DVLS"

$SqlInstance = "localhost\SQLEXPRESS"
$DatabaseName = "dvls"
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

$DvlsVersion = ""
$GatewayVersion = ""

$ProductsHtm = Invoke-RestMethod -Uri "https://devolutions.net/productinfo.htm" -Method 'GET' -ContentType 'text/plain'
foreach ($line in $($ProductsHtm -split "`n")) {
    if ($line -match '^DPSbin\.Version=(.+)$') {
        $DvlsVersion = $matches[1].Trim()
    } elseif ($line -match '^Gatewaybin\.Version=(.+)$') {
        $GatewayVersion = $matches[1].Trim()
    }
}

if ([string]::IsNullOrEmpty($DvlsVersion)) {
    throw "failed to detect DVLS version"
}
Write-Host "DVLS Version: $DVLSVersion"

if ([string]::IsNullOrEmpty($GatewayVersion)) {
    throw "failed to detect DVLS version"
}
Write-Host "Gateway Version: $GatewayVersion"

$DvlsSiteName = "DVLS"
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

Write-Host "Enabling and configuring TLS in SQL Server"

Invoke-Command -ScriptBlock {
    $SqlServerBaseKey = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQLServer"
    $SuperSocketLibKey = Join-Path $SqlServerBaseKey "SuperSocketNetLib"
    $SuperSocketLibTcpKey = Join-Path $SuperSocketLibKey "Tcp"
    $SuperSocketLibTcpIpAllKey = Join-Path $SuperSocketLibTcpKey "IPAll"

    Set-ItemProperty -Path $SuperSocketLibTcpKey -Name "Enabled" -Value 1
    Set-ItemProperty -Path $SuperSocketLibTcpIpAllKey -Name "TcpPort" -Value "1433"
    Set-ItemProperty -Path $SuperSocketLibTcpIpAllKey -Name "TcpDynamicPorts" -Value ""

    $cert = Get-ChildItem "cert:\LocalMachine\My" |
        Where-Object { $_.Subject -like "CN=$Env:COMPUTERNAME.*" } |
        Sort-Object NotBefore -Descending | Select-Object -First 1

    if (-Not $cert) {
        throw "TLS certificate not found for CN=$Env:COMPUTERNAME"
    }

    $thumbprint = $cert.Thumbprint
    $keyId = if ($PSEdition -eq 'Core') {
        $cert.PrivateKey.Key.UniqueName
    } else {
        $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
    }
    $keyFile = Join-Path "$Env:ProgramData\Microsoft\Crypto\RSA\MachineKeys" $keyId

    $scOut = sc.exe showsid 'MSSQL$SQLEXPRESS'
    $sid = ($scOut | Select-String -Pattern '^SERVICE SID:').ToString().Split(':')[1].Trim()

    $acl = Get-Acl -Path $keyFile
    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sidObj, "Read", "Allow")
    $acl.AddAccessRule($rule)
    Set-Acl -Path $keyFile -AclObject $acl

    Set-ItemProperty -Path $SuperSocketLibKey -Name "Certificate" -Value $thumbprint
    Set-ItemProperty -Path $SuperSocketLibKey -Name "ForceEncryption" -Value 0 -Type DWORD

    New-NetFirewallRule -DisplayName "SQL Server TCP 1433" -Direction Inbound -Protocol TCP -LocalPort 1433 -Action Allow

    Restart-Service -Name 'MSSQL$SQLEXPRESS' -Force
    Start-Sleep -Seconds 2
} -Session $VMSession

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

Write-Host "Installing .NET Desktop Runtime"

Invoke-Command -ScriptBlock {
    $MajorVersion = "9.0"
    $RuntimeType = "windowsdesktop"
    $Architecture = if ($Env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { "win-arm64" } else { "win-x64" }
    $ReleasesJsonUrl = "https://builds.dotnet.microsoft.com/dotnet/release-metadata/$MajorVersion/releases.json"
    $ReleasesData = Invoke-RestMethod -Uri $ReleasesJsonUrl

    $LatestReleaseWithDesktop = $ReleasesData.releases |
        Where-Object { $_.windowsdesktop -and $_.windowsdesktop.files } |
        Sort-Object -Property 'release-date' -Descending | Select-Object -First 1

    if (-not $LatestReleaseWithDesktop) {
        throw "Could not find any releases with $RuntimeType runtime."
    }

    $DesktopRuntimeVersion = $LatestReleaseWithDesktop.windowsdesktop.version
    $DesktopRuntimeFiles = $LatestReleaseWithDesktop.windowsdesktop.files
    $Installer = $DesktopRuntimeFiles | Where-Object {
        $_.rid -eq $Architecture -and $_.name -like "$RuntimeType-runtime-*-*.exe"
    } | Select-Object -First 1

    if (-not $Installer) {
        throw "Could not find $RuntimeType runtime installer for $Architecture"
    }

    $DownloadUrl = $Installer.url
    $ExpectedFileHash = $Installer.hash
    $InstallerFileName = Split-Path -Leaf $DownloadUrl
    $InstallerLocalPath = Join-Path $Env:TEMP $InstallerFileName
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest $DownloadUrl -OutFile $InstallerLocalPath
    $ActualFileHash = (Get-FileHash -Algorithm SHA512 $InstallerLocalPath).Hash
    if ($ExpectedFileHash -ine $ActualFileHash) { throw "Unexpected SHA512 file hash for $InstallerFileName`: $ActualFileHash" }
    Start-Process -FilePath $InstallerLocalPath -ArgumentList @('/install', '/quiet', '/norestart', 'OPT_NO_X86=1') -Wait -NoNewWindow
    Remove-Item $InstallerLocalPath -Force | Out-Null

    Write-Host ".NET $RuntimeType runtime $DesktopRuntimeVersion installed successfully."
} -Session $VMSession

Write-Host "Installing Devolutions Console"

Invoke-Command -ScriptBlock { Param($DvlsVersion)
    $ProgressPreference = 'SilentlyContinue'
    $DownloadBaseUrl = "https://cdn.devolutions.net/download"
    $DvlsConsoleExe = "$(Resolve-Path ~)\Documents\Setup.DVLS.Console.exe"
    Invoke-WebRequest "$DownloadBaseUrl/Setup.DVLS.Console.${DvlsVersion}.exe" -OutFile $DvlsConsoleExe
    Start-Process -FilePath $DvlsConsoleExe -ArgumentList @('/exenoui', '/quiet', '/norestart') -Wait
} -Session $VMSession -ArgumentList @($DvlsVersion)

Write-Host "Installing Devolutions Server"

Invoke-Command -ScriptBlock { Param($DvlsVersion, $GatewayVersion,
    $DvlsPath, $DvlsSiteName, $DvlsAccessUri, $DatabaseName,
    $SqlInstance, $SqlUsername, $SqlPassword,
    $DvlsAdminUsername, $DvlsAdminPassword,
    $DvlsAdminEmail)

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

    $PasswordFilePath = [Environment]::GetFolderPath('Desktop')
    New-Item -Path $PasswordFilePath -ItemType 'Directory' -ErrorAction SilentlyContinue | Out-Null

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
        "--pwd-file-path=$PasswordFilePath",
        "--install-devolutions-gateway",
        "--gateway-msi=$GatewayMsi",
        "--disableEncryptConfig",
        "--disablePassword")

    if ($DvlsAccessUri.StartsWith("http://")) {
        $DvlsConsoleArgs += @("--disable-https")
    }

    $DvlsConsoleCli = "${Env:ProgramFiles}\Devolutions\Devolutions Server Console\DPS.Console.CLI.exe"

    Write-Host "& '$DvlsConsoleCli' $($DvlsConsoleArgs -Join ' ')"

    & $DvlsConsoleCli @DvlsConsoleArgs

} -Session $VMSession -ArgumentList @($DvlsVersion, $GatewayVersion,
    $DvlsPath, $DvlsSiteName, $DvlsAccessUri, $DatabaseName,
    $SqlInstance, $SqlUsername, $SqlPassword,
    $DvlsAdminUsername, $DvlsAdminPassword,
    $DvlsAdminEmail)
