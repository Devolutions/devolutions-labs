
$ErrorActionPreference = 'Stop'

Write-Host "Enabling TLS 1.2 for .NET Framework applications"

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWORD
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWORD

Write-Host "Disabling Server Manager automatic launch and Windows Admin Center pop-up"

$ServerManagerReg = "HKLM:\SOFTWARE\Microsoft\ServerManager"
Set-ItemProperty -Path $ServerManagerReg -Name 'DoNotPopWACConsoleAtSMLaunch' -Value '1' -Type DWORD
Set-ItemProperty -Path $ServerManagerReg -Name 'DoNotOpenServerManagerAtLogon' -Value '1' -Type DWORD

Write-Host "Configuring Firefox to trust system root CAs"

$RegPath = "HKLM:\Software\Policies\Mozilla\Firefox\Certificates"
New-Item -Path $RegPath -Force | Out-Null
New-ItemProperty -Path $RegPath -Name "ImportEnterpriseRoots" -Value 1 -Force | Out-Null

Write-Host "Disabling Microsoft Edge first run experience"

$RegPath = "HKLM:\Software\Policies\Microsoft\Edge"
New-Item -Path $RegPath -Force | Out-Null
New-ItemProperty -Path $RegPath -Name "HideFirstRunExperience" -Value 1 -Force | Out-Null
New-ItemProperty -Path $RegPath -Name "NewTabPageLocation" -Value "https://www.google.com" -Force | Out-Null

Write-Host "Loading default user registry hive"

$DefaultUserReg = "HKLM\TempDefault"
$NtuserDatPath = "C:\Users\Default\NTUSER.DAT"
reg load $DefaultUserReg $NtuserDatPath
$HKDU = "Registry::$DefaultUserReg"

Write-Host "Fixing default borderless window style"

$RegPath = "$HKDU\Control Panel\Desktop"
$RegValue = ([byte[]](0x90,0x32,0x07,0x80,0x10,0x00,0x00,0x00))
New-ItemProperty -Path $RegPath -Name "UserPreferencesMask" -Value $RegValue -PropertyType "Binary" -Force | Out-Null

Write-Host "Disabling Bing Search in Start Menu"

$RegPath = "$HKDU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
New-Item -Path $RegPath -Force | Out-Null
Set-ItemProperty -Path $RegPath -Name "BingSearchEnabled" -Value 1 -Type DWORD

Write-Host "Hiding 'Learn more about this picture' desktop icon"

$RegPath = "$HKDU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
New-Item -Path $RegPath -Force | Out-Null
Set-ItemProperty -Path $RegPath -Name '{2cc5ca98-6485-489a-920e-b3e88a6ccce3}' -Value 0 -Type DWORD

Write-Host "Hiding taskbar search box and task view button"

$RegPath = "$HKDU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
New-Item -Path $RegPath -Force | Out-Null
Set-ItemProperty -Path $RegPath -Name "IsSearchBoxSettingEnabled" -Value 0 -Type DWORD
Set-ItemProperty -Path $RegPath -Name "ShowTaskViewButton" -Value 0 -Type DWORD

Write-Host "Fixing DbgHelp DLLs and _NT_SYMBOL_PATH"

$ProgressPreference = "SilentlyContinue"
New-Item -ItemType Directory -Path "C:\symbols" -ErrorAction SilentlyContinue | Out-Null
[Environment]::SetEnvironmentVariable("_NT_SYMBOL_PATH", "srv*c:\symbols*https://msdl.microsoft.com/download/symbols", "Machine")

$DbgHelpDir = "c:\symbols\DbgHelp"
New-Item -ItemType Directory -Path $DbgHelpDir -ErrorAction SilentlyContinue | Out-Null

$NativeDir = if ($Env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { "arm64" } else { "amd64" }
$Packages = @{
    "Microsoft.Debugging.Platform.DbgEng" = "content/$NativeDir/dbghelp.dll";
    "Microsoft.Debugging.Platform.SrcSrv" = "content/$NativeDir/srcsrv.dll";
    "Microsoft.Debugging.Platform.SymSrv" = "content/$NativeDir/symsrv.dll"
}
foreach ($Package in $Packages.GetEnumerator()) {
    $PackageName = $Package.Key
    $FilePath = $Package.Value
    $TempNupkgPath = "$Env:TEMP\$PackageName.zip"
    $TempExtractPath = "$Env:TEMP\$PackageName"
    $DownloadUrl = "https://www.nuget.org/api/v2/package/$PackageName"

    # Download raw .nupkg as a .zip file
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempNupkgPath
    Expand-Archive -Path $TempNupkgPath -DestinationPath $TempExtractPath

    $FileToCopy = Join-Path $TempExtractPath $FilePath
    if (Test-Path -Path $FileToCopy) {
        Copy-Item -Path $FileToCopy -Destination $DbgHelpDir
    }

    Remove-Item -Path $TempNupkgPath
    Remove-Item -Path $TempExtractPath -Recurse
}

@('Process Monitor', 'Process Explorer') | ForEach-Object {
    $RegPath = "$HKDU\Software\Sysinternals\$_"
    New-Item -Path $RegPath -Force | Out-Null
    Set-ItemProperty -Path $RegPath -Name "DbgHelpPath" -Value "C:\symbols\DbgHelp\dbghelp.dll" -Type String
}

Write-Host "Accepting EULA on sysinternals tools"

@(
    "AccessChk", "AccessEnum", "Active Directory Explorer", "ADInsight", "Autologon",
    "Autoruns", "BGInfo", "CacheSet", "ClockRes", "Contig", "Coreinfo", "CPUSTRES",
    "Ctrl2cap", "DbgView", "Desktops", "Disk2Vhd", "Diskmon", "DiskView", "EFSDump",
    "Handle", "Hex2Dec", "Junction", "LdmDump", "ListDLLs", "LiveKd", "LoadOrder",
    "LogonSessions", "Movefile", "NotMyFault", "NTFSInfo", "PendMove", "Portmon",
    "ProcDump", "Process Explorer", "Process Monitor", "PsExec", "PsFile", "PsGetSid",
    "PsInfo", "PsKill", "PsList", "PsLoggedon", "PsLoglist", "PsPasswd", "PsPing",
    "PsService", "PsShutdown", "PsSuspend", "RamMap", "RegDelNull", "Regjump",
    "Regsize", "SDelete", "Share Enum", "ShareEnum", "ShellRunas", "sigcheck",
    "Streams", "Strings", "Sync", "Sysmon", "TcpView", "VMMap", "VolumeID", "Whois",
    "WinObj", "ZoomIt"
) | ForEach-Object {
    $RegPath = "$HKDU\Software\Sysinternals\$_"
    New-Item -Path $RegPath -Force | Out-Null
    Set-ItemProperty -Path $RegPath -Name "EulaAccepted" -Value 1 -Type DWORD
}

Write-Host "Unloading default user registry hive"

[GC]::Collect()
[GC]::WaitForPendingFinalizers()
reg unload $DefaultUserReg

Write-Host "Installing PowerShell prerequisites..."

Install-PackageProvider -Name NuGet -Force
Install-Module -Name PowerShellGet -Force
Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted'

Write-Host "Installing chocolatey package manager"

iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

Write-Host "Installing PowerShell 7"

[Environment]::SetEnvironmentVariable("POWERSHELL_UPDATECHECK", "0", "Machine")
[Environment]::SetEnvironmentVariable("POWERSHELL_TELEMETRY_OPTOUT", "1", "Machine")
iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet -EnablePSRemoting"

Write-Host "Installing useful PowerShell modules"

Install-Module -Name PsHosts -Scope AllUsers
Install-Module -Name Posh-ACME -Scope AllUsers
Install-Module -Name PSWindowsUpdate -Scope AllUsers
Install-Module -Name PSDetour -Scope AllUsers -Force
Install-Module -Name AwakeCoding.DebugTools -Scope AllUsers -Force
Install-Module -Name Microsoft.PowerShell.SecretManagement -Scope AllUsers
Install-Module -Name Microsoft.PowerShell.SecretStore -Scope AllUsers

Write-Host "Installing .NET Framework 4.8"

choco install -y --no-progress netfx-4.8

Write-Host "Installing Remote Server Administration DNS tools"

Install-WindowsFeature RSAT-DNS-Server

Write-Host "Installing Nirsoft tools"

$ProgressPreference = "SilentlyContinue"
New-Item -ItemType Directory -Path "C:\tools" -ErrorAction SilentlyContinue | Out-Null
Set-Location "C:\tools"
# https://www.nirsoft.net/utils/regscanner.html
Invoke-WebRequest 'https://www.nirsoft.net/utils/regscanner_setup.exe' -OutFile "regscanner_setup.exe"
Start-Process -FilePath ".\regscanner_setup.exe" -ArgumentList @('/S') -Wait -NoNewWindow
Remove-Item ".\regscanner_setup.exe"
# https://www.nirsoft.net/utils/full_event_log_view.html
Invoke-WebRequest 'https://www.nirsoft.net/utils/fulleventlogview-x64.zip' -OutFile "fulleventlogview-x64.zip"
Expand-Archive -Path ".\fulleventlogview-x64.zip" -DestinationPath "C:\tools\bin" -Force
Remove-Item ".\fulleventlogview-x64.zip"
# https://www.nirsoft.net/utils/gui_prop_view.html
Invoke-WebRequest 'https://www.nirsoft.net/utils/guipropview-x64.zip' -OutFile "guipropview-x64.zip"
Expand-Archive -Path ".\guipropview-x64.zip" -DestinationPath "C:\tools\bin" -Force
Remove-Item ".\guipropview-x64.zip"
# https://www.nirsoft.net/utils/dns_query_sniffer.html
Invoke-WebRequest 'https://www.nirsoft.net/utils/dnsquerysniffer-x64.zip' -OutFile "dnsquerysniffer-x64.zip"
Expand-Archive -Path ".\dnsquerysniffer-x64.zip" -DestinationPath "C:\tools\bin" -Force
Remove-Item ".\dnsquerysniffer-x64.zip"
# https://www.nirsoft.net/utils/dns_lookup_view.html
Invoke-WebRequest 'https://www.nirsoft.net/utils/dnslookupview.zip' -OutFile "dnslookupview.zip"
Expand-Archive -Path ".\dnslookupview.zip" -DestinationPath "C:\tools\bin" -Force
Remove-Item ".\dnslookupview.zip"
# https://www.nirsoft.net/utils/inside_clipboard.html
Invoke-WebRequest 'https://www.nirsoft.net/utils/insideclipboard.zip' -OutFile "insideclipboard.zip"
Expand-Archive -Path ".\insideclipboard.zip" -DestinationPath "C:\tools\bin" -Force
Remove-Item ".\insideclipboard.zip"
# https://www.nirsoft.net/utils/file_activity_watch.html
Invoke-WebRequest 'https://www.nirsoft.net/utils/fileactivitywatch-x64.zip' -OutFile "fileactivitywatch-x64.zip"
Expand-Archive -Path ".\fileactivitywatch-x64.zip" -DestinationPath "C:\tools\bin" -Force
Remove-Item ".\fileactivitywatch-x64.zip"
# https://www.nirsoft.net/utils/registry_changes_view.html
Invoke-WebRequest 'https://www.nirsoft.net/utils/registrychangesview-x64.zip' -OutFile "registrychangesview-x64.zip"
Expand-Archive -Path ".\registrychangesview-x64.zip" -DestinationPath "C:\tools\bin" -Force
Remove-Item ".\registrychangesview-x64.zip"
# https://www.nirsoft.net/utils/reg_file_from_application.html
Invoke-WebRequest 'https://www.nirsoft.net/utils/regfromapp-x64.zip' -OutFile "regfromapp-x64.zip"
Expand-Archive -Path ".\regfromapp-x64.zip" -DestinationPath "C:\tools\bin" -Force
Remove-Item ".\regfromapp-x64.zip"
# cleanup binary output directory
Remove-Item "C:\tools\bin\*.txt"
Remove-Item "C:\tools\bin\*.chm"

Write-Host "Installing OpenSSL"

$ProgressPreference = "SilentlyContinue"
$openssl_hashes = 'https://github.com/slproweb/opensslhashes/raw/master/win32_openssl_hashes.json'
$openssl_json = (Invoke-WebRequest -UseBasicParsing $openssl_hashes).Content | ConvertFrom-Json
$openssl_filenames = Get-Member -InputObject $openssl_json.files -MemberType NoteProperty | Select-Object -ExpandProperty Name
$openssl_file = $openssl_filenames | ForEach-Object { $openssl_json.files.$($_) } | Where-Object {
    ($_.installer -eq 'msi') -and ($_.bits -eq 64) -and ($_.arch -eq 'INTEL') -and ($_.light -eq $false) -and ($_.basever -like "3.*")
} | Select-Object -First 1
$openssl_file_url = $openssl_file.url
$openssl_file_hash = $openssl_file.sha256
Invoke-WebRequest -UseBasicParsing $openssl_file_url -OutFile "OpenSSL.msi"
$FileHash = (Get-FileHash "OpenSSL.msi" -Algorithm SHA256).Hash
if ($FileHash -ine $openssl_file_hash) {
    throw "Unexpected OpenSSL file hash: actual: $FileHash, expected: $openssl_file_hash"
}
Start-Process msiexec.exe -Wait -ArgumentList @("/i", "OpenSSL.msi", "/qn")
[Environment]::SetEnvironmentVariable("PATH", "${Env:PATH};${Env:ProgramFiles}\OpenSSL-Win64\bin", "Machine")
Remove-Item "OpenSSL.msi"

Write-Host "Installing Devolutions Windows Terminal"

$ProgressPreference = "SilentlyContinue"
$WtVersion = "1.20.11271.0"
$WtDownloadBase = "https://github.com/Devolutions/wt-distro/releases/download"
$WtDownloadUrl = "$WtDownloadBase/v${WtVersion}/WindowsTerminal-${WtVersion}-x64.msi"
Invoke-WebRequest -UseBasicParsing $WtDownloadUrl -OutFile "WindowsTerminal.msi"
Start-Process msiexec.exe -Wait -ArgumentList @("/i", "WindowsTerminal.msi", "/qn")
Remove-Item "WindowsTerminal.msi"

Write-Host "Installing useful chocolatey packages"

$Packages = @(
    'vcredist140',
    'git.install',
    'vlc',
    '7zip',
    'gsudo',
    'ripgrep',
    'nssm',
    'firefox',
    'microsoft-edge',
    'vscode',
    'kdiff3',
    'filezilla',
    'wireshark',
    'sysinternals',
    'sublimetext3',
    'notepadplusplus'
)

foreach ($Package in $Packages) {
    Write-Host "Installing $Package"
    choco install -y --no-progress $Package
}

Write-Host "Enabling OpenSSH client and server features"

Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

Write-Host "Enabling and starting sshd service"

Install-Module -Name Microsoft.PowerShell.RemotingTools -Scope AllUsers -Force
Set-Service -Name sshd -StartupType 'Automatic'
Start-Service sshd

Write-Host "Enabling PowerShell Remoting over SSH"

& pwsh.exe -NoLogo -Command "Enable-SSHRemoting -Force"
Restart-Service sshd

Write-Host "Enabling ICMP requests (ping) in firewall"

New-NetFirewallRule -Name 'ICMPv4' -DisplayName 'ICMPv4' `
    -Description 'Allow ICMPv4' -Profile Any -Direction Inbound -Action Allow `
    -Protocol ICMPv4 -Program Any -LocalAddress Any -RemoteAddress Any

Write-Host "Enabling network discovery, file and printer sharing in firewall"

& netsh advfirewall firewall set rule group="Network Discovery" new enable=yes
& netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=yes

Write-Host "Removing Appx packages that can break sysprep"

Get-AppxPackage -Name Microsoft.MicrosoftEdge.Stable | Remove-AppxPackage
Get-AppxPackage *notepadplusplus* | Remove-AppxPackage

Write-Host "Removing Azure Arc setup with annoying tray icon"

Remove-WindowsCapability -Online -Name AzureArcSetup~~~~
