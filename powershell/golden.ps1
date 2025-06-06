#Requires -RunAsAdministrator
#Requires -PSEdition Core

param(
    [string] $VMName = "IT-TEMPLATE",
    [string] $UserName = "Administrator",
    [string] $Password = "lab123!",
    [string] $OSVersion = $null,
    [string] $SwitchName = "NAT Switch",
    [string] $InputIsoPath = $null,
    [string] $OutputVhdxPath = $null,
    [bool] $InstallWindowsUpdates = $false,
    [bool] $DisableWindowsUpdates = $true,
    [bool] $InstallChocolateyPackages = $true,
    [bool] $InstallSkillableServices = $true
)

$ErrorActionPreference = "Stop"

$OSVersionParam = $OSVersion
$SwitchNameParam = $SwitchName

# load common variables
. .\common.ps1

if (-Not [string]::IsNullOrEmpty($OSVersionParam)) {
    $OSVersion = $OSVersionParam
}

if (-Not [string]::IsNullOrEmpty($SwitchNameParam)) {
    $SwitchName = $SwitchNameParam
}

Write-Host "Options:"
Write-Host "`tOSVersion: $OSVersion"
Write-Host "`tSwitchName: $SwitchName"
Write-Host "`tVMName: $VMName"
Write-Host "`tUserName: $UserName"
Write-Host "`tPassword: $Password"
Write-Host "`tInstallWindowsUpdates: $InstallWindowsUpdates"
Write-Host "`tDisableWindowsUpdates: $DisableWindowsUpdates"
Write-Host "`tInstallChocolateyPackages: $InstallChocolateyPackages"
Write-Host "`tInstallSkillableServices: $InstallSkillableServices"
Write-Host ""

Write-DLabLog "Creating golden image"

if (-Not [string]::IsNullOrEmpty($InputIsoPath)) {
    $IsoFilePath = $InputIsoPath
} else {
    $IsoFilePath = $(Get-DLabIsoFilePath "windows_server_${OSVersion}").FullName
}

if (-Not (Test-Path $IsoFilePath)) {
    throw "ISO file not found: '$IsoFilePath'"
} else {
    Write-DLabLog "Using '$IsoFilePath' ISO file"
}

Write-DLabLog "Scanning image list from Windows ISO"

$ImageList = Get-DLabWindowsImageListFromIso $IsoFilePath | Select-Object -Property Index, Name
$ImageList | Format-List

if ($OSVersion -eq '11') {
    $Image = $ImageList | Where-Object { $_.Name -Like 'Windows * Enterprise' } | Select-Object -First 1
} else {
    $Image = $ImageList | Where-Object { $_.Name -Like 'Windows Server * Standard (Desktop Experience)' } | Select-Object -First 1
}

if (-Not $Image) {
    throw "Could not automatically select image to install from the list"
}

$ImageIndex = $Image.Index
Write-DLabLog "Using Windows image [$ImageIndex]: $($Image.Name)"

Write-DLabLog "Creating Windows answer file"

$AnswerTempPath = Join-Path $([System.IO.Path]::GetTempPath()) "unattend-$VMName"
Remove-Item $AnswerTempPath -Force  -Recurse -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType Directory -Path $AnswerTempPath -ErrorAction SilentlyContinue | Out-Null
$AnswerFilePath = Join-Path $AnswerTempPath "autounattend.xml"

$Params = @{
    UserFullName = "devolutions";
    UserOrganization = "IT-HELP";
    ComputerName = $Name;
    AdministratorPassword = $Password;
    OSVersion = $OSVersion;
    ImageIndex = $ImageIndex;
    UILanguage = "en-US";
    UserLocale = "en-CA";
}

New-DLabAnswerFile $AnswerFilePath @Params

$AnswerIsoPath = Join-Path $([System.IO.Path]::GetTempPath()) "unattend-$VMName.iso"
New-DLabIsoFile -Path $AnswerTempPath -Destination $AnswerIsoPath -VolumeName "unattend"

New-DLabParentVM $VMName -OSVersion $OSVersion -IsoFilePath $IsoFilePath -Force

Add-VMDvdDrive -VMName $VMName -ControllerNumber 1 -Path $AnswerIsoPath

Write-DLabLog "Starting golden VM for Windows installation"

Start-DLabVM $VMName
Start-Sleep 5

Write-DLabLog "Waiting for VM to reboot a first time during installation"

Wait-DLabVM $VMName 'Reboot' -Timeout 600

Get-VMDvdDrive $VMName | Where-Object { $_.DvdMediaType -Like 'ISO' } |
    Remove-VMDvdDrive -ErrorAction SilentlyContinue

Remove-Item -Path $AnswerIsoPath -Force -ErrorAction SilentlyContinue | Out-Null
Remove-Item -Path $AnswerTempPath -Recurse -Force -ErrorAction SilentlyContinue | Out-Null

Write-DLabLog "Waiting for VM to become ready after Windows installation"

Wait-DLabVM $VMName 'PSDirect' -Timeout (45 * 60) -UserName $UserName -Password $Password
$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Write-DLabLog "Shutting down VM post-installation"
Stop-VM $VMName
Wait-DLabVM $VMName 'Shutdown' -Timeout 120

Get-VMNetworkAdapter -VMName $VMName | Remove-VMNetworkAdapter
Add-VMNetworkAdapter -VMName $VMName -SwitchName $SwitchName

Write-DLabLog "Starting VM to begin customization"

Start-DLabVM $VMName
Start-Sleep 5

Wait-DLabVM $VMName 'PSDirect' -Timeout 360 -UserName $UserName -Password $Password
$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Write-DLabLog "Configuring VM network adapter"

if ($SwitchName -eq "NAT Switch") {
    Set-DLabVMNetAdapter $VMName -VMSession $VMSession `
        -SwitchName $SwitchName -NetAdapterName "vEthernet (LAN)" `
        -IPAddress "10.9.0.249" -DefaultGateway "10.9.0.1" `
        -DnsServerAddress "1.1.1.1" `
        -RegisterAutomaticFix $false
}

Write-DLabLog "Testing Internet connectivity"

$ConnectionTest = Invoke-Command -ScriptBlock {
    1..10 | ForEach-Object {
        Start-Sleep -Seconds 1;
        Resolve-DnsName -Name "www.google.com" -Type 'A' -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
    } | Where-Object { $_ -ne $null } | Select-Object -First 1
} -Session $VMSession

if (-Not $ConnectionTest) {
    throw "virtual machine doesn't have Internet access - fail early"
}

Write-DLabLog "Increase WinRM default configuration values"

Invoke-Command -ScriptBlock {
    & 'winrm' 'set' 'winrm/config' '@{MaxTimeoutms=\"1800000\"}'
    & 'winrm' 'set' 'winrm/config/winrs' '@{MaxMemoryPerShellMB=\"800\"}'
} -Session $VMSession

Write-DLabLog "Enabling TLS 1.2 for .NET Framework applications"

Invoke-Command -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWORD
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWORD
} -Session $VMSession

Write-DLabLog "Disabling Server Manager automatic launch and Windows Admin Center pop-up"

Invoke-Command -ScriptBlock {
    $ServerManagerReg = "HKLM:\SOFTWARE\Microsoft\ServerManager"
    Set-ItemProperty -Path $ServerManagerReg -Name 'DoNotPopWACConsoleAtSMLaunch' -Value '1' -Type DWORD
    Set-ItemProperty -Path $ServerManagerReg -Name 'DoNotOpenServerManagerAtLogon' -Value '1' -Type DWORD
} -Session $VMSession

Write-DLabLog "Disabling 'Activate Windows' watermark on desktop"

Invoke-Command -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\Activation' -Name 'Manual' -Value '1' -Type DWORD

    $TaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
	    -Argument "-Command { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\Activation' -Name 'Manual' -Value '1' -Type DWORD }"

    $TaskTrigger = New-ScheduledTaskTrigger -AtStartup

    $Params = @{
        Action = $TaskAction;
        Trigger = $TaskTrigger;
        User = "NT AUTHORITY\SYSTEM";
        TaskName = "Activation Watermark";
        Description = "Remove Windows Activation Watermark";
    }
    Register-ScheduledTask @Params
} -Session $VMSession

$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Write-DLabLog "Fix default borderless windows style"

# https://www.deploymentresearch.com/fixing-borderless-windows-in-windows-server-2019-and-windows-server-2022/
Invoke-Command -ScriptBlock {
    $DefaultUserReg = "HKLM\TempDefault"
    $NtuserDatPath = "C:\Users\Default\NTUSER.DAT"
    reg load $DefaultUserReg $NtuserDatPath
    $HKDU = "Registry::$DefaultUserReg"
    $RegPath = "$HKDU\Control Panel\Desktop"
    $RegValue = ([byte[]](0x90,0x32,0x07,0x80,0x10,0x00,0x00,0x00))
    New-ItemProperty -Path $RegPath -Name "UserPreferencesMask" -Value $RegValue -PropertyType "Binary" -Force | Out-Null
    [GC]::Collect()
    reg unload $DefaultUserReg
} -Session $VMSession

Write-DLabLog "Disabling Bing Search in Start Menu"

Invoke-Command -ScriptBlock {
    $DefaultUserReg = "HKLM\TempDefault"
    $NtuserDatPath = "C:\Users\Default\NTUSER.DAT"
    reg load $DefaultUserReg $NtuserDatPath
    $HKDU = "Registry::$DefaultUserReg"
    $RegPath = "$HKDU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
    New-Item -Path $RegPath -Force | Out-Null
    Set-ItemProperty -Path $RegPath -Name "BingSearchEnabled" -Value 1 -Type DWORD
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    reg unload $DefaultUserReg
} -Session $VMSession

Write-DLabLog "Hiding 'Learn more about this picture' desktop icon"

Invoke-Command -ScriptBlock {
    $DefaultUserReg = "HKLM\TempDefault"
    $NtuserDatPath = "C:\Users\Default\NTUSER.DAT"
    reg load $DefaultUserReg $NtuserDatPath
    $HKDU = "Registry::$DefaultUserReg"
    $RegPath = "$HKDU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
    New-Item -Path $RegPath -Force | Out-Null
    Set-ItemProperty -Path $RegPath -Name '{2cc5ca98-6485-489a-920e-b3e88a6ccce3}' -Value 0 -Type DWORD
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    reg unload $DefaultUserReg
} -Session $VMSession

Write-DLabLog "Tweaking default taskbar and explorer settings"

Invoke-Command -ScriptBlock {
    $DefaultUserReg = "HKLM\TempDefault"
    $NtuserDatPath = "C:\Users\Default\NTUSER.DAT"
    reg load $DefaultUserReg $NtuserDatPath
    $HKDU = "Registry::$DefaultUserReg"
    $RegExplorerPath = "$HKDU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    New-Item -Path $RegExplorerPath -Force | Out-Null
    Set-ItemProperty -Path $RegExplorerPath -Name "IsSearchBoxSettingEnabled" -Value 0 -Type DWORD
    Set-ItemProperty -Path $RegExplorerPath -Name "ShowTaskViewButton" -Value 0 -Type DWORD
    Set-ItemProperty -Path $RegExplorerPath -Name "HideFileExt" -Value 0 -Type DWORD
    Set-ItemProperty -Path $RegExplorerPath -Name "Hidden" -Value 1 -Type DWORD
    Set-ItemProperty -Path $RegExplorerPath -Name "TaskbarDa" -Value 0 -Type DWORD
    Set-ItemProperty -Path $RegExplorerPath -Name "TaskbarMn" -Value 0 -Type DWORD
    Set-ItemProperty -Path $RegExplorerPath -Name "ShowCopilotButton" -Value 0 -Type DWORD
    $RegSearchPath = "$HKDU\Software\Microsoft\Windows\CurrentVersion\Search"
    New-Item -Path $RegSearchPath -Force | Out-Null
    Set-ItemProperty -Path $RegSearchPath -Name "SearchboxTaskbarMode" -Value 0 -Type DWORD
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    reg unload $DefaultUserReg
} -Session $VMSession

Write-DLabLog "Removing Azure Arc setup with annoying tray icon"

Invoke-Command -ScriptBlock {
    Remove-WindowsCapability -Online -Name AzureArcSetup~~~~
} -Session $VMSession

$CloudflareWarpCA = Get-ChildItem "cert:\LocalMachine\Root" |
    Where-Object { $_.Subject -like "*Gateway CA - Cloudflare Managed G1*" }

if ($CloudflareWarpCA) {
    Write-DLabLog "Found Cloudflare WARP CA: $($CloudflareWarpCA.Subject)"

    $TempCertPath = Join-Path $Env:TEMP "CloudflareWarpCA.cer"
    Export-Certificate -Cert $CloudflareWarpCA -FilePath $TempCertPath -Force
    Copy-Item -Path $TempCertPath -Destination "C:\Users\Public\" -ToSession $VMSession
    Remove-Item $TempCertPath -Force | Out-Null

    Write-DLabLog "Importing Cloudflare WARP CA..."
    Invoke-Command -ScriptBlock {
        $CertPath = "C:\Users\Public\CloudflareWarpCA.cer"
        Import-Certificate -FilePath $CertPath -CertStoreLocation "cert:\LocalMachine\Root" | Out-Null
        Remove-Item $CertPath -Force | Out-Null
    } -Session $VMSession
}

Write-DLabLog "Configuring initial PowerShell environment"

Invoke-Command -ScriptBlock {
    Set-ExecutionPolicy Unrestricted -Force
    Install-PackageProvider Nuget -Force
    Install-Module -Name PowerShellGet -Force
    Set-PSRepository -Name "PSGallery" -InstallationPolicy "Trusted"
} -Session $VMSession

Write-DLabLog "Installing chocolatey package manager"

Invoke-Command -ScriptBlock {
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
} -Session $VMSession

$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Write-DLabLog "Installing .NET Framework 4.8"

Invoke-Command -ScriptBlock {
    choco install -y --no-progress netfx-4.8
} -Session $VMSession

Write-DLabLog "Installing git"

Invoke-Command -ScriptBlock {
    $GitReleaseApi = "https://api.github.com/repos/git-for-windows/git/releases/latest"
    $GitRelease = Invoke-RestMethod -Uri $GitReleaseApi -Headers @{ "User-Agent" = "PowerShell" }
    $GitArchSuffix = if ($Env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { "arm64" } else { "64-bit" }
    $Asset = $GitRelease.assets | Where-Object { $_.name -match "^Git-[\d\.]+-$GitArchSuffix\.exe$" } | Select-Object -First 1
    $InstallerUrl = $Asset.browser_download_url
    $InstallerPath = Join-Path $Env:TEMP $($Asset.name)
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath
    $InstallerArgs = @("/VERYSILENT", "/NORESTART", "/NOCANCEL", "/COMPONENTS=gitlfs,assoc,assoc_sh,ext,path")
    Start-Process -FilePath $InstallerPath -ArgumentList $InstallerArgs -Wait
    Remove-Item $InstallerPath -Force
} -Session $VMSession

if ($InstallChocolateyPackages) {
    $Packages = @(
        'vlc',
        '7zip',
        'gsudo',
        'ripgrep',
        'nssm',
        'azcopy10'
        'firefox',
        'microsoft-edge',
        'vscode',
        'kdiff3',
        'filezilla',
        'wireshark',
        'sublimetext3',
        'notepadplusplus'
    )

    foreach ($Package in $Packages) {
        Write-DLabLog "Installing $Package"
        Invoke-Command -Session $VMSession -ScriptBlock { param($Package)
            choco install -y --no-progress $Package
        } -ArgumentList @($Package)
    }
}

Write-DLabLog "Installing OpenSSL"

Invoke-Command -ScriptBlock {
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
    $SystemPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    [Environment]::SetEnvironmentVariable("PATH", "$SystemPath;C:\Program Files\OpenSSL-Win64\bin", "Machine")
    Remove-Item "OpenSSL.msi"
} -Session $VMSession

Write-DLabLog "Installing Devolutions MsRdpEx"

Invoke-Command -ScriptBlock {
    $ProgressPreference = "SilentlyContinue"
    $MsRdpExVersion = (Invoke-RestMethod "https://api.github.com/repos/Devolutions/MsRdpEx/releases/latest").tag_name.TrimStart("v")
    $MsRdpExUrl = "https://github.com/Devolutions/MsRdpEx/releases/download/v$MsRdpExVersion/MsRdpEx-$MsRdpExVersion-x64.msi"
    Invoke-WebRequest -UseBasicParsing -Uri $MsRdpExUrl -OutFile "MsRdpEx.msi"
    Start-Process msiexec.exe -Wait -ArgumentList @("/i", "MsRdpEx.msi", "/qn")
    Remove-Item "MsRdpEx.msi"
} -Session $VMSession

Write-DLabLog "Installing Devolutions Windows Terminal"

Invoke-Command -ScriptBlock {
    $ProgressPreference = "SilentlyContinue"
    $WtVersion = (Invoke-RestMethod "https://api.github.com/repos/Devolutions/wt-distro/releases/latest").tag_name.TrimStart("v")
    $WtDownloadBase = "https://github.com/Devolutions/wt-distro/releases/download"
    $WtDownloadUrl = "$WtDownloadBase/v${WtVersion}/WindowsTerminal-${WtVersion}-x64.msi"
    Invoke-WebRequest -UseBasicParsing $WtDownloadUrl -OutFile "WindowsTerminal.msi"
    Start-Process msiexec.exe -Wait -ArgumentList @("/i", "WindowsTerminal.msi", "/qn")
    Remove-Item "WindowsTerminal.msi"
} -Session $VMSession

Write-DLabLog "Fixing DbgHelp DLLs and _NT_SYMBOL_PATH"

Invoke-Command -ScriptBlock {
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

    $DefaultUserReg = "HKLM\TempDefault"
    $NtuserDatPath = "C:\Users\Default\NTUSER.DAT"
    reg load $DefaultUserReg $NtuserDatPath
    $HKDU = "Registry::$DefaultUserReg"
    @('Process Monitor', 'Process Explorer') | ForEach-Object {
        $RegPath = "$HKDU\Software\Sysinternals\$_"
        New-Item -Path $RegPath -Force | Out-Null
        Set-ItemProperty -Path $RegPath -Name "EulaAccepted" -Value 1 -Type DWORD
        Set-ItemProperty -Path $RegPath -Name "DbgHelpPath" -Value "C:\symbols\DbgHelp\dbghelp.dll" -Type String
    }
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    reg unload $DefaultUserReg
} -Session $VMSession

Write-DLabLog "Accepting EULA on sysinternals tools"

Invoke-Command -ScriptBlock {
    $DefaultUserReg = "HKLM\TempDefault"
    $NtuserDatPath = "C:\Users\Default\NTUSER.DAT"
    reg load $DefaultUserReg $NtuserDatPath
    $HKDU = "Registry::$DefaultUserReg"
    $ToolNames = @(
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
    )
    $ToolNames | ForEach-Object {
        $RegPath = "$HKDU\Software\Sysinternals\$_"
        New-Item -Path $RegPath -Force | Out-Null
        Set-ItemProperty -Path $RegPath -Name "EulaAccepted" -Value 1 -Type DWORD
    }
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    reg unload $DefaultUserReg
} -Session $VMSession

Write-DLabLog "Downloading tool installers"

Invoke-Command -ScriptBlock {
    $ProgressPreference = "SilentlyContinue"
    New-Item -ItemType Directory -Path "C:\tools" -ErrorAction SilentlyContinue | Out-Null
    New-Item -ItemType Directory -Path "C:\tools\bin" -ErrorAction SilentlyContinue | Out-Null
    New-Item -ItemType Directory -Path "C:\tools\scripts" -ErrorAction SilentlyContinue | Out-Null
    New-Item -ItemType Directory -Path "C:\tools\installers" -ErrorAction SilentlyContinue | Out-Null
    $SystemPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    [Environment]::SetEnvironmentVariable("PATH", "$SystemPath;C:\tools\bin", "Machine")
    Set-Location "C:\tools\installers"
    Invoke-WebRequest 'https://npcap.com/dist/npcap-1.78.exe' -OutFile "npcap-1.78.exe"
    Invoke-WebRequest 'http://update.youngzsoft.com/ccproxy/update/ccproxysetup.exe' -OutFile "CCProxySetup.exe"
    Invoke-WebRequest "https://assets.dataflare.app/release/windows/x86_64/Dataflare-Setup.exe" -OutFile "Dataflare-Setup.exe"
} -Session $VMSession

Write-DLabLog "Copying PowerShell helper scripts"

Copy-Item -Path "$PSScriptRoot\scripts\*" -Destination "C:\tools\scripts" -ToSession $VMSession -Recurse -Force

Write-DLabLog "Installing WinSpy"

Invoke-Command -ScriptBlock {
    $ProgressPreference = "SilentlyContinue"
    # https://www.catch22.net/projects/winspy/
    Invoke-WebRequest "https://github.com/strobejb/winspy/releases/download/v1.8.4/WinSpy_Release_x64.zip" -OutFile "WinSpy_Release.zip"
    Expand-Archive -Path ".\WinSpy_Release.zip" -DestinationPath ".\WinSpy_Release" -Force
    Copy-Item ".\WinSpy_Release\winspy.exe" "C:\tools\bin" -Force
    Remove-Item ".\WinSpy_Release*" -Recurse -Force
} -Session $VMSession

Write-DLabLog "Installing Sysinternals Suite"

Invoke-Command -ScriptBlock {
    $ProgressPreference = "SilentlyContinue"
    Invoke-WebRequest "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile "SysinternalsSuite.zip"
    Expand-Archive -Path ".\SysinternalsSuite.zip" -DestinationPath "C:\tools\bin" -Force
    Remove-Item ".\SysinternalsSuite.zip"
} -Session $VMSession

Write-DLabLog "Installing Nirsoft tools"

Invoke-Command -ScriptBlock {
    $ProgressPreference = "SilentlyContinue"
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
} -Session $VMSession

Write-DLabLog "Installing UltraVNC"

Invoke-Command -ScriptBlock {
    Invoke-WebRequest 'https://www.uvnc.eu/download/1430/UltraVNC_1431_X64_Setup.exe' -OutFile "UltraVNC_Setup.exe"
    Start-Process .\UltraVNC_Setup.exe -Wait -ArgumentList ("/VERYSILENT", "/NORESTART")
    Remove-Item .\UltraVNC_Setup.exe
    
    $Params = @{
        Name = "uvnc_service";
        DisplayName = "UltraVNC Server";
        Description = "Provides secure remote desktop sharing";
        BinaryPathName = "$Env:ProgramFiles\uvnc bvba\UltraVNC\winvnc.exe -service";
        DependsOn = "Tcpip";
        StartupType = "Automatic";
    }
    New-Service @Params
    
    $Params = @{
        DisplayName = "Allow UltraVNC";
        Direction = "Inbound";
        Program = "$Env:ProgramFiles\uvnc bvba\UltraVNC\winvnc.exe";
        Action = "Allow"
    }
    New-NetFirewallRule @Params

    $IniFile = "$Env:ProgramFiles\uvnc bvba\UltraVNC\ultravnc.ini"
    $IniData = Get-Content $IniFile | foreach {
        switch ($_) {
            "MSLogonRequired=0" { "MSLogonRequired=1" }
            "NewMSLogon=0" { "NewMSLogon=1" }
            default { $_ }
        }
	}
    $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
    [System.IO.File]::WriteAllLines($IniFile, $IniData, $Utf8NoBomEncoding)

    $AclFile = "$Env:ProgramFiles\uvnc bvba\UltraVNC\acl.txt"
    $AclData = "allow`t0x00000003`t`"BUILTIN\Remote Desktop Users`""
    $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
    [System.IO.File]::WriteAllLines($AclFile, $AclData, $Utf8NoBomEncoding)
    Start-Process -FilePath "$Env:ProgramFiles\uvnc bvba\UltraVNC\MSLogonACL.exe" -ArgumentList @('/i', '/o', $AclFile) -Wait -NoNewWindow
} -Session $VMSession

Write-DLabLog "Configuring Firefox to trust system root CAs"

Invoke-Command -ScriptBlock {
    $RegPath = "HKLM:\Software\Policies\Mozilla\Firefox\Certificates"
    New-Item -Path $RegPath -Force | Out-Null
    New-ItemProperty -Path $RegPath -Name ImportEnterpriseRoots -Value 1 -Force | Out-Null
} -Session $VMSession

Write-DLabLog "Disabling Microsoft Edge first run experience"

Invoke-Command -ScriptBlock {
    $RegPath = "HKLM:\Software\Policies\Microsoft\Edge"
    New-Item -Path $RegPath -Force | Out-Null
    New-ItemProperty -Path $RegPath -Name "HideFirstRunExperience" -Value 1 -Force | Out-Null
    New-ItemProperty -Path $RegPath -Name "NewTabPageLocation" -Value "https://www.google.com" -Force | Out-Null
} -Session $VMSession

Write-DLabLog "Disabling Secure Time Seeding (STS) problematic feature"

Invoke-Command -ScriptBlock {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "UtilizeSslTimeData" -Value 0 -Type DWORD
} -Session $VMSession

Write-DLabLog "Installing Remote Server Administration DNS tools"

Invoke-Command -ScriptBlock {
    Install-WindowsFeature RSAT-DNS-Server
} -Session $VMSession

Write-DLabLog "Enabling OpenSSH client and server features"

Invoke-Command -ScriptBlock {
    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
} -Session $VMSession

Write-DLabLog "Installing PowerShell 7"

Invoke-Command -ScriptBlock {
    [Environment]::SetEnvironmentVariable("POWERSHELL_UPDATECHECK", "0", "Machine")
    [Environment]::SetEnvironmentVariable("POWERSHELL_TELEMETRY_OPTOUT", "1", "Machine")
    iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet -EnablePSRemoting"
} -Session $VMSession

Write-DLabLog "Rebooting VM"

Invoke-Command -ScriptBlock {
    Restart-Computer -Force
} -Session $VMSession

Wait-DLabVM $VMName 'Reboot' -Timeout 120
Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $UserName -Password $Password

$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Write-DLabLog "Installing useful PowerShell modules"

Invoke-Command -ScriptBlock {
    Install-Module -Name PsHosts -Scope AllUsers
    Install-Module -Name Posh-ACME -Scope AllUsers
    Install-Module -Name PSWindowsUpdate -Scope AllUsers
    Install-Module -Name Evergreen -Scope AllUsers -Force
    Install-Module -Name PSDetour -Scope AllUsers -Force
    Install-Module -Name AwakeCoding.DebugTools -Scope AllUsers -Force
    Install-Module -Name Microsoft.PowerShell.SecretManagement -Scope AllUsers
    Install-Module -Name Microsoft.PowerShell.SecretStore -Scope AllUsers
} -Session $VMSession

Write-DLabLog "Enabling and starting sshd service"

Invoke-Command -ScriptBlock {
    Install-Module -Name Microsoft.PowerShell.RemotingTools -Scope AllUsers -Force
    Set-Service -Name sshd -StartupType 'Automatic'
    Start-Service sshd
} -Session $VMSession

$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Write-DLabLog "Enabling PowerShell Remoting over SSH"

Invoke-Command -ScriptBlock {
    & pwsh.exe -NoLogo -Command "Enable-SSHRemoting -Force"
    Restart-Service sshd
} -Session $VMSession

Write-DLabLog "Enabling ICMP requests (ping) in firewall"

Invoke-Command -ScriptBlock {
    New-NetFirewallRule -Name 'ICMPv4' -DisplayName 'ICMPv4' `
        -Description 'Allow ICMPv4' -Profile Any -Direction Inbound -Action Allow `
        -Protocol ICMPv4 -Program Any -LocalAddress Any -RemoteAddress Any
} -Session $VMSession

Write-DLabLog "Enabling network discovery, file and printer sharing in firewall"

Invoke-Command -ScriptBlock {
    & netsh advfirewall firewall set rule group="Network Discovery" new enable=yes
    & netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=yes
} -Session $VMSession

Write-DLabLog "Enabling remote desktop server and firewall rule"

Invoke-Command -ScriptBlock {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

    Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' -Name 'ColorDepth' -Type DWORD -Value 5
    Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fEnableVirtualizedGraphics' -Type DWORD -Value 1
} -Session $VMSession

Write-DLabLog "Changing Windows taskbar default pinned apps"

Invoke-Command -ScriptBlock {
    $LnkPaths = @(
        "%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk"
        "%APPDATA%\Microsoft\Windows\Start Menu\Programs\File Explorer.lnk"
        "%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Windows Terminal.lnk"
        "%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\mstscex.lnk"
    )
    $OutputPath = "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml"
    $xml = New-Object System.Xml.XmlDocument
    $root = $xml.CreateElement("LayoutModificationTemplate", "http://schemas.microsoft.com/Start/2014/LayoutModification")
    $xml.AppendChild($root) | Out-Null
    $root.SetAttribute("xmlns:defaultlayout", "http://schemas.microsoft.com/Start/2014/FullDefaultLayout")
    $root.SetAttribute("xmlns:taskbar", "http://schemas.microsoft.com/Start/2014/TaskbarLayout")
    $root.SetAttribute("Version", "1")
    $collection = $xml.CreateElement("CustomTaskbarLayoutCollection", $root.NamespaceURI)
    $collection.SetAttribute("PinListPlacement", "Replace")
    $root.AppendChild($collection) | Out-Null
    $layout = $xml.CreateElement("defaultlayout:TaskbarLayout", $root.GetAttribute("xmlns:defaultlayout"))
    $collection.AppendChild($layout) | Out-Null
    $pinList = $xml.CreateElement("taskbar:TaskbarPinList", $root.GetAttribute("xmlns:taskbar"))
    $layout.AppendChild($pinList) | Out-Null
    foreach ($lnk in $LnkPaths) {
        $desktopApp = $xml.CreateElement("taskbar:DesktopApp", $root.GetAttribute("xmlns:taskbar"))
        $desktopApp.SetAttribute("DesktopApplicationLinkPath", $lnk)
        $pinList.AppendChild($desktopApp) | Out-Null
    }
    $xml.Save($OutputPath)
} -Session $VMSession

if ($InstallSkillableServices) {
    Write-DLabLog "Installing Skillable Integration Services"

    Invoke-Command -ScriptBlock {
        $ProgressPreference = 'SilentlyContinue'
        $RepoName = "Skillable-Integration-Service"
        $ZipFile = "${RepoName}.zip"
        $DownloadUrl = "https://github.com/LearnOnDemandSystems/${RepoName}/archive/refs/heads/main.zip"
        $OutputPath = Join-Path $Env:TEMP "${RepoName}-main"
        Remove-Item $OutputPath -Recurse -ErrorAction SilentlyContinue | Out-Null
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipFile
        Expand-Archive -Path $ZipFile -DestinationPath $Env:TEMP
        Remove-Item $ZipFile | Out-Null
        Remove-Item "C:\VmIntegrationService" -Recurse -ErrorAction SilentlyContinue | Out-Null
        Expand-Archive "$OutputPath\VmIntegrationService.zip" -DestinationPath "C:\VmIntegrationService"
        Unblock-File "$OutputPath\install.ps1"
        & "$OutputPath\install.ps1"
        Remove-Item $OutputPath -Recurse | Out-Null
    } -Session $VMSession
}

Write-DLabLog "Rebooting VM"

Invoke-Command -ScriptBlock {
    Restart-Computer -Force
} -Session $VMSession

Wait-DLabVM $VMName 'Reboot' -Timeout 120
Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $UserName -Password $Password

$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

if ($InstallWindowsUpdates) {
    Write-DLabLog "Installing Windows updates until VM is fully up-to-date"

    do {
        $WUStatus = Invoke-Command -ScriptBlock {
            $Updates = Get-WUList
            if ($Updates.Count -gt 0) {
                Write-Host "Install-WindowsUpdate $($Updates.Count): $(Get-Date)"
                Install-WindowsUpdate -AcceptAll -AutoReboot | Out-Null
            }
            [PSCustomObject]@{
                UpdateCount = $Updates.Count
                PendingReboot = Get-WURebootStatus -Silent
            }
        } -Session $VMSession

        Write-DLabLog "WUStatus: $($WUStatus.UpdateCount), PendingReboot: $($WUStatus.PendingReboot): $(Get-Date)"

        if ($WUStatus.PendingReboot) {
            Write-Host "Waiting for VM reboot: $(Get-Date)"
            Wait-DLabVM $VMName 'Reboot' -Timeout 120
            Wait-VM $VMName -For IPAddress -Timeout 360
            Start-Sleep -Seconds 60
            $VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password
        }
    } until (($WUStatus.PendingReboot -eq $false) -and ($WUStatus.UpdateCount -eq 0))
}

Write-DLabLog "Remove Appx packages that can break sysprep"

Invoke-Command -ScriptBlock {
    Get-AppxPackage -Name Microsoft.MicrosoftEdge.Stable | Remove-AppxPackage
    Get-AppxPackage *notepadplusplus* | Remove-AppxPackage
} -Session $VMSession

Write-DLabLog "Cleaning up Windows base image (WinSxS folder)"

Invoke-Command -ScriptBlock {
    & dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase
} -Session $VMSession

if ($DisableWindowsUpdates) {
    Write-DLabLog "Disabling Windows Update service permanently"

    Invoke-Command -ScriptBlock {
        Stop-service wuauserv | Set-Service -StartupType Disabled
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 1 -Type DWORD
    } -Session $VMSession
}

Write-DLabLog "Running sysprep to generalize the image for OOBE experience and shut down VM"

Invoke-Command -ScriptBlock {
    & "$Env:WinDir\System32\Sysprep\sysprep.exe" '/oobe' '/generalize' '/shutdown' '/mode:vm'
} -Session $VMSession

Write-DLabLog "Waiting for VM to shut down completely"
Wait-DLabVM $VMName 'Shutdown' -Timeout 900

Write-DLabLog "Deleting the VM (but not the VHDX)"
Remove-VM $VMName -Force

$ParentDisksPath = Get-DLabPath "IMGs"
$ParentDiskFileName = $VMName, 'vhdx' -Join '.'
$ParentDiskPath = Join-Path $ParentDisksPath $ParentDiskFileName

$GoldenDiskFileName = "Windows Server $OSVersion Standard - $(Get-Date -Format FileDate).vhdx"
$GoldenDiskPath = Join-Path $ParentDisksPath $GoldenDiskFileName

if (-Not [string]::IsNullOrEmpty($OutputVhdxPath)) {
    $GoldenDiskPath = $OutputVhdxPath
}

Write-DLabLog "Moving golden VHDX"

if (Test-Path $GoldenDiskPath) {
    Write-DLabLog "Removing previous golden VHDX"
    Remove-Item $GoldenDiskPath -Force | Out-Null
}
Move-Item -Path $ParentDiskPath -Destination $GoldenDiskPath

Write-DLabLog "Optimizing golden VHDX for compact size"
Optimize-VHD -Path $GoldenDiskPath -Mode Full

Write-DLabLog "Setting golden VHDX file as read-only"
Set-ItemProperty -Path $GoldenDiskPath -Name IsReadOnly $true

Write-DLabLog "Golden VHDX Path: '$GoldenDiskPath'"
