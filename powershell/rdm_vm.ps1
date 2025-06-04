. .\common.ps1

$VMAlias = "RDM"
$VMNumber = 9
$VMName = $LabPrefix, $VMAlias -Join "-"
$IpAddress = Get-DLabIpAddress $LabNetworkBase $VMNumber

New-DLabVM $VMName -Password $LocalPassword -OSVersion $OSVersion -Force
Start-DLabVM $VMName

Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $LocalUserName -Password $LocalPassword
$VMSession = New-DLabVMSession $VMName -UserName $LocalUserName -Password $LocalPassword

Set-DLabVMNetAdapter $VMName -VMSession $VMSession `
    -SwitchName $SwitchName -NetAdapterName $NetAdapterName `
    -IPAddress $IPAddress -DefaultGateway $DefaultGateway `
    -DnsServerAddress $DnsServerAddress

Write-Host "Joining domain"

Add-DLabVMToDomain $VMName -VMSession $VMSession `
    -DomainName $DomainName -DomainController $DCHostName `
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

Write-Host "Installing Devolutions PowerShell module"

Invoke-Command -ScriptBlock {
    Install-Module -Name Devolutions.PowerShell -Scope AllUsers -Force
} -Session $VMSession

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

Write-Host "Installing Devolutions Remote Desktop Manager"

Invoke-Command -ScriptBlock {
    $ProductsHtm = Invoke-RestMethod -Uri "https://devolutions.net/productinfo.htm" -Method 'GET' -ContentType 'text/plain'
    $RdmMatches = $($ProductsHtm | Select-String -AllMatches -Pattern "(RDM\S+).Url=(\S+)").Matches
    $RdmKeyName = if ($Env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { "RDMmsiArm" } else { "RDMmsiX64" }
    $RdmWindows = $RdmMatches | Where-Object { $_.Groups[1].Value -eq $RdmKeyName }
    $RdmDownloadUrl = $RdmWindows.Groups[2].Value
    $RdmFileName = [System.IO.Path]::GetFileName($RdmDownloadUrl)
    $TempMsiPath = Join-Path $env:TEMP $RdmFileName
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $RdmDownloadUrl -OutFile $TempMsiPath
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$TempMsiPath`" /quiet /norestart" -Wait -NoNewWindow
    Remove-Item -Path $TempMsiPath -Force | Out-Null
} -Session $VMSession

Write-Host "Changing Windows taskbar default pinned apps"

Invoke-Command -ScriptBlock {
    $LnkPaths = @(
        "%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk"
        "%APPDATA%\Microsoft\Windows\Start Menu\Programs\File Explorer.lnk"
        "%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Remote Desktop Manager\Remote Desktop Manager (RDM).lnk"
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
    Remove-Item "$Env:AppData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\*" -Force -ErrorAction SilentlyContinue
    Remove-Item "$Env:AppData\Microsoft\Windows\Shell\*.dat" -Force -ErrorAction SilentlyContinue
    Remove-Item "$Env:AppData\Microsoft\Windows\Shell\LayoutModification.xml" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Recurse -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TrayNotify" -Name "IconStreams" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TrayNotify" -Name "PastIconsStream" -ErrorAction SilentlyContinue
} -Session $VMSession
