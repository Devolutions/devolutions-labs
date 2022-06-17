Import-Module .\DevolutionsLabs.psm1 -Force

$ErrorActionPreference = "Stop"

$VMName = "IT-TEMPLATE"
$SwitchName = "NAT Switch"
$UserName = "Administrator"
$Password = "lab123!"

$InstallWindowsUpdates = $true
$InstallChocolateyPackages = $true

Write-Host "Creating golden image"

$AnswerTempPath = Join-Path $([System.IO.Path]::GetTempPath()) "unattend-$VMName"
Remove-Item $AnswerTempPath -Force  -Recurse -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType Directory -Path $AnswerTempPath -ErrorAction SilentlyContinue | Out-Null
$AnswerFilePath = Join-Path $AnswerTempPath "autounattend.xml"

$Params = @{
    UserFullName = "devolutions";
    UserOrganization = "IT-HELP";
    ComputerName = $Name;
    AdministratorPassword = $Password;
    UILanguage = "en-US";
    UserLocale = "en-CA";
}

Write-Host "Creating Windows answer file"

New-DLabAnswerFile $AnswerFilePath @Params

$AnswerIsoPath = Join-Path $([System.IO.Path]::GetTempPath()) "unattend-$VMName.iso"
New-DLabIsoFile -Path $AnswerTempPath -Destination $AnswerIsoPath -VolumeName "unattend"

New-DLabParentVM $VMName -SwitchName $SwitchName -Force

Add-VMDvdDrive -VMName $VMName -ControllerNumber 1 -Path $AnswerIsoPath

Write-Host "Starting golden VM"

Start-DLabVM $VMName
Start-Sleep 5

Write-Host "Waiting for VM to reboot"

Wait-DLabVM $VMName 'Reboot' -Timeout 600

Get-VMDvdDrive $VMName | Where-Object { $_.DvdMediaType -Like 'ISO' } |
    Remove-VMDvdDrive -ErrorAction SilentlyContinue

Remove-Item -Path $AnswerIsoPath -Force -ErrorAction SilentlyContinue | Out-Null
Remove-Item -Path $AnswerTempPath -Recurse -Force -ErrorAction SilentlyContinue | Out-Null

Write-Host "Waiting for VM to become ready"

Wait-DLabVM $VMName 'PSDirect' -Timeout 600 -UserName $UserName -Password $Password
$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Write-Host "Setting VM network adapter"

Set-DLabVMNetAdapter $VMName -VMSession $VMSession `
    -SwitchName $SwitchName -NetAdapterName "vEthernet (LAN)" `
    -IPAddress "10.9.0.249" -DefaultGateway "10.9.0.1" `
    -DnsServerAddress "1.1.1.1"

Write-Host "Increase WinRM default configuration values"

Invoke-Command -ScriptBlock {
    & 'winrm' 'set' 'winrm/config' '@{MaxTimeoutms=\"1800000\"}'
    & 'winrm' 'set' 'winrm/config/winrs' '@{MaxMemoryPerShellMB=\"800\"}'
} -Session $VMSession

Write-Host "Enabling TLS 1.2 for .NET Framework applications"

Invoke-Command -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWORD
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWORD
} -Session $VMSession

Write-Host "Disabling Server Manager automatic launch and Windows Admin Center pop-up"

Invoke-Command -ScriptBlock {
    $ServerManagerReg = "HKLM:\SOFTWARE\Microsoft\ServerManager"
    Set-ItemProperty -Path $ServerManagerReg -Name 'DoNotPopWACConsoleAtSMLaunch' -Value '1' -Type DWORD
    Set-ItemProperty -Path $ServerManagerReg -Name 'DoNotOpenServerManagerAtLogon' -Value '1' -Type DWORD
} -Session $VMSession

Write-Host "Disabling 'Activate Windows' watermark on desktop"

Invoke-Command -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\Activation' -Name 'Manual' -Value '1' -Type DWORD

    $TaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
	    -Argument "-Command { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\Activation' -Name 'Manual' -Value '1' -Type DWORD }"

    $TaskTrigger = New-ScheduledTaskTrigger -AtStartup

    Register-ScheduledTask -Action $TaskAction -Trigger $TaskTrigger -TaskName "Activation Watermark" -Description "Remove Windows Activation Watermark"
} -Session $VMSession

$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Write-Host "Configuring initial PowerShell environment"

Invoke-Command -ScriptBlock {
    Set-ExecutionPolicy Unrestricted -Force
    Install-PackageProvider Nuget -Force
    Install-Module -Name PowerShellGet -Force
    Set-PSRepository -Name "PSGallery" -InstallationPolicy "Trusted"
} -Session $VMSession

Write-Host "Installing chocolatey package manager"

Invoke-Command -ScriptBlock {
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
} -Session $VMSession

$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Write-Host "Installing .NET Framework 4.8"

Invoke-Command -ScriptBlock {
    choco install -y --no-progress netfx-4.8
} -Session $VMSession

if ($InstallChocolateyPackages) {
    Invoke-Command -ScriptBlock {
        $Packages = @(
            'git',
            'vlc',
            '7zip',
            'gsudo',
            'nssm',
            'firefox',
            'microsoft-edge',
            'vscode',
            'kdiff3',
            'filezilla',
            'wireshark',
            'sysinternals',
            'sublimetext3',
            'notepadplusplus')

        foreach ($Package in $Packages) {
            Write-Host "Installing $Package"
            choco install -y --no-progress $Package
        }
    } -Session $VMSession
}

Write-Host "Installing OpenSSL"

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
    [Environment]::SetEnvironmentVariable("PATH", "${Env:PATH};${Env:ProgramFiles}\OpenSSL-Win64\bin", "Machine")
    Remove-Item "OpenSSL.msi"
} -Session $VMSession

Write-Host "Downloading tools"

Invoke-Command -ScriptBlock {
    $ProgressPreference = "SilentlyContinue"
    New-Item -ItemType Directory -Path "C:\tools" -ErrorAction SilentlyContinue | Out-Null
    New-Item -ItemType Directory -Path "C:\tools\bin" -ErrorAction SilentlyContinue | Out-Null
    [Environment]::SetEnvironmentVariable("PATH", "${Env:PATH};C:\tools\bin", "Machine")
    Invoke-WebRequest 'https://npcap.com/dist/npcap-1.60.exe' -OutFile "C:\tools\npcap-1.60.exe"
    Invoke-WebRequest 'http://update.youngzsoft.com/ccproxy/update/ccproxysetup.exe' -OutFile "C:\tools\CCProxySetup.exe"
    Invoke-WebRequest 'https://download.tuxfamily.org/dvorak/windows/1.1rc2/bepo-1.1rc2-full.exe' -OutFile "C:\tools\bepo-1.1rc2-full.exe"
} -Session $VMSession

Write-Host "Installing Smallstep CA"

Invoke-Command -ScriptBlock {
    $StepPath = Join-Path $Env:ProgramData "step"
    New-Item -ItemType Directory -Path $StepPath -ErrorAction SilentlyContinue | Out-Null
    New-Item -ItemType Directory -Path "$StepPath\bin" -ErrorAction SilentlyContinue | Out-Null
    [Environment]::SetEnvironmentVariable("STEPPATH", $StepPath, "Machine")
    [Environment]::SetEnvironmentVariable("PATH", "${Env:PATH};$StepPath\bin", "Machine")
    Invoke-WebRequest 'https://dl.step.sm/gh-release/cli/docs-cli-install/v0.19.0/step_windows_0.19.0_amd64.zip' -OutFile "step_windows_0.19.0_amd64.zip"
    Expand-Archive -LiteralPath .\step_windows_0.19.0_amd64.zip -DestinationPath .
    Move-Item ".\step_0.19.0\bin\step.exe" "$StepPath\bin\step.exe"
    Remove-Item .\step_* -Recurse
    Invoke-WebRequest 'https://dl.step.sm/gh-release/certificates/gh-release-header/v0.19.0/step-ca_windows_0.19.0_amd64.zip' -OutFile "step-ca_windows_0.19.0_amd64.zip"
    Expand-Archive -Path ".\step-ca_windows_0.19.0_amd64.zip" -DestinationPath .
    Move-Item ".\step-ca_0.19.0\bin\step-ca.exe" "$StepPath\bin\step-ca.exe"
    Remove-Item .\step-ca_* -Recurse
} -Session $VMSession

Write-Host "Installing UltraVNC"

Invoke-Command -ScriptBlock {
    Invoke-WebRequest 'https://www.uvnc.eu/download/1381/UltraVNC_1_3_81_X64_Setup.exe' -OutFile "UltraVNC_1_3_81_X64_Setup.exe"
    Start-Process .\UltraVNC_1_3_81_X64_Setup.exe -Wait -ArgumentList ("/VERYSILENT", "/NORESTART")
    Remove-Item .\UltraVNC_1_3_81_X64_Setup.exe
    
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

Write-Host "Configuring Firefox to trust system root CAs"

Invoke-Command -ScriptBlock {
    $RegPath = "HKLM:\Software\Policies\Mozilla\Firefox\Certificates"
    New-Item -Path $RegPath -Force | Out-Null
    New-ItemProperty -Path $RegPath -Name ImportEnterpriseRoots -Value 1 -Force | Out-Null
} -Session $VMSession

Write-Host "Installing PowerShell secret management modules"

Invoke-Command -ScriptBlock {
    Install-Module Microsoft.PowerShell.SecretManagement -Scope AllUsers
    Install-Module Microsoft.PowerShell.SecretStore -Scope AllUsers
} -Session $VMSession

Write-Host "Installing useful PowerShell modules"

Invoke-Command -ScriptBlock {
    Install-Module -Name PsHosts -Scope AllUsers
    Install-Module -Name Posh-ACME -Scope AllUsers
    Install-Module -Name PSWindowsUpdate -Scope AllUsers
} -Session $VMSession

Write-Host "Installing Remote Server Administration DNS tools"

Invoke-Command -ScriptBlock {
    Install-WindowsFeature RSAT-DNS-Server
} -Session $VMSession

Write-Host "Enabling OpenSSH client and server features"

Invoke-Command -ScriptBlock {
    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
} -Session $VMSession

Write-Host "Installing PowerShell 7"

Invoke-Command -ScriptBlock {
    [Environment]::SetEnvironmentVariable("POWERSHELL_UPDATECHECK", "0", "Machine")
    [Environment]::SetEnvironmentVariable("POWERSHELL_TELEMETRY_OPTOUT", "1", "Machine")
    iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"
} -Session $VMSession

Write-Host "Rebooting VM"

Invoke-Command -ScriptBlock {
    Restart-Computer -Force
} -Session $VMSession

Wait-DLabVM $VMName 'Reboot' -Timeout 120
Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $UserName -Password $Password

$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Write-Host "Enabling and starting sshd service"

Invoke-Command -ScriptBlock {
    Install-Module -Name Microsoft.PowerShell.RemotingTools -Scope AllUsers -Force
    Set-Service -Name sshd -StartupType 'Automatic'
    Start-Service sshd
} -Session $VMSession

$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Write-Host "Enabling PowerShell Remoting over SSH"

Invoke-Command -ScriptBlock {
    & pwsh.exe -NoLogo -Command "Enable-SSHRemoting -Force"
    Restart-Service sshd
} -Session $VMSession

Write-Host "Enabling ICMP requests (ping) in firewall"

Invoke-Command -ScriptBlock {
    New-NetFirewallRule -Name 'ICMPv4' -DisplayName 'ICMPv4' `
        -Description 'Allow ICMPv4' -Profile Any -Direction Inbound -Action Allow `
        -Protocol ICMPv4 -Program Any -LocalAddress Any -RemoteAddress Any
} -Session $VMSession

Write-Host "Enabling network discovery, file and printer sharing in firewall"

Invoke-Command -ScriptBlock {
    & netsh advfirewall firewall set rule group="Network Discovery" new enable=yes
    & netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=yes
} -Session $VMSession

Write-Host "Enabling remote desktop server and firewall rule"

Invoke-Command -ScriptBlock {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
} -Session $VMSession

Write-Host "Rebooting VM"

Invoke-Command -ScriptBlock {
    Restart-Computer -Force
} -Session $VMSession

Wait-DLabVM $VMName 'Reboot' -Timeout 120
Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $UserName -Password $Password

$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

if ($InstallWindowsUpdates) {
    Write-Host "Installing Windows updates until VM is fully up-to-date"

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

        Write-Host "WUStatus: $($WUStatus.UpdateCount), PendingReboot: $($WUStatus.PendingReboot): $(Get-Date)"

        if ($WUStatus.PendingReboot) {
            Write-Host "Waiting for VM reboot: $(Get-Date)"
            Wait-DLabVM $VMName 'Reboot' -Timeout 120
            Wait-VM $VMName -For IPAddress -Timeout 360
            Start-Sleep -Seconds 60
            $VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password
        }
    } until (($WUStatus.PendingReboot -eq $false) -and ($WUStatus.UpdateCount -eq 0))
}

Write-Host "Cleaning up Windows base image (WinSxS folder)"

Invoke-Command -ScriptBlock {
    & dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase
} -Session $VMSession

Write-Host "Disabling Windows Update service permanently"

Invoke-Command -ScriptBlock {
    Stop-service wuauserv | Set-Service -StartupType Disabled
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 1 -Type DWORD
} -Session $VMSession

Write-Host "Running sysprep to generalize the image for OOBE experience and shut down VM"

Invoke-Command -ScriptBlock {
    & "$Env:WinDir\System32\Sysprep\sysprep.exe" '/oobe' '/generalize' '/shutdown' '/mode:vm'
} -Session $VMSession

Write-Host "Waiting for VM to shut down completely"
Wait-DLabVM $VMName 'Shutdown' -Timeout 120

Write-Host "Deleting the VM (but not the VHDX)"
Remove-VM $VMName -Force

$ParentDisksPath = Get-DLabPath "IMGs"
$ParentDiskFileName = $VMName, 'vhdx' -Join '.'
$ParentDiskPath = Join-Path $ParentDisksPath $ParentDiskFileName

$GoldenDiskFileName = "Windows Server 2019 Standard - $(Get-Date -Format FileDate).vhdx"
$GoldenDiskPath = Join-Path $ParentDisksPath $GoldenDiskFileName

Write-Host "Moving golden VHDX"
Move-Item -Path $ParentDiskPath -Destination $GoldenDiskPath

Write-Host "Optimizing golden VHDX for compact size"
Optimize-VHD -Path $GoldenDiskPath -Mode Full

Write-Host "Setting golden VHDX file as read-only"
Set-ItemProperty -Path $GoldenDiskPath -Name IsReadOnly $true
