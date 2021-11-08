
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
    $ActivationReg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\Activation"
    Set-ItemProperty -Path $ActivationReg -Name 'Manual' -Value '1' -Type DWORD
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

if ($InstallChocolateyPackages) {
    Invoke-Command -ScriptBlock {
        $Packages = @(
            'git',
            'vlc',
            '7zip',
            'gsudo',
            'firefox',
            'microsoft-edge',
            'vscode',
            'openssl',
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
    Install-Module Posh-ACME -Scope AllUsers
    Install-Module PsHosts -Scope AllUsers
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
    iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"
} -Session $VMSession

Write-Host "Enabling and starting sshd service"

Invoke-Command -ScriptBlock {
    Install-Module -Name Microsoft.PowerShell.RemotingTools -Scope AllUsers
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

if ($InstallWindowsUpdates) {
    Write-Host "Installing Windows updates until VM is fully up-to-date"

    do {
        $WUStatus = Invoke-Command -ScriptBlock {
            $Updates = Start-WUScan
            if ($Updates.Count -gt 0) {
                Install-WUUpdates -Updates $Updates
            }
            [PSCustomObject]@{
                UpdateCount = $(Start-WUScan).Count
                PendingReboot = Get-WUIsPendingReboot
            }
        } -Session $VMSession

        if ($WUStatus.PendingReboot) {
            Restart-VM $VMName -Force
            Wait-VM $VMName -For IPAddress -Timeout 360
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
    & "$Env:WinDir\System32\Sysprep\sysprep.exe" /oobe /generalize /shutdown /mode:vm
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
