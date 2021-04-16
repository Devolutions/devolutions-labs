
Import-Module .\DevolutionsLabs.psm1 -Force

$UserName = "Administrator"
$Password = "yolo123!"

$VMName = "IT-TEMPLATE"

New-DLabParentVM $VMName

# perform initial boot and installation manually, then remove ISO drive

Get-VMDvdDrive $VMName | Where-Object { $_.DvdMediaType -Like 'ISO' } |
    Remove-VMDvdDrive -ErrorAction SilentlyContinue

$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Invoke-Command -ScriptBlock {
    Set-ExecutionPolicy Unrestricted -Force
    Install-PackageProvider Nuget -Force
    Install-Module -Name PowerShellGet -Force
    Set-PSRepository -Name "PSGallery" -InstallationPolicy "Trusted"
} -Session $VMSession

Invoke-Command -ScriptBlock {
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
} -Session $VMSession

Invoke-Command -ScriptBlock {
    choco install -y git
    choco install -y vlc
    choco install -y 7zip
    choco install -y gsudo
    choco install -y firefox
    choco install -y vscode
    choco install -y openssl
    choco install -y kdiff3
    choco install -y filezilla
    choco install -y wireshark
    choco install -y sysinternals
    choco install -y sublimetext3
    choco install -y notepadplusplus
} -Session $VMSession

Invoke-Command -ScriptBlock {
    $RegPath = "HKLM:\Software\Policies\Mozilla\Firefox\Certificates"
    New-Item -Path $RegPath -Force | Out-Null
    New-ItemProperty -Path $RegPath -Name ImportEnterpriseRoots -Value 1 -Force | Out-Null
} -Session $VMSession

Invoke-Command -ScriptBlock {
    Install-Module Microsoft.PowerShell.SecretManagement -Scope AllUsers
    Install-Module Microsoft.PowerShell.SecretStore -Scope AllUsers
} -Session $VMSession

Invoke-Command -ScriptBlock {
    Install-Module RdmHelper -Scope AllUsers
    Install-Module WaykClient -Scope AllUsers
    Install-Module WaykBastion -Scope AllUsers
    Install-Module DevolutionsGateway -Scope AllUsers
    Install-Module Posh-ACME -Scope AllUsers
    Install-Module PsHosts -Scope AllUsers
} -Session $VMSession

Invoke-Command -ScriptBlock {
    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
} -Session $VMSession

Invoke-Command -ScriptBlock {
    iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"
} -Session $VMSession

Invoke-Command -ScriptBlock {
    Install-Module -Name Microsoft.PowerShell.RemotingTools -Scope AllUsers
    Set-Service -Name sshd -StartupType 'Automatic'
    Start-Service sshd
} -Session $VMSession

$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Invoke-Command -ScriptBlock {
    & pwsh.exe -NoLogo -Command "Enable-SSHRemoting -Force"
    Restart-Service sshd
} -Session $VMSession

Invoke-Command -ScriptBlock {
    New-NetFirewallRule -Name 'ICMPv4' -DisplayName 'ICMPv4' `
        -Description 'Allow ICMPv4' -Profile Any -Direction Inbound -Action Allow `
        -Protocol ICMPv4 -Program Any -LocalAddress Any -RemoteAddress Any
} -Session $VMSession

Invoke-Command -ScriptBlock {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
} -Session $VMSession

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

Invoke-Command -ScriptBlock {
    & dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase
} -Session $VMSession

Invoke-Command -ScriptBlock {
    Stop-service wuauserv | Set-Service -StartupType Disabled
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 1 -Type DWORD
} -Session $VMSession

Invoke-Command -ScriptBlock {
    & "$Env:WinDir\System32\Sysprep\sysprep.exe" /oobe /generalize /shutdown /mode:vm
} -Session $VMSession

Remove-VM $VMName

$ParentDisksPath = Get-DLabPath "ParentDisks"
$ParentDiskFileName = $VMName, 'vhdx' -Join '.'
$ParentDiskPath = Join-Path $ParentDisksPath $ParentDiskFileName

$GoldenDiskFileName = "Windows Server 2019 Standard - $(Get-Date -Format FileDate).vhdx"
$GoldenDiskPath = Join-Path $ParentDisksPath $GoldenDiskFileName

Move-Item -Path $ParentDiskPath -Destination $GoldenDiskPath
Set-ItemProperty -Path $GoldenDiskPath -Name IsReadOnly $true
