
$ErrorActionPreference = 'Stop'

Write-Host "Increase WinRM default configuration values"

& 'winrm' 'set' 'winrm/config' '@{MaxTimeoutms=\"1800000\"}'
& 'winrm' 'set' 'winrm/config/winrs' '@{MaxMemoryPerShellMB=\"800\"}'

Write-Host "Enabling TLS 1.2 for .NET Framework applications"

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWORD
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWORD

Write-Host "Disabling Server Manager automatic launch and Windows Admin Center pop-up"

$ServerManagerReg = "HKLM:\SOFTWARE\Microsoft\ServerManager"
Set-ItemProperty -Path $ServerManagerReg -Name 'DoNotPopWACConsoleAtSMLaunch' -Value '1' -Type DWORD
Set-ItemProperty -Path $ServerManagerReg -Name 'DoNotOpenServerManagerAtLogon' -Value '1' -Type DWORD

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

Write-Host "Enabling OpenSSH client and server features"

Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

Write-Host "Configuring Firefox to trust system root CAs"

$RegPath = "HKLM:\Software\Policies\Mozilla\Firefox\Certificates"
New-Item -Path $RegPath -Force | Out-Null
New-ItemProperty -Path $RegPath -Name "ImportEnterpriseRoots" -Value 1 -Force | Out-Null

Write-Host "Disable Microsoft Edge first run experience"

$RegPath = "HKLM:\Software\Policies\Microsoft\Edge"
New-Item -Path $RegPath -Force | Out-Null
New-ItemProperty -Path $RegPath -Name "HideFirstRunExperience" -Value 1 -Force | Out-Null
New-ItemProperty -Path $RegPath -Name "NewTabPageLocation" -Value "https://www.google.com" -Force | Out-Null
