#Requires -RunAsAdministrator
#Requires -PSEdition Core

param(
    [string] $VMAlias = "HOST",
    [int] $VMNumber = 50,
    [bool] $ExportVMs = $false
)

. .\common.ps1

$HostVMName = $VMName = $LabPrefix, $VMAlias -Join "-"
$IpAddress = Get-DLabIpAddress $LabNetworkBase $VMNumber

New-DLabVM $VMName -Password $LocalPassword -OSVersion $OSVersion `
    -MemoryBytes 24GB `
    -DynamicMemory $false `
    -CloneParentDisk $true `
    -EnableVirtualization $true -Force

Start-DLabVM $VMName

Start-VM -Name "IT-HELP-RTR"

Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $LocalUserName -Password $LocalPassword
$VMSession = New-DLabVMSession $VMName -UserName $LocalUserName -Password $LocalPassword

$HostDnsServerAddress = "1.1.1.1"

Set-DLabVMNetAdapter $VMName -VMSession $VMSession `
    -SwitchName $SwitchName -NetAdapterName $NetAdapterName `
    -IPAddress $IPAddress -DefaultGateway $DefaultGateway `
    -DnsServerAddress $HostDnsServerAddress

$HostUserName = "Administrator"
$HostPassword = $LocalPassword

$VMSession = New-DLabVMSession $VMName -UserName $HostUserName -Password $HostPassword

Write-DLabLog "Installing Hyper-V with management tools"

Invoke-Command -ScriptBlock {
    Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart
} -Session $VMSession

Write-DLabLog "Waiting for VM to reboot after enabling Hyper-V"

Wait-DLabVM $VMName 'Reboot' -Timeout 120
Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $HostUserName -Password $HostPassword
$VMSession = New-DLabVMSession $VMName -UserName $HostUserName -Password $HostPassword -ConfigurationName "PowerShell.7"

Write-DLabLog "Adding current user to the local Hyper-V Administrators group"

Invoke-Command -ScriptBlock {
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    if (-Not (Get-LocalGroupMember -Group "Hyper-V Administrators" -Member $CurrentUser -ErrorAction SilentlyContinue)) {
        Add-LocalGroupMember -Group "Hyper-V Administrators" -Member @($CurrentUser)
    }
} -Session $VMSession

Write-DLabLog "Installing Devolutions PowerShell module"

Invoke-Command -ScriptBlock {
    Install-Module -Name Devolutions.PowerShell -Scope AllUsers -Force
} -Session $VMSession

Write-DLabLog "Installing .NET Desktop Runtime"

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

Write-DLabLog "Installing Devolutions Remote Desktop Manager"

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

if ($ExportVMs) {
    $VMNames = @("IT-HELP-DC", "IT-HELP-DVLS", "IT-HELP-GW")

    foreach ($VMName in $VMNames) {
        Write-Host "Stopping VM: $VMName"
        Stop-VM -Name $VMName -Force -ErrorAction Stop
    }

    $LabVhdxPath = "C:\Hyper-V\VHDs\IT-HELP-VMS.vhdx"
    $LabVhdxLabel = "IT-HELP-VMS"
    $LabVhdxSize = 128GB

    if (Test-Path $LabVhdxPath) {
        Dismount-VHD -Path $LabVhdxPath -ErrorAction SilentlyContinue
        Remove-Item $LabVhdxPath -Force | Out-Null
    }

    New-VHD -Path $LabVhdxPath -SizeBytes $LabVhdxSize -Dynamic | Out-Null

    Mount-VHD -Path $LabVhdxPath -PassThru | Initialize-Disk -PartitionStyle GPT -PassThru |
        New-Partition -UseMaximumSize -AssignDriveLetter |
        Format-Volume -FileSystem NTFS -NewFileSystemLabel $LabVhdxLabel -Confirm:$false

    $DriveLetter = (Get-DiskImage -ImagePath $LabVhdxPath | Get-Disk | Get-Partition | Get-Volume).DriveLetter
    $DstHyperVPath = "$DriveLetter`:\Hyper-V"
    New-Item -ItemType Directory -Path $DstHyperVPath -ErrorAction SilentlyContinue | Out-Null
    @('ISOs','IMGs','VHDs') | ForEach-Object {
        New-Item -ItemType Directory -Path $(Join-Path $DstHyperVPath $_) -ErrorAction SilentlyContinue | Out-Null
    }

    Get-Item "C:\Hyper-V\ISOs\alpine-*.iso" | ForEach-Object {
        Copy-Item $_.FullName "$DstHyperVPath\ISOs"
    }

    foreach ($VMName in $VMNames) {
        $VmDrives = Get-VMHardDiskDrive -VMName $VMName -ErrorAction Stop
        $drive = $vmDrives | Select-Object -First 1
        $sourceVhdx = $drive.Path
        $outputVhdx = Join-Path -Path "$DstHyperVPath\VHDs" -ChildPath "$VMName.vhdx"
        Convert-VHD -Path $sourceVhdx -DestinationPath $outputVhdx -VHDType Dynamic -DeleteSource:$false -ErrorAction Stop
    }

    # Detect Git root and repo name
    $gitRoot = & git rev-parse --show-toplevel 2>$null
    $repoName = Split-Path $gitRoot -Leaf

    if ($LASTEXITCODE -eq 0 -and $gitRoot -and (Test-Path $gitRoot)) {
        $dstGitParent = Join-Path $DstHyperVPath "git"
        $dstRepoPath = Join-Path $dstGitParent $repoName

        # Ensure parent folder exists
        if (-Not (Test-Path $dstGitParent)) {
            New-Item -ItemType Directory -Path $dstGitParent -Force | Out-Null
        }

        Write-Host "Cloning Git repo from $gitRoot -> $dstRepoPath"
        git clone --local --no-hardlinks "$gitRoot" "$dstRepoPath"

        # Manually copy ignored file (e.g., ADAccounts.json)
        $sourceFile = Join-Path $gitRoot "powershell\ADAccounts.json"
        $targetFile = Join-Path $dstRepoPath "powershell\ADAccounts.json"

        if (Test-Path $sourceFile) {
            Write-Host "Copying ignored file: $sourceFile -> $targetFile"
            Copy-Item -Path $sourceFile -Destination $targetFile -Force
        } else {
            Write-Warning "Ignored file not found: $sourceFile"
        }
    } else {
        Write-Warning "Not in a Git repository, or Git not found."
    }

    Write-DLabLog "Dismounting VHDX: $LabVhdxPath"
    Dismount-VHD -Path $LabVhdxPath -ErrorAction Stop

    Write-DLabLog "Attaching VHDX to host VM"
    Stop-VM -Name $HostVmName -Force -ErrorAction Stop
    Add-VMHardDiskDrive -VMName $HostVmName -ControllerType SCSI -ControllerNumber 0 -Path $LabVhdxPath
    Start-VM -Name $HostVMName

    Write-DLabLog "Waiting for host VM to boot"
    Wait-DLabVM $HostVMName 'Heartbeat' -Timeout 600 -UserName $HostUserName -Password $HostPassword
    $VMSession = New-DLabVMSession $HostVMName -UserName $HostUserName -Password $HostPassword -ConfigurationName "PowerShell.7"

    Invoke-Command -ScriptBlock { Param($LabVhdxLabel)
        Get-Disk | Where-Object IsOffline -eq $true | Set-Disk -IsOffline $false
        $Volume = Get-Volume | Where-Object { $_.FileSystemLabel -eq $LabVhdxLabel }
        $DriveLetter = $Volume.DriveLetter
        $DriveHyperVPath = "$DriveLetter`:\Hyper-V"
        Copy-Item $DriveHyperVPath "C:\Hyper-V" -Recurse -Force
        Set-Location "C:\Hyper-V\git\devolutions-labs\powershell"
        Write-Host "running host_init.ps1 script"
        pwsh.exe .\host_init.ps1
        Write-Host "running rtr_vm.ps1 script"
        pwsh.exe .\rtr_vm.ps1
        Write-Host "Enabling enhanced session mode"
        Set-VMHost -EnableEnhancedSessionMode $true
    } -Session $VMSession -ArgumentList @($LabVhdxLabel)

    Invoke-Command -ScriptBlock { Param([string[]]$VMNames)
        foreach ($VMName in $VMNames) {
            Write-Host "Importing VM: $VMName"

            $VHDPath = "C:\Hyper-V\VHDs\$VMName.vhdx"
            $SwitchName = "LAN Switch"

            if ($VMName.EndsWith("-DC")) {
                $MemoryBytes = 2GB
                $ProcessorCount = 2
            } else {
                $MemoryBytes = 4GB
                $ProcessorCount = 4
            }

            $MemoryStartupBytes = ([math]::Floor(($MemoryBytes / 1MB * 0.5) / 2) * 2) * 1MB
            $MemoryMinimumBytes = $MemoryStartupBytes
            $MemoryMaximumBytes = $MemoryBytes

            New-VM -Name $VMName -VHDPath $VHDPath -SwitchName $SwitchName

            $VMParams = @{
                Name = $VMName;
                ProcessorCount = $ProcessorCount;
                AutomaticStopAction = "Shutdown";
                CheckpointType = "Disabled";
                DynamicMemory = $true;
                MemoryStartupBytes = $MemoryStartupBytes;
                MemoryMinimumBytes = $MemoryMinimumBytes;
                MemoryMaximumBytes = $MemoryMaximumBytes;
            }

            Set-VM @VMParams
            Start-VM $VMName
        }
    } -Session $VMSession -ArgumentList @(,$VMNames)

    Invoke-Command -ScriptBlock {
        Set-Location "C:\Hyper-V\git\devolutions-labs\powershell"
        Write-Host "running host_sync.ps1 script"
        .\host_sync.ps1
    } -Session $VMSession

    Stop-VM -Name $HostVmName -Force -ErrorAction Stop
    $Disk = Get-VMHardDiskDrive -VMName $HostVmName | Where-Object { $_.Path -eq $LabVhdxPath }
    if ($Disk) {
        Write-Host "Removing VHDX from VM: $LabVhdxPath"
        Remove-VMHardDiskDrive -VMHardDiskDrive $Disk
    }
    if (Test-Path $LabVhdxPath) {
        Write-Host "Deleting VHDX file: $LabVhdxPath"
        Remove-Item -Path $LabVhdxPath -Force
    }
    Start-VM -Name $HostVMName
}

Write-DLabLog "Configure lab user with autologon"

Wait-DLabVM $HostVMName 'Heartbeat' -Timeout 600 -UserName $HostUserName -Password $HostPassword
$VMSession = New-DLabVMSession $HostVMName -UserName $HostUserName -Password $HostPassword

$HostUserName = "Administrator"
$HostPassword = "LabUser123!"

Invoke-Command -ScriptBlock { Param($HostUserName, $HostPassword)
    $user = [ADSI]"WinNT://$Env:COMPUTERNAME/$Env:USERNAME,user"
    $user.SetPassword($HostPassword)

    $WinLogonRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $WinLogonRegPath -Name "AutoAdminLogon" -Value "1" -Type String
    Set-ItemProperty -Path $WinLogonRegPath -Name "DefaultUserName" -Value $HostUserName -Type String
    Set-ItemProperty -Path $WinLogonRegPath -Name "DefaultPassword" -Value $HostPassword -Type String
    Set-ItemProperty -Path $WinLogonRegPath -Name "DefaultDomainName" -Value "." -Type String
} -Session $VMSession -ArgumentList @($HostUserName, $HostPassword)
