
if (-Not (Test-Path 'variable:global:IsWindows')) {
    $script:IsWindows = $true; # Windows PowerShell 5.1 or earlier
}

if ($IsWindows) {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
}

function Get-DLabPath
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateSet("ISOs","VHDs","ChildDisks","ParentDisks")]
        [string] $PathName
    )

    $HyperVBasePath = "C:\Hyper-V"

    switch ($PathName) {
        "ISOs" { Join-Path $HyperVBasePath "ISOs" }
        "VHDs" { Join-Path $HyperVBasePath "Virtual Hard Disks" }
        "ChildDisks" { Join-Path $HyperVBasePath "Virtual Hard Disks" }
        "ParentDisks" { Join-Path $HyperVBasePath "Golden Images" }
    }
}

function New-DLabChildDisk
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Name,
        [switch] $Force
    )

    $ParentDisksPath = Get-DLabPath "ParentDisks"
    $ParentDiskFileName = "Windows Server 2019 Standard", 'vhdx' -Join '.'
    $ParentDiskPath = Join-Path $ParentDisksPath $ParentDiskFileName

    if (-Not (Test-Path $ParentDiskPath -PathType 'Leaf')) {
        throw "`"$ParentDiskPath`" cannot be found"
    }

    $ChildDisksPath = Get-DLabPath "ChildDisks"
    $ChildDiskFileName = $Name, 'vhdx' -Join '.'
    $ChildDiskPath = Join-Path $ChildDisksPath $ChildDiskFileName

    if (Test-Path $ChildDiskPath -PathType 'Leaf') {
        if ($Force) {
            Remove-Item -Path $ChildDiskPath
        } else {
            throw "`"$ChildDiskPath`" already exists!"
        }
    }

    New-VHD -Path $ChildDiskPath -ParentPath $ParentDiskPath
}

function New-DLabVM
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Name,
        [string] $Password,
        [switch] $Force
    )

    if ([bool]$(Get-VM $Name)) {
        if ($Force) {
            Remove-VM $Name
        } else {
            throw "VM `"$Name`" already exists!"
        }
    }

    $ChildDisk = New-DLabChildDisk $Name -Force:$Force

    $MountedDisk = Mount-VHD -Path $ChildDisk.Path -PassThru

    $Volumes = $MountedDisk | Get-Partition | Get-Volume | `
        Sort-Object -Property Size -Descending
    $Volume = $Volumes[0]

    $DriveLetter = $Volume.DriveLetter
    $PantherPath = "$DriveLetter`:\Windows\Panther"
    $AnswerFilePath = Join-Path $PantherPath "unattend.xml"

    $Params = @{
        UserFullName = "devolutions";
        UserOrganization = "IT-HELP";
        ComputerName = $Name;
        AdministratorPassword = $Password;
        UILanguage = "en-US";
        UserLocale = "en-CA";
    }

    New-DLabAnswerFile $AnswerFilePath @Params

    Dismount-VHD -Path $ChildDisk.Path

    $Params = @{
        Name = $Name;
        VHDPath = $ChildDisk.Path;
        MemoryStartupBytes = "4GB";
        SwitchName = "LAN Switch";
    }

    New-VM @Params

    $Params = @{
        Name = $Name;
        ProcessorCount = 4;
        AutomaticStopAction = "Shutdown";
        CheckpointType = "Disabled";
    }

    Set-VM @Params
}

function New-DLabAnswerFile
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Path,
        [string] $ComputerName,
        [string] $UserFullName,
        [string] $UserOrganization,
        [string] $AdministratorPassword,
        [string] $UILanguage = "en-US",
        [string] $UserLocale = "en-US",
        [string] $TimeZone = "Eastern Standard Time"
    )

    $Path = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path)

    $TemplateFile = Join-Path $PSScriptRoot "unattend.xml"
    $answer = [XML] $(Get-Content $TemplateFile)

    $windowsPE = $answer.unattend.settings | Where-Object { $_.pass -Like 'windowsPE' }

    $component = $windowsPE.component | Where-Object { $_.name -Like 'Microsoft-Windows-International-Core-WinPE' }

    $component.UILanguage = $UILanguage
    $component.UserLocale = $UserLocale

    $component = $windowsPE.component | Where-Object { $_.name -Like 'Microsoft-Windows-Setup' }

    if (-Not [string]::IsNullOrEmpty($UserFullName)) {
        $component.UserData.FullName = $UserFullName
    }

    if (-Not [string]::IsNullOrEmpty($UserOrganization)) {
        $component.UserData.Organization = $UserOrganization
    }

    $specialize = $answer.unattend.settings | Where-Object { $_.pass -Like 'specialize' }

    $component = $specialize.component | Where-Object { $_.name -Like 'Microsoft-Windows-International-Core' }

    $component.UILanguage = $UILanguage
    $component.UserLocale = $UserLocale

    $component = $specialize.component | Where-Object { $_.name -Like 'Microsoft-Windows-Shell-Setup' }

    if (-Not [string]::IsNullOrEmpty($ComputerName)) {
        $component.ComputerName = $ComputerName
    }

    $oobeSystem = $answer.unattend.settings | Where-Object { $_.pass -Like 'oobeSystem' }
    $component = $oobeSystem.component

    if (-Not [string]::IsNullOrEmpty($AdministratorPassword)) {
        $component.UserAccounts.AdministratorPassword.Value = $AdministratorPassword
    }

    if (-Not [string]::IsNullOrEmpty($TimeZone)) {
        $component.TimeZone = $TimeZone
    }

    $answer.Save($Path)
}
