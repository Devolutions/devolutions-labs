
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
            Stop-VM $Name -Force
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

function New-DLabVMSession
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $VMName,
        [string] $UserName = "Administrator",
        [string] $DomainName = ".\",
        [string] $Password
    )

    if ([string]::IsNullOrEmpty($Password)) {
    	$Credential = Get-Credential -UserName $UserName
    	if ($PSEdition -eq 'Desktop') {
	        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
	        $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
	    } else {
	        $Password = ConvertFrom-SecureString -SecureString $SecureString -AsPlainText
	    }
    } else {
	    $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
		$Credential = New-Object System.Management.Automation.PSCredential @($UserName, $SecurePassword)
    }

    New-PSSession -VMName $VMName -Credential $Credential
}

function Set-DLabVMNetAdapter
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $VMName,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession] $VMSession,
        [Parameter(Mandatory=$true)]
        [string] $SwitchName,
        [Parameter(Mandatory=$true)]
        [string] $NetAdapterName,
        [Parameter(Mandatory=$true)]
        [string] $IPAddress,
        [Parameter(Mandatory=$true)]
        [string] $DefaultGateway,
        [Parameter(Mandatory=$true)]
        [string] $DnsServerAddress
    )

    $VMHostAdapters = Get-VMNetworkAdapter $VMName
    $Switch = $VMHostAdapters | Where-Object { $_.SwitchName -eq $SwitchName }
    $MacAddress = $Switch.MacAddress -Split '(.{2})' -Match '.' -Join '-'

    Invoke-Command -ScriptBlock { Param($MacAddress, $NetAdapterName, $IPAddress, $DnsServerAddress)
        $NetAdapter = Get-NetAdapter | Where-Object { $_.MacAddress -Like $MacAddress }
        Rename-NetAdapter -Name $NetAdapter.Name -NewName $NetAdapterName
        $Params = @{
            IPAddress = $IPAddress;
            InterfaceAlias = $NetAdapterName;
            AddressFamily = "IPv4";
            PrefixLength = 24;
            DefaultGateway = $DefaultGateway;
        }
        New-NetIPAddress @Params
        Set-DnsClientServerAddress -InterfaceAlias $NetAdapterName -ServerAddresses $DnsServerAddress
    } -Session $VMSession -ArgumentList @($MacAddress, $NetAdapterName, $IPAddress, $DnsServerAddress)
}

function Add-DLabVMToDomain
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $VMName,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession] $VMSession,
        [Parameter(Mandatory=$true)]
        [string] $DomainName,
        [Parameter(Mandatory=$true)]
        [string] $UserName,
        [Parameter(Mandatory=$true)]
        [string] $Password
    )

    Invoke-Command -ScriptBlock { Param($DomainName, $UserName, $Password)
        $ConfirmPreference = "High"
        $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential @($UserName, $SecurePassword)
        Add-Computer -DomainName $DomainName -Credential $Credential -Restart
    } -Session $VMSession -ArgumentList @($DomainName, $UserName, $Password)
}

function Set-DLabVMAutologon
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $VMName,
        [Parameter(Mandatory=$true)]
        [string] $UserName,
        [string] $DomainName = ".\",
        [Parameter(Mandatory=$true)]
        [string] $Password,
        [switch] $Restart
    )

    if ([string]::IsNullOrEmpty($Password)) {
    	$Credential = Get-Credential -UserName $UserName
    	if ($PSEdition -eq 'Desktop') {
	        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
	        $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
	    } else {
	        $Password = ConvertFrom-SecureString -SecureString $SecureString -AsPlainText
	    }
    } else {
	    $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
		$Credential = New-Object System.Management.Automation.PSCredential @($UserName, $SecurePassword)
    }

    $VMSession = New-PSSession -VMName $VMName -Credential $Credential

    Invoke-Command -ScriptBlock { Param($UserName, $DomainName, $Password, [bool] $Restart)
        $WinlogonRegPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        New-ItemProperty -Path $WinlogonRegPath -Name AutoAdminLogon -Value 1 -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $WinlogonRegPath -Name ForceAutoLogon -Value 0 -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $WinlogonRegPath -Name DefaultUserName -Value $Username -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $WinlogonRegPath -Name DefaultPassword -Value $Password -PropertyType String -Force | Out-Null
        if ($Restart) {
            Restart-Computer -Force
        }
    } -Session $VMSession -ArgumentList @($UserName, $DomainName, $Password, $Restart)
}
