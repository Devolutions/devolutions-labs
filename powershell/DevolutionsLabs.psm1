
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

function Get-DLabIsoFilePath
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Name
    )

    $IsoPath = Get-DLabPath "ISOs"
    $(Get-ChildItem -Path $IsoPath "*$Name*.iso" | Sort-Object LastWriteTime -Descending)[0]
}

function Get-DLabParentDiskFilePath
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Name
    )

    $ParentDisksPath = Get-DLabPath "ParentDisks"
    $(Get-ChildItem -Path $ParentDisksPath "*$Name*.vhdx" | Sort-Object LastWriteTime -Descending)[0]
}

function New-DLabIsoFile
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Path,
        [Parameter(Mandatory=$true,Position=1)]
        [string] $Destination,
        [Parameter(Mandatory=$true)]
        [string] $VolumeName,
        [switch] $IncludeRoot,
        [switch] $Force
    )

    # https://blog.apps.id.au/powershell-tools-create-an-iso/
    # http://blogs.msdn.com/b/opticalstorage/archive/2010/08/13/writing-optical-discs-using-imapi-2-in-powershell.aspx
    # http://tools.start-automating.com/Install-ExportISOCommand/
    # http://stackoverflow.com/a/9802807/223837

    # http://msdn.microsoft.com/en-us/library/windows/desktop/aa364840.aspx
    $fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    $fsi.FileSystemsToCreate = 4 # FsiFileSystemUDF
    $fsi.FreeMediaBlocks = 0
    $fsi.VolumeName = $VolumeName
    $fsi.Root.AddTree($Path, $IncludeRoot)
    $istream = $fsi.CreateResultImage().ImageStream

    $Options = if ($PSEdition -eq 'Core') {
        @{ CompilerOptions = "/unsafe" }
    } else {
        $cp = New-Object CodeDom.Compiler.CompilerParameters
        $cp.CompilerOptions = "/unsafe"
        $cp.WarningLevel = 4
        $cp.TreatWarningsAsErrors = $true
        @{ CompilerParameters = $cp }
    }

    Add-Type @Options -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices.ComTypes;

namespace IsoHelper {
    public static class FileUtil {
        public static void WriteIStreamToFile(object i, string fileName) {
            IStream inputStream = i as IStream;
            FileStream outputFileStream = File.OpenWrite(fileName);
            int bytesRead = 0;
            int offset = 0;
            byte[] data;
            do {
                data = Read(inputStream, 2048, out bytesRead);
                outputFileStream.Write(data, 0, bytesRead);
                offset += bytesRead;
            } while (bytesRead == 2048);
            outputFileStream.Flush();
            outputFileStream.Close();
        }

        unsafe static private byte[] Read(IStream stream, int toRead, out int read) {
            byte[] buffer = new byte[toRead];
            int bytesRead = 0;
            int* ptr = &bytesRead;
            stream.Read(buffer, toRead, (IntPtr)ptr);
            read = bytesRead;
            return buffer;
        }
    }
}
"@

    [IsoHelper.FileUtil]::WriteIStreamToFile($istream, $Destination)
}

function New-DLabFormattedDisk
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $DiskPath,
        [Parameter(Mandatory=$true)]
        [UInt64] $DiskSize,
        [ValidateSet("MBR","GPT")]
        [string] $PartitionStyle = "GPT",
        [ValidateSet("FAT32","NTFS")]
        [string] $FileSystem = "NTFS",
        [Parameter(Mandatory=$true)]
        [string] $FileSystemLabel,
        [switch] $Force
    )

    if (Test-Path $DiskPath -PathType 'Leaf') {
        if ($Force) {
            Remove-Item -Path $DiskPath
        } else {
            throw "`"$DiskPath`" already exists!"
        }
    }

    New-VHD -Path $DiskPath -Dynamic -SizeBytes $DiskSize
    $NewDisk = Mount-VHD -Path $DiskPath -PassThru

    Initialize-Disk -Number $NewDisk.DiskNumber -PartitionStyle $PartitionStyle
    $Partition = New-Partition -DiskNumber $NewDisk.DiskNumber -AssignDriveLetter -UseMaximumSize
    $Partition | Format-Volume -FileSystem $FileSystem -NewFileSystemLabel $FileSystemLabel

    Dismount-VHD -Path $DiskPath
    $NewDisk
}

function New-DLabParentDisk
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Name,
        [UInt64] $DiskSize,
        [switch] $Force
    )

    $ParentDisksPath = Get-DLabPath "ParentDisks"
    $ParentDiskFileName = $Name, 'vhdx' -Join '.'
    $ParentDiskPath = Join-Path $ParentDisksPath $ParentDiskFileName

    if (Test-Path $ParentDiskPath -PathType 'Leaf') {
        if ($Force) {
            Remove-Item -Path $ParentDiskPath
        } else {
            throw "`"$ParentDiskPath`" already exists!"
        }
    }

    $Params = @{
        Path = $ParentDiskPath;
        Dynamic = $true;
    }

    if ($PSBoundParameters.ContainsKey('DiskSize')) {
        $Params['SizeBytes'] = $DiskSize;
    }

    New-VHD @Params
}

function New-DLabChildDisk
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Name,
        [switch] $Force
    )

    $ParentDiskPath = Get-DLabParentDiskFilePath "Windows Server 2019 Standard"

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

    New-VHD -Path $ChildDiskPath -ParentPath $ParentDiskPath -Differencing
}

function Test-DLabVM
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Name
    )

    [bool]$(Get-VM $Name -ErrorAction SilentlyContinue)
}

function New-DLabRouterVM
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Name,
        [string] $Password,
        [Parameter(Mandatory=$true)]
        [string] $WanSwitchName,
        [Parameter(Mandatory=$true)]
        [string] $LanSwitchName,
        [UInt64] $DiskSize = 32GB,
        [switch] $Force
    )

    if (Test-DLabVM $Name) {
        if ($Force) {
            Stop-VM $Name -Force
            Remove-VM $Name -Force
        } else {
            throw "VM `"$Name`" already exists!"
        }
    }

    $IsoFilePath = $(Get-DLabIsoFilePath "alpine").FullName

    $ParentDisk = New-DLabParentDisk $Name -DiskSize $DiskSize -Force:$Force

    $Params = @{
        Name = $Name;
        VHDPath = $ParentDisk.Path;
        MemoryStartupBytes = 2GB;
    }

    if ($SwitchName) {
        $Params['SwitchName'] = $WanSwitchName;
    }

    New-VM @Params

    Set-VMDvdDrive -VMName $Name -ControllerNumber 1 -Path $IsoFilePath

    $Params = @{
        Name = $Name;
        ProcessorCount = 2;
        AutomaticStopAction = "Shutdown";
        CheckpointType = "Disabled";
    }

    Set-VM @Params

    Add-VMNetworkAdapter -VMName $VMName -SwitchName $LanSwitchName
}

function New-DLabParentVM
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $Name,
        [string] $Password,
        [string] $SwitchName,
        [UInt64] $DiskSize = 128GB,
        [switch] $Force
    )

    if (Test-DLabVM $Name) {
        if ($Force) {
            Stop-VM $Name -Force
            Remove-VM $Name -Force
        } else {
            throw "VM `"$Name`" already exists!"
        }
    }

    $IsoFilePath = $(Get-DLabIsoFilePath "windows_server_2019").FullName

    $ParentDisk = New-DLabParentDisk $Name -DiskSize $DiskSize -Force:$Force

    $Params = @{
        Name = $Name;
        VHDPath = $ParentDisk.Path;
        MemoryStartupBytes = 4GB;
    }

    if ($SwitchName) {
        $Params['SwitchName'] = $SwitchName;
    }

    New-VM @Params

    Set-VMDvdDrive -VMName $Name -ControllerNumber 1 -Path $IsoFilePath

    $Params = @{
        Name = $Name;
        ProcessorCount = 4;
        AutomaticStopAction = "Shutdown";
        CheckpointType = "Disabled";
    }

    Set-VM @Params
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

    if (Test-DLabVM $Name) {
        if ($Force) {
            Stop-VM $Name -Force
            Remove-VM $Name -Force
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
        MemoryStartupBytes = 4GB;
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
    $component = $oobeSystem.component | Where-Object { $_.name -Like 'Microsoft-Windows-Shell-Setup' }

    if (-Not [string]::IsNullOrEmpty($AdministratorPassword)) {
        $component.UserAccounts.AdministratorPassword.Value = $AdministratorPassword
    }

    if (-Not [string]::IsNullOrEmpty($TimeZone)) {
        $component.TimeZone = $TimeZone
    }

    $answer.Save($Path)
}

function Start-DLabVM
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $VMName,
        [string] $UserName,
        [string] $Password,
        [int] $Timeout = 60,
        [switch] $Force
    )

    if (-Not $(Test-DLabVM $VMName)) {
        throw "VM `"$VMName`" does not exist"
    }

    Start-VM $VMName
}

function Get-DLabVMUptime
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $VMName
    )

    if (-Not $(Test-DLabVM $VMName)) {
        throw "VM `"$VMName`" does not exist"
    }

    $(Get-VM $VMName).Uptime
}

function Wait-DLabVM
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $VMName,
        [Parameter(Mandatory=$true,Position=1)]
        [ValidateSet("Heartbeat","IPAddress","Shutdown","Reboot","MemoryOperations","PSDirect")]
        [string] $Condition,
        [TimeSpan] $OldUptime,
        [string] $UserName,
        [string] $Password,
        [int] $Timeout = 60,
        [switch] $Force
    )

    if (-Not $(Test-DLabVM $VMName)) {
        throw "VM `"$VMName`" does not exist"
    }

    if ($Condition -eq 'PSDirect') {
        $Credential = Get-DLabCredential -UserName $UserName -Password $Password
        while ((Invoke-Command -VMName $VMName -Credential $Credential `
            { "test" } -ErrorAction SilentlyContinue) -ne "test") { Start-Sleep 1 }
    } elseif ($Condition -eq 'Shutdown') {
        while ($(Get-VM $VMName).State -ne "Off") { Start-Sleep 1 }
    } elseif ($Condition -eq 'Reboot') {
        if (-Not $PSBoundParameters.ContainsKey('OldUptime')) {
            $OldUptime = $(Get-VM $VMName).Uptime
        }
        do {
            $NewUptime = $(Get-VM $VMName).Uptime
            Start-Sleep 1
        }
        while ($NewUptime -ge $OldUptime)
    } else {
        Wait-VM $VMName -For $Condition -Timeout $Timeout
    }
}

function Get-DLabCredential
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
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

    $Credential
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

    $Credential = Get-DLabCredential -UserName $UserName -DomainName $DomainName -Password $Password

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

    Invoke-Command -ScriptBlock { Param($MacAddress, $NetAdapterName,
        $IPAddress, $DefaultGateway, $DnsServerAddress)
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
        Start-Sleep 5
    } -Session $VMSession -ArgumentList @($MacAddress, $NetAdapterName,
        $IPAddress, $DefaultGateway, $DnsServerAddress)
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
        [string] $DomainController,
        [Parameter(Mandatory=$true)]
        [string] $UserName,
        [Parameter(Mandatory=$true)]
        [string] $Password
    )

    Invoke-Command -ScriptBlock { Param($DomainName, $DomainController, $UserName, $Password)
        $ConfirmPreference = "High"
        $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential @($UserName, $SecurePassword)
        while (-Not [bool](Resolve-DnsName -Name $DomainController -ErrorAction SilentlyContinue)) {
            Write-Host "Waiting for $DomainController..."
            Start-Sleep 1
        }
        Add-Computer -DomainName $DomainName -Credential $Credential -Restart
    } -Session $VMSession -ArgumentList @($DomainName, $DomainController, $UserName, $Password)
}

function Request-DLabCertificate
{
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $VMName,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession] $VMSession,
        [Parameter(Mandatory=$true)]
        [string] $CommonName,
        [int] $KeyLength = 2048,
        [Parameter(Mandatory=$true)]
        [string] $CACommonName,
        [Parameter(Mandatory=$true)]
        [string] $CAHostName,
        [Parameter(Mandatory=$true)]
        [string] $CertificateFile,
        [Parameter(Mandatory=$true)]
        [string] $Password
    )

    Invoke-Command -ScriptBlock { Param($CommonName, $KeyLength,
        $CAHostName, $CACommonName, $CertificateFile, $Password)
    
        $CertInf = @"
[NewRequest]
Subject = "CN=$CommonName"
Exportable = TRUE
KeyLength = $KeyLength
KeySpec = 1
KeyUsage = 0xA0
MachineKeySet = TRUE

[RequestAttributes]
CertificateTemplate = "WebServer"

[EnhancedKeyUsageExtension]
OID = 1.3.6.1.5.5.7.3.1 ; Server Authentication
OID = 1.3.6.1.5.5.7.3.2 ; Client Authentication

[Extensions]
2.5.29.17 = "{text}"; Subject Alternative Names (SANs)
_continue_ = "dns=$CommonName&"
"@

        $TempPath = Join-Path $([System.IO.Path]::GetTempPath()) "certreq-$CommonName"
        Remove-Item $TempPath -Force  -Recurse -ErrorAction SilentlyContinue | Out-Null
        New-Item -ItemType Directory -Path $TempPath -ErrorAction SilentlyContinue | Out-Null

        $TempInfFile = $(Join-Path $TempPath 'cert.inf')
        $TempCsrFile = $(Join-Path $TempPath 'cert.csr')
        $TempCerFile = $(Join-Path $TempPath 'cert.cer')
        $TempRspFile = $(Join-Path $TempPath 'cert.rsp')

        Set-Content -Path $TempInfFile -Value $CertInf

        & 'certreq.exe' '-q' '-new' $TempInfFile $TempCsrFile

        $CAConfigName = "$CAHostName\$CACommonName"
        & 'certreq.exe' '-q' '-submit' '-config' $CAConfigName $TempCsrFile $TempCerFile

        & 'certreq.exe' '-q' '-accept' $TempCerFile

        $Certificate = Get-ChildItem "cert:\LocalMachine\My" |
            Where-Object { $_.Subject -eq "CN=$CommonName" } | Select-Object -First 1
    
        $SecurePassword = ConvertTo-SecureString -String $Password -Force -AsPlainText

        $Params = @{
            Cert = $Certificate;
            ChainOption = "BuildChain";
            FilePath = $CertificateFile;
            Password = $SecurePassword;
        }

        Export-PfxCertificate @Params
        
        Get-ChildItem "cert:\LocalMachine\My" |
            Where-Object { $_.Subject -eq "CN=$CommonName" } |
            Remove-Item

        Remove-Item $TempPath -Force  -Recurse -ErrorAction SilentlyContinue | Out-Null

    } -Session $VMSession -ArgumentList @($CommonName, $KeyLength,
        $CAHostName, $CACommonName, $CertificateFile, $Password)
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
