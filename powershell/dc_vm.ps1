. .\common.ps1

$VMAlias = "DC"
$VMNumber = $DCVMNumber
$VMName = $LabPrefix, $VMAlias -Join "-"
$IpAddress = Get-DLabIpAddress $LabNetworkBase $VMNumber

New-DLabVM $VMName -Password $Password -Force
Start-DLabVM $VMName

Wait-DLabVM $VMName 'PSDirect' -Timeout 600 -UserName $UserName -Password $Password
$VMSession = New-DLabVMSession $VMName -UserName $UserName -Password $Password

Set-DLabVMNetAdapter $VMName -VMSession $VMSession `
    -SwitchName $SwitchName -NetAdapterName $NetAdapterName `
    -IPAddress $IPAddress -DefaultGateway $DefaultGateway `
    -DnsServerAddress $DnsServerForwarder

Invoke-Command -ScriptBlock { Param($DomainName, $DomainNetbiosName, $SafeModeAdministratorPassword)
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    $SafeModeAdministratorPassword = ConvertTo-SecureString $SafeModeAdministratorPassword -AsPlainText -Force
    Install-ADDSForest -DomainName $DomainName -DomainNetbiosName $DomainNetbiosName -InstallDNS `
        -SafeModeAdministratorPassword $SafeModeAdministratorPassword -Force
} -Session $VMSession -ArgumentList @($DomainName, $DomainNetbiosName, $SafeModeAdministratorPassword)

Wait-DLabVM $VMName 'Reboot' -Timeout 120
$BootTime = Get-Date

Wait-DLabVM $VMName 'PSDirect' -Timeout 600 -UserName $DomainUserName -Password $DomainPassword
$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

# wait a good 5-10 minutes for the domain controller promotion to complete after reboot

Invoke-Command -ScriptBlock { Param($BootTime)
    while (-Not [bool]$(Get-EventLog -LogName "System" `
        -Source "Microsoft-Windows-GroupPolicy" -InstanceId 1502 `
        -After $BootTime -ErrorAction SilentlyContinue)) {
            Start-Sleep 10
    }
} -Session $VMSession -ArgumentList @($BootTime)

Write-Host "Create read-only network share"

Invoke-Command -ScriptBlock {
    New-Item "C:\Shared" -ItemType "Directory" | Out-Null
    New-SmbShare -Name "Shared" -Path "C:\Shared" -FullAccess 'ANONYMOUS LOGON','Everyone'
} -Session $VMSession

Write-Host "Disable Active Directory default password expiration policy"

Invoke-Command -ScriptBlock {
    Get-ADDefaultDomainPasswordPolicy -Current LoggedOnUser | Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 00.00:00:00
} -Session $VMSession
