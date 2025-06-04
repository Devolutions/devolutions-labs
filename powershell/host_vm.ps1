#Requires -RunAsAdministrator
#Requires -PSEdition Core

param(
    [string] $VMAlias = "HOST",
    [int] $VMNumber = 50
)

. .\common.ps1

$VMName = $LabPrefix, $VMAlias -Join "-"
$IpAddress = Get-DLabIpAddress $LabNetworkBase $VMNumber

New-DLabVM $VMName -Password $LocalPassword -OSVersion $OSVersion `
    -MemoryBytes 16GB `
    -DynamicMemory $false `
    -EnableVirtualization $true -Force

Start-DLabVM $VMName

Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $LocalUserName -Password $LocalPassword
$VMSession = New-DLabVMSession $VMName -UserName $LocalUserName -Password $LocalPassword

Set-DLabVMNetAdapter $VMName -VMSession $VMSession `
    -SwitchName $SwitchName -NetAdapterName $NetAdapterName `
    -IPAddress $IPAddress -DefaultGateway $DefaultGateway `
    -DnsServerAddress $DnsServerAddress

Write-DLabLog "Joining domain"

Add-DLabVMToDomain $VMName -VMSession $VMSession `
    -DomainName $DomainName -DomainController $DCHostName `
    -UserName $DomainUserName -Password $DomainPassword

Write-DLabLog "Waiting for VM to reboot after domain join"

Wait-DLabVM $VMName 'Reboot' -Timeout 120
Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $DomainUserName -Password $DomainPassword
$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

Write-DLabLog "Installing Hyper-V with management tools"

Invoke-Command -ScriptBlock {
    Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart
} -Session $VMSession

Write-DLabLog "Waiting for VM to reboot after enabling Hyper-V"

Wait-DLabVM $VMName 'Reboot' -Timeout 120
Wait-DLabVM $VMName 'Heartbeat' -Timeout 600 -UserName $DomainUserName -Password $DomainPassword
$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

Write-DLabLog "Adding current user to the local Hyper-V Administrators group"

Invoke-Command -ScriptBlock {
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    if (-Not (Get-LocalGroupMember -Group "Hyper-V Administrators" -Member $CurrentUser -ErrorAction SilentlyContinue)) {
        Add-LocalGroupMember -Group "Hyper-V Administrators" -Member @($CurrentUser)
    }
} -Session $VMSession
