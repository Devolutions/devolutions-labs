
. .\common.ps1

$VMAlias = "DC"
$VMName = $LabPrefix, $VMAlias -Join "-"

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

$AdmfContextStoreName = "Lab"
$AdmfContextStorePath = "~\Documents\ADMF"

Invoke-Command -ScriptBlock { Param($AdmfContextStoreName, $AdmfContextStorePath)
    Install-Module -Name ADMF -Scope AllUsers -Force
    New-Item -Path $AdmfContextStore -ItemType 'Directory' -ErrorAction SilentlyContinue | Out-Null
    New-AdmfContextStore -Name $AdmfContextStoreName -Path $AdmfContextStorePath -Scope SystemDefault
} -Session $VMSession -ArgumentList @($AdmfContextStoreName, $AdmfContextStorePath)

$ContextPath = Join-Path $PSScriptRoot "admf"
$Context = Get-Content "$ContextPath\context.json" | ConvertFrom-Json
$Membership = Get-Content "$ContextPath\Domain\GroupMemberships\membership.json" | ConvertFrom-Json
$Groups = Get-Content "$ContextPath\Domain\Groups\groups.json" | ConvertFrom-Json
$Variables = Get-Content "$ContextPath\Domain\Names\variables.json" | ConvertFrom-Json
$OUs = Get-Content "$ContextPath\Domain\OrganizationalUnits\ous.json" | ConvertFrom-Json

Invoke-Command -ScriptBlock { Param($AdmfContextStorePath, $Context,
    $Membership, $Groups, $Variables, $OUs)
    $ContextVersion = "1.0.0"
    $ContextPath = Join-Path $AdmfContextStorePath "Basic\$ContextVersion"
    $ContextDomainPath = Join-Path $ContextPath "Domain"
    New-Item -Path $ContextPath -ItemType 'Directory' -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $ContextDomainPath -ItemType 'Directory' -ErrorAction SilentlyContinue | Out-Null
    @('GroupMemberships','Groups','Names','Variables','OrganizationalUnits') | ForEach-Object {
        New-Item -Path $(Join-Path $ContextDomainPath $_) -ItemType 'Directory' -ErrorAction SilentlyContinue | Out-Null
    }
    $Context | ConvertTo-Json | Set-Content "$ContextPath\context.json"
    $Membership | ConvertTo-Json | Set-Content "$ContextPath\Domain\GroupMemberships\membership.json"
    $Groups | ConvertTo-Json | Set-Content "$ContextPath\Domain\Groups\groups.json"
    $Variables | ConvertTo-Json | Set-Content "$ContextPath\Domain\Names\variables.json"
    $OUs | ConvertTo-Json | Set-Content "$ContextPath\Domain\OrganizationalUnits\ous.json"
} -Session $VMSession -ArgumentList @($AdmfContextStorePath, $Context,
    $Membership, $Groups, $Variables, $OUs)

Invoke-Command -ScriptBlock { Param()
    $UserDnsDomain = $Env:UserDnsDomain.ToLower()
    Set-AdmfContext -Server $UserDnsDomain -Context "Basic"
    Test-AdmfDomain -Server $UserDnsDomain
    Invoke-AdmfDomain -Server $UserDnsDomain
} -Session $VMSession -ArgumentList @()
