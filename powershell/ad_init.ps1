. .\common.ps1

$VMAlias = "DC"
$VMName = $LabPrefix, $VMAlias -Join "-"

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

$AdmfContextStoreName = "Lab"
$AdmfContextStorePath = "~\Documents\ADMF"

Invoke-Command -ScriptBlock { Param($AdmfContextStoreName, $AdmfContextStorePath)
    Install-Module -Name ADMF -Scope AllUsers -Force
    New-Item -Path $AdmfContextStorePath -ItemType 'Directory' -ErrorAction SilentlyContinue | Out-Null
    New-AdmfContextStore -Name $AdmfContextStoreName -Path $AdmfContextStorePath -Scope SystemDefault
} -Session $VMSession -ArgumentList @($AdmfContextStoreName, $AdmfContextStorePath)

$ContextPath = Join-Path $PSScriptRoot "admf"

$Context = Get-Content "$ContextPath\context.json" | ConvertFrom-Json
$Membership = Get-Content "$ContextPath\Domain\GroupMemberships\membership.json" | ConvertFrom-Json
$Groups = Get-Content "$ContextPath\Domain\Groups\groups.json" | ConvertFrom-Json
$Variables = Get-Content "$ContextPath\Domain\Names\variables.json" | ConvertFrom-Json
$OUs = Get-Content "$ContextPath\Domain\OrganizationalUnits\ous.json" | ConvertFrom-Json
$Users = Get-Content "$ContextPath\Domain\Users\users.json" | ConvertFrom-Json

Invoke-Command -ScriptBlock { Param($AdmfContextStorePath, $Context,
        $Membership, $Groups, $Variables, $OUs, $Users)
    $ContextVersion = "1.0.0"
    $AdmfContextStorePath = Resolve-Path $AdmfContextStorePath
    $ContextPath = Join-Path $AdmfContextStorePath "Basic\$ContextVersion"
    $ContextDomainPath = Join-Path $ContextPath "Domain"
    New-Item -Path $ContextPath -ItemType 'Directory' -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $ContextDomainPath -ItemType 'Directory' -ErrorAction SilentlyContinue | Out-Null
    @('GroupMemberships', 'Groups', 'Names', 'OrganizationalUnits', 'Users') | ForEach-Object {
        New-Item -Path $(Join-Path $ContextDomainPath $_) -ItemType 'Directory' -ErrorAction SilentlyContinue | Out-Null
    }
    $Context | ConvertTo-Json | Set-Content "$ContextPath\context.json"
    $Membership | ConvertTo-Json | Set-Content "$ContextPath\Domain\GroupMemberships\membership.json"
    $Groups | ConvertTo-Json | Set-Content "$ContextPath\Domain\Groups\groups.json"
    $Variables | ConvertTo-Json | Set-Content "$ContextPath\Domain\Names\variables.json"
    $OUs | ConvertTo-Json | Set-Content "$ContextPath\Domain\OrganizationalUnits\ous.json"
    $Users | ConvertTo-Json | Set-Content "$ContextPath\Domain\Users\users.json"
} -Session $VMSession -ArgumentList @($AdmfContextStorePath, $Context,
    $Membership, $Groups, $Variables, $OUs, $Users)

Invoke-Command -ScriptBlock { Param()
    $UserDnsDomain = $Env:UserDnsDomain.ToLower()
    Set-AdmfContext -Server $UserDnsDomain -Context "Basic"
    Test-AdmfDomain -Server $UserDnsDomain
    Invoke-AdmfDomain -Server $UserDnsDomain
} -Session $VMSession -ArgumentList @()

function New-RandomPassword {
    param(
        [Parameter(Position = 0)]
        [int] $Length = 16
    )

    $charsets = @("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789")
    $sb = [System.Text.StringBuilder]::new()
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()

    $bytes = New-Object Byte[] 4
    0 .. ($Length - 1) | ForEach-Object {
        $charset = $charsets[$_ % $charsets.Count]
        $rng.GetBytes($bytes)
        $num = [System.BitConverter]::ToUInt32($bytes, 0)
        $sb.Append($charset[$num % $charset.Length]) | Out-Null
    }

    return $sb.ToString()
}

$ADUsers = $Membership | Where-Object { $_.ItemType -eq 'User' } | Select-Object -ExpandProperty 'Name'

$ADAccounts = @()
foreach ($ADUser in $ADUsers) {
    $ADAccounts += [PSCustomObject]@{
        Identity = $ADUser
        Password = $(New-RandomPassword 16)
    }
}

Set-Content -Path "ADAccounts.json" -Value $($ADAccounts | ConvertTo-Json) -Force

$VMSession = New-DLabVMSession $VMName -UserName $DomainUserName -Password $DomainPassword

$ADAccounts = $(Get-Content -Path "ADAccounts.json") | ConvertFrom-Json

Invoke-Command -ScriptBlock { Param($ADAccounts)
    $ADAccounts | ForEach-Object {
        $Identity = $_.Identity
        $Password = ConvertTo-SecureString $_.Password -AsPlainText -Force
        Write-Host "Setting password for $Identity"
        try {
            Set-ADAccountPassword -Identity $Identity -NewPassword $Password -Reset
        } catch [Exception] {
            Write-Output $_.Exception.GetType().FullName, $_.Exception.Message
        }
    }
} -Session $VMSession -ArgumentList @(,$ADAccounts)
