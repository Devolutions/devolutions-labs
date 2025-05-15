#Requires -RunAsAdministrator
#Requires -PSEdition Core

. .\common.ps1

Write-Host "Creating $LabPrefix lab..."

Write-Host "Creating RTR VM..."
$TimeRTR = Measure-Command { .\rtr_vm.ps1 }
Write-Host "RTR VM creation time: $TimeRTR"

Write-Host "Creating DC VM..."
$TimeDC = Measure-Command { .\dc_vm.ps1 }
Write-Host "DC VM creation time: $TimeDC"

Write-Host "Creating DVLS VM..."
$TimeDVLS = Measure-Command { .\dvls_vm.ps1 }
Write-Host "DVLS VM creation time: $TimeDVLS"

Write-Host "Creating GW VM..."
$TimeGW = Measure-Command { .\gw_vm.ps1 }
Write-Host "GW VM creation time: $TimeGW"

Write-Host "Creating RDM VM..."
$TimeRDM = Measure-Command { .\rdm_vm.ps1 }
Write-Host "RDM VM creation time: $TimeRDM"

Write-Host "Initializing Active Directory..."
.\ad_init.ps1

$TimeLab = $TimeRTR + $TimeDC + $TimeDVLS + $TimeGW + $TimeRDM
Write-Host "Total $LabPrefix lab creation time: $TimeLab"
