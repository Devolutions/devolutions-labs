
. .\common.ps1

Write-Host "Creating $LabPrefix lab..."

Write-Host "Creating RTR VM..."
$TimeRTR = Measure-Command { .\rtr_vm.ps1 }
Write-Host "RTR VM creation time: $TimeRTR"

Write-Host "Creating DC VM..."
$TimeDC = Measure-Command { .\dc_vm.ps1 }
Write-Host "DC VM creation time: $TimeDC"

Write-Host "Creating CA VM..."
$TimeCA = Measure-Command { .\ca_vm.ps1 }
Write-Host "CA VM creation time: $TimeCA"

Write-Host "Creating WAYK VM..."
$TimeWAYK = Measure-Command { .\wayk_vm.ps1 }
Write-Host "WAYK VM creation time: $TimeWAYK"

Write-Host "Creating DVLS VM..."
$TimeDVLS = Measure-Command { .\dvls_vm.ps1 }
Write-Host "DVLS VM creation time: $TimeDVLS"

$TimeLab = $TimeRTR + $TimeDC + $TimeCA + $TimeWAYK + $TimeDVLS
Write-Host "Total $LabPrefix lab creation time: $TimeLab"
