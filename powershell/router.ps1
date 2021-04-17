
Import-Module .\DevolutionsLabs.psm1 -Force

$WanSwitchName = "NAT Switch"
$LanSwitchName = "LAN Switch"

$VMName = "IT-YOLO-RTR"

New-DLabRouterVM $VMName -WanSwitchName $WanSwitchName -LanSwitchName $LanSwitchName
