param(
    [Parameter(Position = 0)]
    [string] $IPAddressMatch = "10.10.0.*"
)

function Get-HyperVNetworkAdapterInfo {
    [CmdletBinding()]
    param()

    $PnpDevices = @(Get-PnpDevice -Class Net | Where-Object { $_.FriendlyName -like '*Hyper-V Network Adapter*' })
    
    $PnpDevices | ForEach-Object {
        $ClassGuid = $_.ClassGuid
        $DeviceDriverProperty = Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_Driver' -ErrorAction SilentlyContinue
        if ($DeviceDriverProperty.Data -match '\\(?<subkey>\d{4})$') {
            $DeviceRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$ClassGuid\$($matches.subkey)"
            $NetCfgInstanceId = Get-ItemPropertyValue -Path $DeviceRegPath -Name NetCfgInstanceId -ErrorAction SilentlyContinue
            $NetCfgInstanceRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$NetCfgInstanceId"
            $NetCfg = Get-ItemProperty -Path $NetCfgInstanceRegPath | Select-Object IPAddress, SubnetMask, DefaultGateway, NameServer, EnableDHCP
            $NetConnectionRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Network\$ClassGuid\$NetCfgInstanceId\Connection"
            $NetAdapterName = Get-ItemPropertyValue -Path $NetConnectionRegPath -Name Name
            [PSCustomObject]@{
                FriendlyName     = $_.FriendlyName
                NetAdapterName   = $NetAdapterName
                Status           = $_.Status
                InstanceId       = $_.InstanceId
                NetCfgInstanceId = $NetCfgInstanceId
                IPAddress        = if ($NetCfg.IPAddress) { $NetCfg.IPAddress[0] } else { '' }
                SubnetMask       = if ($NetCfg.SubnetMask) { $NetCfg.SubnetMask[0] } else { '' }
                DefaultGateway   = if ($NetCfg.DefaultGateway) { $NetCfg.DefaultGateway[0] } else { '' }
                NameServer       = $NetCfg.NameServer
                EnableDHCP       = $NetCfg.EnableDHCP
            }
        }
    }
}

$NetAdapters = Get-HyperVNetworkAdapterInfo
$OldAdapter = $NetAdapters | Where-Object { $_.Status -eq 'Unknown' -and $_.IPAddress -Match $IPAddressMatch } | Select-Object -First 1
$NewAdapter = $NetAdapters | Where-Object { $_.Status -eq 'OK' -and [string]::IsNullOrEmpty($_.IPAddress) } | Select-Object -First 1

if ($OldAdapter -and $NewAdapter) {
    Write-Host "Removing old network adapter: '$($OldAdapter.NetAdapterName)'"
    & pnputil /remove-device "$($OldAdapter.InstanceId)"

    $NetAdapterName = $OldAdapter.NetAdapterName
    $IPAddress = $OldAdapter.IPAddress
    $SubnetMask = $OldAdapter.SubnetMask
    $DefaultGateway = $OldAdapter.DefaultGateway
    $NameServer = $OldAdapter.NameServer
    Write-Host "Renaming new network adapter to '$NetAdapterName'"
    Rename-NetAdapter -Name $NewAdapter.NetAdapterName -NewName $NetAdapterName
    $PrefixLength = ([System.Net.IPAddress]::Parse($SubnetMask).GetAddressBytes() |
        ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, '0') -split '' } | Where-Object { $_ -eq '1' }).Count
    $Params = @{
        IPAddress = $IPAddress;
        InterfaceAlias = $NetAdapterName;
        AddressFamily = "IPv4";
        PrefixLength = $PrefixLength;
        DefaultGateway = $DefaultGateway;
    }
    Write-Host "Configuring '$NetAdapterName':"
    Write-Host "`tIPAddress: $IPAddress`n`tSubnetMask: $SubnetMask`n`tDefaultGateway: $DefaultGateway"
    Set-NetIPInterface -InterfaceAlias $NetAdapterName -Dhcp Disabled
    Get-NetIPAddress -InterfaceAlias $NetAdapterName -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
    New-NetIPAddress @Params
    Write-Host "Setting DNS server: $NameServer"
    Set-DnsClientServerAddress -InterfaceAlias $NetAdapterName -ServerAddresses $NameServer
}

Get-HyperVNetworkAdapterInfo | Where-Object { $_.Status -eq 'Unknown' } | ForEach-Object {
    Write-Host "Removing ghost network adapter: '$($_.NetAdapterName)'"
    & pnputil /remove-device "$($_.InstanceId)"
}
