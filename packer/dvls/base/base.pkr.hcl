source "azure-arm" "base" {
  azure_tags = {
    deployment-type = "packer"
    os_type         = "windows"
    project         = "dvls"
  }
  build_resource_group_name          = var.build_resource_group_name
  client_id                          = var.client_id
  client_secret                      = var.client_secret
  communicator                       = "winrm"
  image_offer                        = "WindowsServer"
  image_publisher                    = "MicrosoftWindowsServer"
  image_sku                          = "2019-datacenter-gensecond"
  managed_image_name                 = var.image_name
  managed_image_resource_group_name  = var.image_resource_group_name
  managed_image_storage_account_type = "Premium_LRS"
  os_type                            = "Windows"
  subscription_id                    = var.subscription_id
  tenant_id                          = var.tenant_id
  vm_size                            = "Standard_D4s_v3"
  winrm_insecure                     = true
  winrm_timeout                      = "60m"
  winrm_use_ssl                      = true
  winrm_username                     = var.username
}

build {
  sources = ["source.azure-arm.base"]

  provisioner "powershell" {
    elevated_password = build.Password
    elevated_user     = var.username
    inline = [
      "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))",
      "choco install --no-progress --yes git",
      "Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart", "Add-WindowsFeature RSAT-Hyper-V-tools",
      "Install-PackageProvider Nuget -Force", "Install-Module -Name PowerShellGet -Force",
      "winrm set winrm/config '@{MaxTimeoutms=\"1800000\"}'",
      "winrm set winrm/config/winrs '@{MaxMemoryPerShellMB=\"800\"}'"
    ]
  }

  provisioner "windows-restart" {
    restart_timeout = "30m"
    timeout         = "1h0m0s"
  }

  provisioner "powershell" {
    elevated_password = build.Password
    elevated_user     = var.username
    inline = [
      "cd ~/Documents", "git clone https://github.com/Devolutions/devolutions-labs.git -b \"${var.lab_git_ref}\"",
      "cd ~/Documents/devolutions-labs/powershell",
      "./host_init.ps1 -IncludeOptional",
      "curl.exe -sqL \"${var.windows_iso_url}\" -o C:\\Hyper-V\\ISOs\\windows_server_2019.iso"
    ]
  }

  provisioner "windows-restart" {
    restart_timeout = "30m"
    timeout         = "1h0m0s"
  }

  provisioner "powershell" {
    elevated_password = build.Password
    elevated_user     = var.username
    inline = [
      "Add-LocalGroupMember -Group \"Hyper-V Administrators\" -Member \"devolutions\"",
      "cd ~/Documents/devolutions-labs/powershell",
      "pwsh.exe ./golden.ps1"
    ]
    timeout = "3h0m0s"
  }

  provisioner "powershell" {
    elevated_password = build.Password
    elevated_user     = var.username
    inline = [
      "cd C:\\Hyper-V\\IMGs",
      "7z a -t7z golden.7z *.vhdx",
      "choco install --no-progress --yes azcopy10",
      "$Env:AZCOPY_CRED_TYPE = "Anonymous",
      "azcopy copy .\\golden.7z \"${var.golden_7z_url}\" --overwrite=true --from-to=LocalBlob --blob-type Detect --follow-symlinks --put-md5 --recursive --log-level=INFO"
    ]
    timeout = "1h30m0s"
  }

  provisioner "windows-restart" {
    restart_timeout = "30m"
    timeout         = "1h0m0s"
  }

  provisioner "powershell" {
    elevated_password = build.Password
    elevated_user     = var.username
    inline = [
      "& $env:SystemRoot\\System32\\Sysprep\\Sysprep.exe /oobe /generalize /quiet /quit /mode:vm",
      "while($true) { $imageState = Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\State | Select ImageState; if($imageState.ImageState -ne 'IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE') { Write-Output $imageState.ImageState; Start-Sleep -s 10  } else { break } }"]
  }
}
