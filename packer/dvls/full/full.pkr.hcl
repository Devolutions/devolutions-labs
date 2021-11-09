source "azure-arm" "full" {
  azure_tags = {
    deployment-type = "packer"
    os_type         = "windows"
    project         = "dvls"
  }
  build_resource_group_name                = var.build_resource_group_name
  client_id                                = var.client_id
  client_secret                            = var.client_secret
  communicator                             = "winrm"
  custom_managed_image_name                = var.base_image_name
  custom_managed_image_resource_group_name = var.base_image_resource_group_name
  managed_image_name                       = var.image_name
  managed_image_resource_group_name        = var.image_resource_group_name
  managed_image_storage_account_type       = "Premium_LRS"
  os_type                                  = "Windows"
  subscription_id                          = var.subscription_id
  tenant_id                                = var.tenant_id
  vm_size                                  = "Standard_D8s_v3"
  winrm_insecure                           = true
  winrm_timeout                            = "60m"
  winrm_use_ssl                            = true
  winrm_username                           = var.username
}

build {
  sources = ["source.azure-arm.full"]

  provisioner "powershell" {
    elevated_password = build.Password
    elevated_user     = var.username
    inline            = [
      "cd ~/Documents",
      "Remove-Item -Path ./devolutions-labs -Recurse -Force",
      "git clone https://github.com/Devolutions/devolutions-labs.git -b \"${var.lab_git_ref}\""
    ]
  }

  provisioner "powershell" {
    elevated_password = build.Password
    elevated_user     = var.username
    inline            = [
      "Add-LocalGroupMember -Group \"Hyper-V Administrators\" -Member \"devolutions\"",
      "cd ~/Documents/devolutions-labs/powershell",
      "pwsh.exe ./build.ps1"
    ]
    timeout           = "3h0m0s"
  }

  provisioner "windows-restart" {
    restart_timeout = "30m"
    timeout         = "1h0m0s"
  }

  provisioner "powershell" {
    elevated_password = build.Password
    elevated_user     = var.username
    inline            = [
      "& $env:SystemRoot\\System32\\Sysprep\\Sysprep.exe /oobe /generalize /quiet /quit /mode:vm",
      "while($true) { $imageState = Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\State | Select ImageState; if($imageState.ImageState -ne 'IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE') { Write-Output $imageState.ImageState; Start-Sleep -s 10  } else { break } }"
    ]
  }
}
