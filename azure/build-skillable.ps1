
$resourceGroup = "SkillableBuilder"
$location = "centralus"
$templateName = "WindowsServer2025Base"
$imageName = "WindowsServer2025-Base"
$runOutputName ='aibSkillable'
$osState = "Specialized"

$BaseCustomizerUrl = "https://raw.githubusercontent.com/Devolutions/devolutions-labs/refs/heads/azure/azure/customizers"
$scriptUri = "$BaseCustomizerUrl/base-windows-customization.ps1"
$skillableScriptUri = "$BaseCustomizerUrl/skillable-integration-services.ps1"

$identityName = "aib-skillable"
$subscriptionId = $((Get-AzContext).Subscription.Id)

if (Test-Path .\AzureLabHelpers.psm1) {
    Import-Module .\AzureLabHelpers.psm1 -Force
}

Register-AzResourceProvider -ProviderNamespace Microsoft.VirtualMachineImages

New-AzResourceGroup -Name $resourceGroup -Location $location -Force

$identity = New-AzUserAssignedIdentity -ResourceGroupName $resourceGroup -Name $identityName -Location $location

New-AzRoleAssignment -ObjectId $identity.PrincipalId `
                     -RoleDefinitionName "Contributor" `
                     -Scope "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup"

New-AzRoleAssignment -ObjectId $identity.PrincipalId `
                     -RoleDefinitionName "Managed Identity Operator" `
                     -Scope "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup"

$imgBuilderId = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$identityName"

# Define replacement values
$variables = @{
    "<region>"        = $location
    "<imgBuilderId>"  = $imgBuilderId
    "<imageName>"     = $imageName
    "<runOutputName>" = $runOutputName
    "<subscriptionID>"= $subscriptionId
    "<rgName>"        = $resourceGroup
    "<scriptUri>"     = $scriptUri
    "<skillableScriptUri>" = $skillableScriptUri
}
# Read template file
$inputTemplatePath = "skillableTemplate.json.in"
$templatePath = "imageTemplate.json"
$template = Get-Content -Raw -Path $inputTemplatePath

# Perform replacements
foreach ($key in $variables.Keys) {
    $template = $template -replace [Regex]::Escape($key), $variables[$key]
}

# Save final output
Set-Content -Path $templatePath -Value $template -Encoding UTF8
$template = $template | ConvertFrom-Json

$innerTemplate = @{
  location = $template.location
  identity = $template.identity
  properties = $template.properties
}

# Delete template if it already exists (cannot be overwritten)

Remove-AzResource -ResourceGroupName $resourceGroup `
                  -ResourceType "Microsoft.VirtualMachineImages/imageTemplates" `
                  -ResourceName $templateName `
                  -ApiVersion $template.apiVersion `
                  -Force

# Create image template resource

New-AzResource -ResourceGroupName $resourceGroup `
               -ResourceType "Microsoft.VirtualMachineImages/imageTemplates" `
               -ResourceName $templateName `
               -Location $innerTemplate.location `
               -Properties $innerTemplate `
               -ApiVersion $template.apiVersion `
               -IsFullObject `
               -Force

Start-AzImageBuilderTemplate -ResourceGroupName $resourceGroup -Name $templateName -NoWait

Wait-AzImageBuilderTemplateCompletion -ResourceGroupName $resourceGroup -TemplateName $templateName

## Publish managed image into Shared Image Gallery

$GalleryName = "SkillableTest"
$Publisher = "DevoLabs"
$Offer = "WindowsServer"
$Sku = "2025-base"

New-AzGallery -ResourceGroupName $resourceGroup -Name $GalleryName -Location $Location

New-AzGalleryImageDefinition -GalleryName $GalleryName -ResourceGroupName $resourceGroup `
    -Location $Location -Name $ImageName -OsType Windows -Publisher $Publisher `
    -Offer $Offer -Sku $Sku -OsState $osState -HyperVGeneration V2

New-AzGalleryImageVersion -GalleryImageDefinitionName $ImageName `
    -GalleryName $GalleryName -ResourceGroupName $resourceGroup `
    -Location $Location -TargetRegion @(@{Name = $Location}) `
    -SourceImageId "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.Compute/images/$imageName" `
    -PublishingProfileEndOfLifeDate (Get-Date).AddYears(3) `
    -Name "1.0.0"
