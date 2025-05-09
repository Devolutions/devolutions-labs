
$resourceGroup = "ImageBuilderRG"
$location = "canadacentral"
$templateName = "WinServerGoldenImage"
$imageName = "WinServer2022-Golden"
$runOutputName ='aibWindows'
$scriptUri = "https://raw.githubusercontent.com/Devolutions/devolutions-labs/refs/heads/azure/azure/customize.ps1"

$subscriptionId = $((Get-AzContext).Subscription.Id)
$identityName = "aib-identity"
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
}

# Read template file
$inputTemplatePath = "imageTemplate.json.in"
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

New-AzResource -ResourceGroupName $resourceGroup `
               -ResourceType "Microsoft.VirtualMachineImages/imageTemplates" `
               -ResourceName $templateName `
               -Location $innerTemplate.location `
               -Properties $innerTemplate `
               -ApiVersion $template.apiVersion `
               -IsFullObject `
               -Force

Start-AzImageBuilderTemplate -ResourceGroupName $resourceGroup -Name $templateName -NoWait

function Wait-AzImageBuilderTemplateCompletion {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string] $ResourceGroupName,

        [Parameter(Mandatory)]
        [string] $TemplateName,

        [int] $PollIntervalSeconds = 30
    )

    Write-Host "⏳ Monitoring build for '$TemplateName' in resource group '$ResourceGroupName'..."
    $template = Get-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $TemplateName
    $start = $template.LastRunStatusStartTime

    if (-not $start) {
        Write-Warning "Build has not started yet. Exiting."
        return
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    do {
        $template = Get-AzImageBuilderTemplate -ResourceGroupName $ResourceGroupName -Name $TemplateName
        $status = $template.LastRunStatusRunState
        $subStatus = $template.LastRunStatusRunSubState
        $message = $template.LastRunStatusMessage

        $elapsed = [datetime]::UtcNow - $start
        $stamp = Get-Date -Format "HH:mm:ss"
        Write-Host "[$stamp] Status: $status / $subStatus (Elapsed: $($elapsed.ToString("hh\:mm\:ss"))) - $message"

        Start-Sleep -Seconds $PollIntervalSeconds
    } while ($status -eq "Running")

    $sw.Stop()
    $end = $template.LastRunStatusEndTime
    $totalTime = $end - $start

    Write-Host ""
    Write-Host "🏁 Build completed."
    Write-Host "🕒 Total build time: $($totalTime.ToString("hh\:mm\:ss"))"
    Write-Host "📦 Final status: $status"
    Write-Host "📨 Message: $message"
}
