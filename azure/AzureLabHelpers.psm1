
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
