$RepoName = "Skillable-Integration-Service"
$ZipFile = "${RepoName}.zip"
$DownloadUrl = "https://github.com/LearnOnDemandSystems/${RepoName}/archive/refs/heads/main.zip"
$OutputPath = Join-Path $Env:TEMP "${RepoName}-main"
Remove-Item $OutputPath -Recurse -ErrorAction SilentlyContinue | Out-Null
Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipFile
Expand-Archive -Path $ZipFile -DestinationPath $Env:TEMP
Remove-Item $ZipFile | Out-Null
Expand-Archive "$OutputPath\VmIntegrationService.zip" -DestinationPath "C:\VmIntegrationService"
& "$OutputPath\install.ps1"
Remove-Item $OutputPath -Recurse | Out-Null