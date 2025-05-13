$ProgressPreference = 'SilentlyContinue'
$RepoName = "Skillable-Integration-Service"
$ZipFile = "${RepoName}.zip"
$DownloadUrl = "https://github.com/LearnOnDemandSystems/${RepoName}/archive/refs/heads/main.zip"
$OutputPath = Join-Path $Env:TEMP "${RepoName}-main"
Remove-Item $OutputPath -Recurse -ErrorAction SilentlyContinue | Out-Null
Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipFile
Expand-Archive -Path $ZipFile -DestinationPath $Env:TEMP
Remove-Item $ZipFile | Out-Null
Remove-Item "C:\VmIntegrationService" -Recurse -ErrorAction SilentlyContinue | Out-Null
Expand-Archive "$OutputPath\VmIntegrationService.zip" -DestinationPath "C:\VmIntegrationService"
Unblock-File "$OutputPath\install.ps1"
& "$OutputPath\install.ps1"
Remove-Item $OutputPath -Recurse | Out-Null