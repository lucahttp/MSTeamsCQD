# https://evotec.xyz/powershell-single-psm1-file-versus-multi-file-modules/
param (
    #[string] $version,
    #[string] $preReleaseTag,
    [string] $apiKey,
    [string] $ModuleName
)

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$srcPath = "$scriptPath";
Write-Host "Proceeding to publish all code found in $srcPath"

Publish-Module `
    -Path $scriptPath `
    -NuGetApiKey $apiKey `
    -Verbose -Force
