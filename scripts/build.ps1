[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [switch]$Rebuild
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$solution = Join-Path $repositoryRoot 'hypervisor.sln'

$msbuildCommand = Get-Command MSBuild.exe -ErrorAction SilentlyContinue
$msbuildPath = if ($msbuildCommand) { $msbuildCommand.Source } else { $null }

if (-not $msbuildPath) {
    $vswherePath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswherePath) {
        $installationPath = & $vswherePath -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($LASTEXITCODE -ne 0) {
            throw 'Visual Studio installation discovery failed.'
        }
        if ($installationPath) {
            $candidate = Join-Path $installationPath 'MSBuild\Current\Bin\amd64\MSBuild.exe'
            if (Test-Path -LiteralPath $candidate) {
                $msbuildPath = $candidate
            }
        }
    }
}

if (-not $msbuildPath) {
    throw 'MSBuild was not found. Install Visual Studio C++ tools and a compatible Windows Driver Kit, or run this script from a Visual Studio developer PowerShell.'
}

& (Join-Path $PSScriptRoot 'dependencies.ps1') -Configuration $Configuration

$target = if ($Rebuild) { 'Rebuild' } else { 'Build' }
& $msbuildPath $solution /nologo /m "/t:$target" "/p:Configuration=$Configuration" /p:Platform=x64 /verbosity:minimal
if ($LASTEXITCODE -ne 0) {
    throw "MSBuild failed with exit code $LASTEXITCODE."
}

$outputPath = Join-Path $repositoryRoot "artifacts\x64\$Configuration\crybullet_p2c_hypervisor.sys"
if (-not (Test-Path -LiteralPath $outputPath)) {
    throw "The build completed without the expected driver: $outputPath"
}

Write-Host "Built $outputPath"
