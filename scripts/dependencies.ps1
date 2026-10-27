[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$dependencyRoot = Join-Path $repositoryRoot 'artifacts\deps'
$zydisCommit = '1ba75aeefae37094c7be8eba07ff81d4fe0f1f20'
$zycoreCommit = '1401fb85ac313f6605ec795c52bf99ea3f292a69'

if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) {
    throw 'Git for Windows is required to fetch the pinned source dependencies.'
}

$vswherePath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswherePath)) {
    throw 'Visual Studio Installer (vswhere.exe) is required to locate the C++ toolchain.'
}
$installationPath = & $vswherePath -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$installationVersion = & $vswherePath -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationVersion
if (-not $installationPath -or -not $installationVersion) {
    throw 'A Visual Studio installation with C++ build tools was not found.'
}

$generator = switch (([version]$installationVersion).Major) {
    17 { 'Visual Studio 17 2022' }
    18 { 'Visual Studio 18 2026' }
    default { throw 'The dependency build supports Visual Studio 2022 or Visual Studio 2026.' }
}

$cmakeCommand = Get-Command cmake.exe -ErrorAction SilentlyContinue
$cmakePath = if ($cmakeCommand) { $cmakeCommand.Source } else {
    Join-Path $installationPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
}
if (-not (Test-Path -LiteralPath $cmakePath)) {
    throw 'CMake is required. Install the C++ CMake tools component in Visual Studio or add CMake to PATH.'
}

function Get-PinnedSource {
    param([string]$Destination, [string]$Url, [string]$Commit)

    if (-not (Test-Path -LiteralPath $Destination)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        & git.exe init --quiet $Destination
        if ($LASTEXITCODE -ne 0) { throw "Could not initialize $Destination" }
        & git.exe -C $Destination fetch --quiet --depth 1 $Url $Commit
        if ($LASTEXITCODE -ne 0) { throw "Could not fetch pinned source from $Url" }
        & git.exe -C $Destination checkout --quiet --detach FETCH_HEAD
        if ($LASTEXITCODE -ne 0) { throw "Could not check out $Commit" }
    }

    $actualCommit = & git.exe -C $Destination rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $actualCommit -ne $Commit) {
        throw "Dependency checkout must be at $Commit`: $Destination"
    }
    $changes = & git.exe -C $Destination status --porcelain --untracked-files=normal
    if ($LASTEXITCODE -ne 0 -or $changes) {
        throw "Dependency checkout contains local changes: $Destination"
    }
}

$zydisSource = Join-Path $dependencyRoot 'zydis'
$zycoreSource = Join-Path $dependencyRoot 'zycore'
Get-PinnedSource $zydisSource 'https://github.com/zyantific/zydis.git' $zydisCommit
Get-PinnedSource $zycoreSource 'https://github.com/zyantific/zycore-c.git' $zycoreCommit

$zycoreGitlink = & git.exe -C $zydisSource ls-tree HEAD dependencies/zycore
if ($LASTEXITCODE -ne 0 -or $zycoreGitlink -notmatch "^160000 commit $zycoreCommit\s") {
    throw 'The pinned Zycore revision does not match the Zydis dependency gitlink.'
}

$buildDirectory = Join-Path $dependencyRoot "build\$Configuration"
$libraryDirectory = Join-Path $dependencyRoot "lib\$Configuration"
$configureArguments = @(
    '-S', $zydisSource, '-B', $buildDirectory,
    '-G', $generator, '-A', 'x64', '-T', 'host=x64',
    "-DCMAKE_GENERATOR_INSTANCE=$installationPath",
    '-DCMAKE_POLICY_VERSION_MINIMUM=3.10',
    '-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY',
    '-DCMAKE_C_FLAGS=/kernel /GS- /Zl',
    '-DCMAKE_C_FLAGS_DEBUG=/Zi /Ob0 /Od /D_DEBUG',
    '-DCMAKE_CXX_FLAGS=/kernel /GS- /Zl /GR- /EHs-c-',
    '-DCMAKE_CXX_FLAGS_DEBUG=/Zi /Ob0 /Od /D_DEBUG',
    "-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY_$($Configuration.ToUpperInvariant())=$libraryDirectory",
    "-DZYAN_ZYCORE_PATH=$zycoreSource",
    '-DZYAN_NO_LIBC=ON',
    '-DZYAN_WHOLE_PROGRAM_OPTIMIZATION=OFF',
    '-DZYDIS_BUILD_SHARED_LIB=OFF',
    '-DZYCORE_BUILD_SHARED_LIB=OFF',
    '-DZYDIS_BUILD_EXAMPLES=OFF',
    '-DZYDIS_BUILD_TOOLS=OFF',
    '-DZYDIS_BUILD_DOXYGEN=OFF',
    '-DZYCORE_BUILD_EXAMPLES=OFF',
    '-DZYCORE_BUILD_TESTS=OFF'
)
& $cmakePath @configureArguments
if ($LASTEXITCODE -ne 0) { throw 'CMake dependency configuration failed.' }
& $cmakePath --build $buildDirectory --config $Configuration --target Zydis --parallel
if ($LASTEXITCODE -ne 0) { throw 'CMake dependency build failed.' }

foreach ($libraryName in 'Zydis.lib', 'Zycore.lib') {
    if (-not (Test-Path -LiteralPath (Join-Path $libraryDirectory $libraryName))) {
        throw "The dependency build did not produce $libraryName."
    }
}
