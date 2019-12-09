param(
    [string] $BuildDir = $null,
    [string] $ProjectDir = $null,
    [string] $Platform = $null,
    [string] $Generator = $null,
    [string] $Configuration = $null,
    [string] $BoostDir = $null,
    [string] $BoostLibraryDir = $null,
    [bool] $UseAsm = $false
)

$ErrorActionPreference = "Stop";
Set-PSDebug -Strict

function Invoke-Exe {
    param(
        [ScriptBlock] $Cmd,
        [int[]] $AllowedExitCodes = @(0)
    )

    $backupErrorActionPreference = $script:ErrorActionPreference
    $script:ErrorActionPreference = 'Continue'

    try {
        & $Cmd
        if ($AllowedExitCodes -notcontains $LastExitCode) {
            throw "External command failed with exit code ${LastExitCode}: $Cmd"
        }
    } finally {
        $script:ErrorActionPreference = $backupErrorActionPreference
    }
}

function Test-AppVeyor {
    return Test-Path env:APPVEYOR
}

function Set-AppVeyorDefaults {
    $script:ProjectDir = $env:APPVEYOR_BUILD_FOLDER
    $script:BuildDir = 'C:\Projects\build'
    $script:Generator = switch ($env:APPVEYOR_BUILD_WORKER_IMAGE) {
        'Visual Studio 2013' { 'Visual Studio 12 2013' }
        'Visual Studio 2015' { 'Visual Studio 14 2015' }
        'Visual Studio 2017' { 'Visual Studio 15 2017' }
        'Visual Studio 2019' { 'Visual Studio 16 2019' }
        default { throw "Unsupported AppVeyor image: $env:APPVEYOR_BUILD_WORKER_IMAGE" }
    }
    $script:Platform = $env:PLATFORM
    $script:Configuration = $env:CONFIGURATION
    $script:BoostDir = $env:appveyor_boost_root
    $script:BoostLibraryDir = $env:appveyor_boost_librarydir
    $script:UseAsm = -not ($env:appveyor_asm -eq '0')
}

function Build-Project {
    param(
        [Parameter(Mandatory=$true)]
        [string] $ProjectDir,
        [Parameter(Mandatory=$true)]
        [string] $BuildDir,
        [Parameter(Mandatory=$true)]
        [string] $Generator,
        [Parameter(Mandatory=$true)]
        [string] $Platform,
        [Parameter(Mandatory=$true)]
        [string] $Configuration,
        [Parameter(Mandatory=$true)]
        [string] $BoostDir,
        [string] $BoostLibraryDir = $null,
        [bool] $UseAsm = $false
    )

    if (-not $BoostLibraryDir) {
        $BoostLibraryDir = "$BoostDir\stage\lib"
    }

    if ($UseAsm) {
        $cmake_asm = 'ON'
    } else {
        $cmake_asm = 'OFF'
    }

    mkdir $BuildDir
    cd $BuildDir

    Invoke-Exe { cmake.exe                     `
        -G $Generator -A $Platform             `
        -D "AES_TOOLS_ASM=$cmake_asm"          `
        -D "BOOST_ROOT=$BoostDir"              `
        -D "BOOST_LIBRARYDIR=$BoostLibraryDir" `
        $ProjectDir
    }
    
    Invoke-Exe { cmake.exe --build . --config $Configuration -- /m }
}

function Build-ProjectAppVeyor {
    if (Test-AppVeyor) {
        Set-AppVeyorDefaults
        $appveyor_cwd = pwd
    }
    
    try {
        Build-Project                                `
            -ProjectDir $script:ProjectDir           `
            -BuildDir $script:BuildDir               `
            -Generator $script:Generator             `
            -Platform $script:Platform               `
            -Configuration $script:Configuration     `
            -BoostDir $script:BoostDir               `
            -BoostLibraryDir $script:BoostLibraryDir `
            -UseAsm $UseAsm
    } finally {
        if (Test-AppVeyor) {
            cd $appveyor_cwd
            Set-PSDebug -Off
        }
    }
}

Build-ProjectAppVeyor
