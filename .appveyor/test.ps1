param(
    [string] $ProjectDir = $null,
    [string] $UtilsDir = $null,
    [string] $PythonDir = $null
)

$ErrorActionPreference = "Stop";

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

function Get-AppVeyorBuildDir {
    return 'C:\Projects\build'
}

function Get-AppVeyorUtilsDir {
    $configuration = $env:CONFIGURATION
    return "$(Get-AppVeyorBuildDir)\utils\$configuration"
}

function Get-AppVeyorPythonDir {
    $platform = $env:PLATFORM
    if ($platform -eq 'x64') {
        return 'C:\Python36-x64'
    } else {
        return 'C:\Python36'
    }
}

function Run-ProjectTests {
    param(
        [Parameter(Mandatory=$true)]
        [string] $ProjectDir,
        [Parameter(Mandatory=$true)]
        [string] $UtilsDir
    )

    $test_dir = "$ProjectDir\test"
    cd $test_dir

    Invoke-Exe { python nist.py --path $UtilsDir --log nist.log }
    Get-Content nist.log -Tail 5
    Invoke-Exe { python cavp.py --path $UtilsDir --log cavp.log }
    Get-Content cavp.log -Tail 5
    Invoke-Exe { python nist.py --path $UtilsDir --log nist.log --boxes }
    Get-Content nist.log -Tail 5
    Invoke-Exe { python cavp.py --path $UtilsDir --log cavp.log --boxes }
    Get-Content cavp.log -Tail 5
    Invoke-Exe { python file.py --path $UtilsDir --log file.log }
    Get-Content file.log -Tail 5
}

if (Test-AppVeyor) {
    $cwd = pwd
    $ProjectDir = $env:APPVEYOR_BUILD_FOLDER
    $UtilsDir = Get-AppVeyorUtilsDir
    $PythonDir = Get-AppVeyorPythonDir
}

if ($PythonDir) {
    $env:PATH = "${PythonDir};${env:PATH}"
}

Run-ProjectTests            `
    -ProjectDir $ProjectDir `
    -UtilsDir $UtilsDir

if (Test-AppVeyor) {
    cd $cwd
}
