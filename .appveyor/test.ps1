param(
    [string] $ProjectDir = $null,
    [string] $UtilsDir = $null,
    [string] $PythonDir = $null
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

function Set-AppVeyorDefaults {
    $script:ProjectDir = $env:APPVEYOR_BUILD_FOLDER
    $script:UtilsDir = Get-AppVeyorUtilsDir
    $script:PythonDir = Get-AppVeyorPythonDir
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

    Invoke-Exe { python.exe nist.py --path $UtilsDir --log nist.log }
    Get-Content nist.log -Tail 5
    Invoke-Exe { python.exe cavp.py --path $UtilsDir --log cavp.log }
    Get-Content cavp.log -Tail 5
    Invoke-Exe { python.exe nist.py --path $UtilsDir --log nist_boxes.log --boxes }
    Get-Content nist_boxes.log -Tail 5
    Invoke-Exe { python.exe cavp.py --path $UtilsDir --log cavp_boxes.log --boxes }
    Get-Content cavp_boxes.log -Tail 5
    Invoke-Exe { python.exe file.py --path $UtilsDir --log file.log }
    Get-Content file.log -Tail 5
}

function Run-ProjectTestsAppVeyor {
    if (Test-AppVeyor) {
        Set-AppVeyorDefaults
        $appveyor_cwd = pwd
    }

    try {
        if ($script:PythonDir) {
            $env:PATH = "${script:PythonDir};${env:PATH}"
        }

        Run-ProjectTests                   `
            -ProjectDir $script:ProjectDir `
            -UtilsDir $script:UtilsDir
    } finally {
        if (Test-AppVeyor) {
            cd $appveyor_cwd
            Set-PSDebug -Off
        }
    }
}

Run-ProjectTestsAppVeyor
