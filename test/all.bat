@setlocal enabledelayedexpansion

@set "script_dir=%~dp0"

@if "%~1"=="" goto exit_with_usage

@set "utils_dir=%~1"

"%script_dir%nist.py" --path "%utils_dir%" || exit /b !errorlevel!
"%script_dir%cavp.py" --path "%utils_dir%" || exit /b !errorlevel!
"%script_dir%file.py" --path "%utils_dir%" || exit /b !errorlevel!

@goto :eof

:exit_with_usage
@echo usage: %~nx0 UTILS_DIR >&2
@exit /b 1
