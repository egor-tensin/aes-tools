@setlocal enabledelayedexpansion

@if [%1] == [] goto exit_with_usage

@set utils_dir=%~1

nist.py --path "%utils_dir%" || exit /b !errorlevel!
cavp.py --path "%utils_dir%" || exit /b !errorlevel!
file.py --path "%utils_dir%" || exit /b !errorlevel!

@goto :eof

:exit_with_usage
@echo usage: %0 UTILS_DIR >&2
@exit /b 1
