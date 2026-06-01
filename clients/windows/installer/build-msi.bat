@echo off
REM build-msi.bat — thin wrapper around build-msi.ps1 for double-click / CMD use.
REM
REM Run from anywhere; resolves its own location. Passes any flags through.
REM
REM Examples:
REM   build-msi.bat
REM   build-msi.bat -Sign
REM   build-msi.bat -Gui
REM   build-msi.bat -Version 2.5.1 -Sign

setlocal
set SCRIPT_DIR=%~dp0

where pwsh >nul 2>nul
if %ERRORLEVEL%==0 (
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%build-msi.ps1" %*
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%build-msi.ps1" %*
)
exit /b %ERRORLEVEL%
