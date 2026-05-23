@echo off
cd /d D:\GHOSTLINK\clients\windows
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cl /O2 /MT main.c crypto.c network.c storage.c tpm.c kyber1024.c /Fe:GHOSTLINK.exe user32.lib gdi32.lib advapi32.lib comdlg32.lib tbs.lib
echo Build: %ERRORLEVEL%
if exist GHOSTLINK.exe (echo SUCCESS — GHOSTLINK.exe built) else (echo FAILED)
