@echo off
if exist "%~dp0dist\Beacon.exe" (
    start "" "%~dp0dist\Beacon.exe" %*
    exit /b 0
)
if exist "%~dp0dist\Beacon\Beacon.exe" (
    start "" "%~dp0dist\Beacon\Beacon.exe" %*
    exit /b 0
)
echo [ERROR] dist\Beacon.exe not found! Please run scripts\build_windows.bat first.
pause
exit /b 1
