@echo off
setlocal
echo ===================================================
echo   Building Beacon Windows Single-EXE Release
echo ===================================================

where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python was not found in PATH. Please install Python 3.10+ and add it to PATH.
    pause
    exit /b 1
)

python scripts\build_windows.py
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build failed! Check the output above.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo Build completed successfully. Output located in: dist\Beacon.exe
pause
