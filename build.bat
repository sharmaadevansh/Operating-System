@echo off
echo ==============================================
echo Building IPC Framework v2 (C++17)
echo ==============================================

:: Find VS build tools automatically
set VCVARS=
for /f "delims=" %%i in ('dir /b /s "C:\Program Files (x86)\Microsoft Visual Studio\*vcvars64.bat" 2^>nul') do (
    set "VCVARS=%%i"
    goto found
)
for /f "delims=" %%i in ('dir /b /s "C:\Program Files\Microsoft Visual Studio\*vcvars64.bat" 2^>nul') do (
    set "VCVARS=%%i"
    goto found
)

:found
if "%VCVARS%"=="" (
    echo [ERROR] Visual Studio vcvars64.bat not found!
    pause
    exit /b 1
)

echo Found VS compiler env at: %VCVARS%
call "%VCVARS%"

echo Compiling main.cpp...
cl /std:c++17 /EHsc /O2 main.cpp /link ws2_32.lib shell32.lib advapi32.lib user32.lib /out:ipc_server.exe

if %ERRORLEVEL% equ 0 (
    echo.
    echo [SUCCESS] Build completed! Saved as ipc_server.exe.
    echo Double-click run.bat to start.
) else (
    echo.
    echo [FAILED] Compilation error.
)
pause
