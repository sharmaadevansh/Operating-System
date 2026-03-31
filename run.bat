@echo off
if not exist "ipc_server.exe" (
    echo [ERROR] ipc_server.exe not found!
    echo Please run build.bat first.
    pause
    exit /b 1
)

echo Starting IPC Framework Server...
ipc_server.exe
pause
