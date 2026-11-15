@echo off
rem Launcher for VR mode through the preservation loader.
rem
rem Referee.dll in the game folder is the preservation loader, which the client
rem binds through its own import. It attaches the patch from preserve\modules\
rem on its own shortly after GameAssembly.dll appears, so there is nothing to
rem start first and no second program to leave running.
rem
rem Requires:
rem   - Steam running (the client will not boot without it),
rem   - Install-PreserveLoader.bat already run in this folder.
setlocal
cd /d "%~dp0"

if not exist "preserve\Referee.dll" (
    echo [!] preserve\Referee.dll not found. Run Install-PreserveLoader.bat first.
    pause
    exit /b 1
)
if not exist "RecRoom.exe" (
    echo [!] RecRoom.exe not found next to this script.
    pause
    exit /b 1
)

echo Launching Rec Room (VR) via PreserveLoader...
start "" "RecRoom.exe" +forcemode:vr
