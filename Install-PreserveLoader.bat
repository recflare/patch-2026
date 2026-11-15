@echo off
rem Installs the preservation loader in place of Referee.dll.
rem
rem What this does:
rem   - MOVES the game's Referee.dll (the protector) to preserve\Referee.dll
rem   - copies PreserveLoader.dll to Referee.dll in its place
rem   - MOVES 2026patch.dll into preserve\modules\  (the folder PreserveLoader scans)
rem
rem Afterwards the game binds the loader through its own import; the loader attaches
rem every *.dll in preserve\modules\ (2026patch.dll and anything else you drop in) once
rem GameAssembly.dll appears. No injector, no remote threads.
rem
rem Requires Steam running (the client will not boot without it).
rem Revert at any time with Restore-RefereeProtector.bat.
setlocal
cd /d "%~dp0"

if not exist "RecRoom.exe" (
    echo [!] This script must be run from the Rec Room folder, next to RecRoom.exe.
    pause
    exit /b 1
)
if not exist "PreserveLoader.dll" (
    echo [!] PreserveLoader.dll not found next to this script.
    echo     Unpack the full release here first.
    pause
    exit /b 1
)
tasklist /fi "imagename eq RecRoom.exe" | find /i "RecRoom.exe" >nul && (
    echo [!] Rec Room is running. Close the game first.
    pause
    exit /b 1
)

if not exist "preserve" mkdir "preserve" || (
    echo [!] Could not create the preserve folder.
    pause
    exit /b 1
)
if not exist "preserve\modules" mkdir "preserve\modules" || (
    echo [!] Could not create the module folder.
    pause
    exit /b 1
)
move /y "Referee.dll" "preserve\Referee.dll" >nul || (
    echo [!] Could not move Referee.dll into preserve\.
    pause
    exit /b 1
)
copy /y "PreserveLoader.dll" "Referee.dll" >nul || (
    echo [!] Could not copy PreserveLoader.dll to Referee.dll.
    echo     Your protector is safe at preserve\Referee.dll -- run Restore-RefereeProtector.bat to undo.
    pause
    exit /b 1
)
if exist "2026patch.dll" move /y "2026patch.dll" "preserve\modules\2026patch.dll" >nul
echo [OK] PreserveLoader installed as Referee.dll.
echo      Protector is at preserve\Referee.dll; modules load from preserve\modules\
echo      Launch with RecRoomPreserve.bat. Revert any time with Restore-RefereeProtector.bat.
