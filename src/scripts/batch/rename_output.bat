@echo off
rem Copies a build's project-named output (DllBuilder.dll/.lib, LibBuilder.lib, etc.) to the
rem product-named files we actually want to ship (CryptoAPI.dll, CryptoAPI_static.lib, ...), then
rem optionally deletes the project-named originals.
rem
rem Usage: rename_output.bat <OutDir> <OldName> <NewName> [DELETE]
rem   DELETE (optional, literal) - remove OldName.* after copying. Note: MSBuild tracks
rem   $(TargetPath) (OldName.*) for its own up-to-date check, so deleting it here means every next
rem   build sees a missing output and relinks unconditionally, even with no source changes -- only
rem   the link step reruns (compiles stay cached), so the extra cost per build is small, not a
rem   full rebuild.
setlocal
set "OUTDIR=%~1"
set "OLDNAME=%~2"
set "NEWNAME=%~3"
set "DODELETE=%~4"

if "%OUTDIR%"=="" goto :usage
if "%OLDNAME%"=="" goto :usage
if "%NEWNAME%"=="" goto :usage

for %%E in (dll lib exp pdb) do (
    if exist "%OUTDIR%%OLDNAME%.%%E" (
        copy /Y "%OUTDIR%%OLDNAME%.%%E" "%OUTDIR%%NEWNAME%.%%E" >nul
        echo   %OLDNAME%.%%E -^> %NEWNAME%.%%E
    )
)

if /I "%DODELETE%"=="DELETE" (
    for %%E in (dll lib exp pdb) do (
        if exist "%OUTDIR%%OLDNAME%.%%E" del /Q "%OUTDIR%%OLDNAME%.%%E"
    )
    echo   removed %OLDNAME%.*
)
exit /b 0

:usage
echo Usage: rename_output.bat OutDir OldName NewName [DELETE]
exit /b 1
