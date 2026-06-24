@echo off
rem ---------------------------------------------------------------------------
rem build.cmd - direct cl.exe build, no CMake required.
rem Run from a "x64 Native Tools Command Prompt for VS" (or x86 if you want).
rem ---------------------------------------------------------------------------
setlocal enabledelayedexpansion

if "%VCINSTALLDIR%"=="" (
    echo [ERROR] Run this from a Visual Studio "x64 Native Tools" prompt.
    echo         vcvarsall.bat / vcvars64.bat must have been called first.
    exit /b 1
)

if not exist build mkdir build
pushd build

set CL_FLAGS=/nologo /W3 /O2 /EHa /std:c++17 /permissive- /utf-8 ^
    /D_UNICODE /DUNICODE /D_CRT_SECURE_NO_WARNINGS /D_WIN32_WINNT=0x0501 ^
    /MT /I..\include

set LINK_FLAGS=/nologo /SUBSYSTEM:CONSOLE shlwapi.lib imagehlp.lib user32.lib advapi32.lib

cl %CL_FLAGS% ^
   ..\src\main.cpp ^
   ..\src\Common.cpp ^
   ..\src\ResourceExtract.cpp ^
   ..\src\ResourceUpdate.cpp ^
   ..\src\CabUtil.cpp ^
   ..\src\Language.cpp ^
   ..\src\HexPatch.cpp ^
   ..\src\Pipeline.cpp ^
   /Fe:wininst_patcher.exe ^
   /link %LINK_FLAGS%

set ERR=%ERRORLEVEL%
popd
if %ERR% neq 0 (
    echo [ERROR] Build failed with code %ERR%.
    exit /b %ERR%
)
echo.
echo [OK] Built build\wininst_patcher.exe
endlocal
