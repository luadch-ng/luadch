rem @echo off

rem ============================================================================
rem  luadch Windows build script (MinGW-w64 + OpenSSL 3.x)
rem
rem  Toolchain locations are read from environment variables, with the legacy
rem  hardcoded paths as defaults so existing setups keep working untouched:
rem
rem      LUADCH_MINGW_DIR    default: C:\MinGW
rem                          must contain bin\gcc.exe
rem
rem      LUADCH_OPENSSL_DIR  default: C:\OpenSSL
rem                          must contain include\openssl\ssl.h,
rem                          libssl-3-x64.dll, libcrypto-3-x64.dll
rem
rem  Run from the repo root. Output: build_mingw\luadch\
rem  Full setup instructions: docs\BUILDING.md
rem ============================================================================

if not defined LUADCH_MINGW_DIR    set "LUADCH_MINGW_DIR=C:\MinGW"
if not defined LUADCH_OPENSSL_DIR  set "LUADCH_OPENSSL_DIR=C:\OpenSSL"

set "openssl_headers=%LUADCH_OPENSSL_DIR%\include"
set "openssl_libs=%LUADCH_OPENSSL_DIR%"
set "PATH=%LUADCH_MINGW_DIR%\bin;%PATH%"

rem -- Sanity checks: fail loudly with actionable messages -----------------------

if not exist "%LUADCH_MINGW_DIR%\bin\gcc.exe" (
    echo.
    echo ERROR: MinGW gcc.exe not found at "%LUADCH_MINGW_DIR%\bin\gcc.exe"
    echo.
    echo Install MinGW-w64 from https://winlibs.com/ and either:
    echo   - place it at C:\MinGW so that C:\MinGW\bin\gcc.exe exists, OR
    echo   - set LUADCH_MINGW_DIR to your install root before running this script.
    echo.
    echo See docs\BUILDING.md for the full setup walkthrough.
    echo.
    exit /b 1
)

if not exist "%openssl_headers%\openssl\ssl.h" (
    echo.
    echo ERROR: OpenSSL headers not found at "%openssl_headers%\openssl\ssl.h"
    echo.
    echo Place an OpenSSL 3.x x64 build at "%LUADCH_OPENSSL_DIR%" so that:
    echo   "%LUADCH_OPENSSL_DIR%\include\openssl\ssl.h"  exists, AND
    echo   "%LUADCH_OPENSSL_DIR%\libssl-3-x64.dll"        exists, AND
    echo   "%LUADCH_OPENSSL_DIR%\libcrypto-3-x64.dll"     exists.
    echo.
    echo Override the location via LUADCH_OPENSSL_DIR. See docs\BUILDING.md.
    echo.
    exit /b 1
)

if not exist "%openssl_libs%\libssl-3-x64.dll" (
    echo.
    echo ERROR: libssl-3-x64.dll not found at "%openssl_libs%\libssl-3-x64.dll"
    echo See docs\BUILDING.md for OpenSSL setup instructions.
    echo.
    exit /b 1
)

if not exist "%openssl_libs%\libcrypto-3-x64.dll" (
    echo.
    echo ERROR: libcrypto-3-x64.dll not found at "%openssl_libs%\libcrypto-3-x64.dll"
    echo See docs\BUILDING.md for OpenSSL setup instructions.
    echo.
    exit /b 1
)

set root=%cd%
set build=%root%\build_mingw
set lib=%root%\lua\src
set include=%lib%
set hub=%build%\luadch

@echo Copy OpenSSL Libs...
xcopy %openssl_libs%\libssl-3-x64.dll "%hub%\" /y /f
xcopy %openssl_libs%\libcrypto-3-x64.dll "%hub%\" /y /f

cd %root%\lua\src
@echo Building lua.dll...
gcc -O2 -Wall -DLUA_BUILD_AS_DLL -DLUA_COMPAT_ALL -c *.c
gcc -shared -o lua.dll lapi.o lcode.o lctype.o ldebug.o ldo.o ldump.o lfunc.o lgc.o llex.o lmem.o lobject.o lopcodes.o lparser.o lstate.o lstring.o ltable.o ltm.o lundump.o lvm.o lzio.o lauxlib.o lbaselib.o lcorolib.o ldblib.o liolib.o lmathlib.o loadlib.o loslib.o lstrlib.o ltablib.o lutf8lib.o linit.o
strip --strip-unneeded lua.dll
xcopy lua.dll "%hub%\*.*" /y /f
del *.o

cd %root%\adclib 
@echo Building adclib.dll...
g++ -O3  -Wall -c -I%include% *.cpp
::g++ -shared -static-libgcc -static-libstdc++ -static -lwinpthread -o adclib.dll *.o -L%lib% -llua
g++ *.o  %hub%\lua.dll  -static-libgcc -static-libstdc++ -static -lwinpthread -shared -o adclib.dll
::g++ -shared -static-libgcc -static-libstdc++ -o adclib.dll *.o -L%lib% -llua
strip --strip-unneeded adclib.dll
xcopy adclib.dll "%hub%\lib\adclib\*.*" /y /f
del adclib.dll
del *.o

cd %root%\res
windres -i res.rc -o icon.o
xcopy icon.o "%root%\hub\*.*" /y /f
del *.o

cd %root%\hub
@echo Building hub.exe...
gcc -O2 -DWINVER=0x0501 -Wall -c -I%include% *.c
gcc -o Luadch.exe *.o -L%lib% -llua
strip --strip-unneeded Luadch.exe
xcopy Luadch.exe "%hub%\*.*" /y /f
del *.exe
del *.o

@echo Installing unicode.lua shim (replaces unmaintained slnunicode C module)...
xcopy %root%\slnunicode\unicode.lua "%hub%\lib\unicode\*.*" /y /f

cd %root%\luasocket\src
gcc -DLUASOCKET_INET_PTON -DWINVER=0x0501 -DLUASO -w -fno-common -fvisibility=hidden  -c -I%include% mime.c compat.c
gcc mime.o compat.o %lib%\lua.dll -shared -Wl,-s -lws2_32 -o mime.dll
xcopy mime.dll "%hub%\lib\luasocket\mime\*.*" /y /f
del mime.o
del compat.o
ren mime.c mime.c.not
ren unix.c unix.c.not
ren usocket.c usocket.c.not
ren unixdgram.c unixdgram.c.not
ren unixstream.c unixstream.c.not
ren serial.c serial.c.not
gcc -DLUASOCKET_INET_PTON -DWINVER=0x0501 -DLUASO -w -fno-common -fvisibility=hidden  -c -I%include% *.c  
::gcc %build%\lua.dll -shared -o socket.dll *.o -lkernel32 -lws2_32
gcc *.o %lib%\lua.dll -shared -Wl,--export-all-symbols,--out-implib,libluasocket.a,-s -lws2_32 -o socket.dll
strip --strip-unneeded socket.dll
xcopy socket.dll "%hub%\lib\luasocket\socket\*.*" /y /f
xcopy *.lua "%hub%\lib\luasocket\lua\*.*" /y /f
ren mime.c.not mime.c
ren unix.c.not unix.c
ren usocket.c.not usocket.c
ren unixdgram.c.not unixdgram.c
ren unixstream.c.not unixstream.c
ren serial.c.not serial.c 
del *.dll
del *.o

@echo Building ssl.dll...
::cd %root%\luasec\src\luasocket
::ren usocket.c usocket.c.not
cd %root%\luasec\src
gcc -DLUASEC_INET_NTOP -DWINVER=0x0501 -DLUASO -w -c -I%include% -I%openssl_headers% -I%root%\luasec\src *.c 
gcc *.o -shared %lib%\lua.dll -L%root%\luasocket\src -lluasocket -L%openssl_libs% -lssl -lcrypto -lkernel32 -lgdi32 -lws2_32 -static-libgcc -o ssl.dll
strip --strip-unneeded ssl.dll
xcopy ssl.dll "%hub%\lib\luasec\ssl\*.*" /y /f
xcopy *.lua "%hub%\lib\luasec\lua\*.*" /y /f
::cd %root%\luasec\src\luasocket
::ren usocket.c.not usocket.c
del *.dll
del *.o
cd %root%\luasec\src\
del *.dll
del *.o

cd %root%\basexx
@echo Copy core...
xcopy basexx.lua "%hub%\lib\basexx\*.*" /y /f
xcopy %root%\core "%hub%\core\*.*" /y /f
xcopy %root%\scripts "%hub%\scripts\*.*" /y /f /e
xcopy %root%\examples\cfg "%hub%\cfg\*.*" /y /f
xcopy %root%\examples\certs "%hub%\certs\*.*" /y /f
xcopy %root%\examples\lang "%hub%\lang\*.*" /y /f
xcopy %root%\docs "%hub%\docs\*.*" /y /f

cd %hub%
mkdir log
cd %root%

@echo Building done.
