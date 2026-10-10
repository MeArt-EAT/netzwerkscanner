@echo off
rem ============================================================================
rem  Netzwerkscanner - Start per Doppelklick
rem  1) Python-Umgebung prüfen/anlegen (ohne Adminrechte)
rem  2) Server MIT Adminrechten in eigenem Fenster starten (für ARP-Scan)
rem  3) Browser OHNE Adminrechte öffnen: http://127.0.0.1:8765
rem  Optionen: start.bat /noadmin   (ohne Adminrechte, nur Ping-Suche)
rem            start.bat /demo      (simulierte Geräte, sendet nichts ins Netz)
rem ============================================================================
setlocal EnableExtensions
chcp 65001 >nul
title Netzwerkscanner
cd /d "%~dp0"

set "APPHOME=%LOCALAPPDATA%\Netzwerkscanner"
set "VENV=%APPHOME%\venv"
set "VPY=%VENV%\Scripts\python.exe"
set "PORT=8765"
set "URL=http://127.0.0.1:%PORT%/"
set "PYTHONDONTWRITEBYTECODE=1"
set "MODE=%~1"

echo.
echo  Netzwerkscanner
echo  ---------------

rem --- Npcap prüfen -------------------------------------------------------------
if not exist "%SystemRoot%\System32\Npcap\wpcap.dll" (
  echo  WARNUNG: Npcap ist nicht installiert. Ohne Npcap kein ARP-Scan, nur Ping-Suche.
  echo           Download: npcap.com - Option "WinPcap API-compatible Mode" AUS lassen.
) else if exist "%SystemRoot%\System32\wpcap.dll" (
  echo  Hinweis: Npcap läuft im WinPcap-Kompatibilitätsmodus oder es gibt WinPcap-Reste.
  echo           Laut Pflichtenheft Npcap ohne diese Option neu installieren.
)

rem --- 1) Python-Umgebung ----------------------------------------------------------
if exist "%VPY%" goto :deps
echo  Lege die Python-Umgebung an: %VENV%
set "BASEPY="
py -3.13 -c "import sys" >nul 2>&1 && set "BASEPY=py -3.13"
if not defined BASEPY py -3.12 -c "import sys" >nul 2>&1 && set "BASEPY=py -3.12"
if not defined BASEPY python -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)" >nul 2>&1 && set "BASEPY=python"
if not defined BASEPY (
  echo  FEHLER: Python 3.12 oder neuer fehlt. Bitte von python.org installieren.
  goto :fail
)
if not exist "%APPHOME%" mkdir "%APPHOME%"
%BASEPY% -m venv "%VENV%" || goto :fail

:deps
set "REQHASH="
for /f "usebackq delims=" %%h in (`powershell -NoProfile -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath 'requirements.txt').Hash"`) do set "REQHASH=%%h"
set "OLDHASH="
if exist "%VENV%\req.sha256" set /p OLDHASH=<"%VENV%\req.sha256"
if /i "%REQHASH%"=="%OLDHASH%" goto :deps_ok
echo  Installiere bzw. aktualisiere die Python-Pakete (einmalig, braucht Internet) ...
"%VPY%" -m pip install --disable-pip-version-check --no-cache-dir -q -r requirements.txt || goto :fail
> "%VENV%\req.sha256" echo %REQHASH%
:deps_ok

rem --- 2) Läuft der Scanner schon? ------------------------------------------------
call :ready 1
if not errorlevel 1 (
  echo  Der Scanner läuft bereits.
  goto :open
)

if /i "%MODE%"=="/demo" (
  echo  Starte im DEMO-Modus ohne Adminrechte ...
  start "Netzwerkscanner (Demo)" "%VPY%" "%~dp0run_server.py" --no-browser --demo
  goto :wait
)
if /i "%MODE%"=="/noadmin" (
  echo  Starte ohne Adminrechte - ARP-Scan nicht möglich, nur Ping-Suche ...
  start "Netzwerkscanner" "%VPY%" "%~dp0run_server.py" --no-browser
  goto :wait
)

echo  Starte den Server mit Adminrechten (Windows fragt gleich nach) ...
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath '%VPY%' -ArgumentList @('\"%~dp0run_server.py\"','--no-browser') -Verb RunAs -ErrorAction Stop; exit 0 } catch { exit 1 }"
if errorlevel 1 (
  echo.
  echo  Adminrechte wurden nicht erteilt. Ohne Adminrechte: start.bat /noadmin
  goto :fail
)

:wait
echo  Warte auf den Server ...
call :ready 30
if errorlevel 1 (
  echo  FEHLER: Der Server antwortet nicht. Bitte das Server-Fenster und die Logdatei prüfen:
  echo          %APPHOME%\data\logs\netscan.log
  goto :fail
)

:open
echo  Öffne %URL%
start "" "%URL%"
echo  Fertig. Dieses Fenster kann geschlossen werden; beendet wird der Scanner im Server-Fenster (Strg+C).
timeout /t 5 >nul
exit /b 0

:ready
rem  %1 = Sekunden warten; errorlevel 0 = Server antwortet
powershell -NoProfile -Command "$end=(Get-Date).AddSeconds(%~1); do { try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 -Uri 'http://127.0.0.1:%PORT%/api/job' | Out-Null; exit 0 } catch { Start-Sleep -Milliseconds 500 } } while ((Get-Date) -lt $end); exit 1" >nul 2>&1
exit /b %errorlevel%

:fail
echo.
pause
exit /b 1
