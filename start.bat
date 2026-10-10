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

rem --- WLAN-Name lesbar? (seit Windows 11 24H2 nur mit Standortberechtigung) ---------
netsh wlan show interfaces 2>nul | findstr /i /c:"Standort" /c:"location" >nul && (
  echo  Hinweis: Windows gibt den WLAN-Namen ohne Standortberechtigung nicht heraus.
  echo           Der Scanner erkennt das Netz dann am Namen des Windows-Netzwerkprofils
  echo           und sperrt den Schul-Hotspot auch so.
)

rem --- 1) Python-Umgebung ----------------------------------------------------------
if exist "%VPY%" goto :deps
echo  Lege die Python-Umgebung an: "%VENV%"
set "BASEPY="
rem  Reihenfolge: 3.13 (entwickelt und getestet), 3.14, 3.12. Nie pauschal "py -3": das kann eine
rem  Free-threaded-Version wie 3.13t sein, für die nicht alle Pakete fertig gebaut vorliegen.
for %%v in (3.13 3.14 3.12) do if not defined BASEPY py -%%v -c "import sys" >nul 2>&1 && set "BASEPY=py -%%v"
if not defined BASEPY python -c "import sys; sys.exit(0 if (3, 12) <= sys.version_info[:2] <= (3, 14) else 1)" >nul 2>&1 && set "BASEPY=python"
if not defined BASEPY (
  echo  FEHLER: Kein passendes Python gefunden - unterstützt werden 3.12 bis 3.14 von python.org.
  echo          Installierte Versionen zeigt der Befehl: py -0p
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
rem  Pfade gehen als Umgebungsvariablen an PowerShell, nicht in den Befehl eingesetzt: sonst brechen
rem  Ordnernamen mit Und-Zeichen oder Apostroph den Aufruf ab. [char]34 setzt das Skript in Anführungszeichen (Leerzeichen).
set "NS_PY=%VPY%"
set "NS_SCRIPT=%~dp0run_server.py"
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath $env:NS_PY -ArgumentList ([char]34 + $env:NS_SCRIPT + [char]34), '--no-browser' -Verb RunAs -ErrorAction Stop; exit 0 } catch { exit 1 }"
if errorlevel 1 (
  echo.
  echo  Adminrechte wurden nicht erteilt. Ohne Adminrechte: start.bat /noadmin
  goto :fail
)

:wait
echo  Warte auf den Server ...
call :ready 30
if errorlevel 1 goto :noserver

:open
echo  Öffne %URL%
start "" "%URL%"
echo  Fertig. Dieses Fenster kann geschlossen werden; beendet wird der Scanner im Server-Fenster (Strg+C).
timeout /t 5 >nul
exit /b 0

:noserver
rem  Außerhalb eines ( )-Blocks und in Anführungszeichen: eine Klammer oder ein Und-Zeichen im Profilpfad,
rem  etwa "Max (Admin)", beendet die Batchdatei sonst mit einem Syntaxfehler ohne pause.
echo  FEHLER: Der Server antwortet nicht. Bitte das Server-Fenster und die Logdatei prüfen:
echo          "%APPHOME%\data\logs\netscan.log"
goto :fail

:ready
rem  %1 = Sekunden warten; errorlevel 0 = Server antwortet
powershell -NoProfile -Command "$end=(Get-Date).AddSeconds(%~1); do { try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 -Uri 'http://127.0.0.1:%PORT%/api/job' | Out-Null; exit 0 } catch { Start-Sleep -Milliseconds 500 } } while ((Get-Date) -lt $end); exit 1" >nul 2>&1
exit /b %errorlevel%

:fail
echo.
pause
exit /b 1
