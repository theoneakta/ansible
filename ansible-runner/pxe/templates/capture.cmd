@echo off
rem Runs inside WinPE on the Proxmox clone of a sysprepped template
rem (playbooks/image_capture.yml). Captures its Windows volume to
rem \\server\images\capture.wim - the playbook renames it after the image
rem (win11.wim, win2025.wim, ...) - records the outcome in
rem capture-result.txt, then powers off; the playbook waits for that.
title Capturing Windows image
wpeutil WaitForNetwork

rem WaitForNetwork can return before DHCP has really finished; a single net
rem use straight after boot failed and the clone powered off within a
rem minute (confirmed live), while the same command worked moments later.
rem So retry for up to ~2 minutes.
set TRIES=0
:map
net use Z: \\${PXE_SERVER_IP}\images ${PXE_SMB_PASSWORD} /user:pxe >nul 2>&1 && goto mapped
set /a TRIES+=1
if %TRIES% geq 24 goto fail_nonet
ping -n 6 127.0.0.1 >nul
goto map
:mapped
del Z:\capture-result.txt 2>nul

set WIN=
for %%d in (C D E F G H I J K L M N O P Q R T U V W Y) do (
  if not defined WIN if exist %%d:\Windows\System32\config\SYSTEM set WIN=%%d:
)
if not defined WIN (echo No Windows volume found. & goto fail)
echo Capturing %WIN%\ ...

del Z:\capture.wim.partial 2>nul
dism /Capture-Image /ImageFile:Z:\capture.wim.partial /CaptureDir:%WIN%\ /Name:"Captured image" /Compress:max /CheckIntegrity || goto fail
del Z:\capture.wim 2>nul
ren Z:\capture.wim.partial capture.wim || goto fail
echo OK> Z:\capture-result.txt
wpeutil shutdown
exit /b 0

:fail
echo FAILED> Z:\capture-result.txt
:fail_nonet
rem Keep the error on screen for 5 minutes (Proxmox console) before powering
rem off - the playbook only notices the failure once the clone is off.
echo.
echo CAPTURE FAILED - see above. Last attempt to reach the share:
net use Z: \\${PXE_SERVER_IP}\images ${PXE_SMB_PASSWORD} /user:pxe
ipconfig
ping -n 300 127.0.0.1 >nul
wpeutil shutdown
