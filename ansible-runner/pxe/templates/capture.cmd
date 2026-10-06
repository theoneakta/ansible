@echo off
rem Runs inside WinPE on the Proxmox clone of a sysprepped template
rem (playbooks/image_capture.yml). Captures its Windows volume to
rem \\server\images\capture.wim - the playbook renames it after the image
rem (win11.wim, win2025.wim, ...) - records the outcome in
rem capture-result.txt, then powers off; the playbook waits for that.
title Capturing Windows image
wpeutil WaitForNetwork

net use Z: \\${PXE_SERVER_IP}\images ${PXE_SMB_PASSWORD} /user:pxe || goto fail_nonet
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
wpeutil shutdown
