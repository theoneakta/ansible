@echo off
rem Runs inside WinPE (injected by wimboot as X:\Windows\System32\action.cmd).
rem Wipes disk 0, applies \\server\images\@IMAGE_FILE@, makes it bootable.
rem One copy per image is rendered from this template at container start
rem (deploy-<image_id>.cmd - see entrypoint.sh and PXE_IMAGES).
title Deploying @IMAGE_LABEL@
wpeutil WaitForNetwork

echo Connecting to \\${PXE_SERVER_IP}\images ...
net use Z: \\${PXE_SERVER_IP}\images ${PXE_SMB_PASSWORD} /user:pxe || goto fail
if not exist Z:\@IMAGE_FILE@ (
  echo No image found at \\${PXE_SERVER_IP}\images\@IMAGE_FILE@ - build and capture it from the GUI first.
  goto fail
)

echo Partitioning disk 0 ...
(
  echo select disk 0
  echo clean
  echo convert gpt
  echo create partition efi size=260
  echo format quick fs=fat32 label="System"
  echo assign letter=S
  echo create partition msr size=16
  echo create partition primary
  echo format quick fs=ntfs label="Windows"
  echo assign letter=W
) > X:\diskpart.txt
diskpart /s X:\diskpart.txt || goto fail

echo Applying @IMAGE_LABEL@ ...
dism /Apply-Image /ImageFile:Z:\@IMAGE_FILE@ /Index:1 /ApplyDir:W:\ || goto fail
bcdboot W:\Windows /s S: /f UEFI || goto fail

echo Done - rebooting into Windows.
wpeutil reboot
exit /b 0

:fail
echo.
echo DEPLOYMENT FAILED - see the messages above.
echo Close this window to reboot, or use it to investigate.
cmd /k
