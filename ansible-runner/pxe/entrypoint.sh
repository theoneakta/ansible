#!/bin/sh
# Renders the templates with this server's address and the share password,
# then runs smbd, nginx and dnsmasq. /data is the bind-mounted pxe/data/
# directory (shared with the gui container):
#   images/  win11-pro.wim (+ capture-result.txt)   -> \\server\images
#   winpe/   boot/bcd, boot/boot.sdi, sources/boot.wim (from the Windows ISO)
#   hosts/   <mac>.ipxe per-machine overrides (image_capture.yml writes one)
set -eu

: "${PXE_SERVER_IP:?set PXE_SERVER_IP in .env}"
: "${PXE_SMB_PASSWORD:?set PXE_SMB_PASSWORD in .env}"
: "${PXE_SUBNET:?set PXE_SUBNET in .env, e.g. 192.168.3.0}"
export PXE_HTTP_PORT="${PXE_HTTP_PORT:-8092}"
export PXE_SERVER_IP PXE_SMB_PASSWORD PXE_SUBNET

mkdir -p /data/images /data/winpe /data/hosts /srv/http/scripts
ln -sfn /data/winpe /srv/http/winpe
ln -sfn /data/hosts /srv/http/hosts

# Only these variables get substituted - iPXE scripts use ${...} syntax too.
VARS='$PXE_SERVER_IP $PXE_HTTP_PORT $PXE_SMB_PASSWORD $PXE_SUBNET'
envsubst "$VARS" < /templates/boot.ipxe   > /srv/http/boot.ipxe
envsubst "$VARS" < /templates/deploy.cmd  > /srv/http/scripts/deploy.cmd
envsubst "$VARS" < /templates/capture.cmd > /srv/http/scripts/capture.cmd
cp /templates/winpeshl.ini /srv/http/scripts/winpeshl.ini
# WinPE's cmd.exe wants CRLF line endings.
sed -i 's/\r*$/\r/' /srv/http/scripts/deploy.cmd /srv/http/scripts/capture.cmd /srv/http/scripts/winpeshl.ini
envsubst "$VARS" < /templates/dnsmasq.conf > /etc/dnsmasq.d/pxe.conf
envsubst "$VARS" < /templates/nginx.conf   > /etc/nginx/conf.d/pxe.conf
cp /templates/smb.conf /etc/samba/smb.conf

id pxe >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin pxe
printf '%s\n%s\n' "$PXE_SMB_PASSWORD" "$PXE_SMB_PASSWORD" | smbpasswd -a -s pxe >/dev/null

smbd --foreground --no-process-group --debug-stdout &
nginx -g 'daemon off;' &
exec dnsmasq --keep-in-foreground --log-facility=- --conf-file=/etc/dnsmasq.d/pxe.conf
