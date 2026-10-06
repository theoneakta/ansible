#!/bin/sh
# Renders the templates with this server's address and the share password,
# then runs smbd, nginx and dnsmasq. /data is the bind-mounted pxe/data/
# directory (shared with the gui container):
#   images/  <image_id>.wim (+ capture-result.txt)  -> \\server\images
#   winpe/   boot/bcd, boot/boot.sdi, sources/boot.wim (from the Windows ISO)
#   hosts/   <mac>.ipxe per-machine overrides (image_capture.yml writes one)
set -eu

: "${PXE_SERVER_IP:?set PXE_SERVER_IP in .env}"
: "${PXE_SMB_PASSWORD:?set PXE_SMB_PASSWORD in .env}"
: "${PXE_SUBNET:?set PXE_SUBNET in .env, e.g. 192.168.3.0}"
export PXE_HTTP_PORT="${PXE_HTTP_PORT:-8092}"
export PXE_SERVER_IP PXE_SMB_PASSWORD PXE_SUBNET
# Deployable images: "<image_id>=<menu label>;..." - image_id matches the
# keys under `images:` in inventory/image.yml (and so <image_id>.wim).
PXE_IMAGES="${PXE_IMAGES:-win11=Windows 11 Pro;win2025=Windows Server 2025}"

mkdir -p /data/images /data/winpe /data/hosts /srv/http/scripts
chmod 755 /srv/http
ln -sfn /data/winpe /srv/http/winpe
ln -sfn /data/hosts /srv/http/hosts

# Only these variables get substituted - iPXE scripts use ${...} syntax too.
VARS='$PXE_SERVER_IP $PXE_HTTP_PORT $PXE_SMB_PASSWORD $PXE_SUBNET'
rm -f /srv/http/scripts/deploy-*.cmd
envsubst "$VARS" < /templates/capture.cmd > /srv/http/scripts/capture.cmd
cp /templates/winpeshl.ini /srv/http/scripts/winpeshl.ini

# Per image: a deploy script, a menu item, and a confirm-then-boot target.
items=/tmp/menu-items; targets=/tmp/deploy-targets; : > "$items"; : > "$targets"
echo "$PXE_IMAGES" | tr ';' '\n' | while IFS='=' read -r id label; do
  [ -n "$id" ] || continue
  envsubst "$VARS" < /templates/deploy.cmd \
    | sed -e "s|@IMAGE_FILE@|$id.wim|g" -e "s|@IMAGE_LABEL@|$label|g" > "/srv/http/scripts/deploy-$id.cmd"
  printf 'item deploy-%s Deploy %s  (ERASES disk 0)\n' "$id" "$label" >> "$items"
  cat >> "$targets" <<EOF
:deploy-$id
echo
echo This ERASES disk 0 on this PC and installs $label.
prompt --key y --timeout 30000 Press 'y' within 30 seconds to continue, anything else to go back... || goto menu
set action deploy-$id.cmd
goto winpe

EOF
done
envsubst "$VARS" < /templates/boot.ipxe \
  | sed -e "/^#@MENU_ITEMS@$/{r $items" -e 'd}' -e "/^#@DEPLOY_TARGETS@$/{r $targets" -e 'd}' > /srv/http/boot.ipxe

# WinPE's cmd.exe wants CRLF line endings.
sed -i 's/\r*$/\r/' /srv/http/scripts/*.cmd /srv/http/scripts/winpeshl.ini
envsubst "$VARS" < /templates/dnsmasq.conf > /etc/dnsmasq.d/pxe.conf
envsubst "$VARS" < /templates/nginx.conf   > /etc/nginx/conf.d/pxe.conf
cp /templates/smb.conf /etc/samba/smb.conf

id pxe >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin pxe
printf '%s\n%s\n' "$PXE_SMB_PASSWORD" "$PXE_SMB_PASSWORD" | smbpasswd -a -s pxe >/dev/null

smbd --foreground --no-process-group --debug-stdout &
nginx -g 'daemon off;' &
exec dnsmasq --keep-in-foreground --log-facility=- --conf-file=/etc/dnsmasq.d/pxe.conf
