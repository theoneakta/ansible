#!/bin/sh
# Renders the templates with this server's address and the share password,
# then runs smbd, nginx and dnsmasq. /data is the bind-mounted pxe/data/
# directory (shared with the gui container):
#   images/  <image_id>.wim (+ capture-result.txt)  -> \\server\images
#   winpe/   boot/bcd, boot/boot.sdi, sources/boot.wim (from the Windows ISO)
#   hosts/   <mac>.ipxe per-machine overrides (image_capture.yml writes one)
#   linux/   <image_id>/ - extracted Linux ISO (installer + repo, image_publish_linux.yml)
#   ks/      <image_id>.ks - kickstarts for those Linux images
set -eu

: "${PXE_SERVER_IP:?set PXE_SERVER_IP in .env}"
: "${PXE_SMB_PASSWORD:?set PXE_SMB_PASSWORD in .env}"
: "${PXE_SUBNET:?set PXE_SUBNET in .env, e.g. 192.168.3.0}"
export PXE_HTTP_PORT="${PXE_HTTP_PORT:-8092}"
export PXE_SERVER_IP PXE_SMB_PASSWORD PXE_SUBNET
# Deployable images: "<image_id>=<menu label>[=linux];..." - image_id matches
# the keys under `images:` in inventory/image.yml. Windows images deploy
# <image_id>.wim through WinPE; "=linux" ones network-install from linux/<id>.
PXE_IMAGES="${PXE_IMAGES:-win11=Windows 11 Pro;win2025=Windows Server 2025;rocky10=Rocky Linux 10=linux}"

mkdir -p /data/images /data/winpe /data/hosts /data/linux /data/ks /srv/http/scripts
chmod 755 /srv/http
ln -sfn /data/winpe /srv/http/winpe
ln -sfn /data/hosts /srv/http/hosts
ln -sfn /data/linux /srv/http/linux
ln -sfn /data/ks /srv/http/ks

# Only these variables get substituted - iPXE scripts use ${...} syntax too.
VARS='$PXE_SERVER_IP $PXE_HTTP_PORT $PXE_SMB_PASSWORD $PXE_SUBNET'
rm -f /srv/http/scripts/deploy-*.cmd
envsubst "$VARS" < /templates/capture.cmd > /srv/http/scripts/capture.cmd
cp /templates/winpeshl.ini /srv/http/scripts/winpeshl.ini

# Per image: a menu item and a confirm-then-boot target. Windows images also
# get a deploy-<id>.cmd for WinPE; Linux images boot their installer straight
# from the tree image_publish_linux.yml extracted, with their kickstart.
items=/tmp/menu-items; targets=/tmp/deploy-targets; : > "$items"; : > "$targets"
echo "$PXE_IMAGES" | tr ';' '\n' | while IFS='=' read -r id label kind; do
  [ -n "$id" ] || continue
  printf ':deploy-%s\necho\n' "$id" >> "$targets"
  if [ "${kind:-windows}" = linux ]; then
    printf 'item deploy-%s Deploy %s  (ERASES the first disk)\n' "$id" "$label" >> "$items"
    printf '%s\n' \
      "echo This ERASES the first disk on this machine and installs $label." \
      "prompt --key y --timeout 30000 Press 'y' within 30 seconds to continue, anything else to go back... || goto menu" \
      "kernel \${base}/linux/$id/images/pxeboot/vmlinuz initrd=initrd.img inst.repo=\${base}/linux/$id inst.ks=\${base}/ks/$id.ks ip=dhcp || goto failed" \
      "initrd \${base}/linux/$id/images/pxeboot/initrd.img || goto failed" \
      "boot || goto failed" \
      "" >> "$targets"
  else
    envsubst "$VARS" < /templates/deploy.cmd \
      | sed -e "s|@IMAGE_FILE@|$id.wim|g" -e "s|@IMAGE_LABEL@|$label|g" > "/srv/http/scripts/deploy-$id.cmd"
    printf 'item deploy-%s Deploy %s  (ERASES disk 0)\n' "$id" "$label" >> "$items"
    printf '%s\n' \
      "echo This ERASES disk 0 on this PC and installs $label." \
      "prompt --key y --timeout 30000 Press 'y' within 30 seconds to continue, anything else to go back... || goto menu" \
      "set action deploy-$id.cmd" \
      "goto winpe" \
      "" >> "$targets"
  fi
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
