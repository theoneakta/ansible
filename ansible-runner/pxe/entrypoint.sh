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
      "set action deploy-$id" \
      "goto winpe" \
      "" >> "$targets"
  fi
done
envsubst "$VARS" < /templates/boot.ipxe \
  | sed -e "/^#@MENU_ITEMS@$/{r $items" -e 'd}' -e "/^#@DEPLOY_TARGETS@$/{r $targets" -e 'd}' > /srv/http/boot.ipxe

# WinPE's cmd.exe wants CRLF line endings.
sed -i 's/\r*$/\r/' /srv/http/scripts/*.cmd

# Per-action WinPE images: /data/winpe/build/<action>.wim = image 1 of the
# Windows ISO's boot.wim (plain WinPE - DISM, diskpart, bcdboot, networking),
# with the action's script baked in as startnet.cmd (preceded by wpeinit,
# like the stock one). Built in the background, and rebuilt whenever
# boot.wim is (re)extracted or a script changes.
# Baking the script in keeps boot.ipxe simple and the WinPE self-contained
# (no wimboot file injection to get right). The classic bootmgfw.efi is also
# extracted and handed to wimboot explicitly, instead of the newer
# bootmgfw_EX.efi it would otherwise pick.
build_winpe() {
  src=/data/winpe/sources/boot.wim
  out=/data/winpe/build
  [ -f "$src" ] || return 0
  mkdir -p "$out"
  if [ ! -f "$out/bootmgfw.efi" ] || [ "$src" -nt "$out/bootmgfw.efi" ]; then
    wimextract "$src" 1 /Windows/Boot/EFI/bootmgfw.efi --dest-dir="$out" --no-acls >/dev/null 2>&1 \
      && touch "$out/bootmgfw.efi" && chmod 644 "$out/bootmgfw.efi"
  fi
  for script in /srv/http/scripts/*.cmd; do
    action=$(basename "$script" .cmd)
    wim="$out/$action.wim"
    sum=$(cat "$script" | md5sum | cut -d' ' -f1)
    if [ -f "$wim" ] && [ ! "$src" -nt "$wim" ] && [ "$(cat "$wim.md5" 2>/dev/null)" = "$sum" ]; then
      continue
    fi
    echo "building WinPE for $action"
    tmp="$out/.$action.wim.tmp"
    { printf 'wpeinit\r\n'; cat "$script"; } > /tmp/startnet-$action.cmd
    rm -f "$tmp"
    # wiminfo --boot marks the exported (single) image as the boot image.
    if wimexport "$src" 1 "$tmp" >/dev/null 2>&1 \
       && wimupdate "$tmp" 1 --command="add /tmp/startnet-$action.cmd /Windows/System32/startnet.cmd" >/dev/null 2>&1 \
       && wiminfo "$tmp" 1 --boot >/dev/null 2>&1; then
      chmod 644 "$tmp" && mv -f "$tmp" "$wim" && echo "$sum" > "$wim.md5"
      echo "built $wim"
    else
      echo "failed to build $wim" >&2; rm -f "$tmp"
    fi
  done
}
( while true; do build_winpe; sleep 30; done ) &
envsubst "$VARS" < /templates/dnsmasq.conf > /etc/dnsmasq.d/pxe.conf
envsubst "$VARS" < /templates/nginx.conf   > /etc/nginx/conf.d/pxe.conf
cp /templates/smb.conf /etc/samba/smb.conf

id pxe >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin pxe
printf '%s\n%s\n' "$PXE_SMB_PASSWORD" "$PXE_SMB_PASSWORD" | smbpasswd -a -s pxe >/dev/null

smbd --foreground --no-process-group --debug-stdout &
nginx -g 'daemon off;' &
exec dnsmasq --keep-in-foreground --log-facility=- --conf-file=/etc/dnsmasq.d/pxe.conf
