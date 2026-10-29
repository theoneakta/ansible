#!/usr/bin/env bash
# Sentry Lens collector - Linux installer, served by Sentry Lens at /collector/install.sh.
#
#   curl -fsSL __SENTRY_URL__/collector/install.sh | sudo bash -s -- --key slc_...
#
# Downloads the collector for this CPU from Sentry Lens, checks it against
# SHA256SUMS, installs it as /usr/local/bin/sentry-collector and runs it as a
# systemd service under its own unprivileged user (with only CAP_NET_RAW, for
# ping where the system doesn't allow unprivileged ICMP). Its key goes in
# /etc/sentry-collector/collector.conf, readable by root and that user only.
# Running it again updates the collector in place; so does Update on the
# Collectors page, through the updater it installs (sentry-collector-update).
#
# Options:  --key slc_...   the collector's key (Sentry Lens > Assets > Collectors)
#           --url URL       Sentry Lens's address (default: where this script came from)
#           --insecure      don't check Sentry Lens's TLS certificate
#           --uninstall     stop and remove the collector
set -euo pipefail

URL="__SENTRY_URL__"
KEY=""
VERIFY=1
ACTION=install
while [ $# -gt 0 ]; do
  case "$1" in
    --key) KEY="${2:-}"; shift 2 ;;
    --url) URL="${2:-}"; shift 2 ;;
    --insecure) VERIFY=0; shift ;;
    --uninstall) ACTION=uninstall; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
URL="${URL%/}"

[ "$(id -u)" -eq 0 ] || { echo "Run it as root (sudo)." >&2; exit 1; }
command -v systemctl >/dev/null || { echo "This installer needs systemd." >&2; exit 1; }

BIN=/usr/local/bin/sentry-collector
DIR=/etc/sentry-collector
CONF="$DIR/collector.conf"
UNIT=/etc/systemd/system/sentry-collector.service
# The updater (Update on the Collectors page): the collector, unprivileged,
# drops a file in its state folder; the .path unit starts the updater as root,
# which fetches the collector from Sentry Lens itself, checks it, installs it.
UPDATER=/usr/local/libexec/sentry-collector-update
UPATH=/etc/systemd/system/sentry-collector-update.path
USVC=/etc/systemd/system/sentry-collector-update.service

if [ "$ACTION" = uninstall ]; then
  systemctl disable --now sentry-collector sentry-collector-update.path 2>/dev/null || true
  rm -f "$UNIT" "$BIN" "$UPDATER" "$UPATH" "$USVC"
  rm -rf "$DIR" /var/lib/sentry-collector
  systemctl daemon-reload
  userdel sentry-collector 2>/dev/null || true
  echo "Sentry Lens collector removed."
  exit 0
fi

case "$KEY" in slc_*) ;; *) echo "--key slc_... is needed (Sentry Lens > Assets > Collectors)." >&2; exit 2 ;; esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported CPU: $(uname -m) (amd64 and arm64 only)." >&2; exit 1 ;;
esac

if command -v curl >/dev/null; then
  fetch() { curl -fsSL $([ "$VERIFY" = 1 ] || echo -k) "$1" -o "$2"; }
elif command -v wget >/dev/null; then
  fetch() { wget -q $([ "$VERIFY" = 1 ] || echo --no-check-certificate) "$1" -O "$2"; }
else
  echo "curl or wget is needed." >&2; exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
FILE="sentry-collector-linux-$ARCH"
echo "Downloading $FILE from $URL ..."
fetch "$URL/collector/download/$FILE" "$tmp/sentry-collector"
fetch "$URL/collector/download/SHA256SUMS" "$tmp/SHA256SUMS"
want="$(awk -v f="$FILE" '$2 == f || $2 == "*"f {print $1}' "$tmp/SHA256SUMS")"
got="$(sha256sum "$tmp/sentry-collector" | awk '{print $1}')"
if [ -z "$want" ] || [ "$want" != "$got" ]; then
  echo "The download doesn't match its checksum - not installed." >&2; exit 1
fi

# The key must be one Sentry Lens accepts, or the service would run and be
# turned away every minute. The key the collector would really use: a key it
# was rotated to, kept for this same install key, else this one.
STATE=/var/lib/sentry-collector/key.json
use_key="$KEY"
if [ -f "$STATE" ] && [ "$(sed -n 's/.*"config_key_sha256":"\([0-9a-f]*\)".*/\1/p' "$STATE")" = \
     "$(printf %s "$KEY" | sha256sum | awk '{print $1}')" ]; then
  use_key="$(sed -n 's/.*"key":"\(slc_[^"]*\)".*/\1/p' "$STATE")"
fi
if command -v curl >/dev/null; then
  # (/tmp may be noexec: then the version is unknown, which only delays a key rotation.)
  version="$( (chmod +x "$tmp/sentry-collector" && "$tmp/sentry-collector" version) 2>/dev/null | awk '{print $2}' || true)"
  # The key goes in on stdin (-H @-), not on the command line other users can read.
  code="$(printf 'Authorization: Bearer %s\n' "$use_key" | curl -s -o /dev/null -w '%{http_code}' \
          $([ "$VERIFY" = 1 ] || echo -k) -H @- "$URL/api/collector/config?version=$version" || true)"
  case "$code" in
    200) echo "Sentry Lens accepts the key." ;;
    401) echo "Sentry Lens doesn't accept this key: it was replaced, or its collector deleted." >&2
         echo "Get the current install line from Assets > Collectors (Replace key) - not installed." >&2
         exit 1 ;;
    *) echo "Couldn't check the key with Sentry Lens (HTTP $code) - installing anyway." >&2 ;;
  esac
fi

install -m 0755 "$tmp/sentry-collector" "$BIN"
command -v restorecon >/dev/null && restorecon "$BIN" 2>/dev/null || true
id sentry-collector >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin sentry-collector
install -d -m 0750 -o root -g sentry-collector "$DIR"
( umask 027
  printf 'SENTRY_URL=%s\nSENTRY_KEY=%s\nSENTRY_TLS_VERIFY=%s\nSENTRY_STATE=/var/lib/sentry-collector\n' "$URL" "$KEY" "$VERIFY" > "$CONF" )
chown root:sentry-collector "$CONF"
chmod 0640 "$CONF"

cat > "$UNIT" <<EOF
# Sentry Lens collector - installed from $URL/collector/install.sh
[Unit]
Description=Sentry Lens collector
After=network-online.target
Wants=network-online.target

[Service]
User=sentry-collector
Group=sentry-collector
ExecStart=$BIN run --config $CONF
Restart=always
RestartSec=30
# Where a rotated key is kept (Sentry Lens > Collectors > Rotate key).
StateDirectory=sentry-collector
StateDirectoryMode=0700
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
EOF

install -d -m 0755 "$(dirname "$UPDATER")"
cat > "$UPDATER" <<'EOF'
#!/bin/sh
# Sentry Lens collector - updater, installed by install.sh and started by
# sentry-collector-update.path when the collector asks (Update on the
# Collectors page). Uses nothing from the request: it downloads the collector
# from the Sentry Lens in collector.conf, checks it against SHA256SUMS,
# installs it and restarts the service.
set -eu
CONF=/etc/sentry-collector/collector.conf
REQ=/var/lib/sentry-collector/update.request
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"; rm -f "$REQ"' EXIT
url="$(sed -n 's/^SENTRY_URL=//p' "$CONF")"
insecure=""; [ "$(sed -n 's/^SENTRY_TLS_VERIFY=//p' "$CONF")" = 0 ] && insecure=1
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) exit 1 ;; esac
file="sentry-collector-linux-$arch"
if command -v curl >/dev/null; then
  fetch() { curl -fsSL ${insecure:+-k} "$1" -o "$2"; }
else
  fetch() { wget -q ${insecure:+--no-check-certificate} "$1" -O "$2"; }
fi
fetch "$url/collector/download/$file" "$tmp/c"
fetch "$url/collector/download/SHA256SUMS" "$tmp/sums"
want="$(awk -v f="$file" '$2 == f || $2 == "*"f {print $1}' "$tmp/sums")"
got="$(sha256sum "$tmp/c" | awk '{print $1}')"
if [ -z "$want" ] || [ "$want" != "$got" ]; then
  echo "the download doesn't match its checksum - not updated" >&2; exit 1
fi
chmod 0755 "$tmp/c"
new="$("$tmp/c" version | awk '{print $2}')"
install -m 0755 "$tmp/c" /usr/local/bin/sentry-collector
command -v restorecon >/dev/null && restorecon /usr/local/bin/sentry-collector 2>/dev/null || true
systemctl restart sentry-collector
echo "updated to $new"
EOF
chmod 0755 "$UPDATER"
cat > "$USVC" <<EOF
# Sentry Lens collector - its updater (see $UPDATER)
[Unit]
Description=Sentry Lens collector update

[Service]
Type=oneshot
ExecStart=$UPDATER
EOF
cat > "$UPATH" <<EOF
# Sentry Lens collector - starts its updater when the collector asks
[Unit]
Description=Sentry Lens collector update request

[Path]
PathExists=/var/lib/sentry-collector/update.request

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sentry-collector >/dev/null 2>&1
systemctl enable --now sentry-collector-update.path >/dev/null 2>&1
systemctl restart sentry-collector
sleep 3
if systemctl is-active --quiet sentry-collector; then
  echo "Sentry Lens collector $("$BIN" version | awk '{print $2}') is running - its first sweep shows in Sentry Lens within a few minutes."
  journalctl -u sentry-collector -n 3 --no-pager 2>/dev/null || true
else
  echo "It didn't start - see: journalctl -u sentry-collector" >&2
  exit 1
fi
