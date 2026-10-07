# PXE server for deploying the Windows 11 image - see README.md
# ("Windows 11 image + PXE deployment").
#   dnsmasq  proxy-DHCP + TFTP: hands PXE clients the iPXE binaries below,
#            alongside the router's own DHCP (never hands out addresses)
#   nginx    HTTP: boot menu, wimboot, WinPE files, deploy/capture scripts
#   samba    \\<server>\images - the captured .wim (read by deploy, written
#            by capture)

# --- iPXE, with a tiny script embedded that chains straight to this
# server's HTTP menu. Embedding avoids the classic proxy-DHCP loop (iPXE
# re-requesting iPXE forever) without needing any DHCP option tricks.
# The `exit` after the chain matters: when the menu returns (its "Boot from
# local disk" entry, the default), iPXE must hand back to the firmware's
# next boot device - without it the script fell through into its own error
# message and an iPXE shell, so a PXE-first PC never reached its disk
# (confirmed live).
FROM debian:trixie-slim AS ipxe
ARG PXE_SERVER_IP
ARG PXE_HTTP_PORT=8092
RUN test -n "$PXE_SERVER_IP" || (echo "PXE_SERVER_IP build arg is required" && false)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git ca-certificates liblzma-dev perl \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/ipxe/ipxe.git /ipxe
RUN printf '%s\n' \
        '#!ipxe' \
        ':retry' \
        'dhcp || goto retry' \
        "chain http://${PXE_SERVER_IP}:${PXE_HTTP_PORT}/boot.ipxe || goto failed" \
        'exit' \
        ':failed' \
        "echo Could not load http://${PXE_SERVER_IP}:${PXE_HTTP_PORT}/boot.ipxe - is the pxe container running?" \
        'shell' > /embed.ipxe \
    && make -C /ipxe/src -j"$(nproc)" bin/undionly.kpxe bin-x86_64-efi/snponly.efi EMBED=/embed.ipxe

# --- runtime
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        dnsmasq nginx samba gettext-base ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/nginx/sites-enabled/default

COPY --from=ipxe /ipxe/src/bin/undionly.kpxe /ipxe/src/bin-x86_64-efi/snponly.efi /srv/tftp/
# dnsmasq appends ".0" to pxe-service file names for BIOS clients.
RUN cp /srv/tftp/undionly.kpxe /srv/tftp/undionly.0 && cp /srv/tftp/snponly.efi /srv/tftp/snponly.efi.0

# mkdir first: ADD --chmod would otherwise apply 644 to the parent directory
# it creates too, leaving /srv/http untraversable (nginx 403 on everything).
RUN mkdir -p /srv/http
ADD --chmod=644 https://github.com/ipxe/wimboot/releases/download/v2.9.0/wimboot /srv/http/wimboot

COPY templates/ /templates/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
