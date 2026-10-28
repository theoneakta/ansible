# The collector, for every system Sentry Lens hands it out to (dist.py):
# Linux amd64/arm64 and Windows x64, from collector/ - with their SHA256SUMS.
FROM golang:1.24-bookworm AS collector
WORKDIR /src
COPY collector/go.mod collector/go.sum ./
RUN go mod download
COPY collector/ ./
RUN set -e; for t in linux/amd64 linux/arm64 windows/amd64; do \
      os=${t%/*}; arch=${t#*/}; ext=""; [ "$os" = windows ] && ext=.exe; \
      CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w" -o /dist/sentry-collector-$os-$arch$ext .; \
    done; \
    cd /dist && sha256sum sentry-collector-* > SHA256SUMS; \
    sed -n 's/^const Version = "\(.*\)"/\1/p' /src/main.go > /dist/VERSION

FROM python:3.12-slim

RUN pip install --no-cache-dir \
        "fastapi==0.115.*" \
        "uvicorn==0.32.*" \
        "requests==2.32.*" \
        "pyjwt[crypto]==2.9.*" \
        "itsdangerous==2.2.*" \
        "python-multipart==0.0.*" \
        "ldap3==2.9.*" \
        "python-socketio[client]==5.*"

WORKDIR /app
COPY app.py auth.py dns.py live.py categories.py checks.py kuma.py infra.py assets.py snmp.py dist.py dockerops.py creds.py vault.py /app/
COPY static /app/static
COPY installers /app/installers
COPY --from=collector /dist /app/collector-dist

# Nothing written at runtime - an unprivileged user with no host account is
# fine under CIS (no volumes to chown).
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
