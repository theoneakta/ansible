"""Sentry Lens: hands out the collector - like Netdata's kickstart, one line
on the machine and it's running.

  /collector/install.sh             Linux: downloads, checks, installs a systemd service
  /collector/install.ps1            Windows: the same, as a Windows service
  /collector/download/<file>        the binaries (built into this image from
                                    collector/, see the Dockerfile) and SHA256SUMS

None of it is secret (outside the sign-in, like /api/collector/): the key on
the command line is what lets a collector in. The scripts carry this
server's address - the one asked for (?url=), else the one they were fetched
from - so the line the Collectors page shows works as it is.
"""
import os
import re

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse

DIST = os.path.join(os.path.dirname(__file__), "collector-dist")
HERE = os.path.dirname(__file__)
router = APIRouter()
FILES = re.compile(r"sentry-collector-(linux-amd64|linux-arm64|windows-amd64\.exe)|SHA256SUMS")


def base_url(request: Request, url: str = ""):
    """The address collectors reach Sentry Lens at: ?url=, else what this request came to."""
    if url:
        if not re.fullmatch(r"https?://[A-Za-z0-9.\-:\[\]]+(/[A-Za-z0-9._~/-]*)?", url):
            raise HTTPException(400, "url: http(s)://host[:port]")
        return url.rstrip("/")
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{proto}://{host}".rstrip("/")


def script(name, request, url):
    with open(os.path.join(HERE, "installers", name), encoding="utf-8") as f:
        return f.read().replace("__SENTRY_URL__", base_url(request, url))


@router.get("/collector/install.sh", response_class=PlainTextResponse)
def install_sh(request: Request, url: str = ""):
    return PlainTextResponse(script("install.sh", request, url), media_type="text/x-shellscript")


@router.get("/collector/install.ps1", response_class=PlainTextResponse)
def install_ps1(request: Request, url: str = ""):
    return PlainTextResponse(script("install.ps1", request, url), media_type="text/plain")


@router.get("/collector/download/{name}")
def download(name: str):
    if not FILES.fullmatch(name):
        raise HTTPException(404, "no such file")
    path = os.path.join(DIST, name)
    if not os.path.isfile(path):
        raise HTTPException(404, "not built into this image")
    return FileResponse(path, media_type="text/plain" if name == "SHA256SUMS" else "application/octet-stream", filename=name)


def version():
    """The collector version built into this image (the build writes it next to the binaries)."""
    try:
        with open(os.path.join(DIST, "VERSION"), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""
