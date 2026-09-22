#!/usr/bin/env python3
"""Print, as a JSON array, every Windows service short-name referenced by an
ansible.windows.win_service / win_service_info task anywhere under a CIS
role's tasks/ directory.

Used by cis_hardening.yml's pre_tasks to find every service that role might
try to stop, so their currently-running dependents can be stopped first -
Windows refuses to stop a service while a dependent is still running, and
the vendored role (overwritten from GitHub on every build, so not ours to
patch) doesn't order its controls with that in mind. See README.md,
"CIS Benchmark hardening" for the SSDPSRV/upnphost case that prompted this.

Usage: discover_cis_services.py <role-name>
  e.g. discover_cis_services.py Windows-11-CIS
"""
import json
import pathlib
import re
import sys

ROLES_DIR = pathlib.Path("/usr/share/ansible/roles")
# A win_service(_info) module line, then (within a few lines, any order of
# the module's other args) a bare `name: <ServiceShortName>` - never quoted,
# unlike the task's own quoted "N.N | PATCH | ..." description field.
SERVICE_RE = re.compile(
    r"ansible\.windows\.win_service(?:_info)?:\s*\n(?:[ \t]+\S.*\n){0,4}?[ \t]+name:\s*([A-Za-z0-9_.]+)\s*$",
    re.MULTILINE,
)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: discover_cis_services.py <role-name>", file=sys.stderr)
        return 1
    role_dir = ROLES_DIR / sys.argv[1] / "tasks"
    if not role_dir.is_dir():
        print(f"no such role tasks dir: {role_dir}", file=sys.stderr)
        return 1

    names = set()
    for path in role_dir.rglob("*.yml"):
        names.update(SERVICE_RE.findall(path.read_text(encoding="utf-8", errors="ignore")))

    print(json.dumps(sorted(names)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
