"""Site-specific values for the scripts, read from the runner's own inventory.

Addresses, URLs and account details are never kept in git: they live in
inventory/group_vars/all/site.yml on the runner (see inventory/site.example.yml
for the keys). Only plain values are read here - keys whose value is a Jinja
template ("{{ ... }}") only make sense inside Ansible.
"""
from pathlib import Path

import yaml

SITE_FILE = Path("/ansible/inventory/group_vars/all/site.yml")


def site(key: str):
    try:
        data = yaml.safe_load(SITE_FILE.read_text()) or {}
    except OSError as e:
        raise SystemExit(f"Cannot read {SITE_FILE}: {e}")
    if key not in data or data[key] in (None, ""):
        raise SystemExit(f"'{key}' is not set in {SITE_FILE} - see inventory/site.example.yml.")
    return data[key]
