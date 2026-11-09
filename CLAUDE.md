# Working on this repo

This repo is **public**. Real addresses, host names-to-roles, user names,
server paths and account details are in `CLAUDE.local.md` (gitignored) and on
the runner itself - never in a tracked file.

## Where it runs

ansible-runner runs as Docker containers on the runner host (see
`CLAUDE.local.md`). Ansible is only installed **inside the `ansible-gui-1`
container** (not on the host, not on this PC). Playbooks run there only.

## Site values live on the runner, not in git

- `inventory/hosts.yml` - the real inventory, including the groups the
  playbooks target (`firewall`, `vps`, `trivy_targets`, `docker_hosts`, ...).
  Git keeps `inventory/hosts.example.yml` only.
- `inventory/group_vars/all/site.yml` - every `site_*` value (addresses, URLs,
  paths, account maps). Git keeps `inventory/site.example.yml` only.
- `inventory/image.yml` - image build settings. Git keeps `image.example.yml`.
- `gui/data/defaults.json` - what the GUI pre-fills (section `site`).

Playbooks, scripts and the GUI read those; a hardcoded address in a tracked
file is a bug. Examples use 192.0.2.x / 198.51.100.x / 203.0.113.x.
Before committing: `git diff --cached | grep -nE '([0-9]{1,3}\.){3}[0-9]{1,3}'`.

## Deploying changes

The container mounts `playbooks/`, `inventory/`, `scripts/`, `pxe/data`,
`gui/data` live from the deploy directory (no rebuild). Copy files with `scp`.
**Never copy `inventory/` from git over the server's** - the server's is the
real one.

`gui/` code (app.py, static/) is baked into the image - copy it, then
`docker compose build gui && docker compose up -d gui`. A rebuild kills any run
in progress (and wipes the container's /tmp) - check first that no
`ansible-playbook` is running in `ansible-gui-1`.

## Rules

- Credentials live in the Ansible vault (group vault + per-host
  `inventory/host_vars/<host>/vault.yml` on the server). Use them; never print
  secrets, never guess credentials.
- Inventory groups: `windows`, `linux`, `ssh` (SSH-only, e.g. the firewall and
  the NAS - root logins), `web` (web app logins).
- Ask before changes to the firewall, the NAS, or anything destructive.
