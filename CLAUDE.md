# Working on this repo

## Where it runs

ansible-runner runs as Docker containers on **192.168.3.8** (docker-apps2), in
`/home/mbmondor/docker/ansible`. Ansible is only installed **inside the
`ansible-gui-1` container** (not on the host, not on this PC).

## Connecting (from this PC, Git Bash)

```bash
ssh -i ~/.ssh/claude_agent_key -o BatchMode=yes claude@192.168.3.8 'docker ps'
```

- User `claude`, key `~/.ssh/claude_agent_key` (in this Windows profile only); `claude` can run `docker`.
- From PowerShell: `ssh -i $env:USERPROFILE\.ssh\claude_agent_key claude@192.168.3.8 ...`
- Never a password, never `mbmondor`.

Run Ansible inside the container (vault password is a mounted secret):

```bash
ssh -i ~/.ssh/claude_agent_key -o BatchMode=yes claude@192.168.3.8 \
  'docker exec -w /ansible ansible-gui-1 ansible-playbook playbooks/<name>.yml \
     --vault-password-file /run/secrets/vault_pass'
```

Ad-hoc against a host: `docker exec -w /ansible ansible-gui-1 ansible <host> -m shell -a '...' --vault-password-file /run/secrets/vault_pass`

## Deploying changes

The container mounts these from `/home/mbmondor/docker/ansible` (live, no rebuild):
`playbooks/`, `inventory/`, `scripts/`, `pxe/data`, `gui/data`.

```bash
scp -i ~/.ssh/claude_agent_key ansible-runner/playbooks/<file> claude@192.168.3.8:/home/mbmondor/docker/ansible/playbooks/
```

`gui/` code (app.py, static/) is baked into the image - copy it, then rebuild:

```bash
ssh ... 'cd /home/mbmondor/docker/ansible && docker compose build gui && docker compose up -d gui'
```

A rebuild kills any run in progress (and wipes the container's /tmp) - check
first that no `ansible-playbook` is running in `ansible-gui-1`.

## Rules

- Credentials live in the Ansible vault (group vault + per-host
  `inventory/host_vars/<host>/vault.yml` on the server). Use them; never print
  secrets, never guess credentials.
- The inventory on the server (`inventory/hosts.yml`) is the real one; groups
  `windows`, `linux`, `ssh` (SSH-only, e.g. OPNsense 192.168.3.1, TrueNAS
  192.168.3.188 - root logins), `web` (web app logins).
- Ask before changes to the firewall, the NAS, or anything destructive.
