# ansible-runner

A containerized Ansible you can call on demand to configure Windows PCs (WinRM), with credentials stored in an encrypted Ansible Vault. Includes a playbook that installs/upgrades a standard software list via Chocolatey.

Nothing runs in the background: each `./run.sh` call starts a throwaway container, runs, and removes it.

## Requirements

- Docker with the Compose plugin (`docker compose`)
- `bash` and `openssl` on the host running `run.sh`
- Target Windows PCs with WinRM enabled and reachable (default: HTTPS on port 5986)

## Project layout

```
ansible-runner/
├── Dockerfile                  # ansible-core, pywinrm, pypsrp, CredSSP, collections
├── docker-compose.yml          # service definition (used via run.sh)
├── ansible.cfg
├── run.sh                      # main entry point
├── .vault_pass                 # vault password (created by --vault-init, gitignored)
├── inventory/
│   ├── hosts.yml               # list your PCs here
│   ├── group_vars/windows/
│   │   ├── vars.yml            # connection settings (plain text)
│   │   └── vault.yml           # encrypted credentials (created by --vault-init)
│   └── host_vars/<host>/       # optional per-host overrides
├── playbooks/
│   └── install_software.yml
└── gui/                        # web GUI (own Dockerfile, started via --gui)
    ├── app.py
    ├── static/index.html
    └── data/                   # run history SQLite db, gitignored
```

`playbooks/` and `inventory/` are mounted into the container, so edits take effect immediately without rebuilding.

## Quick start

```bash
./run.sh --build          # build the image
./run.sh --vault-init     # create .vault_pass + encrypted credentials file
./run.sh --vault-edit     # set vault_win_user / vault_win_password
# edit inventory/hosts.yml with your PCs
./run.sh --ping           # test connectivity and credentials
./run.sh install_software.yml
```

## Usage

| Command | What it does |
|---|---|
| `./run.sh <playbook.yml> [args]` | Run a playbook from `playbooks/`; extra args go to `ansible-playbook` |
| `./run.sh --ping` | `win_ping` against the `windows` group |
| `./run.sh --shell` | Open a bash shell in the container |
| `./run.sh --build` | Build or rebuild the image |
| `./run.sh --gui` | Start the [web GUI](#web-gui) at `http://localhost:8080` |

Examples:

```bash
./run.sh install_software.yml --limit pc01.example.local
./run.sh install_software.yml -e wazuh_manager=10.0.0.5
./run.sh install_software.yml --check          # dry run
```

### Install-time parameters

`run.sh` accepts friendly flags for packages that need extra settings and translates them into Ansible extra-vars for you. Anything not listed below (e.g. `--limit`, `--check`, raw `-e foo=bar`) is passed straight through to `ansible-playbook`.

| Flag | Effect |
|---|---|
| `--wazuh-manager <ip\|fqdn>` | Installs the Wazuh agent and points it at this manager (omit to skip Wazuh entirely) |
| `--wazuh-port <port>` | Manager port, default `1514` |
| `--wazuh-protocol <tcp\|udp>` | default `tcp` |
| `--wazuh-group <group>` | Agent group for enrollment |
| `--wazuh-agent-name <name>` | Override the agent's registered name |
| `--wazuh-registration-password <pw>` | Password for manager auto-enrollment |
| `--tailscale-authkey <key>` | Joins the tailnet with this key right after install (overrides the vault default, see below) |
| `--git-name <name>` | Sets `git config --global user.name` |
| `--git-email <email>` | Sets `git config --global user.email` |
| `--wsl-allow-reboot` | Let the run reboot the PC if needed to finish installing WSL/Ubuntu (see below) |

```bash
./run.sh install_software.yml \
  --wazuh-manager 10.0.0.5 --wazuh-group workstations \
  --git-name "Michel Mondor" --git-email michel.bernard.mondor@gmail.com
```

**Tailscale auth key default:** so you don't have to pass `--tailscale-authkey` on every run, store it in the vault as `vault_tailscale_authkey` (new vaults created with `--vault-init` already include an empty placeholder for it; for an existing vault run `./run.sh --vault-edit` and add the line). `vars.yml` maps it to `tailscale_authkey`, which every host uses by default; `--tailscale-authkey` on the command line still overrides it for a one-off run (e.g. a different tailnet).

## Web GUI

A small web UI runs the playbook without touching a terminal. It runs entirely in its own Docker container (`gui` service) alongside the `ansible` container - nothing is installed on the Windows/host machine.

```bash
./run.sh --vault-init     # must exist first - the GUI needs it to reach hosts
./run.sh --gui            # builds (first time) and starts it
```

Open http://localhost:8080 (bound to localhost only). From there you can:

- **Hosts** - pick specific hosts from `inventory/hosts.yml`, or run against all of them.
- **Credentials** - set the Windows username/password (and default Tailscale key) for the group or a specific host. Submitting encrypts the values straight into the matching vault file (`group_vars/windows/vault.yml` or `host_vars/<host>/vault.yml`) using Ansible Vault; the GUI never displays them back.
- **Install parameters** - toggle Wazuh (manager, port, protocol, group, agent name, registration password), a one-off Tailscale key override, Git identity (name/email), and whether WSL/Ubuntu is allowed to reboot the PC to finish installing - the same params as the [CLI flags](#install-time-parameters) above.
- **History** - every run is logged (SQLite, persisted under `gui/data/`) with a per-host, per-package breakdown of what installed, what was already up to date, and what failed.

Manage it with:

| Command | What it does |
|---|---|
| `./run.sh --gui` | Build (if needed) and start the GUI at `http://localhost:8080` |
| `./run.sh --gui-stop` | Stop it |
| `./run.sh --gui-logs` | Tail its logs |

**Security note:** the GUI can trigger installs on real machines using the stored vault credentials, and lets anyone who can reach it write new credentials into the vault. The port is bound to `127.0.0.1` by default (see `docker-compose.yml`) - keep it that way unless you put a trusted reverse proxy with auth in front of it.

## Credentials (Ansible Vault)

Credentials are stored in `inventory/group_vars/windows/vault.yml`, encrypted with AES-256. `vars.yml` maps them to `ansible_user` / `ansible_password`, so playbooks use them automatically. The encrypted file is safe to commit; `.vault_pass` is not.

| Command | What it does |
|---|---|
| `./run.sh --vault-init` | Create `.vault_pass` and an encrypted starter `vault.yml` |
| `./run.sh --vault-edit [file]` | Edit encrypted file (default: group credentials) |
| `./run.sh --vault-view [file]` | Show decrypted contents |
| `./run.sh --vault-create <file>` | Create a new encrypted file |
| `./run.sh --vault-rekey [file]` | Change the vault password (then update `.vault_pass`) |

**Vault password:** if `.vault_pass` exists it is mounted read-only into the container. If you delete it, you are prompted for the vault password on every run.

> **Back up `.vault_pass`** (e.g. in a password manager). If it is lost, the encrypted credentials cannot be recovered.

### Different credentials for specific PCs

```bash
./run.sh --vault-create inventory/host_vars/pc02.example.local/vault.yml
```

Inside, set:

```yaml
vault_win_user: someotheruser
vault_win_password: theirpassword
```

Host-level values override the group default for that host.

## Inventory and connection settings

Add hosts to `inventory/hosts.yml` under the `windows` group. Connection defaults are in `inventory/group_vars/windows/vars.yml`:

```yaml
ansible_connection: winrm
ansible_port: 5986
ansible_winrm_transport: ntlm        # or credssp / kerberos
ansible_winrm_server_cert_validation: ignore
```

`server_cert_validation: ignore` is convenient for self-signed certificates; switch to `validate` once your hosts have trusted certs.

For Linux targets, uncomment the `~/.ssh` mount in `docker-compose.yml` and add a matching inventory group.

## The software playbook

`playbooks/install_software.yml` installs Chocolatey if missing, then installs or upgrades each package to the latest version (`state: latest`).

- Packages are installed one at a time with `ignore_errors`, so one bad package ID does not stop the run. A summary lists any that failed.
- `pdfgear` and `battle.net` are less certain package IDs. Verify with `choco search <name>`.
- The Wazuh agent only installs if you pass `-e wazuh_manager=<ip-or-fqdn>`.
- **WSL + latest Ubuntu** installs on every run via `wsl --install -d Ubuntu` (skipped if Ubuntu is already registered). Requires Windows 10 2004+/Windows 11. Enabling the underlying Windows features can require a reboot to finish - by default the playbook just warns and leaves the PC running; pass `--wsl-allow-reboot` (or `-e wsl_allow_reboot=true`) to let it reboot and complete automatically. Note the distro's first launch still needs an interactive step to create the Linux user account (`wsl -d Ubuntu`), which isn't automated here.
- Some items are not installable via Chocolatey (Bitdefender, Punch! Software, Duplicate Cleaner Pro, DownloadHelper, Plantronics Hub / Poly Lens). The playbook prints them at the end as a manual-install reminder.

To add your own playbooks, drop them into `playbooks/` and run `./run.sh yourplaybook.yml`.

## Updating Ansible / collections

Rebuild to pull newer versions:

```bash
./run.sh --build
```

## Troubleshooting

- **`winrm` connection errors / timeouts:** confirm WinRM is enabled on the target (`winrm quickconfig`), the port is open, and the transport matches the host's configuration.
- **`Decryption failed`:** wrong or missing vault password; check `.vault_pass`.
- **Authentication failures:** verify with `./run.sh --vault-view`; local accounts may need `.\username` or a host-specific override.
- **Files in mounted folders owned by root:** `run.sh` runs the container as your host UID/GID to avoid this.
