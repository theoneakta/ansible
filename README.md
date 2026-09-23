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
├── Dockerfile                  # ansible-core, pywinrm, pypsrp, CredSSP, collections, roles
├── docker-compose.yml          # service definition (used via run.sh)
├── ansible.cfg
├── requirements.yml            # third-party roles (CIS hardening), installed at build time
├── run.sh                      # main entry point
├── .vault_pass                 # vault password (created by --vault-init, gitignored)
├── inventory/
│   ├── hosts.yml               # list your PCs here
│   ├── group_vars/windows/
│   │   ├── vars.yml            # connection settings (plain text)
│   │   └── vault.yml           # encrypted credentials (created by --vault-init)
│   └── host_vars/<host>/       # optional per-host overrides
├── playbooks/
│   ├── install_software.yml
│   └── cis_hardening.yml       # CIS Benchmark hardening (see below) - CLI and GUI
├── scripts/
│   └── setup-winrm-ssl.ps1     # run on each target PC to enable WinRM/HTTPS
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
| `./run.sh --gui` | Start the [web GUI](#web-gui) at `http://<docker-host>:8090` |

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
| `--wsl-distro <name>` | Install this WSL distro (repeatable for multiple; omit entirely to skip WSL) |
| `--wsl-allow-reboot` | Let the run reboot the PC if needed to finish the WSL distro install(s) (see below) |
| `--wsl-user <name>` | Provision the WSL distro(s) for this Windows user instead of the WinRM account (repeatable; see below) |
| `--win11debloat` | Runs [Win11Debloat](https://github.com/Raphire/Win11Debloat) with its own recommended defaults (`-RunDefaults -Silent`), unattended (see below) |
| `--rsat` | Installs every available RSAT (Remote Server Administration Tools) capability (see below) |

```bash
./run.sh install_software.yml \
  --wazuh-manager 10.0.0.5 --wazuh-group workstations \
  --git-name "Michel Mondor" --git-email michel.bernard.mondor@gmail.com
```

**Tailscale is opt-in per run:** joining never happens just because a key is stored - pass `--tailscale-join` (or check "Join Tailscale tailnet" in the GUI) to join with the key stored in vault, or `--tailscale-authkey <key>` to join with a different key for that run (e.g. a different tailnet) without needing `--tailscale-join` too. To store the default key, add it to the vault as `vault_tailscale_authkey` (new vaults created with `--vault-init` already include an empty placeholder for it; for an existing vault run `./run.sh --vault-edit` and add the line) - `vars.yml` maps it to `tailscale_authkey`, used only once joining is explicitly requested.

## Web GUI

A small web UI runs the playbook without touching a terminal. It runs entirely in its own Docker container (`gui` service) alongside the `ansible` container - nothing is installed on the Windows/host machine.

```bash
./run.sh --vault-init     # must exist first - the GUI needs it to reach hosts
./run.sh --gui            # builds (first time) and starts it
```

Open `http://<docker-host>:8090` (reachable from your LAN, gated by GitHub sign-in - see below). From there you can:

- **Hosts** - pick specific hosts from `inventory/hosts.yml`, run against all of them, or add a new host (name/IP) straight into the inventory.
- **Credentials** - set the Windows username/password (and default Tailscale key) for the group or a specific host. Submitting encrypts the values straight into the matching vault file (`group_vars/windows/vault.yml` or `host_vars/<host>/vault.yml`) using Ansible Vault; the GUI never displays them back.
- **Software** - check "All packages" (default) or uncheck it to pick specific packages from the list in `install_software.yml` for this run.
- **Install parameters** - toggle Wazuh (manager, port, protocol, group, agent name, registration password), joining Tailscale, Git identity (name/email), WSL (opt in, pick one or more distros to install, whether the run may reboot the PC to finish, and optionally provision specific other Windows users too), Win11Debloat, and RSAT - the same params as the [CLI flags](#install-time-parameters) above.
- **CIS Benchmark hardening** - a separate section for `cis_hardening.yml` (see [below](#cis-benchmark-hardening)): pick the target OS, level, and all-or-specific-sections, with an audit-only mode. Deliberately kept apart from the install form above - it's a different kind of operation with real security-setting consequences, not just more packages.
- **History** - every run (either kind) is logged (SQLite, persisted under `gui/data/`) with a per-host, per-package breakdown of what installed, what was already up to date, and what failed.

Manage it with:

| Command | What it does |
|---|---|
| `./run.sh --gui` | Build (if needed) and start the GUI at `http://<docker-host>:8090` |
| `./run.sh --gui-stop` | Stop it |
| `./run.sh --gui-logs` | Tail its logs |

**Security note:** the GUI can trigger installs on real machines using the stored vault credentials, and lets anyone who can reach it write new credentials into the vault. Two layers protect it:

1. **Network:** bound to `0.0.0.0:8090` (see `docker-compose.yml`) - reachable from your LAN, which is only safe because of the sign-in gate below. Change it to `127.0.0.1:8080:8000` if you'd rather it only be reachable from the Docker host itself.
2. **GitHub sign-in:** every page and `/api/*` route requires a signed-in, explicitly-allowed GitHub account. With nothing configured, the GUI refuses to serve anything (a 503 page, not a silent fallback to no-auth).

### GitHub sign-in

The GUI is gated behind GitHub OAuth. Nobody can view or use it - including `/api/*` - without signing in as an account on an explicit allow-list.

**One-time setup, on GitHub:**

1. GitHub -> Settings -> Developer settings -> [OAuth Apps](https://github.com/settings/developers) -> **New OAuth App**.
2. **Homepage URL**: wherever the GUI will be reachable - either the plain LAN address (e.g. `http://192.168.3.8:8090`) or a real domain if it's behind a reverse proxy (e.g. `https://ansible.example.com`, via Tailscale Serve/Funnel or similar).
3. **Authorization callback URL**: the same host + `/auth/callback` (e.g. `https://ansible.example.com/auth/callback`) - this must match `GITHUB_OAUTH_REDIRECT_URI` below exactly (scheme, host, port if non-default, path). Changing which URL the GUI is reached through later (new domain, adding a reverse proxy, etc.) means updating both this GitHub setting and `.env` together - they have to keep matching.
4. Register it, then generate a **Client secret**. You now have a Client ID and Client Secret.

**One-time setup, on the Docker host:** create `ansible-runner/.env` (gitignored, same idea as `.vault_pass`):

```bash
GITHUB_OAUTH_CLIENT_ID=<from the OAuth App>
GITHUB_OAUTH_CLIENT_SECRET=<from the OAuth App>
GITHUB_OAUTH_REDIRECT_URI=https://ansible.example.com/auth/callback
GITHUB_ALLOWED_USERS=theoneakta        # comma-separated GitHub usernames, case-insensitive
```

Then `./run.sh --gui` (or rebuild if it's already running: `docker compose --profile gui build gui && docker compose --profile gui up -d gui`). Visiting the GUI now redirects to a sign-in page; only usernames in `GITHUB_ALLOWED_USERS` get past `/auth/callback` - anyone else authenticates fine with GitHub but is then explicitly rejected. `SESSION_SECRET_KEY` is optional - omit it and a random one is generated per container start (sessions just don't survive a restart, no secret to manage); set it to keep people signed in across redeploys.

This only requires the OAuth App's Client ID/Secret and read-only `read:user` scope (just enough to read the authenticated username) - it never touches your repos or org data.

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

## Preparing a target Windows PC

Before adding a PC to the inventory, enable WinRM/HTTPS on it. From an elevated PowerShell prompt **on that PC**:

```powershell
.\scripts\setup-winrm-ssl.ps1 -ControllerAddress 192.168.3.8   # your Ansible control host's IP
```

This enables WinRM, creates a self-signed certificate and HTTPS listener on port 5986, opens the firewall, enables NTLM (Negotiate) auth, and - importantly - sets `LocalAccountTokenFilterPolicy=1` so a local (non-domain) administrator account other than the built-in `Administrator` can authenticate over the network at all. Without that registry value, WinRM rejects an otherwise-correct username/password from any other local admin account with a plain "Access is denied", which looks identical to a wrong password. It also raises WinRM's default operation timeout and per-shell quotas, which are too tight for long-running tasks like installing a large package via Chocolatey. Safe to re-run - it only changes what isn't already set.

**`-ControllerAddress` is strongly recommended.** Without it, the WinRM firewall rule(s) accept connections from any address on the network (`RemoteAddress: Any`) - anything that can route to the PC can attempt a WinRM connection, subject to real credentials. Passing your Ansible control host's IP scopes every enabled `*WinRM*` firewall rule to that address only. This is a separate, narrower door than the AV note below: it doesn't fix what that note is about, but it does mean the only thing that can reach WinRM at all is your own automation host.

### Code signing

`scripts/setup-winrm-ssl.ps1` is Authenticode-signed with a self-signed certificate (`scripts/ansible-runner-codesign.cer`, committed to the repo - just the public cert, no private key). This is preventive hygiene, not a fix for the Bitdefender note above - that block is on Ansible's own `-EncodedCommand` WinRM invocation, which never touches a `.ps1` file on disk, so no amount of signing reaches it. It also doesn't cover the CIS audit script or Win11Debloat's script - both are third-party content pulled fresh from their own sources on every run, not ours to sign.

Being *signed* and being *trusted* are different things: a self-signed cert has no chain to a CA Windows already trusts, so until you import it, `Get-AuthenticodeSignature` (and Bitdefender/Windows' own heuristics) will show it as signed-but-unknown, not signed-and-trusted. To actually trust it on a machine:

```powershell
Import-Certificate -FilePath .\scripts\ansible-runner-codesign.cer -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath .\scripts\ansible-runner-codesign.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

(Both stores, since it's self-signed: `Root` because there's no other CA to chain to, `TrustedPublisher` because that's what code-signing trust checks actually look at.)

The private key lives only in `Cert:\CurrentUser\My` on whichever machine generated it - it's never exported to a file, so it can't end up in git. After editing any script in `scripts/`, re-sign it with:

```powershell
.\scripts\sign-scripts.ps1
```

If you ever regenerate the certificate (new machine, lost store), see that script's header comment - you'll need to re-export and re-commit `ansible-runner-codesign.cer`, and anyone who'd trusted the old one needs to trust the new one too.

## Inventory and connection settings

Add hosts to `inventory/hosts.yml` under the `windows` group. Connection defaults are in `inventory/group_vars/windows/vars.yml`:

```yaml
ansible_connection: psrp
ansible_port: 5986
ansible_psrp_protocol: https
ansible_psrp_auth: ntlm              # or credssp / kerberos / certificate
ansible_psrp_cert_validation: ignore
```

`psrp` (PowerShell Remoting Protocol), not the more commonly-seen `winrm` connection plugin - see the Troubleshooting entry below on why. Both still talk to the same WinRM/WS-Man HTTPS listener `setup-winrm-ssl.ps1` sets up; this only changes which client protocol the controller uses. `cert_validation: ignore` is convenient for self-signed certificates; switch to `validate` once your hosts have trusted certs.

For Linux targets, uncomment the `~/.ssh` mount in `docker-compose.yml` and add a matching inventory group.

## The software playbook

`playbooks/install_software.yml` installs Chocolatey if missing, then installs or upgrades each package to the latest version (`state: latest`).

- Packages are installed one at a time with `ignore_errors`, so one bad package ID does not stop the run. A summary lists any that failed.
- `pdfgear` and `battle.net` are less certain package IDs. Verify with `choco search <name>`.
- The Wazuh agent only installs if you pass `-e wazuh_manager=<ip-or-fqdn>`.
- **WSL is opt-in**: off by default, and skipped entirely unless you pass one or more `--wsl-distro <name>` flags (or `-e wsl_enabled=true -e 'wsl_distros_selected=["Ubuntu"]'`) - see `wsl_distros_available` in the playbook for the built-in list (Ubuntu variants, Debian, Kali Linux, openSUSE, Fedora, AlmaLinux, Oracle Linux); any name from `wsl --list --online` works even if not in that list. Already-installed distros are skipped. Requires Windows 10 2004+/Windows 11. Enabling the underlying Windows feature for the first distro on a machine can require a reboot to finish - by default the playbook just warns and leaves the PC running; pass `--wsl-allow-reboot` (or `-e wsl_allow_reboot=true`) to let it reboot and complete automatically. The install itself uses `--no-launch` to skip the distro's interactive first-run setup (which would otherwise hang forever waiting for a prompt that never comes over WinRM) - a distro's first launch still needs a manual `wsl -d <name>` step to create its Linux user account, which isn't automated here.
  - **WSL distros are per-user, not machine-wide**: only the account that ran `wsl --install` can see/use them. By default that's this playbook's WinRM user - fine if that account is only ever used for automation, not so useful otherwise. Pass `--wsl-user <name>` (repeatable, or `-e 'wsl_target_users=["jsmith","jdoe"]'`) to install for those specific Windows users **instead**: this creates a Scheduled Task per user, triggered at their next logon, running as themselves via `logon_type: interactive_token` (no password needed), and skips installing for the WinRM account entirely. (A first attempt auto-provisioned via a script dropped into the all-users Startup folder instead; abandoned after Bitdefender blocked the write outright as a protected autostart location, regardless of the script's content - Scheduled Tasks are a more ordinary admin operation and didn't hit the same block in testing, but this is newer/less battle-tested than the rest of the playbook.) The exact manual command is always printed in the run's own output too, for anyone else not listed.
- Some items are not installable via Chocolatey (Bitdefender, Punch! Software, Duplicate Cleaner Pro, DownloadHelper, Plantronics Hub / Poly Lens). The playbook prints them at the end as a manual-install reminder.
- **Win11Debloat is opt-in**: off by default, pass `--win11debloat` (or `-e win11debloat_enabled=true`) to enable it. Downloads and runs the latest [Win11Debloat](https://github.com/Raphire/Win11Debloat) script straight from `debloat.raphi.re` on the target with its own maintainers' recommended defaults (`-RunDefaults -Silent`) - removes their default bloatware list and applies their default privacy/UI tweaks, unattended. There's no per-run customization of *which* apps/tweaks here on purpose; it's meant to be their standard profile as-is. Review the [project's own docs](https://github.com/Raphire/Win11Debloat/wiki/Command%E2%80%90line-Interface) if you want different behavior later.
- **RSAT is opt-in**: off by default, pass `--rsat` (or `-e rsat_enabled=true`) to install every available RSAT (Remote Server Administration Tools) capability - AD DS, DNS, DHCP, Group Policy, Hyper-V, and the rest. RSAT ships as Windows Capabilities (Features on Demand), not Chocolatey packages, so it's installed via `Add-WindowsCapability` rather than through `choco_packages`. No per-tool selection here; it's all of them or none. Each missing capability downloads from Windows Update, so a fresh machine can take a while.

To add your own playbooks, drop them into `playbooks/` and run `./run.sh yourplaybook.yml`.

## CIS Benchmark hardening

`playbooks/cis_hardening.yml` applies one of [ansible-lockdown's](https://github.com/ansible-lockdown) CIS Benchmark roles - Windows 11, or Windows Server 2019/2022/2025 - to the selected host(s). Available both in the web GUI (its own "CIS Benchmark hardening" section) and on the CLI.

> **This is a fundamentally different kind of operation from `install_software.yml`.** It changes real security settings on the target - password/lockout policy, audit policy, services, network protocols, and more. Some controls can affect remote management itself (the same WinRM access this whole toolkit depends on) or break older/legacy software. **Read the relevant role's own documentation first, and test against a non-critical PC before running it against anything you rely on.**

**Self-lockout protection is on by default.** `cis_hardening.yml` sets `win_skip_for_test: true` - the role's own maintainer-documented safety switch, off by default upstream. Without it, control 1.2.2 (Account lockout threshold) locks out the very account WinRM/psrp uses to manage the host after 5 failed authentications - a previously-reported upstream incident, and one we hit ourselves: a real run applied it, WinRM started rejecting the account shortly after, and recovery needed local/console access to re-run `setup-winrm-ssl.ps1`. `true` also skips every other control that can similarly strand the connection - `2.2.16`/`2.2.20` (breaks local admin connection), `5.39`/`18.10.88.x`/`18.10.89.1` (disable WinRM itself or its auth methods) - plus a few unrelated ones (`5.21`/`18.10.56.3.2.1` disable RDP, `9.3.4` breaks reboot). Trade-off: those specific controls then never get applied, so a run won't be 100% benchmark-complete. Override with `-e win_skip_for_test=false` for a specific run only if you have real console/IPMI access as a fallback in case it strands the connection.

A **second, separate** self-lockout control isn't covered by `win_skip_for_test` at all: `18.4.1` ("Apply UAC restrictions to local accounts on network logons") sets `LocalAccountTokenFilterPolicy=0` - the exact opposite of what `setup-winrm-ssl.ps1` sets it to. That value is what lets a local admin account *other than the built-in "Administrator" (RID 500)* - i.e. whatever account this toolkit actually authenticates as - get a full token over a network logon; the moment `18.4.1` applies, every subsequent WinRM/psrp authentication from that account is rejected. Confirmed live, the same way as `1.2.2`, just later in the run (`18.4.1` runs well into section 18). This isn't a bug to patch, it's a genuine, unavoidable conflict between this specific control and automating as a non-built-in local admin - so `cis_hardening.yml` also defaults `win11cis_rule_18_4_1`/`win19cis_rule_18_4_1`/`win22cis_rule_18_4_1`/`win25cis_rule_18_4_1` to `false` (all 4 roles have their own copy of this control). Only override it (e.g. `-e win11cis_rule_18_4_1=true`) if the automation account is ever changed to the actual built-in Administrator, or you're prepared to re-run `setup-winrm-ssl.ps1` afterward.

A **third** exclusion, this one not about WinRM at all: `2.3.1.1` ("Block Microsoft accounts") sets `NoConnectedUser=3` under `HKLM:\Software\Microsoft\Windows\Currentversion\Policies\System` - Microsoft's documented value for "Users can't add or log on with Microsoft accounts." This control is written for domain-joined enterprise environments where people sign in with domain credentials; applied to a non-domain personal PC where a Microsoft account is the only way to sign in at all, it locks the person out of their own desktop, not just some hypothetical newly-added account. Confirmed live. `win11cis_rule_2_3_1_1` defaults to `false` - **Windows 11 only**, deliberately not excluded on the server roles, where blocking personal Microsoft accounts on a domain-joined member server/DC is the actually-intended, appropriate use of this control.

**Which OS to target, then level, then all-or-specific-sections** - the GUI cascades through these (fetching the real options from `/api/cis/options`, backed by `CIS_PROFILES` in `gui/app.py` - the single source of truth, verified against each role's actual installed source rather than assumed):

- **Windows 11** levels: `1` (corporate/enterprise) or `2` (high security) - each also pulls in that level's separate BitLocker-tagged controls automatically.
- **Server 2019/2022/2025** levels are split by machine role instead of a simple 1/2, since that's how the roles themselves are built: `1-dc`, `1-member`, `1-standalone`, `2-dc`, `2-standalone` (Domain Controller / Domain Member / Member Server; note there's no `2-member` upstream - a benchmark design choice, not an oversight here). These roles default to direct Ansible remediation (not their alternate GPO-generation mode), which needs no extra configuration.
- **Sections** (all 4 roles use the same 7 numbers/names): 1 Account Policies, 2 Local Policies, 5 System Services, 9 Windows Defender Firewall, 17 Advanced Audit Policy Configuration, 18 Administrative Templates (Computer), 19 Administrative Templates (User). "All" applies the whole level; "Specific sections" toggles each one on/off via the role's own `win<x>cis_section<N>` variables.
- **Individual controls** - click "items" next to any section to expand it and turn off specific controls one at a time (e.g. just `2.3.1.1`), via the role's own `win<x>cis_rule_<id>` variables. These aren't a hardcoded list: `/api/cis/controls?os=<os>&section=<n>` parses them straight out of that role's actual installed task files on request (cached after the first look), since there's no practical way to keep ~200+ controls per role, across 4 roles, accurate by hand. Only explicitly-unchecked controls are sent (everything else keeps the role's own default), so the request stays small no matter how large a section is.

On the CLI, `run.sh` handles OS + level for you (section-level selection is GUI-only for now):

```bash
./run.sh cis_hardening.yml --cis-os windows11 --cis-level 1                  # Windows 11, Level 1
./run.sh cis_hardening.yml --cis-os windows2022 --cis-level 1-standalone     # Server 2022, Level 1 Member Server
./run.sh cis_hardening.yml --cis-os windows11 --cis-level 1 --cis-audit-only # report what would change, without changing anything
```

| Flag | Effect |
|---|---|
| `--cis-os <windows11\|windows2019\|windows2022\|windows2025>` | Which role to apply (default `windows11`) |
| `--cis-level <id>` | Which level for that OS (`1`/`2` for Windows 11; `1-dc`/`1-member`/`1-standalone`/`2-dc`/`2-standalone` for servers) |
| `--cis-audit-only` | Report only - sets the role's own `audit_only`/`setup_audit`/`run_audit` vars, makes no changes |

All 4 roles are installed from `requirements.yml` at image build time (`ansible-galaxy install -r requirements.yml`) - rebuild (`./run.sh --build` and, for the GUI, `./run.sh --gui` after a fresh build) after changing a pinned `version`. Which role actually runs is chosen dynamically via the `cis_role` variable (an `include_role: name: "{{ cis_role }}"` on a single generic playbook) - note that dynamic includes don't automatically inherit `--tags` filtering the way a static `roles:` list does, so the include step itself is tagged `always` and the real filtering happens on the tasks discovered inside, which already carry their own correct tags.

**Service-dependency ordering.** The vendored roles disable services in control-number order, not dependency order - e.g. Windows-11-CIS stops `SSDPSRV` (control 5.30) before `upnphost` (5.31), which depends on it. Windows refuses to stop a service while a running dependent needs it ("has dependent services"), and since the role has no `ignore_errors`, Ansible then aborts *every remaining task for that host* - one ordering conflict silently skips hundreds of otherwise-fine controls, not just the one that failed. This isn't something we can fix in the role itself (overwritten from GitHub on every `--build`), so `cis_hardening.yml` works around it with a `pre_tasks` step: `playbooks/files/discover_cis_services.py` scans whichever role is selected for every service any `win_service`/`win_service_info` task references (no hardcoded list - same "read it from the role's actual source" approach as the section/control discovery in the GUI), then the playbook checks each one's currently-running dependents and stops (not disables) them before the role runs. `WinRM` is explicitly never touched by this, even if discovered, since stopping it would sever the very connection running the playbook. Skipped entirely when `audit_only` is set, which must make zero real changes.

## Updating Ansible / collections

Rebuild to pull newer versions:

```bash
./run.sh --build
```

## Troubleshooting

- **`psrp`/WinRM connection errors or timeouts:** confirm WinRM is enabled on the target (`winrm quickconfig`), the port is open, and `ansible_psrp_auth` matches what the host's WinRM service actually has enabled (see `setup-winrm-ssl.ps1`).
- **`Decryption failed`:** wrong or missing vault password; check `.vault_pass`.
- **Authentication failures:** verify with `./run.sh --vault-view`; local accounts may need `.\username` or a host-specific override.
- **Files in mounted folders owned by root:** `run.sh` runs the container as your host UID/GID to avoid this.
- **CIS `--cis-audit-only`/`audit_only` fails with `Access is denied` / `CreateProcessW() failed (Win32ErrorCode 5)`, specifically on the `Pre Audit | Run pre_remediation audit` task:** Bitdefender blocking `C:\Program Files\syver\syver.exe` from running. `run_audit.ps1` (part of the CIS role's audit setup) shells out to `syver.exe` - a small third-party binary freshly downloaded from `github.com/krameff/syver` on every audit run - to actually perform the scan. A fresh, unsigned, just-downloaded executable about to run for the first time is a mainstream AV trigger, and this reproduces identically regardless of connection plugin (`psrp` or `winrm`) or WinRM auth method (NTLM/CredSSP made no difference either), since the block happens *inside* `run_audit.ps1` when it launches `syver.exe` - it was never about how Ansible itself reaches the host for this specific step. Fix: a Bitdefender exception scoped to `C:\Program Files\syver\syver.exe` (or its folder) - open **Protection History**, find the blocked `syver.exe` event, and use its **"Add to exceptions"** action, or add a manual exception under Protection > Antivirus > Manage Exceptions. Much narrower than exempting `powershell.exe` itself - this is one specific known third-party tool. Consumer Bitdefender has no scriptable exclusion API and has tamper protection, so this has to be done by hand on the target; nothing here can do it for you automatically. Per-host: this exception (and the failure) is specific to whichever PC hasn't had it added yet, not fleet-wide.

- **CIS `audit_only` fails with `PSSecurityException: ... running scripts is disabled on this system` on that same task, once the Bitdefender issue above is cleared:** a second, independent problem underneath the first one - `& 'run_audit.ps1' @auditArgs` runs a saved script *file*, which PowerShell's execution policy governs (unlike this toolkit's other downloaded-script usage, e.g. Win11Debloat, which runs an in-memory scriptblock and is immune to it). The role's own execution-policy check only looks at GPO-enforced `MachinePolicy`/`UserPolicy` - it misses a plain `LocalMachine`-scope `Restricted` policy, the common case on a PC never explicitly configured for scripting, so it reports "OK" even when this blocks. `cis_hardening.yml` now fixes this itself (a `pre_tasks` step, only when `run_audit`/`audit_only` is set): sets `LocalMachine` to `RemoteSigned` if it's currently `Restricted` or `AllSigned`, nothing stronger - `RemoteSigned` only requires signing for scripts marked as downloaded from the internet (a `Zone.Identifier` stream), and Ansible's own download/unarchive mechanism doesn't set that marker the way a browser would, so the unsigned audit script still runs fine under it. Confirmed working end-to-end on 192.168.3.17 (full audit completed: "Count: 1309, Failed: 319, Skipped: 540") once both this and the Bitdefender exception were in place.

  Separately, and why the default connection plugin above is `psrp` rather than `winrm`: the `winrm` connection plugin executes *every other* module by spawning a fresh `powershell.exe -noninteractive -encodedcommand <base64>` process per task, which is its own distinct false-positive pattern Bitdefender was directly observed blocking (confirmed from Bitdefender's own notification for an earlier, unrelated task). `psrp` runs module code inside a persistent remote runspace instead (the same protocol `Invoke-Command`/`Enter-PSSession` use), with no new process spawned per task - this held up in practice: every other task in a full CIS run succeeded cleanly under `psrp`, with only the `syver.exe` launch (a genuinely different problem) still failing.
