#!/usr/bin/env bash
# On-demand Ansible runner with Ansible Vault support.
#
#   ./run.sh install_software.yml [ansible-playbook args]
#   ./run.sh --ping                      win_ping the windows group
#   ./run.sh --shell                     bash in the container
#   ./run.sh --build                     (re)build image
#
# Web GUI (runs in its own container, nothing installed on the host):
#   ./run.sh --gui                       build (if needed) and start at http://localhost:8080
#   ./run.sh --gui-stop                  stop it
#   ./run.sh --gui-logs                  tail its logs
#
# Convenience install params (translated to `-e key=value` for you):
#   --wazuh-manager <ip|fqdn>            Wazuh manager address (installs the agent)
#   --wazuh-port <port>                  default: 1514
#   --wazuh-protocol <tcp|udp>           default: tcp
#   --wazuh-group <group>
#   --wazuh-agent-name <name>
#   --wazuh-registration-password <pw>
#   --tailscale-join                     join the tailnet using the key stored in vault
#   --tailscale-authkey <key>            join the tailnet with this key instead (overrides vault)
#   --git-name <name>                    git config --global user.name
#   --git-email <email>                  git config --global user.email
#   --wsl-distro <name>                  install this WSL distro (repeatable; omit to skip WSL entirely)
#   --wsl-allow-reboot                   let the WSL distro install reboot the PC if needed
#   --wsl-user <name>                    also provision the WSL distro(s) for this Windows user (repeatable)
#   --win11debloat                       run Win11Debloat with its own recommended defaults, silently
#   --rsat                               install all RSAT (Remote Server Administration Tools) capabilities
#
# For playbooks/cis_hardening.yml (CIS Benchmark hardening - see its own header comment first):
#   --cis-os <windows11|windows2019|windows2022|windows2025>  default: windows11
#   --cis-level <id>                     windows11: 1 or 2
#                                         servers:   1-dc, 1-member, 1-standalone, 2-dc, or 2-standalone
#   --cis-audit-only                     report what would change without making changes
#   (section-level selection is GUI-only for now - use --tags/-e directly on the CLI if needed)
# Any other args (e.g. --limit, --check, -e foo=bar) pass straight through.
#
# Example:
#   ./run.sh install_software.yml --wazuh-manager 10.0.0.5 --tailscale-authkey tskey-...
#
# Vault:
#   ./run.sh --vault-init                create .vault_pass + encrypted group creds
#   ./run.sh --vault-edit [file]         edit (default: group_vars/windows/vault.yml)
#   ./run.sh --vault-view [file]         show decrypted contents
#   ./run.sh --vault-create <file>       new encrypted file, e.g. per-host creds:
#                                        inventory/host_vars/pc02.example.local/vault.yml
#   ./run.sh --vault-rekey [file]        change vault password (then update .vault_pass)
set -euo pipefail
cd "$(dirname "$0")"

DEFAULT_VAULT="inventory/group_vars/windows/vault.yml"
PASSFILE=".vault_pass"

RUN=(docker compose --profile run run --rm --user "$(id -u):$(id -g)")
VAULT_ARGS=()
if [[ -f "$PASSFILE" ]]; then
  RUN+=(-v "$PWD/$PASSFILE:/run/secrets/vault_pass:ro" -e ANSIBLE_VAULT_PASSWORD_FILE=/run/secrets/vault_pass)
else
  VAULT_ARGS=(--ask-vault-pass)   # no pass file: prompt each run
fi

vault() { "${RUN[@]}" --entrypoint ansible-vault ansible "$@"; }

case "${1:-}" in
  --build) docker compose --profile run build ;;
  --shell) "${RUN[@]}" --entrypoint bash ansible ;;
  --ping)  "${RUN[@]}" --entrypoint ansible ansible windows -m ansible.windows.win_ping "${VAULT_ARGS[@]}" ;;

  --vault-init)
    if [[ ! -f "$PASSFILE" ]]; then
      umask 077; openssl rand -base64 32 > "$PASSFILE"
      echo "Created $PASSFILE  -> BACK THIS UP (password manager). Lose it = lose the secrets."
      # re-exec so the pass file gets mounted
      exec "$0" --vault-init
    fi
    if [[ -f "$DEFAULT_VAULT" ]]; then echo "$DEFAULT_VAULT already exists."; exit 0; fi
    mkdir -p "$(dirname "$DEFAULT_VAULT")"
    cat > "$DEFAULT_VAULT" <<'YML'
vault_win_user: administrator
vault_win_password: changeme
vault_tailscale_authkey: ""
YML
    vault encrypt "$DEFAULT_VAULT"
    echo "Now run: ./run.sh --vault-edit   (set the real username/password)"
    ;;

  --gui)
    [[ -f "$PASSFILE" ]] || { echo "No $PASSFILE found. Run ./run.sh --vault-init first (the GUI needs it to reach hosts)."; exit 1; }
    mkdir -p gui/data
    docker compose --profile gui up -d --build gui
    echo "GUI running at http://localhost:8080"
    ;;
  --gui-stop) docker compose --profile gui stop gui ;;
  --gui-logs) docker compose --profile gui logs -f gui ;;

  --vault-edit)   vault edit   "${2:-$DEFAULT_VAULT}" ;;
  --vault-view)   vault view   "${2:-$DEFAULT_VAULT}" ;;
  --vault-rekey)  vault rekey  "${2:-$DEFAULT_VAULT}" ;;
  --vault-create) [[ -n "${2:-}" ]] || { echo "Usage: $0 --vault-create <file>"; exit 1; }
                  mkdir -p "$(dirname "$2")"; vault create "$2" ;;

  "") echo "Usage: $0 <playbook.yml> [args] | --ping | --shell | --build | --gui* | --vault-*"; exit 1 ;;
  *)
    pb="$1"; shift
    EXTRA_VARS=()
    PASSTHRU=()
    WSL_DISTROS=()
    WSL_TARGET_USERS=()
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --wazuh-manager)               EXTRA_VARS+=(-e "wazuh_manager=$2"); shift 2 ;;
        --wazuh-port)                  EXTRA_VARS+=(-e "wazuh_manager_port=$2"); shift 2 ;;
        --wazuh-protocol)              EXTRA_VARS+=(-e "wazuh_protocol=$2"); shift 2 ;;
        --wazuh-group)                 EXTRA_VARS+=(-e "wazuh_group=$2"); shift 2 ;;
        --wazuh-agent-name)            EXTRA_VARS+=(-e "wazuh_agent_name=$2"); shift 2 ;;
        --wazuh-registration-password) EXTRA_VARS+=(-e "wazuh_registration_password=$2"); shift 2 ;;
        --tailscale-authkey)           EXTRA_VARS+=(-e "tailscale_authkey=$2" -e "tailscale_join_enabled=true"); shift 2 ;;
        --tailscale-join)              EXTRA_VARS+=(-e "tailscale_join_enabled=true"); shift ;;
        --git-name)                    EXTRA_VARS+=(-e "git_user_name=$2"); shift 2 ;;
        --git-email)                   EXTRA_VARS+=(-e "git_user_email=$2"); shift 2 ;;
        --wsl-distro)                  WSL_DISTROS+=("$2"); shift 2 ;;
        --wsl-allow-reboot)            EXTRA_VARS+=(-e "wsl_allow_reboot=true"); shift ;;
        --wsl-user)                    WSL_TARGET_USERS+=("$2"); shift 2 ;;
        --win11debloat)                EXTRA_VARS+=(-e "win11debloat_enabled=true"); shift ;;
        --rsat)                        EXTRA_VARS+=(-e "rsat_enabled=true"); shift ;;
        --cis-os)                      CIS_OS="$2"; shift 2 ;;
        --cis-level)                   CIS_LEVEL_ID="$2"; shift 2 ;;
        --cis-audit-only)              EXTRA_VARS+=(-e "audit_only=true" -e "setup_audit=true" -e "run_audit=true"); shift ;;
        *) PASSTHRU+=("$1"); shift ;;
      esac
    done
    if [[ ${#WSL_DISTROS[@]} -gt 0 ]]; then
      # A single JSON-object -e argument, not `-e key=[...]` shorthand: this
      # ansible-core version does not auto-parse the shorthand form as JSON,
      # it stays a literal string and silently breaks any `loop:` over it.
      distros_json=$(printf '"%s",' "${WSL_DISTROS[@]}"); distros_json="[${distros_json%,}]"
      users_json="[]"
      if [[ ${#WSL_TARGET_USERS[@]} -gt 0 ]]; then
        users_json=$(printf '"%s",' "${WSL_TARGET_USERS[@]}"); users_json="[${users_json%,}]"
      fi
      EXTRA_VARS+=(-e "{\"wsl_enabled\": true, \"wsl_distros_selected\": $distros_json, \"wsl_target_users\": $users_json}")
    fi
    if [[ -n "${CIS_OS:-}" || -n "${CIS_LEVEL_ID:-}" ]]; then
      # Keep in sync with CIS_PROFILES in gui/app.py (the single source of
      # truth, verified against each role's actual installed source).
      CIS_OS="${CIS_OS:-windows11}"
      CIS_LEVEL_ID="${CIS_LEVEL_ID:-1}"
      case "$CIS_OS" in
        windows11)   CIS_ROLE=Windows-11-CIS ;;
        windows2019) CIS_ROLE=Windows-2019-CIS ;;
        windows2022) CIS_ROLE=Windows-2022-CIS ;;
        windows2025) CIS_ROLE=Windows-2025-CIS ;;
        *) echo "Unknown --cis-os '$CIS_OS' (expected windows11, windows2019, windows2022, or windows2025)" >&2; exit 1 ;;
      esac
      case "$CIS_OS:$CIS_LEVEL_ID" in
        windows11:1)     CIS_TAGS="level1-corporate-enterprise-environment,level1-bitlocker" ;;
        windows11:2)     CIS_TAGS="level2-high-security-sensitive-data-environment,level2-bitlocker" ;;
        *:1-dc)          CIS_TAGS="level1-domaincontroller" ;;
        *:1-member)      CIS_TAGS="level1-domainmember" ;;
        *:1-standalone)  CIS_TAGS="level1-memberserver" ;;
        *:2-dc)          CIS_TAGS="level2-domaincontroller" ;;
        *:2-standalone)  CIS_TAGS="level2-memberserver" ;;
        *) echo "Unknown --cis-level '$CIS_LEVEL_ID' for --cis-os '$CIS_OS'" >&2; exit 1 ;;
      esac
      EXTRA_VARS+=(-e "cis_role=$CIS_ROLE")
      PASSTHRU+=(--tags "$CIS_TAGS")
    fi
    "${RUN[@]}" ansible "playbooks/${pb}" "${PASSTHRU[@]}" "${EXTRA_VARS[@]}" "${VAULT_ARGS[@]}"
    ;;
esac
