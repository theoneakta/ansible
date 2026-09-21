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
#   --wsl-all-users                      also provision the WSL distro(s) for every other Windows user
#   --win11debloat                       run Win11Debloat with its own recommended defaults, silently
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
        --wsl-all-users)               EXTRA_VARS+=(-e "wsl_all_users=true"); shift ;;
        --win11debloat)                EXTRA_VARS+=(-e "win11debloat_enabled=true"); shift ;;
        *) PASSTHRU+=("$1"); shift ;;
      esac
    done
    if [[ ${#WSL_DISTROS[@]} -gt 0 ]]; then
      json=$(printf '"%s",' "${WSL_DISTROS[@]}"); json="[${json%,}]"
      EXTRA_VARS+=(-e "wsl_enabled=true" -e "wsl_distros_selected=$json")
    fi
    "${RUN[@]}" ansible "playbooks/${pb}" "${PASSTHRU[@]}" "${EXTRA_VARS[@]}" "${VAULT_ARGS[@]}"
    ;;
esac
