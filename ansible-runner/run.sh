#!/usr/bin/env bash
# On-demand Ansible runner with Ansible Vault support.
#
#   ./run.sh install_software.yml [ansible-playbook args]
#   ./run.sh --ping                      win_ping the windows group
#   ./run.sh --shell                     bash in the container
#   ./run.sh --build                     (re)build image
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
YML
    vault encrypt "$DEFAULT_VAULT"
    echo "Now run: ./run.sh --vault-edit   (set the real username/password)"
    ;;

  --vault-edit)   vault edit   "${2:-$DEFAULT_VAULT}" ;;
  --vault-view)   vault view   "${2:-$DEFAULT_VAULT}" ;;
  --vault-rekey)  vault rekey  "${2:-$DEFAULT_VAULT}" ;;
  --vault-create) [[ -n "${2:-}" ]] || { echo "Usage: $0 --vault-create <file>"; exit 1; }
                  mkdir -p "$(dirname "$2")"; vault create "$2" ;;

  "") echo "Usage: $0 <playbook.yml> [args] | --ping | --shell | --build | --vault-*"; exit 1 ;;
  *)  pb="$1"; shift; "${RUN[@]}" ansible "playbooks/${pb}" "$@" "${VAULT_ARGS[@]}" ;;
esac
