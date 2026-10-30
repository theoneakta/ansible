# The live install's settings for the SentryLens repo's deploy/

The source of truth for running SentryLens's playbooks against the live install.
The runner holds only a copy, at `playbooks/sentrylens/` (the repo's `deploy`,
`app`, `flowd`, `sensor`), with these three files placed as:

    inventory.yml  -> playbooks/sentrylens/deploy/inventory.yml
    site.yml       -> playbooks/sentrylens/deploy/group_vars/all/site.yml
    secrets.yml    -> playbooks/sentrylens/deploy/group_vars/all/secrets.yml

`playbooks/sentrylens/deploy/.vault/` (the vault's certificate, root-owned) lives
only on the runner - leave it when refreshing the copy.

Run from the runner, both inventories (host names are the runner's, so logins come
from its vault):

    docker exec -w /ansible/playbooks/sentrylens/deploy ansible-gui-1 \
      ansible-playbook -i inventory.yml -i /ansible/inventory/hosts.yml \
      playbooks/<name>.yml --vault-password-file /run/secrets/vault_pass
