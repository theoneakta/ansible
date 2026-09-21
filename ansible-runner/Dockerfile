FROM python:3.12-slim

ENV ANSIBLE_HOST_KEY_CHECKING=False \
    ANSIBLE_FORCE_COLOR=1 \
    PYTHONUNBUFFERED=1 \
    ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections \
    ANSIBLE_ROLES_PATH=/usr/share/ansible/roles

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client sshpass git ca-certificates nano \
    && rm -rf /var/lib/apt/lists/*

# ansible + Windows connection libs (WinRM / PSRP / CredSSP)
RUN pip install --no-cache-dir \
        ansible-core \
        pywinrm \
        pypsrp \
        requests-credssp \
        passlib

# Collections used by the playbooks
RUN ansible-galaxy collection install \
        ansible.windows \
        community.windows \
        chocolatey.chocolatey \
        ansible.posix \
        community.general

WORKDIR /ansible
COPY ansible.cfg /ansible/ansible.cfg

# Third-party roles (CIS hardening - see playbooks/cis_hardening.yml)
COPY requirements.yml /ansible/requirements.yml
RUN ansible-galaxy install -r /ansible/requirements.yml

# `docker run ... playbooks/foo.yml` runs ansible-playbook.
# Override with --entrypoint ansible (ad-hoc) or --entrypoint bash (shell).
ENTRYPOINT ["ansible-playbook"]
CMD ["--version"]
