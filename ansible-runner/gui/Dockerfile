FROM python:3.12-slim

ENV ANSIBLE_HOST_KEY_CHECKING=False \
    PYTHONUNBUFFERED=1 \
    ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections \
    ANSIBLE_ROLES_PATH=/usr/share/ansible/roles

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client sshpass ca-certificates iputils-ping git \
        curl gpg xorriso 7zip \
    && rm -rf /var/lib/apt/lists/*

# Packer, for the Windows image build (playbooks/image_build.yml). xorriso
# lets it pack autounattend.xml into an ISO; 7zip extracts WinPE from the
# Windows ISO (image_capture.yml).
RUN curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $(. /etc/os-release && echo "$VERSION_CODENAME") main" \
        > /etc/apt/sources.list.d/hashicorp.list \
    && apt-get update && apt-get install -y --no-install-recommends packer \
    && rm -rf /var/lib/apt/lists/* \
    && (command -v 7z >/dev/null || ln -s "$(command -v 7zz)" /usr/local/bin/7z)

# Packer plugins baked into the image, so a build doesn't depend on GitHub
# being reachable (image_build.yml still runs `packer init`, a no-op then).
ENV PACKER_PLUGIN_PATH=/usr/share/packer/plugins
COPY playbooks/packer/win11/plugins.pkr.hcl /tmp/packer-init/plugins.pkr.hcl
RUN packer init /tmp/packer-init && rm -rf /tmp/packer-init

# Same Ansible stack as the main runner image, plus the small web app's deps.
RUN pip install --no-cache-dir \
        ansible-core \
        pywinrm \
        pypsrp \
        requests-credssp \
        passlib \
        fastapi \
        "uvicorn[standard]" \
        pyyaml \
        requests \
        itsdangerous

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

COPY gui/app.py /ansible/gui/app.py
COPY gui/static /ansible/gui/static
COPY gui/callback_plugins /ansible/gui/callback_plugins

EXPOSE 8000
CMD ["uvicorn", "gui.app:app", "--host", "0.0.0.0", "--port", "8000"]
