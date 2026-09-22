FROM python:3.12-slim

ENV ANSIBLE_HOST_KEY_CHECKING=False \
    PYTHONUNBUFFERED=1 \
    ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections \
    ANSIBLE_ROLES_PATH=/usr/share/ansible/roles

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client sshpass ca-certificates iputils-ping git \
    && rm -rf /var/lib/apt/lists/*

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
