FROM python:3.12-slim

ENV ANSIBLE_HOST_KEY_CHECKING=False \
    PYTHONUNBUFFERED=1 \
    ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client sshpass ca-certificates \
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
        pyyaml

RUN ansible-galaxy collection install \
        ansible.windows \
        community.windows \
        chocolatey.chocolatey \
        ansible.posix \
        community.general

WORKDIR /ansible
COPY ansible.cfg /ansible/ansible.cfg
COPY gui/app.py /ansible/gui/app.py
COPY gui/static /ansible/gui/static

EXPOSE 8000
CMD ["uvicorn", "gui.app:app", "--host", "0.0.0.0", "--port", "8000"]
