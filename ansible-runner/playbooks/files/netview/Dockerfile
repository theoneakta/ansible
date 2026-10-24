FROM python:3.12-slim

RUN pip install --no-cache-dir \
        "fastapi==0.115.*" \
        "uvicorn==0.32.*" \
        "requests==2.32.*" \
        "pyjwt[crypto]==2.9.*"

WORKDIR /app
COPY app.py dns.py live.py categories.py /app/
COPY static /app/static

# Nothing written at runtime - an unprivileged user with no host account is
# fine under CIS (no volumes to chown).
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
