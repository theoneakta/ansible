# Sentry Lens sensor: nfstream (nDPI) on the interfaces the traffic is mirrored to.
FROM python:3.12-slim
RUN pip install --no-cache-dir nfstream==6.6.0
COPY sensor.py /sensor.py
CMD ["python", "-u", "/sensor.py"]
