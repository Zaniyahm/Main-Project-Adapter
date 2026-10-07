# Minimum Safe Deployment gate — NOT live-tested here (no Docker daemon
# available in the build environment this was written in). Review this
# file and test it yourself with `docker build` / `docker run` before
# actually deploying — everything else in this project was verified
# live; this file is reviewed-correct but not run-confirmed.

FROM python:3.12-slim

# Non-root user — never run the honeypot as root, even inside the container.
RUN groupadd -r honeypot && useradd -r -g honeypot -d /app honeypot

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# The shared SQLite DB/JSONL log lives on a mounted volume (see the run
# command below) — OFF-container, so a compromised container can't
# erase its own evidence.
RUN mkdir -p /app/shared/instance && chown -R honeypot:honeypot /app

USER honeypot

EXPOSE 3306 5432

CMD ["python3", "registry.py"]
