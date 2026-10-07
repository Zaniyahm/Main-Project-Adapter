# Minimum Safe Deployment — Run Instructions

**NOT live-tested** — no Docker daemon was available in the environment
this was written in. Everything else in this project was verified with
real running processes; this is reviewed-correct config, not
run-confirmed. Test it yourself before actually exposing it to the
internet.

## Build

```bash
docker build -t db-honeypot .
```

## Run (Minimum Safe Deployment gate — every flag below is required, not optional)

```bash
mkdir -p ./instance-data   # host directory — OFF-container persistence for logs/DB

docker run -d \
  --name db-honeypot \
  --user honeypot \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp \
  --memory 256m \
  --cpus 0.5 \
  --pids-limit 100 \
  -v "$(pwd)/instance-data:/app/shared/instance" \
  -p 3306:3306 \
  -p 5432:5432 \
  db-honeypot
```

**What each flag is for:**
- `--cap-drop ALL` — the container gets zero Linux capabilities beyond
  the bare minimum needed to run Python and bind a socket.
- `--read-only` + `--tmpfs /tmp` — the container's own filesystem can't
  be written to at all (blocks any hypothetical malicious-code-write
  scenario), except for a throwaway in-memory `/tmp`.
- `-v ./instance-data:/app/shared/instance` — the actual database and
  JSONL log live on the HOST, not inside the container. If the
  container is ever compromised, the attacker can't tamper with or
  erase the honeypot's own evidence of their activity.
- `--memory` / `--cpus` / `--pids-limit` — hard resource caps, so even
  a bug or an attempted resource-exhaustion attack can't take down the
  host machine.
- `--security-opt no-new-privileges` — blocks any privilege-escalation
  path even if a vulnerability existed in something running inside.

## Before actually deploying to the internet

1. Confirm `docker build` succeeds and the two ports actually come up
   (`docker logs db-honeypot` should show both adapters' startup lines).
2. Run the exact same manual verification commands used throughout this
   project (`mysql -h <public-ip> ... --skip-ssl`, `psql "host=<public-ip> ... sslmode=disable"`)
   from a SEPARATE machine, not localhost, to confirm it's actually
   reachable and behaves the same as it did locally.
3. Confirm `./instance-data/legacy_cms.db` and `./instance-data/honeypot_events.jsonl`
   are actually being written to on the HOST, not just inside the
   container — this is the entire point of the volume mount.
4. Only after all of the above: point a domain/firewall rule at it, or
   otherwise make it genuinely reachable from the public internet.
