# Deploying with Docker

Arbiter ships a `Dockerfile` and a Compose file under `deploy/`.

## Compose (recommended)

```bash
git clone https://github.com/holdmyagent/arbiter.git
cd arbiter
docker compose -f deploy/docker-compose.yml up -d
```

```yaml
services:
  arbiter:
    build: { context: .., dockerfile: deploy/Dockerfile }
    image: ghcr.io/holdmyagent/arbiter:latest
    ports: ["8000:8000"]
    volumes: ["hma-data:/data"]
    restart: unless-stopped
volumes:
  hma-data:
```

The named volume `hma-data` holds `config.toml` and the SQLite database
(`/data/config.toml`, `/data/arbiter.sqlite3`) — back it up as a unit if
you care about request/audit history.

You don't have to build locally; every tagged release also publishes
`ghcr.io/holdmyagent/arbiter:latest` and `ghcr.io/holdmyagent/arbiter:vX.Y.Z`,
so `docker compose up -d` will pull instead of build once you drop the
`build:` key (or run `docker compose pull && docker compose up -d`).

## First run

On first start, the container's entrypoint runs `hma init` for you if
`/data/config.toml` doesn't exist yet, then execs `hma serve`. Grab the
generated tokens and admin password from the container logs on that first
boot — they're printed once, same as running `hma init` locally:

```bash
docker compose -f deploy/docker-compose.yml logs arbiter
```

The dashboard is at `http://<host>:8000/dashboard`.

## Configuration

The image sets `HMA_CONFIG=/data/config.toml`, `HMA_DB_PATH=/data/arbiter.sqlite3`,
and `HMA_HOST=0.0.0.0` (the container has to bind all interfaces to be
reachable from outside it — this is not the same as exposing it to the
internet; see [`docs/deploy-nginx.md`](deploy-nginx.md) and
[`docs/deploy-tailscale.md`](deploy-tailscale.md) for how to actually
expose it safely). Override any other setting with an `HMA_*` environment
variable in the Compose file, e.g.:

```yaml
services:
  arbiter:
    image: ghcr.io/holdmyagent/arbiter:latest
    environment:
      HMA_NTFY_TOPIC: "hma-a7f3c9d1"
      HMA_WEBHOOK_URL: "https://example.com/hooks/arbiter"
      HMA_WEBHOOK_SECRET: "..."
    ports: ["8000:8000"]
    volumes: ["hma-data:/data"]
    restart: unless-stopped
volumes:
  hma-data:
```

See [`docs/apns.md`](apns.md) for mounting an APNs `.p8` key into the
container (bind-mount it read-only and point `HMA_APNS_KEY_PATH` at the
mounted path).

## Plain `docker run`

```bash
docker volume create hma-data
docker run -d --name arbiter \
  -p 8000:8000 \
  -v hma-data:/data \
  --restart unless-stopped \
  ghcr.io/holdmyagent/arbiter:latest
docker logs arbiter   # first-boot tokens + admin password
```

## Updating

```bash
docker compose -f deploy/docker-compose.yml pull
docker compose -f deploy/docker-compose.yml up -d
```

The volume (and its `config.toml`/database) survives the container being
recreated. Database migrations run automatically on startup.
