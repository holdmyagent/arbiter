# Deploying with systemd (Linux)

`deploy/holdmyagent.service` runs Arbiter as a long-lived, sandboxed
service under a dedicated user.

```ini
[Unit]
Description=Hold My Agent — Arbiter approval server
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=holdmyagent
ExecStart=/opt/holdmyagent/venv/bin/hma serve
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=%h/.local/share/holdmyagent %h/.config/holdmyagent

[Install]
WantedBy=multi-user.target
```

`ProtectSystem=strict` makes the whole filesystem read-only to the
service except the two paths listed in `ReadWritePaths` — `%h` expands to
the `holdmyagent` user's home directory, and those two paths are exactly
where `hma init`/`hma serve` write `config.toml` and the SQLite database
by default. If you point `HMA_CONFIG`/`HMA_DB_PATH` elsewhere, add that
path to `ReadWritePaths` too, or the service will fail to start.

## Setup

1. Create a dedicated system user with a real home directory (systemd
   needs one to resolve `%h`):

   ```bash
   sudo useradd --system --create-home --home-dir /var/lib/holdmyagent \
     --shell /usr/sbin/nologin holdmyagent
   ```

2. Install Arbiter into a venv only that user can write to:

   ```bash
   sudo mkdir -p /opt/holdmyagent
   sudo python3 -m venv /opt/holdmyagent/venv
   sudo /opt/holdmyagent/venv/bin/pip install holdmyagent
   sudo chown -R holdmyagent:holdmyagent /opt/holdmyagent
   ```

3. Generate the config as that user:

   ```bash
   sudo -u holdmyagent /opt/holdmyagent/venv/bin/hma init
   ```

   This writes `/var/lib/holdmyagent/.config/holdmyagent/config.toml` and
   prints the tokens and admin password once — copy them down now.

4. Install and start the unit:

   ```bash
   sudo cp deploy/holdmyagent.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now holdmyagent
   ```

5. Check it came up:

   ```bash
   sudo systemctl status holdmyagent
   curl -fsS localhost:8000/health
   journalctl -u holdmyagent -f
   ```

## Binding to a LAN interface

By default the server binds `127.0.0.1`. To reach it from other devices
on your network, either set `host = "0.0.0.0"` in `config.toml`, or add
an environment override to the unit:

```ini
[Service]
Environment=HMA_HOST=0.0.0.0
```

then `sudo systemctl daemon-reload && sudo systemctl restart holdmyagent`.
As with the Docker image, binding `0.0.0.0` makes it reachable on the
LAN, not the internet — put a reverse proxy or Tailscale in front of it
for anything beyond that (see [`docs/deploy-nginx.md`](deploy-nginx.md)
and [`docs/deploy-tailscale.md`](deploy-tailscale.md)).

## Updating

```bash
sudo /opt/holdmyagent/venv/bin/pip install --upgrade holdmyagent
sudo systemctl restart holdmyagent
```

Database migrations run automatically on the next `hma serve` start.
