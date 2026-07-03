# Deploying behind nginx

Arbiter has no built-in TLS — it expects a reverse proxy in front of it
for anything reachable outside your own machine. This is a complete nginx
server block: HTTPS termination, the `/v1/stream` WebSocket upgrade, and
the one header Arbiter actually checks (`X-Forwarded-Proto`) to decide
whether the dashboard's session cookie gets marked `Secure`.

## Server block

```nginx
upstream arbiter {
    server 127.0.0.1:8000;
}

# Required for WebSocket upgrade: nginx only sets the Connection header to
# "upgrade" when the client actually asked for one; otherwise it closes.
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    server_name arbiter.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name arbiter.example.com;

    ssl_certificate     /etc/letsencrypt/live/arbiter.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/arbiter.example.com/privkey.pem;

    # The dashboard's session cookie is only marked Secure when Arbiter sees
    # this header say "https" — without it, login still works but the
    # cookie loses the Secure flag.
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;

    # /v1/stream is a long-lived WebSocket (live dashboard updates); it
    # needs the Upgrade/Connection headers and a proxy_read_timeout longer
    # than the server's own 30s heartbeat, or nginx will kill it as idle.
    location /v1/stream {
        proxy_pass http://arbiter;
        proxy_http_version 1.1;
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 3600s;
    }

    location / {
        proxy_pass http://arbiter;
    }
}
```

## Getting a certificate

If you have a public DNS name pointed at the box, `certbot` will fetch
and renew the certificate referenced above:

```bash
sudo apt install certbot python3-certbot-nginx   # Debian/Ubuntu
sudo certbot --nginx -d arbiter.example.com
```

If Arbiter isn't meant to be reachable from the public internet at all —
which is the more common case, since it's a single-owner approval server
— skip the public certificate entirely and use
[`docs/deploy-tailscale.md`](deploy-tailscale.md) instead, which handles
TLS for you over your tailnet.

## Applying it

```bash
sudo cp arbiter.conf /etc/nginx/sites-available/arbiter.conf
sudo ln -s /etc/nginx/sites-available/arbiter.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

## Verifying

```bash
curl -fsS https://arbiter.example.com/health
# WebSocket upgrade check (expects HTTP/1.1 101):
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Key: $(openssl rand -base64 16)" -H "Sec-WebSocket-Version: 13" \
  -H "Authorization: Bearer <app_token>" \
  https://arbiter.example.com/v1/stream
```

If the WebSocket check hangs or returns a plain `400`/`404` instead of a
`101 Switching Protocols`, double-check the `map`/`Upgrade`/`Connection`
lines above — that's almost always a missed upgrade header, not an
Arbiter problem.

Arbiter itself should keep binding `127.0.0.1` (the default) behind this
proxy — there's no reason for the raw, unencrypted port to be reachable
from anywhere but the proxy on the same host.
