# Self-hosting Iris

Iris ships as a single Docker image: a static Rust binary plus the client's
static files, nothing else. There is no database, no external service
dependency, and no persistent state — every session's data lives in memory
for the duration of that session and is gone when it ends.

## Docker quick-start

Requires Docker with the Compose plugin.

From the repo root:

```
docker compose up --build
```

This builds three stages (WASM crypto module → SRI-stamped client → release
server binary → minimal `debian:stable-slim` runtime) and starts one
container, healthcheck included, listening on `127.0.0.1:8080`. Open
`http://127.0.0.1:8080` to confirm it's serving, then put a reverse proxy in
front of it (below) for real traffic.

The image binds to loopback only by design — it is not meant to be exposed
directly to the internet. Terminate TLS and handle the public-facing port at
your reverse proxy.

## Reverse proxy

Either of these terminates TLS and forwards to the container's `127.0.0.1:8080`.
Both matter for Iris specifically: WebSocket upgrade headers must pass
through (this is how devices pair and how encrypted frames relay), and the
proxy should set `X-Forwarded-For` so the server's per-IP rate limiting sees
the real client IP instead of the proxy's own loopback address.

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name iris.example.com;

    ssl_certificate     /etc/letsencrypt/live/iris.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/iris.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

### Caddy

Caddy proxies WebSockets and provisions TLS automatically — no extra
directives needed:

```
iris.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

## Environment variables

Set these on the `iris` service in `docker-compose.yml`. All are optional;
defaults match a typical single-machine deployment behind a reverse proxy.

| Variable | Default | Purpose |
|---|---|---|
| `BEEM_HOST` | `127.0.0.1` | Interface the server binds to inside the container. |
| `BEEM_PORT` | `8080` | Port the server binds to inside the container. |
| `BEEM_SESSION_SECS` | `3600` | Max lifetime of a paired session before the server force-closes it. |
| `BEEM_WORDMARK_TEXT` | unset (no override) | Replaces the landing-page wordmark text with your own brand name. |
| `BEEM_ACCENT_COLOR` | unset (no override) | Replaces the UI accent color (any valid CSS color value, e.g. `#ff6600`). |
| `BEEM_AUDIT` | unset (off) | Set to `1` to log one stderr line per connection-end: `[audit] session=<ip-fingerprint> bytes_in=<n> bytes_out=<n> duration_s=<n>`. A paired session produces two lines (one per peer). Never logs content, pairing codes, or raw IPs — the fingerprint is a salted hash. |

(`BEEM_` prefix is intentional — Iris was originally codenamed Beem; the
wire protocol and env vars keep the old name for deployment stability. See
`README.md`.)

Both branding vars are optional and off by default — leave them unset to
run with the stock Iris/Iriszip branding.

## Backups / ops

Nothing persists, so there is nothing to back up. Rooms, rate-limit state,
and session data all live in server memory and are discarded on session end
or process restart. Restarting the container is always safe — the worst
case is that any sessions mid-transfer at that moment are dropped and the
two devices need to re-pair.

## License

Self-hosting Iris internally — for your own team, customers you serve
directly, or personal use — is free under the license's use grant
(see `LICENSE.server`). A commercial license is required only if you intend
to run Iris as a public-facing hosted service offered to third parties as a
substantially similar product. The `client/` code is separately MIT-licensed
(see `LICENSE.client`). See `README.md` for the full license breakdown.
