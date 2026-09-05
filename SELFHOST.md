# Self-hosting Iriszip

Iriszip ships as a single Docker image: a static Rust binary plus the client's
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
Both matter for Iriszip specifically: WebSocket upgrade headers must pass
through (this is how devices pair and how encrypted frames relay), and the
proxy should set `X-Forwarded-For` so the server's per-IP rate limiting sees
the real client IP instead of the proxy's own address. The shipped
`docker-compose.yml` already tells the server to believe that header from the
compose bridge gateway (`IRIS_CLIENT_IP_HEADER` / `IRIS_TRUSTED_PROXIES` below);
if your proxy sends a different header, change the name there.

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
| `IRIS_CLIENT_IP_HEADER` | unset (no header read) | Name of the **one** forwarded-IP header to believe, e.g. `cf-connecting-ip` or `x-forwarded-for`. **Set this if a proxy fronts the server.** While it is unset the per-IP rate limits, the attempt budget, the 30-minute/24-hour ban ladder and the concurrent-connection cap all key on the TCP peer — which behind a proxy is the proxy, so every client shares one bucket. The server prints a startup notice saying so. |
| `IRIS_TRUSTED_PROXIES` | unset (loopback only) | Comma-separated exact addresses whose forwarded header is believed, and which are skipped as hops while walking it. Loopback is always trusted, so this is only needed when the proxy reaches the server from another address — **The shipped `docker-compose.yml` pins the bridge subnet to `172.28.0.0/24` and sets this to the gateway `172.28.0.1` for you.** If a header is configured but never gets believed, the server warns once. |
| `IRIS_ALLOWED_ORIGINS` | unset (same-origin only) | Comma-separated extra origins accepted on the `/ws` handshake, matched whole and including the scheme (e.g. `https://app.example`). By default a browser socket is accepted only when its `Origin` host matches the `Host` the server was addressed as; this refuses a hostile page from spending a visitor's attempt budget. Needed only when the page is served from a different host than the socket. A request with **no** `Origin` (a CLI client) is always allowed — only browsers are bound by that header. |
| `BEEM_AUDIT` | unset (off) | Set to `1` to log one stderr line per connection-end: `[audit] session=<ip-fingerprint> bytes_in=<n> bytes_out=<n> duration_s=<n>`. A paired session produces two lines (one per peer). Never logs content, pairing codes, or raw IPs — the fingerprint is salted with a random value minted at startup, so it correlates within one run of the server and cannot be traced back to an address afterwards. |

(`BEEM_` prefix is intentional — Iriszip was originally codenamed Beem; the
wire protocol and env vars keep the old name for deployment stability. See
`README.md`.)

Both branding vars are optional and off by default — leave them unset to
run with the stock Iriszip branding.

## Backups / ops

Nothing persists, so there is nothing to back up. Rooms, rate-limit state,
and session data all live in server memory and are discarded on session end
or process restart. Restarting the container is always safe — the worst
case is that any sessions mid-transfer at that moment are dropped and the
two devices need to re-pair.

## License

Self-hosting Iriszip — for your own team, for customers you serve directly, or
for personal use — is free. The server is AGPL-3.0 (`LICENSE.server`), the
crypto module is Apache-2.0 (`LICENSE.crypto`), and the client is MIT
(`LICENSE.client`). See `README.md` for the full breakdown.

Two practical notes for self-hosters:

- **If you run Iriszip unmodified, you have nothing extra to do.** The AGPL's
  source-offer obligation is satisfied by the public repository.
- **If you modify the server and let people outside your organisation use
  it over the network,** AGPL section 13 requires you to offer those users
  the corresponding source of your modified version. Publishing your fork,
  or linking it from the page, is enough.

A commercial license — which waives the copyleft obligation for proprietary
or embedded use — is available; see `ENTERPRISE.md`.
