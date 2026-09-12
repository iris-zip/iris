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
| `IRIS_TURN_URLS` | unset (no TURN lane) | Comma-separated ICE server URLs handed to browsers once they have joined a room, e.g. `stun:turn.example.com:3478,turn:turn.example.com:3478?transport=udp,turns:turn.example.com:443?transport=tcp`. Set together with `IRIS_TURN_SECRET`; with either unset the server does not serve `/turn.json` and there is no TURN lane (see **Relay** below). |
| `IRIS_TURN_SECRET` | unset | The shared secret of your coturn `use-auth-secret` setup. From it the server mints one short-lived TURN REST credential per session (`username = <unix expiry>:<room tag>`, `credential = base64(HMAC-SHA1(secret, username))`), valid for 75 minutes (the default session lifetime plus 15), and only to a browser that proves membership of a live room. The value never appears in the repo or in any log. |
| `BEEM_MAX_RELAY_BYTES` | `12884901888` (12 GiB) | Ceiling on the bytes the WebSocket relay lane moves for one session, charged twice (inbound from the sender and outbound to the receiver), so the default carries about 6 GiB of payload. Both peers are warned at 80 %. Set `0` to disable the ceiling on bandwidth you pay for yourself. A resource bound, not a confidentiality control: the server holds no keys. |

(`BEEM_` prefix is intentional — Iriszip was originally codenamed Beem; the
wire protocol and env vars keep the old name for deployment stability. See
`README.md`.)

Both branding vars are optional and off by default — leave them unset to
run with the stock Iriszip branding.

## Relay (STUN/TURN)

A transfer tries a direct WebRTC path first (same network, then hole-punched
across the internet). When no direct path exists, packets go through a TURN
relay if you have configured one, otherwise through the WebSocket relay inside
this server. Both carry ciphertext only; the lane changes speed, never
confidentiality.

- **With `IRIS_TURN_URLS` and `IRIS_TURN_SECRET` set**, browsers fetch your
  relay's address and a per-session credential from `/turn.json` after joining
  a room, and no packet of a transfer touches any host but yours.
- **With them unset, the default, the browser asks a public STUN server
  (`stun:stun.l.google.com:19302`) for its own public address.** This fallback
  is intentional: it is what lets a bare `docker compose up` work without a
  second machine. STUN carries no file data, no pairing code and no key; it
  answers "what is my address as seen from outside". There is no TURN lane in
  this mode; the fallback when no direct path exists is the WebSocket relay
  above. Point the two variables at your own coturn when your policy requires
  that nothing leaves your infrastructure.

Minimal coturn `turnserver.conf` matching the credentials the server mints:

```
listening-port=3478
fingerprint
use-auth-secret
# plus coturn's shared-secret directive, set to the same value as IRIS_TURN_SECRET
realm=turn.example.com
no-stdout-log
log-file=/dev/null
```

The last two lines keep coturn from writing peer addresses anywhere; keep them
if your instance is to log nothing about users. Open 3478 (UDP and TCP) and
coturn's relay port range on the firewall. For a `turns:` URL on 443 add
`tls-listening-port=443`, `cert=` and `pkey=`.

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
