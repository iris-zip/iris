# Iris

End-to-end encrypted, post-quantum-hybrid, ephemeral text and file transfer between any devices — Apple, Android, PC, Mac, console, anything with a browser. Pair two devices with a 6-digit code, type or drop a file, done. No accounts, no ads, no logs, no persistence. Live at [iriszip.com](https://iriszip.com).

> Iris was originally codenamed **Beem**; the wire-protocol identifiers (`beem-v1 …`, `BEEM-CLOSE:`, `BEEM_*` env vars) intentionally retain the old name for protocol and deployment stability.

## Why

Most "send file to my other device" tools either:

- route through a third-party relay that can see your content, or
- ship a chat/SaaS app with accounts, logs, analytics, and a huge attack surface, or
- use classical crypto only, so a future quantum-capable attacker who records today can decrypt years later.

Iris is the opposite: nothing is persisted, the relay is blind, and the session key is hybrid — an attacker must break SPAKE2 *and* X25519 *and* ML-KEM-768 to read a transcript, classical or quantum.

## Quick start (local)

Requires Rust (stable), `wasm-pack`, and a modern browser.

```
# build the WASM crypto module
cd crypto && wasm-pack build --target web --out-dir ../client/pkg

# run the server (binds 127.0.0.1:8080)
cd ../server && cargo run
```

Open `http://127.0.0.1:8080` in two browser tabs (or tab + phone on the same LAN if you flip the bind to `0.0.0.0`).

## Usage

1. On the first tab click **Send**. A 6-digit code appears, alongside a QR code.
2. On the second tab click **Receive**, enter the code, hit **Join** — or just scan the QR code with the other device's camera, which deep-links straight into the session and auto-joins with no typing.
3. When both tabs show the chat view, the hybrid handshake finished successfully.
4. Type text, or click **Send file…** to transfer a file (up to 1 GB).

The 6-digit code is valid for 60 seconds; each code is single-use and pairs exactly two clients.

Once in the chat view:

- Images up to 10 MB render inline in the transcript on both sides, with a confirm step before sending.
- Every message has a copy button.
- Long messages collapse behind a fade with **See more** / **See less**.
- If the peer's browser is backgrounded (phone screen off, app switch), the session shows an honest "peer is away" state and recovers automatically instead of dying.
- When one side leaves, the other side's session vanishes immediately rather than waiting for a timeout.

## Connection lanes

WebRTC picks the best available path automatically; the UI labels which one you got. Fastest to slowest:

1. **Direct LAN** — both devices on the same network.
2. **P2P (internet)** — a direct hole-punched peer-to-peer path.
3. **Relay (TURN)** — a TURN relay forwards packets when a direct path can't be established (common on mobile carriers behind CGNAT). The relay is Iris's own coturn server; clients authenticate to it with short-lived credentials (2-hour expiry) minted on demand. It forwards ciphertext only and cannot read anything.
4. **WebSocket relay through the app server** — the fallback if WebRTC fails entirely. Also ciphertext only.

Which lane you get affects speed, never confidentiality.

## How the security works

- **PAKE (SPAKE2 over Ed25519):** the 6-digit code is never sent over the network; both sides derive a shared secret *only if* they typed the same code. A wrong code produces a different key and the handshake aborts before any data flows.
- **Classical KEX (X25519):** standard elliptic-curve Diffie-Hellman.
- **Post-quantum KEX (ML-KEM-768):** the NIST-standardized Kyber lattice KEM. Resistant to attackers with large-scale quantum computers.
- **Key combine:** `key = HKDF-SHA256(PAKE_key ‖ X25519_shared ‖ ML-KEM_shared, salt=transcript, info="beem-v1 aead")` — the salt binds the full public handshake transcript. The session key is safe as long as *any one* of the three primitives remains unbroken.
- **Directional traffic keys:** the combined key is split via HKDF into two independent one-way keys (sender→receiver and receiver→sender), so the two directions never share a (key, nonce) pair.
- **Channel cipher:** ChaCha20-Poly1305 with a 12-byte monotonic-counter nonce per direction and transport. Every frame carries its own nonce; a tampered frame fails AEAD and is dropped.
- **Server role:** pure opaque-byte relay over WebSocket. It never learns the code value, key, plaintext, filenames, or sizes. It logs exactly one line at startup (the listen banner) and nothing else.

The full rationale lives in the project's internal design notes.

## Threat model

**In scope**

- Passive and active eavesdroppers on the network path.
- A curious or compromised relay operator (including us).
- A nation-state actor recording today for *store-now-decrypt-later* attacks with a future quantum computer.
- Data brokers scraping codes or trying to brute-force them.

**Out of scope (MVP)**

- Compromised endpoint devices (keyloggers, malware, hostile OS).
- Malicious browser extensions with DOM access.
- Users coerced into typing a code under duress.
- Traffic-analysis-based deanonymization (Iris is not an anonymity tool; use Tor if that is your threat).

## Hardening (phase 12, already shipped)

- `POST /new` rate-limited per source IP (10-request burst, ~10/min sustained).
- WS frame and message size capped at 200 KB (room for one 128 KB encrypted chunk).
- Session duration capped at 60 minutes; server closes cleanly after.
- Strict `^\d{6}$` validation of the code query parameter.
- Response headers: HSTS, strict CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
- Zero content, IP, or code in server logs.

## Independent cryptographic security review

The Iris cryptographic protocol was independently reviewed by the Scientific Cyber Security Association (SCSA), lead reviewer Prof. Dr. Maksim Iavich, certificate dated 19 July 2026.

Scope reviewed: SPAKE2, X25519, ML-KEM-768, HKDF-SHA-256 hybrid key derivation and transcript binding, and ChaCha20-Poly1305 AEAD. Every security objective evaluated — authentication, confidentiality, integrity, forward secrecy, replay and reflection resistance, MITM resistance, unknown key-share resistance, transcript binding, hybrid key security, store-now-decrypt-later resistance, and post-quantum readiness — was assessed as achieved under the review's stated assumptions and adversarial model.

The public executive-summary certificate is in-repo at [`client/certificate.pdf`](./client/certificate.pdf), and live at [iriszip.com/certificate.pdf](https://iriszip.com/certificate.pdf).

The review covers the cryptographic protocol design only. It does not cover endpoint compromise, side channels, or weak RNG — the certificate says so explicitly.

## Reporting security issues

See [`client/.well-known/security.txt`](./client/.well-known/security.txt) (contact: admin@iriszip.com) for details and disclosure timeline.

## Licenses

- **`server/` and `crypto/`** — see the LICENSE files in this repository for this release's terms.
- **`client/`** — [MIT](./LICENSE.client). The client is public-facing code; MIT signals we trust it to be forked and embedded.

## Self-hosting

Iris can be self-hosted, so you can run your own instance. There's more than one way to expose it to the internet; see [`SELFHOST.md`](./SELFHOST.md) for the Docker single-image path (`docker compose up --build`). Below is one specific option: fronting a self-hosted instance with a Cloudflare Tunnel.

### Option: Cloudflare Tunnel

A home or VPS machine can be made reachable from the internet via [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) without opening an inbound port. This hides the origin IP, terminates TLS on Cloudflare's edge, and gives you DDoS protection for free. The `iris.example.com` hostname below is a placeholder — substitute your own domain.

One-time setup (run these commands manually):

```
# 1. install cloudflared (see Cloudflare's docs for your distro)

# 2. authenticate once — opens a browser
cloudflared tunnel login

# 3. create a named tunnel
cloudflared tunnel create iris

# 4. point a DNS record at it (replace iris.example.com with your domain)
cloudflared tunnel route dns iris iris.example.com
```

Create `~/.cloudflared/config.yml`:

```yaml
tunnel: iris
credentials-file: /home/<user>/.cloudflared/<tunnel-id>.json

ingress:
  - hostname: iris.example.com
    service: http://127.0.0.1:8080
  - service: http_status:404
```

Run the tunnel and the server in parallel:

```
cloudflared tunnel run iris
# in another shell:
cd server && cargo run --release
```

Keep the server bound to `127.0.0.1:8080` — Cloudflare connects over the outbound tunnel, so there is no open inbound port on your router and your home IP never appears in a response.

When testing, verify:

- `https://iris.example.com` loads with a valid Cloudflare TLS cert.
- WebSocket connection upgrades to `wss://` automatically (the client picks `wss` when `location.protocol === "https:"`).
- `curl -I https://iris.example.com` response headers include Cloudflare's `cf-ray` and do **not** expose your origin IP anywhere.

## Roadmap

Iris is developed in numbered phases. Post-1.0 plans include:

- SCSA QRNG entropy integration (Phase 14) so the 6-digit codes come from a verifiable quantum random-number generator, with OS CSPRNG as a fallback.
