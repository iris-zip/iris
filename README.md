# Iriszip

Browser-to-browser encrypted file and text transfer with no accounts, no app
install, and self-hostable infrastructure. Live at [iriszip.com](https://iriszip.com).

> Iriszip was originally codenamed **Beem**; the wire-protocol identifiers
> (`beem-v1 …`, `BEEM-CLOSE:`, `BEEM_*` env vars) intentionally retain the old
> name for protocol and deployment stability.

## Overview

- Open the site on two devices, match a 9-digit code (or scan a QR), and files
  and text move directly between them, end-to-end encrypted.
- Works across ecosystems: anything with a modern browser can pair with
  anything else, from an iPhone to an Xbox.
- Nothing is stored. Sessions are ephemeral; when they end, they are gone.
- The pairing itself is authenticated with a PAKE, and the session key is a
  hybrid of classical and post-quantum key exchange, independently reviewed.
- The whole thing is open source and self-hostable.

## Why Iriszip exists

Moving a file between two devices that belong to different ecosystems is still
strangely hard. Most tools want an account, an app on both sides, or a cloud
in the middle that holds your content. Iriszip started as a way to skip all of
that: open a URL on both devices, pair them, move the file. The security model
grew serious afterwards, because a tool that carries files between people
should not do encryption halfway.

Two promises define the design. No account. Nothing is stored.

## How a connection works

1. One side clicks **Send** and gets a 9-digit code plus a QR code.
2. The other side types the code, or scans the QR, which deep-links straight
   into the session.
3. When both sides show the connected view, the handshake has completed.
   Type text, or send a file (up to 1 GB).

Of the 9 digits, 6 are issued by the server and route the connection to the
right session. The other 3 are generated in the sender's browser and are never
sent to the server; they travel only inside the QR code, the link fragment, or
whatever channel you read the code over. The full 9-digit code is the SPAKE2
password, so a wrong code aborts the handshake on both ends before any data
flows. The routing code is valid for 60 seconds and pairs exactly two clients.

Once connected:

- Images render inline in the transcript, with a confirm step before sending.
- Every message has a copy button; long messages collapse behind **See more**.
- If the peer's browser is backgrounded (screen off, app switch, file picker),
  the session shows an honest "peer is away" state and recovers automatically.
- When one side leaves, the other side's session ends immediately.

## Connection lanes

WebRTC picks the best available path automatically; the UI labels which one
you got. Fastest to slowest:

1. **Direct LAN**: both devices on the same network, local network speed.
2. **P2P (internet)**: a direct hole-punched peer-to-peer path.
3. **Relay (TURN)**: a TURN relay forwards packets when a direct path cannot
   be established (common on mobile carriers behind CGNAT). Clients
   authenticate to it with short-lived credentials minted per session. It
   forwards ciphertext only.
4. **Server relay**: a WebSocket relay through the app server, the fallback if
   WebRTC fails entirely. Also ciphertext only.

Which lane you get affects speed, never confidentiality. Lanes 3 and 4 are
relayed, not peer-to-peer, and the labels say so deliberately; calling a
relayed path "peer-to-peer" would be untrue, so we don't.

## Cryptographic design

- **PAKE (SPAKE2):** the full 9-digit code is the password. Both sides derive
  a shared secret only if they hold the same code; a wrong code produces a
  different key and the handshake aborts before any data flows.
- **Classical KEX (X25519):** standard elliptic-curve Diffie-Hellman.
- **Post-quantum KEX (ML-KEM-768):** the NIST-standardized lattice KEM.
- **Key combine:** `key = HKDF-SHA256(PAKE_key ‖ X25519_shared ‖ ML-KEM_shared,
  salt=transcript, info="beem-v1 aead")`. The salt binds the full public
  handshake transcript. The session key holds as long as any one of the three
  primitives remains unbroken, including against an attacker recording today
  to decrypt with a future quantum computer.
- **Directional traffic keys:** the combined key is split via HKDF into two
  independent one-way keys, so the two directions never share a (key, nonce)
  pair.
- **Channel cipher:** ChaCha20-Poly1305 with a 12-byte monotonic-counter nonce
  per direction and transport. A tampered frame fails AEAD and is dropped.

The full protocol specification, wire format and test vectors are in
[`SPEC-PROTOCOL.md`](./SPEC-PROTOCOL.md). The crate inventory and what each
dependency is trusted for is in [`SPEC-CRATES.md`](./SPEC-CRATES.md).

## Independent cryptographic review

The Iriszip cryptographic protocol was independently reviewed by the
Scientific Cyber Security Association (SCSA), lead reviewer
Prof. Dr. Maksim Iavich, certificate dated 19 July 2026.

Scope reviewed: SPAKE2, X25519, ML-KEM-768, HKDF-SHA-256 hybrid key derivation
and transcript binding, and ChaCha20-Poly1305 AEAD. Every security objective
evaluated (authentication, confidentiality, integrity, forward secrecy, replay
and reflection resistance, MITM resistance, unknown key-share resistance,
transcript binding, hybrid key security, store-now-decrypt-later resistance,
and post-quantum readiness) was assessed as achieved under the review's stated
assumptions and adversarial model.

The public executive-summary certificate is in-repo at
[`client/certificate.pdf`](./client/certificate.pdf) and live at
[iriszip.com/certificate.pdf](https://iriszip.com/certificate.pdf).

The review covers the cryptographic protocol design only. It does not cover
endpoint compromise, side channels, or weak RNG. The certificate says so
explicitly, and so do we.

## What the server can and cannot see

The server is an opaque-byte relay. It sees the 6 routing digits (it issued
them), connection metadata while a session is alive, and, on relayed lanes,
the size and timing of ciphertext frames, like any relay would. Client
addresses are held in memory for rate limiting while a session runs and are
never logged or kept.

It cannot see the 3 secret digits, the derived keys, message text, file
contents, or filenames. It logs one line at startup and nothing else.

## Threat model

**In scope**

- Passive and active eavesdroppers on the network path.
- A curious or compromised relay operator (including us).
- An attacker recording traffic today for store-now-decrypt-later attacks
  with a future quantum computer.
- Anyone scraping or brute-forcing pairing codes.

**Out of scope**

- Compromised endpoint devices (keyloggers, malware, hostile OS).
- Malicious browser extensions with DOM access.
- Users coerced into typing a code under duress.
- Traffic-analysis deanonymization. Iriszip is not an anonymity tool; if that
  is your threat, use Tor.

## Server hardening

- `POST /new` is rate-limited per source IP, with an escalating cooldown and
  ban ladder behind it.
- WS frame and message size are capped at 200 KB (room for one 128 KB
  encrypted chunk).
- Session duration is capped at 60 minutes; the server closes cleanly after.
- Strict `^\d{6}$` validation of the routing code.
- Response headers: HSTS, strict CSP, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
- Zero content, addresses, or codes in server logs.

## Quick start (local)

Requires Rust (stable), `wasm-pack`, and a modern browser.

```
# build the WASM crypto module
cd crypto && wasm-pack build --target web --out-dir ../client/pkg

# run the server (binds 127.0.0.1:8080)
cd ../server && cargo run
```

Open `http://127.0.0.1:8080` in two browser tabs (or tab plus phone on the
same LAN if you flip the bind to `0.0.0.0`). See [`BUILD.md`](./BUILD.md) for
the full build story.

## Self-hosting

You can run your own instance; see [`SELFHOST.md`](./SELFHOST.md) for the
Docker single-image path (`docker compose up --build`) and for fronting a
self-hosted instance with a tunnel so no inbound port is exposed.

## Browser support and known limitations

Modern browsers on phones, tablets, laptops and desktops are the supported
surface. TV and console browsers vary: transfers and chat generally work, but
some TV browsers have no download manager, so a received file cannot be saved
there. The 1 GB file cap exists mainly because of mobile browser memory
limits, and may change.

## Repository structure and licenses

Iriszip is open source. Every part of it can be read, run, self-hosted, and
modified for free, by individuals and by companies, at any scale.

- **`client/`**: [MIT](./LICENSE.client). The code that runs in your browser.
  Fork it, embed it, ship it.
- **`crypto/`**: [Apache-2.0](./LICENSE.crypto). The reviewed encryption core,
  with an express patent grant, so it can be reused in other projects,
  including proprietary ones.
- **`server/`**: [AGPL-3.0](./LICENSE.server). Free to run, including inside a
  company. If you modify it and offer it to others over a network, AGPL
  section 13 requires you to publish your modified source.

## Commercial use

A commercial license that waives the AGPL publication obligation is available
for proprietary or embedded use; see [`ENTERPRISE.md`](./ENTERPRISE.md) or
contact admin@iriszip.com. Running the unmodified server inside your own
organization needs no commercial license at all.

## Reporting security issues

Email security@iriszip.com, never a public issue. [`SECURITY.md`](./SECURITY.md)
has the full policy and disclosure timeline;
[`client/.well-known/security.txt`](./client/.well-known/security.txt) is the
machine-readable pointer.

## Supporting the public service

The public site is free, with no ads and no tracking, and runs on donated
infrastructure time and bandwidth. If it is useful to you, iriszip.com/donate
lists the ways to help keep it running.
