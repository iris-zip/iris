# Iriszip

Browser-to-browser encrypted file and text transfer with no accounts, no app
install, and self-hostable infrastructure. Live at [iriszip.com](https://iriszip.com).

> Iriszip was originally codenamed **Beem**; the wire-protocol identifiers
> (`beem-v1 …`, `BEEM-CLOSE:`, `BEEM_*` env vars) intentionally retain the old
> name for protocol and deployment stability.

## Overview

- Open the site on two devices, match a 9-digit code (or scan a QR), and files
  and text move directly between them, end-to-end encrypted.
- Works across modern phone, tablet, laptop and desktop browsers, regardless
  of ecosystem. TV and console support varies by browser.
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

## How this was built

Most of the code in this repository was written with an AI coding agent
(Claude Code). I designed the protocol, decided what gets built and in what
order, review every change, and run the test suites before anything ships.
Iriszip is a solo project, and this is how one person builds and maintains
something of this scope.

What that does and does not mean for trust:

| Part | Independently reviewed? |
|---|---|
| Cryptographic protocol design | Yes: SCSA review, certificate above |
| Implementation (crypto core, server, client) | No |

So the reviewed part and the machine-written part are not the same part, and
you should read the review claim exactly that narrowly. What compensates:

- The crypto core (`crypto/src/lib.rs`) is small, a little over 200 lines
  outside its tests, and uses standard primitives in standard constructions
  only: SPAKE2, X25519, ML-KEM-768, HKDF-SHA-256, ChaCha20-Poly1305, from the
  RustCrypto and dalek crates. Nothing novel, nothing hand-rolled.
- It carries known-answer tests against published vectors (RFC 7748,
  Wycheproof, NIST SHA-256) and negative-path tests for every rejection it is
  supposed to make, in-repo, runnable with one command (see `BUILD.md`).
- You do not have to trust anyone about what the site actually runs. The
  served JavaScript and WASM are byte-verifiable against this repository
  through `HASHES.md` and the SRI hashes in `index.html`. The limit: SRI
  covers the declared subresources, not the HTML that declares them, which
  is why the hashes are also published here.
- Implementation review is welcome and cheap to start: the protocol is
  specified in `SPEC-PROTOCOL.md`, and the trusted surface is the one file
  above. Findings go to security@iriszip.com.

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

Tor Browser works at its Standard security level. The higher levels disable
WebAssembly, which the encryption core needs, so Iriszip deliberately refuses
to start rather than run unverified. On Tor, transfers use the relay lane,
because Tor disables WebRTC by design.

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

The public site is free, with no ads and no tracking. When both devices share
a network, the transfer goes directly between them and costs nothing to carry.
When they are far apart, the relayed paths run on infrastructure the project
pays for out of pocket. Donations keep those paths open for everyone;
[iriszip.com/donate](https://iriszip.com/donate) lists the ways to help.
