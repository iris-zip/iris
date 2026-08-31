# Changelog

Notable changes to Iriszip, newest first.

Versions follow [semantic versioning](https://semver.org/). Iriszip is one product with
one version number: the git tag, `server/Cargo.toml` and `crypto/Cargo.toml` always
agree. A change to the wire protocol or the key schedule is a major version, because
two peers on different major versions cannot talk to each other.

## 1.0.0 — 2026-08-31

First public release. Everything below is what 1.0.0 contains, not what changed
since some earlier version — there was no earlier public version.

### Pairing and transport

- Pair two devices with a 9-digit code; its 6 routing digits are valid for 60
  seconds, single-use, good for exactly two clients. Or scan the QR code and skip
  the typing entirely.
- Four connection paths, picked automatically and labelled honestly in the interface:
  direct LAN, peer-to-peer over the internet, a TURN relay for carrier networks
  behind CGNAT, and a WebSocket relay through the app server if WebRTC fails
  outright. Which path you get changes the speed and nothing else — every path
  carries the same ciphertext.
- Transfers survive a network change. Switch from WiFi to mobile data mid-file and
  the session reconnects rather than dying.
- Files up to 1 GB. Images up to 10 MB preview inline on both sides.
- Data is striped across parallel channels, each with its own nonce space.
- If chunks go missing, the receiver asks for them again instead of failing the
  whole transfer.

### Cryptography

- Three of the code's 9 digits are generated in the browser and never sent to the
  server; only the 6 routing digits ever reach it. SPAKE2 over Ed25519 runs on the
  full code: both sides derive the same secret only if they hold the same code, and
  a wrong code produces a different key and the handshake stops before any data moves.
- The session key combines three independent key exchanges — SPAKE2, X25519, and
  ML-KEM-768 — through HKDF-SHA-256, salted with the full handshake transcript. An
  attacker has to break all three. ML-KEM-768 is there for the recorded-now,
  decrypted-later problem.
- Each direction gets its own one-way key, so the two directions can never collide
  on a nonce.
- ChaCha20-Poly1305 for the channel, with a monotonic counter nonce per direction and
  per transport. A tampered frame fails authentication and is dropped.
- Keys are wiped on teardown. The panic button wipes a session immediately.
- The protocol has been reviewed by an outside cryptanalysis organisation. Their
  certificate is published here as `certificate.pdf`.

### What the server knows

- Nothing. It relays opaque bytes. It never sees the code, the key, the plaintext,
  filenames, or file sizes.
- It writes one log line at startup and nothing after that. No addresses, no
  identifiers, no record of who connected to whom.
- Nothing is written to disk. Relayed bytes pass through memory and are gone.

### Interface

- A SHA-256 receipt for every completed file, computed independently on both ends
  and compared, so "delivered" means the receiver confirmed the bytes — not that the
  sender finished uploading.
- The connection state shown on screen is the real one. If the peer's phone is
  backgrounded it says so, and recovers on its own. If one side leaves, the other
  side's session disappears immediately instead of hanging on a timeout.
- Drag and drop, paste an image from the clipboard, copy any message, collapse long
  ones.
- Dark and light themes.

### Running it yourself

- Docker Compose and a plain binary both work. See [`SELFHOST.md`](./SELFHOST.md).
- The Rust toolchain is pinned, so the WASM module builds reproducibly. Expected
  hashes are in [`BUILD.md`](./BUILD.md).
- Browser test suite and CI included.

### Licensing

- `server/` — AGPL-3.0, with a commercial licence available for organisations that
  cannot accept AGPL terms.
- `crypto/` — Apache-2.0, including the patent grant.
- `client/` — MIT.

---

Iriszip was originally codenamed **Beem**. The wire-protocol identifiers (`beem-v1`,
`BEEM-CLOSE:`, `BEEM_*` environment variables) deliberately keep the old name, so
renaming the project did not break anyone's deployment.
