# Iris Crypto Crate Inventory (companion to SPEC-PROTOCOL.md)

Snapshot 2026-07-17, from `crypto/Cargo.lock`. "Documented" = the crate/project
documents the property; "Uncertain" = not independently verified line-by-line.

| Crate | Version | Constant-time / zeroization status |
|---|---|---|
| x25519-dalek | 2.0.1 | Documented: constant-time scalar mult; `Zeroize` on `StaticSecret`/`SharedSecret` (feature enabled here) |
| ml-kem (RustCrypto) | 0.2.3 | Documented: `ZeroizeOnDrop` on decapsulation key (feature enabled). Constant-time NTT/field math is a RustCrypto design goal — Uncertain (not line-verified) |
| chacha20poly1305 | 0.10.1 | Documented: constant-time cipher/MAC, subtle-based tag comparison on decrypt |
| spake2 | 0.5.0-pre.0 (pinned) | **Uncertain**: pre-release; NO zeroize impls anywhere in the crate; group ops via curve25519-dalek 5.0.0-pre.6 (separate pre-release line) |
| hkdf / sha2 / hmac | 0.12.4 / 0.10.9 / 0.12.1 | Documented: branch-free over secret data (RustCrypto) |
| zeroize | 1.8.2 | Documented: fence-protected best-effort wipe |
| subtle | 2.6.1 (transitive) | Constant-time primitives, used internally by dalek crates |
| curve25519-dalek | 4.1.3 (via x25519) + 5.0.0-pre.6 (via spake2) | Two major lines coexist — see watch-items |
| getrandom/rand_core (OsRng) | 0.2.17/0.6.4 (+0.4.2/0.10.1 transitive) | OS CSPRNG (browser: `crypto.getRandomValues`) |

Server (`server/Cargo.lock`): no TLS/AEAD/KEX crates at all — only `rand 0.8.5`
(`thread_rng`, a ChaCha-based CSPRNG reseeded from the OS) for pairing-code
generation. TLS terminates at Cloudflare/reverse proxy by design.

## Watch-items (booked, not bugs)

1. **spake2 0.5.0-pre.0 zeroization gap** — the crate never wipes the pairing
   code, `Password`, or `Spake2` internal state; our only cleanup is dropping/
   freeing the state. Exposure bounded by the ephemeral session + the pairing
   code's one-time nature. Revisit when spake2 publishes a stable release
   (upstream issue material).
2. **Duplicate hash stacks** — hkdf 0.13.0 / sha2 0.11.0 / hmac 0.13.0 are also
   compiled in transitively (via the spake2/ml-kem toolchain) next to the 0.12/
   0.10 line our code calls. Binary-size + supply-chain surface, not a
   functional issue. Collapse when spake2 stabilizes.
3. **Two curve25519-dalek majors** (4.1.3 + 5.0.0-pre.6) — same origin as (2).
