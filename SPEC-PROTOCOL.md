# Iris Protocol Specification (beem-v1)

Normative specification of the Iris handshake, key schedule, and record layer as
implemented in `crypto/src/lib.rs` + `client/app.js`. Written 2026-07-17 to satisfy
audit recommendations covering transcript serialization, zeroization,
counter exhaustion, constant-time behaviour and test vectors. Wire labels keep the
historical `beem-v1` prefix; changing them would break compatibility for zero
security gain.

## 1. Roles and pairing code

- **Sender** = SPAKE2 role **A**; **Receiver** = SPAKE2 role **B**.
  SPAKE2 identities are the single bytes `"A"` and `"B"`.
- Pairing code: exactly **6 ASCII decimal digits** (space = 10^6), generated
  server-side from the OS CSPRNG, single-use, burned after 5 room lookups.
- The relay server forwards opaque frames only; it contributes no cryptographic
  material and never sees any secret.

## 2. Handshake message sequence

All handshake frames are raw binary WebSocket messages, exact sizes enforced;
any size mismatch aborts. Order is fixed:

| # | Direction | Content | Size (bytes) |
|---|-----------|---------|------|
| 1 | B → A | `pakeMsgB (33) ‖ xPkB (32)` | 65 |
| 2 | A → B | `pakeMsgA (33) ‖ xPkA (32) ‖ mlEk (1184)` | 1249 |
| 3 | B → A | `mlCt` (ML-KEM-768 ciphertext) | 1088 |
| 4 | B → A | `ConfB` confirmation tag | 16 |
| 5 | A → B | `ConfA` confirmation tag | 16 |

(4 and 5 may cross on the wire; each side verifies the peer tag before entering
chat.) SPAKE2 messages are 33 bytes (Ed25519 group element, spake2 crate encoding
with role prefix consumed by the crate). X25519 public keys are 32-byte u-coordinates
(RFC 7748). ML-KEM-768 encodings are FIPS 203 byte strings (ek 1184, dk 2400,
ct 1088, ss 32).

## 3. Transcript serialization (normative)

```
T = xPkA ‖ xPkB ‖ mlEk ‖ mlCt          (32 + 32 + 1184 + 1088 = 2336 bytes)
```

- Concatenation order is fixed as above on **both** sides (sender's key first,
  regardless of which side computes it).
- Components are the raw encoded bytes exactly as sent on the wire — no length
  prefixes, no separators, no re-encoding. Unambiguous because every component
  has a fixed length.
- No optional fields exist in beem-v1. Any future optional field MUST be
  length-prefixed and MUST be included in T.
- SPAKE2 messages are deliberately not in T: the SPAKE2 output key `K_PAKE`
  enters the IKM (§4), which binds them cryptographically; the audit accepted
  this construction.

## 4. Key schedule

```
K_PAKE = SPAKE2-Ed25519(code, idA="A", idB="B")        (64 bytes)
K_ECDH = X25519(skX, peer xPk)                          (32 bytes; low-order/
         non-contributory peer keys are rejected)
K_PQ   = ML-KEM-768 shared secret                       (32 bytes)

IKM        = K_PAKE ‖ K_ECDH ‖ K_PQ
PRK        = HKDF-SHA256-Extract(salt = T, IKM)
derivedKey = HKDF-SHA256-Expand(PRK, "beem-v1 aead", 32)

# directional traffic keys (WebCrypto HKDF, salt = empty):
PRK2   = HKDF-SHA256-Extract(salt = "", derivedKey)
K_s2r  = HKDF-SHA256-Expand(PRK2, "beem-v1 s2r", 32)    sender → receiver
K_r2s  = HKDF-SHA256-Expand(PRK2, "beem-v1 r2s", 32)    receiver → sender

# key confirmation tags (first 16 bytes):
ConfA  = HKDF-SHA256-Expand(PRK2, "beem-v1 confirm-A", 32)[0..16]   sent by A
ConfB  = HKDF-SHA256-Expand(PRK2, "beem-v1 confirm-B", 32)[0..16]   sent by B
```

Each side verifies the **peer's** tag (directional labels prevent reflection by
the untrusted relay). Mismatch → abort "Wrong code" before any application data.

## 5. Record layer

Frame format (WS relay and every DataChannel path identical):

```
frame = type (1 byte) ‖ nonce (12 bytes) ‖ ChaCha20-Poly1305 ciphertext+tag
nonce = 0x00 0x00 0x00 ‖ transport (1 byte) ‖ counter (8 bytes, big-endian u64)
```

- `transport`: `0x00` = WebSocket relay, `0x01 + pathId` = DataChannel path
  (4 paths → `0x01..0x04`). Disjoint nonce spaces per transport/path.
- Each direction uses its own traffic key (§4), so identical counters in
  opposite directions can never collide.
- Encryption key: sender always uses its `sendKey`; frames >200 KiB are
  rejected before decrypt.
- Replay: WS counters must be strictly increasing; DC paths use a 1024-bit
  sliding window (DTLS/IPsec style), recorded only after successful
  authentication.

### Counter exhaustion (normative)

Counters are 64-bit. Before constructing any nonce, the implementation MUST
check `counter >= 2^64 − 1` and, if reached, terminate the session immediately
("Session ended: counter exhausted.") without emitting the frame. Counters
increment only after a nonce is successfully issued and are never reset within
a session (including transport fallback/reconnect, which reuses the same key
and counter space). Re-establishment requires a full new handshake with a fresh
pairing code.

## 6. Zeroization (normative)

On session end/abort (`zeroizeKeys()`, client) the following are overwritten
with zeros then dereferenced: `derivedKey, sendKey, recvKey, pakeKey, xShared,
xSk, xPk, mlDk, mlEk, ownPakeMsg, myHash, expectedPeerHash`; the SPAKE2 state
handle is freed (drops the scalar inside WASM memory). During the handshake,
intermediates are wiped at the point of use: keypair output buffers, ML-KEM
shared-secret copies, encaps output, and the Rust side zeroizes its local
copies of secret bytes (secret-key arrays, decapsulation-key copies, the
concatenated IKM) on every path, including error paths.

**Accepted residuals (documented):**
1. wasm-bindgen FFI marshalling buffers (the temporary copies the JS↔WASM glue
   makes when passing byte arrays) are not reachable for explicit zeroization
   (internal design notes).
2. The `spake2 0.5.0-pre.0` crate implements no zeroization internally: the
   pairing code bytes and SPAKE2 group state are dropped, not wiped, inside
   WASM memory (see `SPEC-CRATES.md` watch-item 1).

Ephemeral session model + process memory protection bound both exposures;
implementation-level Medium risk common to WASM crypto.

## 7. Constant-time properties

The protocol relies on the constant-time guarantees of the underlying
RustCrypto/dalek crates; confirmation-tag comparison on the client uses a
fixed-length byte comparison over 16-byte HKDF outputs (both operands are
derived secrets — no attacker-controlled early exit). Crate inventory and their
documented constant-time properties: see `SPEC-CRATES.md` (companion file).

## 8. Test vectors

Independently computed from RFC 5869 (HKDF) and RFC 8439 (ChaCha20-Poly1305);
conforming implementations MUST reproduce them. (Handshake-level vectors for
SPAKE2/X25519/ML-KEM require deterministic RNG injection and are deliberately
out of scope for v1 — the primitives carry their own FIPS/RFC vectors.)

**V1 — hkdf_combine.** Inputs: `K_PAKE = 0x01 × 64`, `K_ECDH = 0x02 × 32`,
`K_PQ = 0x03 × 32`, `T = 0xA1×32 ‖ 0xA2×32 ‖ 0xB1×8 ‖ 0xB2×8` (vector-only
shortened transcript; real T is 2336 bytes).

```
derivedKey = 1b0214ca97649d1a7e6792026fb7c86b121d71ed01004d9c5dfb914ba17e41a0
```

**V2 — directional keys** from V1 `derivedKey`:

```
K_s2r = c42478fb7734da5ea586d5acc719ad0b5a14d5521b327a7fc335982a7d0b3183
K_r2s = fe01e264c6fdf8290b80686eaeb753f319f4be21f6c180c67aba1d2544922dff
```

**V3 — confirmation tags** from V1 `derivedKey`:

```
ConfA = 9dca258d01cea5aed1210da7a2ea2e98
ConfB = 69069a10a668dcb64682879baf829c5c
```

**V4 — record encryption.** Key = `K_s2r` (V2), nonce = transport 0 /
counter 0, plaintext = `"hello beem"`, no AAD:

```
nonce     = 000000000000000000000000
ct ‖ tag  = 724b433ad03ad3d8fb57ebb5a9aec5cf37ec051c1eecd05efa55
```

**V5 — nonce construction.** DC path 2 (transport byte `0x03`), counter 1:

```
nonce = 000000030000000000000001
```

**Replay rejection (behavioral):** after a frame with counter *c* is accepted
on WS, any frame with counter ≤ *c* MUST be rejected before decryption. On a DC
path, a duplicate counter within the 1024-bit window MUST be rejected; a
counter more than 1024 behind the watermark MUST be rejected.
