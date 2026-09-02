// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Scar

use chacha20poly1305::{
    aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce,
};
use hkdf::Hkdf;
use ml_kem::{
    array::{typenum::Unsigned, Array},
    kem::{Decapsulate, Encapsulate},
    EncodedSizeUser, KemCore, MlKem768,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

#[wasm_bindgen]
pub struct PakeState {
    inner: Spake2<Ed25519Group>,
    first_msg: Vec<u8>,
}

#[wasm_bindgen]
impl PakeState {
    #[wasm_bindgen(getter)]
    pub fn msg(&self) -> Vec<u8> {
        self.first_msg.clone()
    }
}

// Double-call protection lives at the FFI boundary, not here: wasm-bindgen
// consumes the JS handle (nulls its pointer) before this body runs, so a second
// call on the same handle throws the glue's "null pointer passed to rust"
// TypeError. An in-struct guard could never fire.
#[wasm_bindgen]
pub fn finish_pake(state: PakeState, peer_msg: &[u8]) -> Result<Vec<u8>, JsError> {
    state
        .inner
        .finish(peer_msg)
        .map_err(|e| JsError::new(&format!("pake finish: {:?}", e)))
}

#[wasm_bindgen]
pub fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    if key.len() != 32 {
        return Err(JsError::new("key must be 32 bytes"));
    }
    if nonce.len() != 12 {
        return Err(JsError::new("nonce must be 12 bytes"));
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|e| JsError::new(&format!("encrypt: {:?}", e)))
}

#[wasm_bindgen]
pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
    if key.len() != 32 {
        return Err(JsError::new("key must be 32 bytes"));
    }
    if nonce.len() != 12 {
        return Err(JsError::new("nonce must be 12 bytes"));
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| JsError::new(&format!("decrypt: {:?}", e)))
}

// ---- X25519 ----
#[wasm_bindgen]
pub fn x25519_keypair() -> Vec<u8> {
    let sk = StaticSecret::random_from_rng(OsRng);
    let pk = PublicKey::from(&sk);
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(sk.as_bytes());
    out.extend_from_slice(pk.as_bytes());
    out
}

#[wasm_bindgen]
pub fn x25519_shared(sk_bytes: &[u8], peer_pk: &[u8]) -> Result<Vec<u8>, JsError> {
    if sk_bytes.len() != 32 || peer_pk.len() != 32 {
        return Err(JsError::new("x25519: keys must be 32 bytes"));
    }
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(sk_bytes);
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(peer_pk);
    let sk = StaticSecret::from(sk_arr);
    sk_arr.zeroize(); // From copies — wipe the local copy of the secret key
    let pk = PublicKey::from(pk_arr);
    let shared = sk.diffie_hellman(&pk);
    // Reject low-order / non-contributory peer keys (these force an all-zero
    // shared secret). Defense-in-depth — the hybrid construction already prevents
    // exploitation, but an explicit check removes the reliance on that assumption.
    if !shared.was_contributory() {
        return Err(JsError::new("x25519: non-contributory peer key rejected"));
    }
    Ok(shared.as_bytes().to_vec())
}

// ---- ML-KEM-768 ----
type MlEk = <MlKem768 as KemCore>::EncapsulationKey;
type MlDk = <MlKem768 as KemCore>::DecapsulationKey;

#[wasm_bindgen]
pub fn mlkem_keygen() -> Vec<u8> {
    let (dk, ek) = MlKem768::generate(&mut OsRng);
    let mut dk_bytes = dk.as_bytes();
    let ek_bytes = ek.as_bytes();
    let mut out = Vec::with_capacity(dk_bytes.len() + ek_bytes.len());
    out.extend_from_slice(&dk_bytes);
    out.extend_from_slice(&ek_bytes);
    dk_bytes.as_mut_slice().zeroize(); // encoded copy of the decapsulation key
    out
}

#[wasm_bindgen]
pub fn mlkem_ek_len() -> usize {
    <MlEk as EncodedSizeUser>::EncodedSize::USIZE
}

#[wasm_bindgen]
pub fn mlkem_dk_len() -> usize {
    <MlDk as EncodedSizeUser>::EncodedSize::USIZE
}

#[wasm_bindgen]
pub fn mlkem_encaps(ek_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    let arr = Array::try_from(ek_bytes)
        .map_err(|_| JsError::new("mlkem_encaps: bad ek length"))?;
    let ek = <MlEk as EncodedSizeUser>::from_bytes(&arr);
    let (ct, mut ss) = ek
        .encapsulate(&mut OsRng)
        .map_err(|e| JsError::new(&format!("encaps: {:?}", e)))?;
    let mut out = Vec::with_capacity(ct.len() + ss.len());
    out.extend_from_slice(&ct);
    out.extend_from_slice(&ss);
    ss.as_mut_slice().zeroize(); // local copy of the shared secret
    Ok(out)
}

#[wasm_bindgen]
pub fn mlkem_decaps(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    let mut dk_arr = Array::try_from(dk_bytes)
        .map_err(|_| JsError::new("mlkem_decaps: bad dk length"))?;
    let dk = <MlDk as EncodedSizeUser>::from_bytes(&dk_arr);
    dk_arr.as_mut_slice().zeroize(); // local copy of the decapsulation key
    let ct_arr = Array::try_from(ct_bytes)
        .map_err(|_| JsError::new("mlkem_decaps: bad ct length"))?;
    let mut ss = dk
        .decapsulate(&ct_arr)
        .map_err(|e| JsError::new(&format!("decaps: {:?}", e)))?;
    let out = ss.to_vec();
    ss.as_mut_slice().zeroize(); // local copy of the shared secret
    Ok(out)
}

// ---- HKDF-SHA256 combiner ----
// transcript = xPkA ‖ xPkB ‖ mlEk ‖ mlCt — binds all public handshake material into the salt
#[wasm_bindgen]
pub fn hkdf_combine(
    pake_key: &[u8],
    x_shared: &[u8],
    kem_shared: &[u8],
    transcript: &[u8],
) -> Result<Vec<u8>, JsError> {
    let mut ikm = Vec::with_capacity(pake_key.len() + x_shared.len() + kem_shared.len());
    ikm.extend_from_slice(pake_key);
    ikm.extend_from_slice(x_shared);
    ikm.extend_from_slice(kem_shared);
    let hk = Hkdf::<Sha256>::new(Some(transcript), &ikm);
    let mut out = [0u8; 32];
    let res = hk.expand(b"beem-v1 aead", &mut out);
    ikm.zeroize(); // ikm concatenates all three shared secrets — wipe on every path
    res.map_err(|e| JsError::new(&format!("hkdf: {:?}", e)))?;
    Ok(out.to_vec())
}

#[wasm_bindgen]
pub fn start_pake(code: &str, role: &str) -> Result<PakeState, JsError> {
    // The protocol layer enforces a 9-digit code; this guard makes the
    // module self-defending if reused elsewhere — an empty password must not
    // silently produce a PAKE protected by nothing. Upper bound is sanity only.
    if code.is_empty() || code.len() > 64 {
        return Err(JsError::new("invalid code length"));
    }
    let password = Password::new(code.as_bytes());
    let id_a = Identity::new(b"A");
    let id_b = Identity::new(b"B");
    let (state, msg) = match role {
        "A" => Spake2::<Ed25519Group>::start_a(&password, &id_a, &id_b),
        "B" => Spake2::<Ed25519Group>::start_b(&password, &id_a, &id_b),
        _ => return Err(JsError::new("invalid role: must be \"A\" or \"B\"")),
    };
    Ok(PakeState {
        inner: state,
        first_msg: msg,
    })
}

// 21.2 Streaming SHA-256 for file checksums: chunks are hashed as they pass
// through the transfer path, so neither side materializes the whole file in a
// second buffer just to hash it (previously a 2× RAM spike on receive).
#[wasm_bindgen]
pub struct Sha256Stream {
    inner: Sha256,
}

#[wasm_bindgen]
impl Sha256Stream {
    #[wasm_bindgen(constructor)]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Sha256Stream {
        Sha256Stream { inner: Sha256::new() }
    }

    pub fn update(&mut self, chunk: &[u8]) {
        self.inner.update(chunk);
    }

    /// Lowercase hex digest; resets the state so the handle can't double-finalize.
    pub fn finalize_hex(&mut self) -> String {
        let done = std::mem::replace(&mut self.inner, Sha256::new());
        done.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    wasm_bindgen_test_configure!(run_in_browser);

    // TEST-W-001 — PAKE success: same code → identical derived keys
    #[wasm_bindgen_test]
    fn test_pake_success() {
        let pa = start_pake("123456789", "A").unwrap();
        let pb = start_pake("123456789", "B").unwrap();
        let msg_a = pa.msg();
        let msg_b = pb.msg();
        let key_a = finish_pake(pa, &msg_b).unwrap();
        let key_b = finish_pake(pb, &msg_a).unwrap();
        assert_eq!(key_a, key_b);
        assert_eq!(key_a.len(), 32);
    }

    // TEST-W-002 — PAKE mismatch: different codes → keys must NOT match
    #[wasm_bindgen_test]
    fn test_pake_mismatch() {
        let pa = start_pake("123456789", "A").unwrap();
        let pb = start_pake("987654321", "B").unwrap();
        let msg_a = pa.msg();
        let msg_b = pb.msg();
        let key_a = finish_pake(pa, &msg_b).unwrap();
        let key_b = finish_pake(pb, &msg_a).unwrap();
        assert_ne!(key_a, key_b, "mismatched codes must not produce equal keys");
    }

    // TEST-W-003 — ChaCha20-Poly1305 roundtrip
    #[wasm_bindgen_test]
    fn test_chacha_roundtrip() {
        let key   = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plain = b"hello beem";
        let ct = encrypt(&key, &nonce, plain).unwrap();
        let pt = decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, plain);
    }

    // TEST-W-004 — AEAD tamper rejection: flipped byte → decrypt must error
    #[wasm_bindgen_test]
    fn test_chacha_tamper_rejected() {
        let key   = [0x42u8; 32];
        let nonce = [0u8; 12];
        let mut ct = encrypt(&key, &nonce, b"tamper test").unwrap();
        *ct.last_mut().unwrap() ^= 0xff;
        assert!(decrypt(&key, &nonce, &ct).is_err(), "tampered ciphertext must be rejected");
    }

    // TEST-W-005 — Nonce/key size validation
    #[wasm_bindgen_test]
    fn test_key_nonce_size_validation() {
        let good_key   = [0u8; 32];
        let good_nonce = [0u8; 12];
        assert!(encrypt(&[0u8; 31], &good_nonce, b"x").is_err(), "31-byte key");
        assert!(encrypt(&[0u8; 33], &good_nonce, b"x").is_err(), "33-byte key");
        assert!(encrypt(&good_key,  &[0u8; 11], b"x").is_err(), "11-byte nonce");
        assert!(encrypt(&good_key,  &[0u8; 13], b"x").is_err(), "13-byte nonce");
        assert!(decrypt(&[0u8; 31], &good_nonce, b"x").is_err(), "decrypt 31-byte key");
        assert!(decrypt(&good_key,  &[0u8; 11], b"x").is_err(), "decrypt 11-byte nonce");
    }

    // TEST-W-006 — HKDF determinism: same inputs → same output 100×; different inputs → different output
    #[wasm_bindgen_test]
    fn test_hkdf_determinism() {
        let pake = vec![1u8; 32];
        let x    = vec![2u8; 32];
        let kem  = vec![3u8; 32];
        let tr   = vec![4u8; 64]; // dummy transcript (xPkA ‖ xPkB)
        let out1 = hkdf_combine(&pake, &x, &kem, &tr).unwrap();
        assert_eq!(out1.len(), 32);
        for _ in 0..100 {
            assert_eq!(hkdf_combine(&pake, &x, &kem, &tr).unwrap(), out1);
        }
        let out2 = hkdf_combine(&[0u8; 32], &x, &kem, &tr).unwrap();
        assert_ne!(out1, out2, "different inputs must produce different output");
        // transcript binding: same secrets + different transcript → different key
        let out3 = hkdf_combine(&pake, &x, &kem, &vec![0u8; 64]).unwrap();
        assert_ne!(out1, out3, "different transcript must produce different key");
    }

    // TEST-W-007 — X25519 shared-secret agreement
    #[wasm_bindgen_test]
    fn test_x25519_agreement() {
        let kp_a = x25519_keypair(); // sk[0..32] | pk[32..64]
        let kp_b = x25519_keypair();
        let shared_a = x25519_shared(&kp_a[..32], &kp_b[32..]).unwrap();
        let shared_b = x25519_shared(&kp_b[..32], &kp_a[32..]).unwrap();
        assert_eq!(shared_a, shared_b, "x25519 DH must be symmetric");
        assert_eq!(shared_a.len(), 32);
    }

    // TEST-W-008 — ML-KEM-768 encaps/decaps roundtrip
    #[wasm_bindgen_test]
    fn test_mlkem_roundtrip() {
        let keypair = mlkem_keygen();
        let dk_len  = mlkem_dk_len();
        let dk = &keypair[..dk_len];
        let ek = &keypair[dk_len..];

        let encaps_out = mlkem_encaps(ek).unwrap();
        // encaps_out = ct || ss (ss is always 32 bytes)
        let ct         = &encaps_out[..encaps_out.len() - 32];
        let ss_encaps  = &encaps_out[encaps_out.len() - 32..];

        let ss_decaps = mlkem_decaps(dk, ct).unwrap();
        assert_eq!(ss_encaps, ss_decaps.as_slice(), "decaps must recover encaps shared secret");
    }

    // TEST-W-010 — start_pake input validation: empty/oversized code and bad role rejected
    #[wasm_bindgen_test]
    fn test_start_pake_input_validation() {
        assert!(start_pake("", "A").is_err(), "empty code must be rejected");
        assert!(start_pake(&"9".repeat(65), "A").is_err(), "oversized code must be rejected");
        assert!(start_pake("123456789", "X").is_err(), "invalid role must be rejected");
        assert!(start_pake("123456789", "A").is_ok(), "valid 9-digit code must pass");
    }

    // TEST-W-009 — Full handshake E2E: PAKE + X25519 + ML-KEM → identical derived keys on both sides
    #[wasm_bindgen_test]
    fn test_full_handshake_e2e() {
        // PAKE
        let pa = start_pake("123456789", "A").unwrap();
        let pb = start_pake("123456789", "B").unwrap();
        let msg_a = pa.msg();
        let msg_b = pb.msg();
        let pake_a = finish_pake(pa, &msg_b).unwrap();
        let pake_b = finish_pake(pb, &msg_a).unwrap();

        // X25519
        let kp_a = x25519_keypair();
        let kp_b = x25519_keypair();
        let x_shared_a = x25519_shared(&kp_a[..32], &kp_b[32..]).unwrap();
        let x_shared_b = x25519_shared(&kp_b[..32], &kp_a[32..]).unwrap();

        // ML-KEM: A owns the keypair; B encapsulates to A's ek
        let mlkem_kp  = mlkem_keygen();
        let dk_len    = mlkem_dk_len();
        let dk_a      = &mlkem_kp[..dk_len];
        let ek_a      = &mlkem_kp[dk_len..];
        let enc_out   = mlkem_encaps(ek_a).unwrap();
        let ct        = &enc_out[..enc_out.len() - 32];
        let kem_b     = &enc_out[enc_out.len() - 32..]; // B's view of shared secret
        let kem_a     = mlkem_decaps(dk_a, ct).unwrap(); // A decapsulates

        // HKDF combine on both sides — transcript = xPkA ‖ xPkB ‖ mlEk ‖ mlCt
        let mut tr = Vec::new();
        tr.extend_from_slice(&kp_a[32..]); // xPkA (sender)
        tr.extend_from_slice(&kp_b[32..]); // xPkB (receiver)
        tr.extend_from_slice(ek_a);
        tr.extend_from_slice(ct);
        let derived_a = hkdf_combine(&pake_a, &x_shared_a, &kem_a, &tr).unwrap();
        let derived_b = hkdf_combine(&pake_b, &x_shared_b, kem_b,  &tr).unwrap();

        assert_eq!(derived_a, derived_b, "full handshake must produce equal keys on both sides");
        assert_eq!(derived_a.len(), 32);
    }

    // TEST-W-011 — 21.2 streaming SHA-256: known vectors + split/one-shot equivalence
    #[wasm_bindgen_test]
    fn test_sha256_stream() {
        let mut s = Sha256Stream::new();
        assert_eq!(
            s.finalize_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let mut s = Sha256Stream::new();
        s.update(b"abc");
        assert_eq!(
            s.finalize_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut split = Sha256Stream::new();
        split.update(b"hello ");
        split.update(b"streaming ");
        split.update(b"world");
        let mut oneshot = Sha256Stream::new();
        oneshot.update(b"hello streaming world");
        assert_eq!(split.finalize_hex(), oneshot.finalize_hex());
    }

    // Shared helpers for the hex-encoded known-answer vectors below.
    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // TEST-W-012 — X25519 KAT, RFC 7748 section 6.1 Alice/Bob DH example.
    // Source: https://www.rfc-editor.org/rfc/rfc7748.txt section 6.1 (fetched directly).
    #[wasm_bindgen_test]
    fn test_x25519_rfc7748_section_6_1() {
        let alice_sk = hex_decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pk = hex_decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_sk   = hex_decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_pk   = hex_decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared   = hex_decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519_shared(&alice_sk, &bob_pk).unwrap(), shared);
        assert_eq!(x25519_shared(&bob_sk, &alice_pk).unwrap(), shared);
    }

    // TEST-W-013 — X25519 KAT, RFC 7748 section 5.2 first X25519 scalar-mult
    // test vector (plain scalar-mult, base is contributory so it goes through
    // x25519_shared with no rejection).
    // Source: https://www.rfc-editor.org/rfc/rfc7748.txt section 5.2 (fetched directly).
    #[wasm_bindgen_test]
    fn test_x25519_rfc7748_section_5_2_vector1() {
        let scalar = hex_decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u      = hex_decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let out    = hex_decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(x25519_shared(&scalar, &u).unwrap(), out);
    }

    // TEST-W-014 — X25519 negative: non-contributory / low-order peer keys rejected.
    // The all-zero peer key and u=1 are the trivial low-order inputs (RFC 7748
    // section 6.1 notes the all-zero shared secret comes from small-order inputs
    // and recommends rejecting it). The third value is a documented order-8
    // small-order point; the same constant is used as a "low order point" test
    // vector in the Go standard library's crypto/ecdh tests
    // (https://go.dev/src/crypto/ecdh/ecdh_test.go, lowOrderPoint), which in turn
    // traces to the libsodium/x25519-dalek small-order blacklist. Any clamped
    // scalar is a multiple of 8, so DH with a point whose order divides 8
    // collapses to the identity (all-zero) shared secret, which x25519_shared
    // rejects via was_contributory().
    #[wasm_bindgen_test]
    fn test_x25519_low_order_peer_rejected() {
        let sk = [0x11u8; 32]; // arbitrary scalar; clamping normalizes it
        let all_zero = [0u8; 32];
        let mut one = [0u8; 32];
        one[0] = 1;
        let small_order = hex_decode("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800");
        assert!(x25519_shared(&sk, &all_zero).is_err(), "all-zero peer key must be rejected");
        assert!(x25519_shared(&sk, &one).is_err(), "u=1 peer key must be rejected");
        assert!(x25519_shared(&sk, &small_order).is_err(), "small-order peer key must be rejected");
    }

    // TEST-W-015 — X25519 wrong-length inputs rejected (31 and 33 bytes on either side).
    #[wasm_bindgen_test]
    fn test_x25519_length_validation() {
        let good = [0u8; 32];
        assert!(x25519_shared(&[0u8; 31], &good).is_err(), "31-byte sk");
        assert!(x25519_shared(&[0u8; 33], &good).is_err(), "33-byte sk");
        assert!(x25519_shared(&good, &[0u8; 31]).is_err(), "31-byte peer pk");
        assert!(x25519_shared(&good, &[0u8; 33]).is_err(), "33-byte peer pk");
    }

    // TEST-W-016 — ChaCha20-Poly1305 KAT, Wycheproof chacha20_poly1305_test.json,
    // testGroups[0] (ivSize 96, keySize 256, tagSize 128), empty aad, tcId 2/34/72
    // (empty msg, 16-byte msg, 64-byte "longer" msg).
    // Source: https://raw.githubusercontent.com/C2SP/wycheproof/master/testvectors_v1/chacha20_poly1305_test.json
    // (fetched directly with curl; our encrypt/decrypt have no AAD parameter, so
    // only tcIds with "aad": "" apply). Our encrypt returns ct||tag.
    #[wasm_bindgen_test]
    fn test_chacha_wycheproof_valid_empty_aad() {
        struct Case {
            tc_id: u32,
            key: &'static str,
            iv: &'static str,
            msg: &'static str,
            ct: &'static str,
            tag: &'static str,
        }
        let cases = [
            Case {
                tc_id: 2,
                key: "80ba3192c803ce965ea371d5ff073cf0f43b6a2ab576b208426e11409c09b9b0",
                iv: "4da5bf8dfd5852c1ea12379d",
                msg: "",
                ct: "",
                tag: "76acb342cf3166a5b63c0c0ea1383c8d",
            },
            Case {
                tc_id: 34,
                key: "59d4eafb4de0cfc7d3db99a8f54b15d7b39f0acc8da69763b019c1699f87674a",
                iv: "2fcb1b38a99e71b84740ad9b",
                msg: "549b365af913f3b081131ccb6b825588",
                ct: "e9110e9f56ab3ca483500ceabab67a13",
                tag: "836ccabf15a6a22a51c1071cfa68fa0c",
            },
            Case {
                tc_id: 72,
                key: "5b1d1035c0b17ee0b0444767f80a25b8c1b741f4b50a4d3052226baa1c6fb701",
                iv: "d61040a313ed492823cc065b",
                msg: "d096803181beef9e008ff85d5ddc38ddacf0f09ee5f7e07f1e4079cb64d0dc8f5e6711cd4921a7887de76e2678fdc67618f1185586bfea9d4c685d50e4bb9a82",
                ct: "9a4ef22b181677b5755c08f747c0f8d8e8d4c18a9cc2405c12bb51bb1872c8e8b877678bec442cfcbb0ff464a64b74332cf072898c7e0eddf6232ea6e27efe50",
                tag: "9ff3427a0f32fa566d9ca0a78aefc013",
            },
        ];
        for c in cases.iter() {
            let key = hex_decode(c.key);
            let iv = hex_decode(c.iv);
            let msg = hex_decode(c.msg);
            let mut expected = hex_decode(c.ct);
            expected.extend_from_slice(&hex_decode(c.tag));
            let got = encrypt(&key, &iv, &msg).unwrap();
            assert_eq!(got, expected, "tcId {} encrypt mismatch", c.tc_id);
            let dec = decrypt(&key, &iv, &expected).unwrap();
            assert_eq!(dec, msg, "tcId {} decrypt mismatch", c.tc_id);
        }
    }

    // TEST-W-017 — ChaCha20-Poly1305 negative, Wycheproof-derived (empty aad).
    // The Wycheproof file's native "invalid" entries for the ivSize=96/keySize=256
    // group (tcId 146-205, "Flipped bit ... in tag" etc.) all carry "aad": "000102",
    // which our AAD-less encrypt/decrypt cannot represent; there are no native
    // "result": "invalid" entries with "aad": "" in this file (checked by loading
    // the fetched JSON and filtering testGroups[0] for result == "invalid": every
    // hit has aad == "000102", none have aad == ""). So these two cases are
    // derived locally by flipping bits in the tag of the valid, empty-aad tcId 2
    // and tcId 34 vectors above (same Wycheproof source), following the same
    // "Flipped bit 0 in tag" / "Tag changed to all zero" pattern the file itself
    // uses for its non-empty-aad invalid entries.
    #[wasm_bindgen_test]
    fn test_chacha_wycheproof_derived_invalid_empty_aad() {
        let key = hex_decode("80ba3192c803ce965ea371d5ff073cf0f43b6a2ab576b208426e11409c09b9b0");
        let iv = hex_decode("4da5bf8dfd5852c1ea12379d");
        let mut tampered = hex_decode("76acb342cf3166a5b63c0c0ea1383c8d"); // tcId 2 tag, empty msg
        tampered[0] ^= 0x01; // flip bit 0 in tag
        assert!(decrypt(&key, &iv, &tampered).is_err(), "tcId 2 tag with bit 0 flipped must be rejected");

        let key2 = hex_decode("59d4eafb4de0cfc7d3db99a8f54b15d7b39f0acc8da69763b019c1699f87674a");
        let iv2 = hex_decode("2fcb1b38a99e71b84740ad9b");
        let mut ct_tag2 = hex_decode("e9110e9f56ab3ca483500ceabab67a13"); // tcId 34 ct
        ct_tag2.extend_from_slice(&[0u8; 16]); // tag changed to all zero
        assert!(decrypt(&key2, &iv2, &ct_tag2).is_err(), "tcId 34 tag changed to all zero must be rejected");
    }

    // TEST-W-018 — AEAD negative paths beyond the existing flipped-last-byte test:
    // wrong key, wrong nonce, tampered ciphertext body (not just the tag),
    // truncated ciphertext, empty ciphertext, and a bare 16-byte all-zero
    // ciphertext (tag-only, no body) must all be rejected.
    #[wasm_bindgen_test]
    fn test_chacha_negative_paths() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let ct = encrypt(&key, &nonce, b"negative path test").unwrap();

        let mut wrong_key = key;
        wrong_key[0] ^= 0x01; // single bit flipped
        assert!(decrypt(&wrong_key, &nonce, &ct).is_err(), "wrong key must be rejected");

        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 0x01;
        assert!(decrypt(&key, &wrong_nonce, &ct).is_err(), "wrong nonce must be rejected");

        let mut body_flipped = ct.clone();
        body_flipped[0] ^= 0x01; // first ciphertext byte, not the tag
        assert!(decrypt(&key, &nonce, &body_flipped).is_err(), "flipped ciphertext body byte must be rejected");

        let truncated = &ct[..15];
        assert!(decrypt(&key, &nonce, truncated).is_err(), "15-byte ciphertext must be rejected");

        assert!(decrypt(&key, &nonce, &[]).is_err(), "empty ciphertext must be rejected");

        let zeros16 = [0u8; 16];
        assert!(decrypt(&key, &nonce, &zeros16).is_err(), "16 zero bytes (tag-only, no body) must be rejected");
    }

    // TEST-W-019 — Nonce distinctness: same key + same plaintext, different
    // nonces, must produce different ciphertexts (ChaCha20 keystream depends on
    // the nonce; a collision here would mean keystream reuse).
    #[wasm_bindgen_test]
    fn test_chacha_distinct_nonces_distinct_ciphertexts() {
        let key = [0x77u8; 32];
        let plain = b"same plaintext, different nonce";
        let ct1 = encrypt(&key, &[0u8; 12], plain).unwrap();
        let mut nonce2 = [0u8; 12];
        nonce2[11] = 1;
        let ct2 = encrypt(&key, &nonce2, plain).unwrap();
        assert_ne!(ct1, ct2, "different nonces must yield different ciphertexts");
    }

    // TEST-W-020 — SHA-256 KAT, NIST FIPS 180 448-bit two-block message
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".
    // Verified independently (not via the sha2 crate under test) with:
    //   python3 -c "import hashlib; print(hashlib.sha256(b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq').hexdigest())"
    // which prints 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1,
    // matching the value pinned below.
    #[wasm_bindgen_test]
    fn test_sha256_nist_two_block_vector() {
        let mut s = Sha256Stream::new();
        s.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            s.finalize_hex(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    // TEST-W-021 — SHA-256 KAT, NIST FIPS 180 one-million-'a' vector, fed through
    // Sha256Stream::update in chunks to also exercise the streaming path.
    // Verified independently (not via the sha2 crate under test) with:
    //   python3 -c "import hashlib; print(hashlib.sha256(b'a'*1000000).hexdigest())"
    // which prints cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0,
    // matching the value pinned below.
    #[wasm_bindgen_test]
    fn test_sha256_million_a_vector() {
        let mut s = Sha256Stream::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            s.update(&chunk);
        }
        assert_eq!(
            s.finalize_hex(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    // TEST-W-022 — hkdf_combine KAT, cross-checked against an independent
    // hand-rolled RFC 5869 HKDF-Extract/HKDF-Expand (HMAC-SHA256, not the hkdf
    // crate under test) with pake_key=[0x01]*32, x_shared=[0x02]*32,
    // kem_shared=[0x03]*32, transcript=[0x04]*64 (salt = transcript,
    // ikm = pake || x || kem, info = "beem-v1 aead"). Reproduce with:
    //   python3 -c "
    //   import hmac, hashlib
    //   def extract(salt, ikm): return hmac.new(salt, ikm, hashlib.sha256).digest()
    //   def expand(prk, info, l):
    //       t = b''; okm = b''
    //       for i in range(1, -(-l // 32) + 1):
    //           t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
    //           okm += t
    //       return okm[:l]
    //   ikm = bytes([1]*32) + bytes([2]*32) + bytes([3]*32)
    //   prk = extract(bytes([4]*64), ikm)
    //   print(expand(prk, b'beem-v1 aead', 32).hex())"
    // which prints 9964fc812131c375f213030f533625fc8ee5b6283bf9fb164c8e195f06f45fca.
    #[wasm_bindgen_test]
    fn test_hkdf_combine_known_answer() {
        let pake = vec![0x01u8; 32];
        let x = vec![0x02u8; 32];
        let kem = vec![0x03u8; 32];
        let transcript = vec![0x04u8; 64];
        let out = hkdf_combine(&pake, &x, &kem, &transcript).unwrap();
        assert_eq!(
            hex_encode(&out),
            "9964fc812131c375f213030f533625fc8ee5b6283bf9fb164c8e195f06f45fca"
        );
    }

    // TEST-W-023 — hkdf_combine KAT, empty transcript. Per RFC 5869 section 2.2,
    // an absent salt is treated as a HashLen (32-byte) all-zero string; the hkdf
    // crate's Hkdf::new(Some(&[]), ..) applies the same rule for an explicit
    // empty salt, which is what hkdf_combine passes when transcript is empty. So
    // the independent Python side below uses 32 zero bytes as the salt:
    //   python3 -c "
    //   import hmac, hashlib
    //   def extract(salt, ikm): return hmac.new(salt, ikm, hashlib.sha256).digest()
    //   def expand(prk, info, l):
    //       t = b''; okm = b''
    //       for i in range(1, -(-l // 32) + 1):
    //           t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
    //           okm += t
    //       return okm[:l]
    //   ikm = bytes([1]*32) + bytes([2]*32) + bytes([3]*32)
    //   prk = extract(bytes(32), ikm)
    //   print(expand(prk, b'beem-v1 aead', 32).hex())"
    // which prints 5278d38b75d16460def1e74ca6cfadbdf17c609c7a3d6e87706b48b925eaf49f.
    #[wasm_bindgen_test]
    fn test_hkdf_combine_known_answer_empty_transcript() {
        let pake = vec![0x01u8; 32];
        let x = vec![0x02u8; 32];
        let kem = vec![0x03u8; 32];
        let out = hkdf_combine(&pake, &x, &kem, &[]).unwrap();
        assert_eq!(
            hex_encode(&out),
            "5278d38b75d16460def1e74ca6cfadbdf17c609c7a3d6e87706b48b925eaf49f"
        );
    }

    // TEST-W-024 — ML-KEM-768 sizes match FIPS 203 Table 3 ("Sizes (in bytes) of
    // keys and ciphertexts of ML-KEM"): encapsulation key 1184, decapsulation
    // key 2400, ciphertext 1088, shared secret 32.
    // Source: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf, Table 3
    // (fetched directly and read with pdftotext to confirm the row values).
    #[wasm_bindgen_test]
    fn test_mlkem_sizes_match_fips203_table3() {
        assert_eq!(mlkem_ek_len(), 1184);
        assert_eq!(mlkem_dk_len(), 2400);
        let keypair = mlkem_keygen();
        let dk_len = mlkem_dk_len();
        let ek = &keypair[dk_len..];
        let encaps_out = mlkem_encaps(ek).unwrap();
        assert_eq!(encaps_out.len() - 32, 1088, "ciphertext must be 1088 bytes");
    }

    // TEST-W-025 — ML-KEM-768 has no seedable/deterministic entry point in this
    // module's exported API (mlkem_keygen and mlkem_encaps always draw from
    // OsRng), so no ACVP known-answer test can be pinned here. Confirmed via
    // WebFetch of https://github.com/RustCrypto/KEMs/tree/master/ml-kem/tests
    // that the ml-kem crate itself carries ACVP-derived key-gen.json and
    // encap-decap.json vectors (its README states they are taken from the NIST
    // ACVP repository), so KAT coverage for the primitive exists upstream even
    // though it cannot be exercised through this crate's non-seedable API.
    // What we *can* test here is FIPS 203's implicit-rejection property: a
    // tampered ciphertext must decapsulate WITHOUT error to a shared secret that
    // differs from the one produced at encapsulation time (never silently
    // "succeed" with the same secret, and never surface a decrypt error either).
    #[wasm_bindgen_test]
    fn test_mlkem_tampered_ciphertext_implicit_rejection() {
        let keypair = mlkem_keygen();
        let dk_len = mlkem_dk_len();
        let dk = &keypair[..dk_len];
        let ek = &keypair[dk_len..];

        let encaps_out = mlkem_encaps(ek).unwrap();
        let ct_len = encaps_out.len() - 32;
        let mut ct = encaps_out[..ct_len].to_vec();
        let ss_encaps = &encaps_out[ct_len..];

        ct[0] ^= 0x01; // tamper with the ciphertext
        let ss_decaps = mlkem_decaps(dk, &ct).unwrap();
        assert_ne!(
            ss_encaps,
            ss_decaps.as_slice(),
            "tampered ciphertext must implicitly-reject to a different shared secret"
        );
    }

    // TEST-W-026 — ML-KEM-768 wrong-length inputs rejected: bad ct length and bad
    // dk length in decaps, bad ek length in encaps (sizes per FIPS 203 Table 3,
    // see TEST-W-024).
    #[wasm_bindgen_test]
    fn test_mlkem_length_validation() {
        let keypair = mlkem_keygen();
        let dk_len = mlkem_dk_len();
        let dk = &keypair[..dk_len];
        let ek = &keypair[dk_len..];

        let encaps_out = mlkem_encaps(ek).unwrap();
        let ct_len = encaps_out.len() - 32;
        let ct = &encaps_out[..ct_len];

        assert!(mlkem_decaps(dk, &ct[..ct_len - 1]).is_err(), "1-byte-short ct must be rejected");
        let mut ct_long = ct.to_vec();
        ct_long.push(0);
        assert!(mlkem_decaps(dk, &ct_long).is_err(), "1-byte-long ct must be rejected");

        assert!(mlkem_decaps(&dk[..dk_len - 1], ct).is_err(), "1-byte-short dk must be rejected");
        let mut dk_long = dk.to_vec();
        dk_long.push(0);
        assert!(mlkem_decaps(&dk_long, ct).is_err(), "1-byte-long dk must be rejected");

        assert!(mlkem_encaps(&ek[..ek.len() - 1]).is_err(), "1-byte-short ek must be rejected");
        let mut ek_long = ek.to_vec();
        ek_long.push(0);
        assert!(mlkem_encaps(&ek_long).is_err(), "1-byte-long ek must be rejected");
    }

    // TEST-W-027 — SPAKE2 finish_pake: wrong-length peer message rejected.
    #[wasm_bindgen_test]
    fn test_spake2_peer_message_length_validation() {
        let pa = start_pake("123456789", "A").unwrap();
        assert!(finish_pake(pa, &[0u8; 31]).is_err(), "31-byte peer message");
        let pa = start_pake("123456789", "A").unwrap();
        assert!(finish_pake(pa, &[0u8; 33]).is_err(), "33-byte peer message");
        let pa = start_pake("123456789", "A").unwrap();
        assert!(finish_pake(pa, &[]).is_err(), "empty peer message");
    }

    // TEST-W-028 — SPAKE2 finish_pake: a random 32-byte peer message that is not
    // a valid group element must either be rejected outright, or (if the point
    // decode happens to succeed) must not produce a key matching the honest
    // counterpart's key.
    #[wasm_bindgen_test]
    fn test_spake2_garbage_peer_message() {
        let pa = start_pake("123456789", "A").unwrap();
        let pb = start_pake("123456789", "B").unwrap();
        let msg_b = pb.msg();
        let key_b = finish_pake(pb, &pa.msg()).unwrap();
        // Fixed non-random "garbage" 32 bytes so the test is deterministic; not a
        // published vector, just an arbitrary value that is not msg_b.
        let mut garbage = [0xabu8; 32];
        garbage[0] = 0xff;
        assert_ne!(garbage.as_slice(), msg_b.as_slice());
        match finish_pake(pa, &garbage) {
            Err(_) => {} // rejected outright: fine
            Ok(key_a) => assert_ne!(key_a, key_b, "garbage peer message must not derive the honest key"),
        }
    }

    // TEST-W-029 — SPAKE2 role/code binding: two "A" roles with the same code
    // must not produce equal keys (SPAKE2 requires opposite roles), and a code
    // differing only in the last digit must not produce equal keys either.
    #[wasm_bindgen_test]
    fn test_spake2_role_and_code_binding() {
        let pa1 = start_pake("123456789", "A").unwrap();
        let pa2 = start_pake("123456789", "A").unwrap();
        let msg1 = pa1.msg();
        let msg2 = pa2.msg();
        // The spake2 crate itself tags each message with its side and rejects a
        // same-side peer with a BadSide error before any key is derived, which
        // trivially satisfies "must not produce equal keys" (no key at all). If
        // some future spake2 version instead produced a key here, it would still
        // have to not equal the other side's key.
        match (finish_pake(pa1, &msg2), finish_pake(pa2, &msg1)) {
            (Err(_), Err(_)) => {}
            (Ok(key1), Ok(key2)) => {
                assert_ne!(key1, key2, "A paired with A (same code) must not produce equal keys")
            }
            _ => {} // one side errored, the other didn't: still not "equal keys"
        }

        let pa = start_pake("123456789", "A").unwrap();
        let pb = start_pake("123456788", "B").unwrap(); // last digit differs
        let msg_a = pa.msg();
        let msg_b = pb.msg();
        let key_a = finish_pake(pa, &msg_b).unwrap();
        let key_b = finish_pake(pb, &msg_a).unwrap();
        assert_ne!(key_a, key_b, "codes differing in the last digit must not produce equal keys");
    }
}
