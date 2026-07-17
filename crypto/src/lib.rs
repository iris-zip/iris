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
use sha2::Sha256;
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
// TypeError. An in-struct guard could never fire (F2).
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
    // reject low-order / non-contributory peer keys (these force an all-zero
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
    // the protocol layer enforces a 6-digit code; this guard makes the
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

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    wasm_bindgen_test_configure!(run_in_browser);

    // TEST-W-001 — PAKE success: same code → identical derived keys
    #[wasm_bindgen_test]
    fn test_pake_success() {
        let pa = start_pake("12345", "A").unwrap();
        let pb = start_pake("12345", "B").unwrap();
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
        let pa = start_pake("12345", "A").unwrap();
        let pb = start_pake("99999", "B").unwrap();
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
        assert!(start_pake("12345", "X").is_err(), "invalid role must be rejected");
        assert!(start_pake("12345", "A").is_ok(), "valid 5-digit code must pass");
    }

    // TEST-W-009 — Full handshake E2E: PAKE + X25519 + ML-KEM → identical derived keys on both sides
    #[wasm_bindgen_test]
    fn test_full_handshake_e2e() {
        // PAKE
        let pa = start_pake("12345", "A").unwrap();
        let pb = start_pake("12345", "B").unwrap();
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

}

