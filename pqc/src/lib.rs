//! Post-Quantum Cryptography support for Solana.
//!
//! Provides Falcon-512 signature verification, address derivation, and proxy
//! signature generation for PoH/txid compatibility.

use curve25519_dalek::edwards::CompressedEdwardsY;
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureTrait, PublicKey as PublicKeyTrait,
    SecretKey as SecretKeyTrait,
};
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;
use solana_signature::Signature;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Falcon-512 public key size in bytes.
pub const FALCON512_PUBKEY_LEN: usize = 897;

/// Maximum Falcon-512 detached signature size in bytes.
/// Falcon signatures are variable-length; on the wire we always reserve this
/// many bytes and store the actual length in a 2-byte LE prefix.
pub const FALCON512_SIG_MAX_LEN: usize = 666;

/// Total bytes occupied by a PQC signer in the wire signature section:
/// 2B actual-sig-length prefix + 897B pubkey + 666B signature (padded).
pub const FALCON512_WIRE_LEN: usize = 2 + FALCON512_PUBKEY_LEN + FALCON512_SIG_MAX_LEN;

/// Bit index within the V1 `TransactionConfigMask` that signals PQC
/// signatures are present.
pub const PQC_CONFIG_MASK_BIT: u8 = 5;

/// Algorithm identifier for Falcon-512. Bit 5 is a pure flag (no config
/// value on the wire) — the algorithm is always Falcon-512 in the prototype.
pub const FALCON512_ALGORITHM_ID: u32 = 0;

// ---------------------------------------------------------------------------
// Curve-point check
// ---------------------------------------------------------------------------

/// Returns `true` if the 32-byte value is a valid point on the Ed25519 curve.
///
/// PQC-derived addresses must **not** lie on the curve so they can never
/// collide with Ed25519 keypair-based accounts (same principle as Solana
/// PDAs).
fn bytes_are_curve_point(bytes: &[u8; 32]) -> bool {
    CompressedEdwardsY::from_slice(bytes)
        .map(|y| y.decompress().is_some())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// FalconPublicKey
// ---------------------------------------------------------------------------

/// A Falcon-512 public key (897 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct FalconPublicKey([u8; FALCON512_PUBKEY_LEN]);

impl FalconPublicKey {
    /// Construct from a 897-byte slice. Returns `None` on wrong length.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != FALCON512_PUBKEY_LEN {
            return None;
        }
        let mut buf = [0u8; FALCON512_PUBKEY_LEN];
        buf.copy_from_slice(bytes);
        Some(Self(buf))
    }

    /// Raw bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; FALCON512_PUBKEY_LEN] {
        &self.0
    }

    /// Derive a 32-byte Solana address guaranteed to be **off** the Ed25519
    /// curve, analogous to how Solana PDAs avoid collisions with Ed25519
    /// keypairs.
    ///
    /// `address = SHA-256(falcon_pubkey || bump)` where `bump` is the
    /// highest `u8` (starting from 255) that produces an off-curve hash.
    /// On average only 1–2 iterations are needed (~50 % of SHA-256 outputs
    /// are valid curve points).
    pub fn derive_address(&self) -> Pubkey {
        for bump in (0u8..=255).rev() {
            let hash: [u8; 32] = Sha256::new()
                .chain_update(&self.0)
                .chain_update([bump])
                .finalize()
                .into();

            if !bytes_are_curve_point(&hash) {
                return Pubkey::new_from_array(hash);
            }
        }
        panic!("could not derive off-curve PQC address after 256 attempts");
    }
}

impl core::fmt::Debug for FalconPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FalconPublicKey({}..)", hex::encode(&self.0[..8]))
    }
}

// ---------------------------------------------------------------------------
// FalconSignature
// ---------------------------------------------------------------------------

/// A Falcon-512 detached signature (variable length, up to 666 bytes).
///
/// On the wire the signature section always occupies [`FALCON512_SIG_MAX_LEN`]
/// bytes (zero-padded), preceded by a 2-byte LE actual-length prefix.
#[derive(Clone)]
pub struct FalconSignature {
    buf: [u8; FALCON512_SIG_MAX_LEN],
    len: usize,
}

impl FalconSignature {
    /// Construct from raw bytes (actual signature, not padded).
    /// Returns `None` if the slice is empty or exceeds 666 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > FALCON512_SIG_MAX_LEN {
            return None;
        }
        let mut buf = [0u8; FALCON512_SIG_MAX_LEN];
        buf[..bytes.len()].copy_from_slice(bytes);
        Some(Self {
            buf,
            len: bytes.len(),
        })
    }

    /// Construct from the padded wire representation.
    ///
    /// `wire` must be exactly `2 + FALCON512_SIG_MAX_LEN` bytes:
    /// `[actual_len_le16][signature_padded_to_666]`.
    pub fn from_wire(wire: &[u8]) -> Option<Self> {
        if wire.len() < 2 + FALCON512_SIG_MAX_LEN {
            return None;
        }
        let actual_len = u16::from_le_bytes([wire[0], wire[1]]) as usize;
        if actual_len == 0 || actual_len > FALCON512_SIG_MAX_LEN {
            return None;
        }
        let mut buf = [0u8; FALCON512_SIG_MAX_LEN];
        buf.copy_from_slice(&wire[2..2 + FALCON512_SIG_MAX_LEN]);
        Some(Self {
            buf,
            len: actual_len,
        })
    }

    /// Actual signature bytes (not padded).
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Actual signature length.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Verify this signature against a Falcon-512 public key and message.
    ///
    /// Mirrors the `Signature::verify()` API from `solana-signature`.
    pub fn verify(&self, pubkey: &FalconPublicKey, message: &[u8]) -> bool {
        let Ok(pk) = falcon512::PublicKey::from_bytes(pubkey.as_bytes()) else {
            return false;
        };
        let Ok(sig) = falcon512::DetachedSignature::from_bytes(self.as_bytes()) else {
            return false;
        };
        falcon512::verify_detached_signature(&sig, message, &pk).is_ok()
    }

    /// Generate a 64-byte proxy signature for PoH and txid compatibility.
    ///
    /// `proxy = SHA-256(falcon_signature) || SHA-256(falcon_pubkey)`
    ///
    /// This is deterministic — same inputs always produce the same proxy.
    pub fn to_proxy_signature(&self, pubkey: &FalconPublicKey) -> Signature {
        let sig_hash = Sha256::digest(self.as_bytes());
        let pk_hash = Sha256::digest(pubkey.as_bytes());
        let mut proxy = [0u8; 64];
        proxy[..32].copy_from_slice(&sig_hash);
        proxy[32..].copy_from_slice(&pk_hash);
        Signature::from(proxy)
    }

    /// Serialize to the wire format: `[actual_len_le16][signature_padded_to_666]`.
    pub fn to_wire(&self) -> [u8; 2 + FALCON512_SIG_MAX_LEN] {
        let mut out = [0u8; 2 + FALCON512_SIG_MAX_LEN];
        out[..2].copy_from_slice(&(self.len as u16).to_le_bytes());
        out[2..].copy_from_slice(&self.buf);
        out
    }
}

impl core::fmt::Debug for FalconSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "FalconSignature(len={}, {}..)",
            self.len,
            hex::encode(&self.buf[..8.min(self.len)])
        )
    }
}

// ---------------------------------------------------------------------------
// Config mask helpers
// ---------------------------------------------------------------------------

/// Check whether a V1 `TransactionConfigMask` has the PQC bit set.
#[inline]
pub fn is_pqc_config_mask(mask: u32) -> bool {
    mask & (1u32 << PQC_CONFIG_MASK_BIT) != 0
}

// ---------------------------------------------------------------------------
// AuthScheme — centralized signature verification abstraction
// ---------------------------------------------------------------------------

/// Describes how the fee-payer (signer 0) of a transaction is authenticated.
///
/// For Ed25519 transactions, `signatures[0]` is the raw Ed25519 signature and
/// can be verified directly.  For PQC (Falcon-512) transactions,
/// `signatures[0]` is a deterministic 64-byte hash (the "proxy signature")
/// and the real Falcon material lives in a trailing blob.
pub enum AuthScheme<'a> {
    Ed25519,
    Falcon {
        pubkey: &'a [u8],
        signature: &'a [u8],
    },
}

impl<'a> AuthScheme<'a> {
    /// Verify signer 0 against the message bytes and `account_keys[0]`.
    ///
    /// - **Ed25519**: `hash_signature` is the real Ed25519 signature;
    ///   verified directly against `account_key` and `message`.
    /// - **Falcon**: verifies (1) that the Falcon pubkey derives to
    ///   `account_key`, (2) that the Falcon signature is valid over
    ///   `message`, and (3) that `hash_signature` matches the
    ///   deterministic proxy hash of the Falcon material.
    pub fn verify_signer(
        &self,
        hash_signature: &Signature,
        account_key: &Pubkey,
        message: &[u8],
    ) -> bool {
        match self {
            AuthScheme::Ed25519 => hash_signature.verify(account_key.as_ref(), message),
            AuthScheme::Falcon { pubkey, signature } => {
                let Some(falcon_pk) = FalconPublicKey::from_bytes(pubkey) else {
                    eprintln!("[PQC] AuthScheme: invalid falcon pubkey len={}", pubkey.len());
                    return false;
                };
                let Some(falcon_sig) = FalconSignature::from_bytes(signature) else {
                    eprintln!("[PQC] AuthScheme: invalid falcon sig len={}", signature.len());
                    return false;
                };

                let derived = falcon_pk.derive_address();
                if derived != *account_key {
                    eprintln!("[PQC] AuthScheme: address mismatch derived={} expected={}",
                        derived, account_key);
                    return false;
                }

                if !falcon_sig.verify(&falcon_pk, message) {
                    eprintln!("[PQC] AuthScheme: Falcon sig verify FAILED, msg_len={}", message.len());
                    return false;
                }

                let expected_proxy = falcon_sig.to_proxy_signature(&falcon_pk);
                if *hash_signature != expected_proxy {
                    eprintln!("[PQC] AuthScheme: proxy mismatch, wire={} expected={}",
                        hash_signature, expected_proxy);
                    return false;
                }
                true
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Signing (for tests and client code)
// ---------------------------------------------------------------------------

/// Generate a Falcon-512 keypair. Returns `(public_key, secret_key_bytes)`.
pub fn generate_falcon_keypair() -> (FalconPublicKey, Vec<u8>) {
    let (pk, sk) = falcon512::keypair();
    let pk_bytes = pk.as_bytes();
    let mut pub_arr = [0u8; FALCON512_PUBKEY_LEN];
    pub_arr.copy_from_slice(pk_bytes);
    (FalconPublicKey(pub_arr), sk.as_bytes().to_vec())
}

/// Sign a message with a Falcon-512 secret key.
pub fn falcon_sign(message: &[u8], secret_key: &[u8]) -> Option<FalconSignature> {
    let Ok(sk) = falcon512::SecretKey::from_bytes(secret_key) else {
        return None;
    };
    let detached = falcon512::detached_sign(message, &sk);
    let sig_bytes = detached.as_bytes();
    FalconSignature::from_bytes(sig_bytes)
}

// ---------------------------------------------------------------------------
// hex helper (minimal, avoids extra dependency)
// ---------------------------------------------------------------------------

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_and_address() {
        let (pk, _sk) = generate_falcon_keypair();
        assert_eq!(pk.as_bytes().len(), FALCON512_PUBKEY_LEN);

        let addr = pk.derive_address();
        assert!(!bytes_are_curve_point(&addr.to_bytes()));
    }

    #[test]
    fn test_sign_and_verify() {
        let (pk, sk) = generate_falcon_keypair();
        let message = b"Hello PQC Solana!";

        let sig = falcon_sign(message, &sk).expect("signing should succeed");
        assert!(sig.verify(&pk, message));
        assert!(!sig.verify(&pk, b"wrong message"));
    }

    #[test]
    fn test_sign_verify_with_v1_message_bytes() {
        let (pk, sk) = generate_falcon_keypair();
        let message: Vec<u8> = (0..256).map(|i| i as u8).collect();

        let sig = falcon_sign(&message, &sk).expect("signing should succeed");
        assert!(sig.verify(&pk, &message));
    }

    #[test]
    fn test_proxy_signature_deterministic() {
        let (pk, sk) = generate_falcon_keypair();
        let sig = falcon_sign(b"test", &sk).unwrap();

        let proxy1 = sig.to_proxy_signature(&pk);
        let proxy2 = sig.to_proxy_signature(&pk);
        assert_eq!(proxy1, proxy2);
        assert_ne!(proxy1, Signature::default());
    }

    #[test]
    fn test_wire_roundtrip() {
        let (pk, sk) = generate_falcon_keypair();
        let sig = falcon_sign(b"wire roundtrip", &sk).unwrap();
        let original_len = sig.len();

        let wire = sig.to_wire();
        assert_eq!(wire.len(), 2 + FALCON512_SIG_MAX_LEN);

        let restored = FalconSignature::from_wire(&wire).expect("should parse wire");
        assert_eq!(restored.len(), original_len);
        assert_eq!(restored.as_bytes(), sig.as_bytes());
        assert!(restored.verify(&pk, b"wire roundtrip"));
    }

    #[test]
    fn test_address_is_off_curve_and_deterministic() {
        for _ in 0..50 {
            let (pk, _sk) = generate_falcon_keypair();
            let addr1 = pk.derive_address();
            let addr2 = pk.derive_address();

            assert_eq!(addr1, addr2, "derive_address must be deterministic");
            assert!(
                !bytes_are_curve_point(&addr1.to_bytes()),
                "PQC address must NOT lie on the Ed25519 curve"
            );
        }
    }

    #[test]
    fn test_from_bytes_wrong_length() {
        assert!(FalconPublicKey::from_bytes(&[0u8; 32]).is_none());
        assert!(FalconPublicKey::from_bytes(&[0u8; 896]).is_none());
        assert!(FalconPublicKey::from_bytes(&[0u8; 898]).is_none());

        assert!(FalconSignature::from_bytes(&[]).is_none());
        assert!(FalconSignature::from_bytes(&[0u8; 667]).is_none());
    }

    #[test]
    fn test_is_pqc_config_mask() {
        assert!(!is_pqc_config_mask(0b0_0000));
        assert!(!is_pqc_config_mask(0b1_1111));
        assert!(is_pqc_config_mask(0b10_0000));
        assert!(is_pqc_config_mask(0b11_1111));
        assert!(is_pqc_config_mask(1u32 << PQC_CONFIG_MASK_BIT));
    }

    #[test]
    fn test_falcon512_constants() {
        assert_eq!(falcon512::public_key_bytes(), FALCON512_PUBKEY_LEN);
        assert_eq!(falcon512::signature_bytes(), FALCON512_SIG_MAX_LEN);
    }

    #[test]
    fn test_auth_scheme_ed25519() {
        let auth = AuthScheme::Ed25519;
        let bad_sig = Signature::default();
        let bad_key = Pubkey::new_from_array([0u8; 32]);
        assert!(!auth.verify_signer(&bad_sig, &bad_key, b"msg"));
    }

    #[test]
    fn test_auth_scheme_falcon() {
        let (pk, sk) = generate_falcon_keypair();
        let message = b"auth scheme test";
        let sig = falcon_sign(message, &sk).unwrap();
        let proxy = sig.to_proxy_signature(&pk);
        let addr = pk.derive_address();

        let auth = AuthScheme::Falcon {
            pubkey: pk.as_bytes(),
            signature: sig.as_bytes(),
        };
        assert!(auth.verify_signer(&proxy, &addr, message));

        // Wrong message fails
        assert!(!auth.verify_signer(&proxy, &addr, b"wrong"));

        // Wrong proxy fails
        let bad_proxy = Signature::default();
        assert!(!auth.verify_signer(&bad_proxy, &addr, message));

        // Wrong address fails
        let bad_addr = Pubkey::new_from_array([1u8; 32]);
        assert!(!auth.verify_signer(&proxy, &bad_addr, message));
    }
}
