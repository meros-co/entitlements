//! Offline verification of licence tokens, plus the device identity that
//! signs licence-service requests.
//!
//! Token format: `base64url(payload_bytes) "." base64url(Ed25519 signature)`,
//! unpadded. The signature is verified over the exact payload bytes against
//! a product public key selected by the payload's `kid`, and only then is the
//! payload trusted. The payload's `features` object is product-defined: each
//! product supplies its own type (`F`) and its trial value.
//!
//! Time handling: verification takes `now` explicitly (testable against
//! fixed vectors); a 14-day grace period follows `exp`; clock rollback is
//! detected by persisting the maximum wall time ever seen.
//!
//! Device requests are signed over `"{method}|{path}|{device_id}|{ts}"`
//! with the device's Ed25519 key, which [`Store`] generates once and keeps.

mod store;

pub use store::Store;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde::de::DeserializeOwned;

/// Grace period after `exp` before a licence lapses.
pub const GRACE_SECS: i64 = 14 * 24 * 3600;

/// Clock-rollback tolerance: system time this far behind the max time we
/// have ever observed is treated as tampering.
pub const ROLLBACK_TOLERANCE_SECS: i64 = 24 * 3600;

/// A product's public keys, `(kid, base64url Ed25519 public key)`. Rotation
/// = append.
pub type ProductKeys = &'static [(&'static str, &'static str)];

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(bound = "F: DeserializeOwned")]
pub struct EntitlementPayload<F> {
    pub v: u32,
    pub kid: String,
    pub jti: String,
    pub account_id: String,
    pub account_type: String,
    pub account_name: String,
    pub seat_id: String,
    pub device_id: String,
    pub device_pubkey: String,
    pub iat: i64,
    pub exp: i64,
    pub features: F,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    /// Before `exp`.
    Valid,
    /// Past `exp` but within the grace window — features still apply.
    Grace,
    /// Past grace (or clock rollback detected) — treat as unlicensed.
    Expired,
}

#[derive(Debug, PartialEq)]
pub enum EntitlementError {
    Malformed(&'static str),
    UnknownKey(String),
    BadSignature,
    BadPayload(String),
    UnsupportedVersion(u32),
}

impl std::fmt::Display for EntitlementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed token: {m}"),
            Self::UnknownKey(kid) => write!(f, "unknown signing key: {kid}"),
            Self::BadSignature => write!(f, "signature verification failed"),
            Self::BadPayload(e) => write!(f, "invalid payload: {e}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported token version: {v}"),
        }
    }
}

impl std::error::Error for EntitlementError {}

/// Parses and cryptographically verifies a token against `keys`. Makes no
/// time judgment — pair with [`validity`].
pub fn verify<F: DeserializeOwned>(
    keys: ProductKeys,
    token: &str,
) -> Result<EntitlementPayload<F>, EntitlementError> {
    let (payload_b64, sig_b64) = token
        .split_once('.')
        .ok_or(EntitlementError::Malformed("missing '.' separator"))?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64.trim())
        .map_err(|_| EntitlementError::Malformed("payload not base64url"))?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64.trim())
        .map_err(|_| EntitlementError::Malformed("signature not base64url"))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|_| EntitlementError::Malformed("signature must be 64 bytes"))?;

    // Parse first to learn the kid; nothing is trusted until verify passes.
    let payload: EntitlementPayload<F> = serde_json::from_slice(&payload_bytes)
        .map_err(|e| EntitlementError::BadPayload(e.to_string()))?;
    if payload.v != 1 {
        return Err(EntitlementError::UnsupportedVersion(payload.v));
    }
    let key_b64 = keys
        .iter()
        .find(|(kid, _)| *kid == payload.kid)
        .map(|(_, key)| *key)
        .ok_or_else(|| EntitlementError::UnknownKey(payload.kid.clone()))?;
    let key_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(key_b64)
        .ok()
        .and_then(|v| v.try_into().ok())
        .expect("embedded product key must be 32 bytes of base64url");
    let key = VerifyingKey::from_bytes(&key_bytes)
        .expect("embedded product key must be a valid Ed25519 point");

    key.verify_strict(&payload_bytes, &signature)
        .map_err(|_| EntitlementError::BadSignature)?;
    Ok(payload)
}

/// Checks that every key decodes to a valid Ed25519 point. [`verify`]
/// `expect`s this, so call it from a product's tests: a mispasted key would
/// otherwise only panic when the first token with that kid arrives.
pub fn check_keys(keys: ProductKeys) -> Result<(), String> {
    for (kid, key_b64) in keys {
        let bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(key_b64)
            .map_err(|_| format!("{kid}: not base64url"))?
            .try_into()
            .map_err(|_| format!("{kid}: not 32 bytes"))?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| format!("{kid}: not a valid Ed25519 point"))?;
    }
    Ok(())
}

/// Time-based validity of a verified payload.
///
/// `max_seen_time` is the largest wall time ever observed (persisted);
/// a clock earlier than that minus tolerance means rollback → Expired.
pub fn validity<F>(payload: &EntitlementPayload<F>, now: i64, max_seen_time: i64) -> Validity {
    if now < max_seen_time - ROLLBACK_TOLERANCE_SECS {
        return Validity::Expired;
    }
    if now < payload.exp {
        Validity::Valid
    } else if now < payload.exp + GRACE_SECS {
        Validity::Grace
    } else {
        Validity::Expired
    }
}

/// Effective features: the entitlement's when valid or in grace, `trial`
/// otherwise.
pub fn effective_features<F: Clone>(
    payload: Option<&EntitlementPayload<F>>,
    now: i64,
    max_seen_time: i64,
    trial: impl FnOnce() -> F,
) -> F {
    match payload {
        Some(p) if validity(p, now, max_seen_time) != Validity::Expired => p.features.clone(),
        _ => trial(),
    }
}

/// Builds the device request signature input string:
/// `"{method}|{path}|{device_id}|{ts}"`.
pub fn request_sig_input(method: &str, path: &str, device_id: &str, ts: i64) -> String {
    format!("{method}|{path}|{device_id}|{ts}")
}

/// Signs a device API request with the device's Ed25519 signing key.
pub fn sign_request(seed: &[u8; 32], method: &str, path: &str, device_id: &str, ts: i64) -> String {
    use ed25519_dalek::{Signer, SigningKey};
    let key = SigningKey::from_bytes(seed);
    let sig = key.sign(request_sig_input(method, path, device_id, ts).as_bytes());
    URL_SAFE_NO_PAD.encode(sig.to_bytes())
}

#[cfg(test)]
pub(crate) mod testkit {
    //! A throwaway product key and token minting for the tests.

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub const SEED: [u8; 32] = [7; 32];

    #[derive(Debug, Clone, Deserialize, PartialEq)]
    pub struct Feat {
        pub tier: String,
        pub watermark: bool,
    }

    pub fn trial() -> Feat {
        Feat { tier: "trial".into(), watermark: true }
    }

    /// The test product's keys: "test-a" is [`SEED`]'s public key.
    pub fn keys() -> ProductKeys {
        static KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        static KEYS: std::sync::OnceLock<Vec<(&'static str, &'static str)>> =
            std::sync::OnceLock::new();
        let key = KEY.get_or_init(|| {
            URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&SEED).verifying_key().to_bytes())
        });
        KEYS.get_or_init(|| vec![("test-a", key.as_str())]).as_slice()
    }

    pub fn payload_json(kid: &str, exp: i64, watermark: bool) -> String {
        format!(
            r#"{{"v":1,"kid":"{kid}","jti":"j1","account_id":"acc_1","account_type":"individual","account_name":"Test","seat_id":"seat_1","device_id":"d_1","device_pubkey":"pk","iat":{iat},"exp":{exp},"features":{{"tier":"individual","watermark":{watermark}}}}}"#,
            iat = exp - 30 * 86_400
        )
    }

    pub fn mint(payload: &str) -> String {
        let sig = SigningKey::from_bytes(&SEED).sign(payload.as_bytes());
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload.as_bytes()),
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;

    const NOW: i64 = 1_790_000_000;

    #[test]
    fn a_minted_token_verifies_and_parses() {
        let token = mint(&payload_json("test-a", NOW + 86_400, false));
        let p: EntitlementPayload<Feat> = verify(keys(), &token).unwrap();
        assert_eq!(p.account_id, "acc_1");
        assert!(!p.features.watermark);
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let token = mint(&payload_json("test-a", NOW + 86_400, false));
        let (payload_b64, sig_b64) = token.split_once('.').unwrap();
        let bytes = URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
        let forged = String::from_utf8(bytes)
            .unwrap()
            .replace("\"watermark\":false", "\"watermark\":true");
        let forged = format!("{}.{}", URL_SAFE_NO_PAD.encode(forged), sig_b64);
        assert_eq!(verify::<Feat>(keys(), &forged), Err(EntitlementError::BadSignature));
    }

    #[test]
    fn unknown_kids_and_versions_and_garbage_are_rejected() {
        let token = mint(&payload_json("other", NOW, false));
        assert_eq!(
            verify::<Feat>(keys(), &token),
            Err(EntitlementError::UnknownKey("other".into()))
        );
        let v2 = mint(&payload_json("test-a", NOW, false).replace("\"v\":1", "\"v\":2"));
        assert_eq!(verify::<Feat>(keys(), &v2), Err(EntitlementError::UnsupportedVersion(2)));
        assert!(matches!(
            verify::<Feat>(keys(), "not-a-token"),
            Err(EntitlementError::Malformed(_))
        ));
    }

    #[test]
    fn validity_windows_and_rollback() {
        let token = mint(&payload_json("test-a", NOW + 60, false));
        let p: EntitlementPayload<Feat> = verify(keys(), &token).unwrap();
        assert_eq!(validity(&p, NOW, NOW), Validity::Valid);
        assert_eq!(validity(&p, p.exp + 60, p.exp + 60), Validity::Grace);
        let later = p.exp + GRACE_SECS + 60;
        assert_eq!(validity(&p, later, later), Validity::Expired);
        // We've seen time NOW; clock jumps back 3 days → expired.
        assert_eq!(validity(&p, NOW - 3 * 86_400, NOW), Validity::Expired);
        // A rollback within tolerance (e.g. timezone fix) is fine.
        assert_eq!(validity(&p, NOW - 3600, NOW), Validity::Valid);
    }

    #[test]
    fn effective_features_fall_back_to_trial() {
        let token = mint(&payload_json("test-a", NOW + 60, false));
        let p: EntitlementPayload<Feat> = verify(keys(), &token).unwrap();
        assert!(!effective_features(Some(&p), NOW, NOW, trial).watermark);
        let later = p.exp + GRACE_SECS + 60;
        assert!(effective_features(Some(&p), later, later, trial).watermark);
        assert!(effective_features::<Feat>(None, NOW, NOW, trial).watermark);
    }

    #[test]
    fn request_signatures_verify_with_the_device_key() {
        use ed25519_dalek::{SigningKey, Verifier};
        let seed = [3u8; 32];
        let sig = sign_request(&seed, "POST", "/v1/device/renew", "d_x", 1_789_000_123);
        assert_eq!(
            request_sig_input("POST", "/v1/device/renew", "d_x", 1_789_000_123),
            "POST|/v1/device/renew|d_x|1789000123"
        );
        let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(sig).unwrap()).unwrap();
        SigningKey::from_bytes(&seed)
            .verifying_key()
            .verify(b"POST|/v1/device/renew|d_x|1789000123", &sig)
            .unwrap();
    }

    #[test]
    fn check_keys_catches_bad_keys() {
        assert!(check_keys(keys()).is_ok());
        assert!(check_keys(&[("bad", "not-base64!")]).is_err());
        assert!(check_keys(&[("short", "AAAA")]).is_err());
    }
}
