//! Persistence: the cached token, the max-seen wall time (clock-rollback
//! anchor), and the device identity keypair.
//!
//! Storage lives in an app-private directory given at startup with
//! [`Store::init`]. Before init (or on I/O failure) everything degrades to
//! trial — never crash an app over licensing state.

use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::de::DeserializeOwned;

use crate::{EntitlementPayload, ProductKeys, Validity, effective_features, validity, verify};

/// One product's entitlement state on this device. Construct it as a
/// `static` (`new` is `const`) and call [`init`](Self::init) at startup.
///
/// Files in the storage directory: `entitlement.token`, `max_time`,
/// `device_id`, `device_seed`.
pub struct Store<F> {
    keys: ProductKeys,
    trial: fn() -> F,
    dir: Mutex<Option<PathBuf>>,
    /// Seconds added to the clock by test runs (see
    /// [`set_test_clock_offset`](Self::set_test_clock_offset)).
    test_clock_offset: AtomicI64,
    _features: PhantomData<fn() -> F>,
}

impl<F: DeserializeOwned + Clone> Store<F> {
    /// `keys` verify tokens; `trial` is what an unlicensed install gets.
    pub const fn new(keys: ProductKeys, trial: fn() -> F) -> Self {
        Self {
            keys,
            trial,
            dir: Mutex::new(None),
            test_clock_offset: AtomicI64::new(0),
            _features: PhantomData,
        }
    }

    fn file(&self, name: &str) -> Option<PathBuf> {
        self.dir.lock().unwrap().as_ref().map(|d| d.join(name))
    }

    /// Moves the entitlement clock forward by `secs` for automated tests, so
    /// renewal, grace and expiry can be exercised in seconds. Forward only: an
    /// offset can make a licence look older, never extend one.
    pub fn set_test_clock_offset(&self, secs: i64) {
        self.test_clock_offset.store(secs.max(0), Ordering::SeqCst);
    }

    /// Wall time (unix seconds) as the store sees it.
    pub fn now_unix(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
            + self.test_clock_offset.load(Ordering::SeqCst)
    }

    /// Sets the storage directory and advances the max-seen-time anchor.
    pub fn init(&self, dir: &str) {
        let path = PathBuf::from(dir);
        let _ = std::fs::create_dir_all(&path);
        *self.dir.lock().unwrap() = Some(path);
        self.observe_time();
    }

    /// Records "we have seen this wall time" — call at startup and periodically.
    pub fn observe_time(&self) {
        let now = self.now_unix();
        if now > self.max_seen_time() {
            if let Some(f) = self.file("max_time") {
                let _ = std::fs::write(f, now.to_string());
            }
        }
    }

    pub fn max_seen_time(&self) -> i64 {
        self.file("max_time")
            .and_then(|f| std::fs::read_to_string(f).ok())
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }

    /// Verifies and persists a token.
    pub fn apply_token(&self, token: &str) -> Result<(), String> {
        let payload: EntitlementPayload<F> = verify(self.keys, token).map_err(|e| e.to_string())?;
        if validity(&payload, self.now_unix(), self.max_seen_time()) == Validity::Expired {
            return Err("token is already expired".into());
        }
        let f = self
            .file("entitlement.token")
            .ok_or("entitlement storage not initialized")?;
        std::fs::write(f, token).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn clear_token(&self) {
        if let Some(f) = self.file("entitlement.token") {
            let _ = std::fs::remove_file(f);
        }
    }

    /// The cached, re-verified payload (None = unlicensed/trial).
    pub fn current_payload(&self) -> Option<EntitlementPayload<F>> {
        let token = std::fs::read_to_string(self.file("entitlement.token")?).ok()?;
        verify(self.keys, token.trim()).ok()
    }

    /// Effective features right now: the licence's when valid or in grace,
    /// the trial's otherwise.
    pub fn current_features(&self) -> F {
        self.observe_time();
        effective_features(
            self.current_payload().as_ref(),
            self.now_unix(),
            self.max_seen_time(),
            self.trial,
        )
    }

    /// The cached payload and its validity right now (None = trial).
    pub fn current(&self) -> Option<(Validity, EntitlementPayload<F>)> {
        self.observe_time();
        let now = self.now_unix();
        let max_seen = self.max_seen_time();
        self.current_payload().map(|p| (validity(&p, now, max_seen), p))
    }

    /// Device identity: an Ed25519 seed generated on first use, and an id
    /// `d_<uuid>`. Returns (device_id, seed).
    pub fn device_identity(&self) -> Option<(String, [u8; 32])> {
        let id_file = self.file("device_id")?;
        let seed_file = self.file("device_seed")?;

        let device_id = match std::fs::read_to_string(&id_file) {
            Ok(s) => s.trim().to_string(),
            Err(_) => {
                let id = format!("d_{}", uuid_v4());
                std::fs::write(&id_file, &id).ok()?;
                id
            }
        };
        let seed: [u8; 32] = match std::fs::read_to_string(&seed_file)
            .ok()
            .and_then(|s| URL_SAFE_NO_PAD.decode(s.trim()).ok())
            .and_then(|v| v.try_into().ok())
        {
            Some(seed) => seed,
            None => {
                let mut seed = [0u8; 32];
                getrandom(&mut seed).ok()?;
                std::fs::write(&seed_file, URL_SAFE_NO_PAD.encode(seed)).ok()?;
                seed
            }
        };
        Some((device_id, seed))
    }

    /// The device public key (base64url) for activation requests.
    pub fn device_pubkey(&self) -> Option<String> {
        let (_, seed) = self.device_identity()?;
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        Some(URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()))
    }

    /// Signs an API request with the stored device key. Returns
    /// `(device_id, signature_b64url)`. The private key never leaves this
    /// crate: callers receive only the id and signature to attach.
    pub fn sign_request(&self, method: &str, path: &str, ts: i64) -> Option<(String, String)> {
        let (device_id, seed) = self.device_identity()?;
        let sig = crate::sign_request(&seed, method, path, &device_id, ts);
        Some((device_id, sig))
    }
}

fn getrandom(buf: &mut [u8]) -> Result<(), String> {
    use ring::rand::{SecureRandom, SystemRandom};
    SystemRandom::new().fill(buf).map_err(|_| "rng failure".into())
}

fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    let _ = getrandom(&mut b);
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::*;

    #[test]
    fn store_round_trip() {
        let store: Store<Feat> = Store::new(keys(), trial);
        let dir = tempfile::TempDir::new().unwrap();
        store.init(dir.path().to_str().unwrap());

        // Trial state before any token.
        assert!(store.current_features().watermark);
        assert!(store.current().is_none());

        // Device identity is generated once and stable.
        let (id1, seed1) = store.device_identity().unwrap();
        let (id2, seed2) = store.device_identity().unwrap();
        assert_eq!(id1, id2);
        assert_eq!(seed1, seed2);
        assert!(id1.starts_with("d_"));
        assert_eq!(store.device_pubkey().unwrap().len(), 43); // 32 bytes b64url

        // Max-seen-time advances monotonically.
        let t1 = store.max_seen_time();
        assert!(t1 > 0);
        store.observe_time();
        assert!(store.max_seen_time() >= t1);

        // Garbage token is rejected and nothing is persisted.
        assert!(store.apply_token("not-a-token").is_err());
        assert!(store.current_payload().is_none());

        // A good token unlocks; clearing returns to trial.
        let now = store.now_unix();
        store.apply_token(&mint(&payload_json("test-a", now + 86_400, false))).unwrap();
        assert!(!store.current_features().watermark);
        assert_eq!(store.current().unwrap().0, Validity::Valid);
        store.clear_token();
        assert!(store.current_features().watermark);

        // An already-expired token is refused.
        let old = now - crate::GRACE_SECS - 86_400;
        assert_eq!(
            store.apply_token(&mint(&payload_json("test-a", old, false))),
            Err("token is already expired".to_string())
        );
    }

    #[test]
    fn uninitialised_store_is_trial_and_refuses_tokens() {
        let store: Store<Feat> = Store::new(keys(), trial);
        assert!(store.current_features().watermark);
        assert!(store.device_identity().is_none());
        let token = mint(&payload_json("test-a", store.now_unix() + 86_400, false));
        assert_eq!(
            store.apply_token(&token),
            Err("entitlement storage not initialized".to_string())
        );
    }

    #[test]
    fn the_test_clock_only_moves_forward() {
        let store: Store<Feat> = Store::new(keys(), trial);
        let base = store.now_unix();
        store.set_test_clock_offset(-86_400);
        assert!(store.now_unix() >= base, "a negative offset must not turn the clock back");
        store.set_test_clock_offset(30 * 86_400);
        assert!(store.now_unix() >= base + 30 * 86_400);
    }
}
