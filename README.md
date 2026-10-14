# meros-entitlement

Offline licence tokens for Meros apps, and the device identity that signs
licence-service requests.

- **Token:** `base64url(payload) "." base64url(Ed25519 signature)`, unpadded.
  The signature covers the exact payload bytes and is checked against the
  product key named by the payload's `kid` before anything in the payload
  is trusted. The payload's `features` object is product-defined.
- **Time:** a 14-day grace period follows `exp`; a clock more than a day
  behind the latest time ever seen counts as rollback and expires the
  licence.
- **Device identity:** an Ed25519 seed and a `d_<uuid>` id, generated once
  and kept in the app's storage. Requests are signed over
  `"{method}|{path}|{device_id}|{ts}"`; the private key never leaves the
  crate.

```rust
use meros_entitlement::{ProductKeys, Store};

#[derive(Clone, serde::Deserialize)]
struct Features { tier: String, watermark: bool }

fn trial() -> Features { Features { tier: "trial".into(), watermark: true } }

const KEYS: ProductKeys = &[("prod-2027a", "<base64url public key>")];
static STORE: Store<Features> = Store::new(KEYS, trial);

STORE.init(&app_private_dir);
STORE.apply_token(&token_from_server)?;
let watermark = STORE.current_features().watermark;
let (device_id, sig) = STORE.sign_request("POST", "/v1/device/renew", ts).unwrap();
```

Call `meros_entitlement::check_keys(KEYS)` from a test so a mispasted key
fails the build, not the first activation.

The server side of the contract (token issuance, the device-signed API) is
specified by each product's licence service.

## Licence

Proprietary, © Meros.
