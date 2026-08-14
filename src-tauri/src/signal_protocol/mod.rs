//! Signal Protocol Handler

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::SystemTime;

use libsignal_protocol::kem::{KeyType as KemKeyType, PublicKey as KemPublicKey};
use libsignal_protocol::{
    DeviceId, GenericSignedPreKey, IdentityKey, IdentityKeyPair, KeyPair, KyberPreKeyId,
    KyberPreKeyRecord, PreKeySignalMessage, ProtocolAddress, PublicKey, SignalMessage,
    SignedPreKeyId, SignedPreKeyRecord, Timestamp,
};

use parking_lot::RwLock;
use rand::{SeedableRng, rngs::StdRng};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{hash, post_quantum, random};
use crate::error::{QorError, QorResult};
use crate::state::AppState;

mod store;
pub use store::*;

const SIGNAL_PQ_KEM_ALGORITHM: &str = "ML-KEM-1024";
const SIGNAL_PQ_KDF_ALGORITHM: &str = "BLAKE3-SHA3-512-DOMAIN-SEPARATED";
const SIGNAL_PQ_AEAD_ALGORITHM: &str = "XCHACHA20-POLY1305";
const SIGNAL_DEVICE_ID_MAX: u32 = 127;
const MAX_SIGNAL_STORE_BLOB_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_SIGNAL_PLAINTEXT_BYTES: usize = 64 * 1024;
const MAX_PENDING_DECRYPTS: usize = 512;
const MAX_PENDING_DECRYPT_PLAINTEXT_BYTES: usize = MAX_SIGNAL_PLAINTEXT_BYTES;
const MAX_PENDING_DECRYPT_TOTAL_BYTES: usize = 8 * 1024 * 1024;
const MAX_PENDING_TRANSPORT_MESSAGE_ID_BYTES: usize = 256;
const MAX_PENDING_APPLICATION_TYPE_BYTES: usize = 64;
const SIGNAL_CURVE_PUBLIC_KEY_BYTES: usize = 33;
const SIGNAL_IDENTITY_SIGNATURE_BYTES: usize = 64;
const SIGNAL_ML_KEM_PUBLIC_KEY_BYTES: usize = post_quantum::ML_KEM_PUBLIC_KEY_SIZE + 1;
const MAX_SIGNAL_CIPHERTEXT_BYTES: usize = 512 * 1024;
const MAX_PEER_ML_KEM_KEYS: usize = 10_000;
type StaticMlKemKeyPair = (Vec<u8>, Zeroizing<Vec<u8>>);
type SignalStores = (
    Arc<Mutex<InMemorySessionStore>>,
    Arc<Mutex<InMemoryIdentityKeyStore>>,
    Arc<Mutex<InMemoryPreKeyStore>>,
    Arc<Mutex<InMemorySignedPreKeyStore>>,
    Arc<Mutex<InMemoryKyberPreKeyStore>>,
);
type SerializedSignalState = (
    Zeroizing<Vec<u8>>,
    Zeroizing<Vec<u8>>,
    Zeroizing<Vec<u8>>,
    Zeroizing<Vec<u8>>,
);

pub(crate) enum SignalDecryptOutput {
    Plaintext(Vec<u8>),
    AuthenticatedPlaintextRejected,
}

fn static_ml_kem_binding_payload(
    username: &str,
    registration_id: u32,
    device_id: u32,
    public_key: &[u8],
) -> QorResult<Vec<u8>> {
    let username_len = u16::try_from(username.len())
        .map_err(|_| QorError::InvalidArgument("Username too long".to_string()))?;
    let mut payload = Vec::with_capacity(
        crate::protocol_keys::SIGNAL_STATIC_ML_KEM_BINDING.len()
            + 2
            + username.len()
            + 8
            + public_key.len(),
    );
    payload.extend_from_slice(crate::protocol_keys::SIGNAL_STATIC_ML_KEM_BINDING);
    payload.extend_from_slice(&username_len.to_be_bytes());
    payload.extend_from_slice(username.as_bytes());
    payload.extend_from_slice(&registration_id.to_be_bytes());
    payload.extend_from_slice(&device_id.to_be_bytes());
    payload.extend_from_slice(public_key);
    Ok(payload)
}

fn decode_exact_signal_base64(
    value: &str,
    expected_bytes: usize,
    label: &str,
) -> QorResult<Vec<u8>> {
    let expected_encoded = expected_bytes
        .checked_add(2)
        .and_then(|length| length.checked_div(3))
        .and_then(|length| length.checked_mul(4))
        .ok_or_else(|| QorError::InvalidArgument(format!("Invalid {}", label)))?;
    if value.len() != expected_encoded || !value.is_ascii() {
        return Err(QorError::InvalidArgument(format!("Invalid {}", label)));
    }
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
        .map_err(|_| QorError::InvalidArgument(format!("Invalid {}", label)))?;
    if decoded.len() != expected_bytes
        || base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &decoded) != value
    {
        return Err(QorError::InvalidArgument(format!("Invalid {}", label)));
    }
    Ok(decoded)
}

fn decode_bounded_signal_base64(
    value: &str,
    min_bytes: usize,
    max_bytes: usize,
    label: &str,
) -> QorResult<Vec<u8>> {
    let max_encoded = max_bytes
        .checked_add(2)
        .and_then(|length| length.checked_div(3))
        .and_then(|length| length.checked_mul(4))
        .ok_or_else(|| QorError::InvalidArgument(format!("Invalid {}", label)))?;
    if value.is_empty()
        || value.len() > max_encoded
        || !value.len().is_multiple_of(4)
        || !value.is_ascii()
    {
        return Err(QorError::InvalidArgument(format!("Invalid {}", label)));
    }
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
        .map_err(|_| QorError::InvalidArgument(format!("Invalid {}", label)))?;
    if decoded.len() < min_bytes
        || decoded.len() > max_bytes
        || base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &decoded) != value
    {
        return Err(QorError::InvalidArgument(format!("Invalid {}", label)));
    }
    Ok(decoded)
}

fn read_signal_store<T: DeserializeOwned>(
    db: &crate::database::DatabaseManager,
    store: &str,
    username: &str,
) -> QorResult<Option<T>> {
    let Some(blob) = db.get_secure(store, username)? else {
        return Ok(None);
    };
    let blob = Zeroizing::new(blob);
    if blob.len() > MAX_SIGNAL_STORE_BLOB_BYTES {
        return Err(QorError::SignalProtocol(format!(
            "Signal store {} exceeds size limit",
            store
        )));
    }
    serde_json::from_slice(&blob)
        .map(Some)
        .map_err(|_| QorError::SignalProtocol(format!("Invalid Signal store {}", store)))
}

fn serialize_signal_records<K: Serialize>(
    mut records: Vec<(K, Vec<u8>)>,
    label: &str,
) -> QorResult<Zeroizing<Vec<u8>>> {
    let serialized = serde_json::to_vec(&records);
    for (_, bytes) in &mut records {
        bytes.zeroize();
    }
    serialized.map(Zeroizing::new).map_err(|_| {
        QorError::SignalProtocol(format!("Failed to serialize Signal {} store", label))
    })
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingDecryptedMessage {
    pub pending_id: String,
    pub from_username: String,
    pub sender_identity_key: String,
    pub identity_root_fingerprint: String,
    pub identity_bundle_fingerprint: String,
    pub transport_message_id: String,
    pub application_type: String,
    pub plaintext: String,
}

fn signal_device_id_for_identity(identity: &IdentityKey) -> u32 {
    let mut material = crate::protocol_keys::SIGNAL_ACCOUNT_DEVICE_ID.to_vec();
    material.extend_from_slice(&identity.serialize());
    let digest = hash::blake3(&material);
    (u32::from(digest[0]) % SIGNAL_DEVICE_ID_MAX) + 1
}

fn validate_signal_device_identity_binding(
    identity: &IdentityKey,
    device_id: u32,
) -> QorResult<()> {
    if device_id != signal_device_id_for_identity(identity) {
        return Err(QorError::SignalProtocol(
            "Signal device id does not match the authenticated identity".to_string(),
        ));
    }
    Ok(())
}

fn signal_device_id(value: u32, label: &str) -> QorResult<DeviceId> {
    DeviceId::try_from(value).map_err(|_| {
        QorError::InvalidArgument(format!("Invalid {} Signal device id: {}", label, value))
    })
}

fn signal_rng() -> QorResult<StdRng> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut())
        .map_err(|_| QorError::Internal("Operating-system entropy unavailable".to_string()))?;
    Ok(StdRng::from_seed(*seed))
}

fn first_session_device_id(
    session_store: &InMemorySessionStore,
    peer_username: &str,
) -> Option<u32> {
    for device_id in 1..=SIGNAL_DEVICE_ID_MAX {
        let device = DeviceId::try_from(device_id).ok()?;
        let address = ProtocolAddress::new(peer_username.to_string(), device);
        if session_store.has_session(&address) {
            return Some(device_id);
        }
    }
    None
}

/// Signal Protocol handler
pub struct SignalHandler {
    session_stores: RwLock<HashMap<String, Arc<Mutex<InMemorySessionStore>>>>,
    identity_stores: RwLock<HashMap<String, Arc<Mutex<InMemoryIdentityKeyStore>>>>,
    prekey_stores: RwLock<HashMap<String, Arc<Mutex<InMemoryPreKeyStore>>>>,
    signed_prekey_stores: RwLock<HashMap<String, Arc<Mutex<InMemorySignedPreKeyStore>>>>,
    kyber_prekey_stores: RwLock<HashMap<String, Arc<Mutex<InMemoryKyberPreKeyStore>>>>,
    session_locks: Arc<RwLock<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    lifecycle_lock: Arc<tokio::sync::Mutex<()>>,
    lifecycle_epoch: AtomicU64,
    active_account: RwLock<Option<(String, String)>>,
    peer_ml_kem_keys: RwLock<HashMap<(String, String), Vec<u8>>>,
    static_mlkem_keys: RwLock<HashMap<String, StaticMlKemKeyPair>>,
}

impl SignalHandler {
    /// Create new Signal handler
    pub fn new() -> Self {
        Self {
            session_stores: RwLock::new(HashMap::new()),
            identity_stores: RwLock::new(HashMap::new()),
            prekey_stores: RwLock::new(HashMap::new()),
            signed_prekey_stores: RwLock::new(HashMap::new()),
            kyber_prekey_stores: RwLock::new(HashMap::new()),
            session_locks: Arc::new(RwLock::new(HashMap::new())),
            lifecycle_lock: Arc::new(tokio::sync::Mutex::new(())),
            lifecycle_epoch: AtomicU64::new(0),
            active_account: RwLock::new(None),
            peer_ml_kem_keys: RwLock::new(HashMap::new()),
            static_mlkem_keys: RwLock::new(HashMap::new()),
        }
    }

    pub fn clear_all(&self) {
        self.lifecycle_epoch.fetch_add(1, Ordering::AcqRel);
        *self.active_account.write() = None;
        self.session_stores.write().clear();
        self.identity_stores.write().clear();
        self.prekey_stores.write().clear();
        self.signed_prekey_stores.write().clear();
        self.kyber_prekey_stores.write().clear();
        self.session_locks.write().clear();
        self.peer_ml_kem_keys.write().clear();
        self.static_mlkem_keys.write().clear();
    }

    pub(crate) fn clear_account_state(&self, username: &str, account_owner: &str) {
        let deactivated = {
            let mut active = self.active_account.write();
            if active
                .as_ref()
                .is_some_and(|(active_username, active_owner)| {
                    active_username == username && active_owner == account_owner
                })
            {
                *active = None;
                true
            } else {
                false
            }
        };
        if !deactivated {
            return;
        }
        self.lifecycle_epoch.fetch_add(1, Ordering::AcqRel);
        self.session_stores.write().remove(username);
        self.identity_stores.write().remove(username);
        self.prekey_stores.write().remove(username);
        self.signed_prekey_stores.write().remove(username);
        self.kyber_prekey_stores.write().remove(username);
        let session_prefix = format!("{}:", username);
        self.session_locks
            .write()
            .retain(|key, _| !key.starts_with(&session_prefix));
        self.peer_ml_kem_keys
            .write()
            .retain(|(owner, _), _| owner != username);
        self.static_mlkem_keys.write().remove(username);
    }

    /// Validate username format
    fn validate_username(username: &str) -> QorResult<()> {
        if !(3..=100).contains(&username.len())
            || !username.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(QorError::InvalidArgument(
                "Invalid canonical Signal username".to_string(),
            ));
        }

        Ok(())
    }

    fn set_authenticated_peer_ml_kem_key(
        &self,
        owner: &str,
        peer: &str,
        key: Vec<u8>,
    ) -> QorResult<()> {
        post_quantum::validate_ml_kem_public_key(&key)?;
        let mut keys = self.peer_ml_kem_keys.write();
        let map_key = (owner.to_string(), peer.to_string());
        if !keys.contains_key(&map_key)
            && keys
                .keys()
                .filter(|(candidate, _)| candidate == owner)
                .count()
                >= MAX_PEER_ML_KEM_KEYS
        {
            return Err(QorError::SignalProtocol(
                "Peer ML-KEM key store is full".to_string(),
            ));
        }
        keys.insert(map_key, key);
        Ok(())
    }

    fn peer_static_ml_kem_key(&self, owner: &str, peer: &str) -> QorResult<Vec<u8>> {
        self.peer_ml_kem_keys
            .read()
            .get(&(owner.to_string(), peer.to_string()))
            .cloned()
            .ok_or_else(|| {
                QorError::NotInitialized("Peer static ML-KEM key unavailable".to_string())
            })
    }

    pub async fn has_peer_static_ml_kem_key(&self, owner: &str, peer: &str) -> QorResult<bool> {
        Self::validate_username(owner)?;
        Self::validate_username(peer)?;
        Ok(self
            .peer_ml_kem_keys
            .read()
            .contains_key(&(owner.to_string(), peer.to_string())))
    }

    fn serialize_peer_ml_kem_keys(&self, owner: &str) -> QorResult<Zeroizing<Vec<u8>>> {
        let keys = self.peer_ml_kem_keys.read();
        let mut entries = keys
            .iter()
            .filter(|&((candidate, _peer), _key)| candidate == owner)
            .map(|((_candidate, peer), key)| (peer.clone(), key.clone()))
            .collect::<Vec<_>>();
        if entries.len() > MAX_PEER_ML_KEM_KEYS {
            return Err(QorError::SignalProtocol(
                "Peer ML-KEM key store record limit exceeded".to_string(),
            ));
        }
        entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        serde_json::to_vec(&entries)
            .map(Zeroizing::new)
            .map_err(|_| {
                QorError::SignalProtocol("Failed to serialize peer ML-KEM keys".to_string())
            })
    }

    async fn acquire_session_lock(&self, key: &str) -> SessionLockGuard {
        let lock = {
            let mut locks = self.session_locks.write();
            locks
                .entry(key.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };

        let lock_identity = Arc::downgrade(&lock);
        let guard = lock.lock_owned().await;

        SessionLockGuard {
            guard: Some(guard),
            key: key.to_string(),
            lock_identity,
            registry: self.session_locks.clone(),
        }
    }

    pub(crate) fn lifecycle_epoch(&self) -> u64 {
        self.lifecycle_epoch.load(Ordering::Acquire)
    }

    pub(crate) async fn acquire_account_state_lock(
        &self,
        username: &str,
        account_owner: &str,
        expected_epoch: u64,
    ) -> QorResult<AccountStateLockGuard> {
        let lifecycle_guard = self.lifecycle_lock.clone().lock_owned().await;
        if self.lifecycle_epoch() != expected_epoch {
            return Err(QorError::NotInitialized(
                "Signal account lifecycle changed".to_string(),
            ));
        }
        if !self
            .active_account
            .read()
            .as_ref()
            .is_some_and(|(active_username, active_owner)| {
                active_username == username && active_owner == account_owner
            })
        {
            return Err(QorError::NotInitialized(
                "Signal command does not match the active account".to_string(),
            ));
        }
        let account_guard = self
            .acquire_session_lock(&format!("\0account\0{}", username))
            .await;
        Ok(AccountStateLockGuard {
            _lifecycle_guard: lifecycle_guard,
            _account_guard: account_guard,
        })
    }

    pub(crate) async fn acquire_account_initialization_lock(
        &self,
        username: &str,
        account_owner: &str,
        expected_epoch: u64,
    ) -> QorResult<AccountStateLockGuard> {
        let lifecycle_guard = self.lifecycle_lock.clone().lock_owned().await;
        if self.lifecycle_epoch() != expected_epoch {
            return Err(QorError::NotInitialized(
                "Signal account lifecycle changed".to_string(),
            ));
        }
        if self
            .active_account
            .read()
            .as_ref()
            .is_some_and(|(active_username, active_owner)| {
                active_username != username || active_owner != account_owner
            })
        {
            return Err(QorError::NotInitialized(
                "A different Signal account is already active".to_string(),
            ));
        }
        let account_guard = self
            .acquire_session_lock(&format!("\0account\0{}", username))
            .await;
        Ok(AccountStateLockGuard {
            _lifecycle_guard: lifecycle_guard,
            _account_guard: account_guard,
        })
    }

    pub(crate) fn activate_account(&self, username: &str, account_owner: &str) -> QorResult<()> {
        let mut active = self.active_account.write();
        if active
            .as_ref()
            .is_some_and(|(active_username, active_owner)| {
                active_username != username || active_owner != account_owner
            })
        {
            return Err(QorError::NotInitialized(
                "A different Signal account is already active".to_string(),
            ));
        }
        *active = Some((username.to_string(), account_owner.to_string()));
        Ok(())
    }

    pub(crate) async fn acquire_lifecycle_lock(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.lifecycle_lock.clone().lock_owned().await
    }

    fn get_or_create_stores(&self, username: &str) -> SignalStores {
        let session_store = {
            let mut stores = self.session_stores.write();
            stores
                .entry(username.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(InMemorySessionStore::new())))
                .clone()
        };

        let identity_store = {
            let mut stores = self.identity_stores.write();
            stores
                .entry(username.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(InMemoryIdentityKeyStore::new())))
                .clone()
        };

        let prekey_store = {
            let mut stores = self.prekey_stores.write();
            stores
                .entry(username.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(InMemoryPreKeyStore::new())))
                .clone()
        };

        let signed_prekey_store = {
            let mut stores = self.signed_prekey_stores.write();
            stores
                .entry(username.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(InMemorySignedPreKeyStore::new())))
                .clone()
        };

        let kyber_prekey_store = {
            let mut stores = self.kyber_prekey_stores.write();
            stores
                .entry(username.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(InMemoryKyberPreKeyStore::new())))
                .clone()
        };

        (
            session_store,
            identity_store,
            prekey_store,
            signed_prekey_store,
            kyber_prekey_store,
        )
    }

    async fn own_signal_device_id(&self, username: &str) -> QorResult<u32> {
        let (_, identity_store, _, _, _) = self.get_or_create_stores(username);
        let identity_store = identity_store.lock().await;
        let identity = identity_store
            .get_identity_key_pair()
            .ok_or_else(|| QorError::NotInitialized("No identity key pair".to_string()))?;
        Ok(signal_device_id_for_identity(identity.identity_key()))
    }

    /// Generate identity keys for a user
    pub async fn generate_identity(&self, username: &str) -> QorResult<IdentityBundle> {
        Self::validate_username(username)?;

        let (_, identity_store, _, _, _) = self.get_or_create_stores(username);
        let identity_store = identity_store.lock().await;

        if let Some(existing) = identity_store.get_identity_key_pair() {
            let reg_id = match identity_store.get_local_registration_id() {
                Some(existing_id) => existing_id,
                None => {
                    let new_id = generate_registration_id()?;
                    identity_store.set_local_registration_id(new_id);
                    new_id
                }
            };

            return Ok(IdentityBundle {
                identity_key_public: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    existing.public_key().serialize(),
                ),
                registration_id: reg_id,
            });
        }

        // Generate new identity
        let mut rng = signal_rng()?;
        let identity_key_pair = IdentityKeyPair::generate(&mut rng);
        let registration_id = generate_registration_id()?;

        identity_store.set_identity_key_pair(identity_key_pair);
        identity_store.set_local_registration_id(registration_id);

        Ok(IdentityBundle {
            identity_key_public: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                identity_key_pair.public_key().serialize(),
            ),
            registration_id,
        })
    }

    /// Generate signed pre-key
    pub async fn generate_signed_prekey(
        &self,
        username: &str,
        key_id: u32,
    ) -> QorResult<SignedPreKey> {
        Self::validate_username(username)?;

        let (_, identity_store, _, signed_prekey_store, _) = self.get_or_create_stores(username);
        let identity_store = identity_store.lock().await;
        let signed_prekey_store = &mut *signed_prekey_store.lock().await;

        let identity_key_pair = identity_store
            .get_identity_key_pair()
            .ok_or_else(|| QorError::NotInitialized("No identity key pair".to_string()))?;

        let mut rng = signal_rng()?;
        let key_pair = KeyPair::generate(&mut rng);
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| QorError::SignalProtocol("System clock predates Unix epoch".to_string()))?
            .as_millis();

        let signature = identity_key_pair
            .private_key()
            .calculate_signature(&key_pair.public_key.serialize(), &mut rng)
            .map_err(|e| QorError::SignalProtocol(e.to_string()))?;

        let signed_prekey_record = SignedPreKeyRecord::new(
            key_id.into(),
            Timestamp::from_epoch_millis(timestamp as u64),
            &key_pair,
            &signature,
        );

        signed_prekey_store
            .store_signed_pre_key(key_id.into(), &signed_prekey_record)
            .map_err(QorError::SignalProtocol)?;

        Ok(SignedPreKey {
            key_id,
            public_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                key_pair.public_key.serialize(),
            ),
            signature: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                signature,
            ),
        })
    }

    pub async fn generate_ml_kem_prekey(
        &self,
        username: &str,
        key_id: u32,
    ) -> QorResult<MlKemPreKey> {
        Self::validate_username(username)?;

        let (_, identity_store, _, _, kyber_prekey_store) = self.get_or_create_stores(username);
        let identity_store = identity_store.lock().await;
        let kyber_prekey_store = &mut *kyber_prekey_store.lock().await;

        let identity_key_pair = identity_store
            .get_identity_key_pair()
            .ok_or_else(|| QorError::NotInitialized("No identity key pair".to_string()))?;

        let kyber_record = KyberPreKeyRecord::generate(
            KemKeyType::MLKEM1024,
            key_id.into(),
            identity_key_pair.private_key(),
        )
        .map_err(|e| QorError::SignalProtocol(e.to_string()))?;

        let public_key_bytes = kyber_record
            .public_key()
            .map_err(|e| QorError::SignalProtocol(e.to_string()))?
            .serialize();

        let signature = kyber_record
            .signature()
            .map_err(|e| QorError::SignalProtocol(e.to_string()))?
            .to_vec();

        kyber_prekey_store
            .store_kyber_pre_key(key_id.into(), &kyber_record)
            .map_err(QorError::SignalProtocol)?;

        Ok(MlKemPreKey {
            key_id,
            public_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                public_key_bytes,
            ),
            signature: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                signature,
            ),
        })
    }

    /// Create pre-key bundle for distribution
    pub async fn create_prekey_bundle(&self, username: &str) -> QorResult<PreKeyBundle> {
        Self::validate_username(username)?;

        let (_, identity_store, _, signed_prekey_store, kyber_prekey_store) =
            self.get_or_create_stores(username);

        self.generate_identity(username).await?;

        const PREKEY_ROTATION_MS: u64 = 24 * 60 * 60 * 1000;
        const PREKEY_RETENTION_MS: u64 = 7 * PREKEY_ROTATION_MS;
        let now_ms = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| QorError::SignalProtocol(format!("System clock error: {}", e)))?
            .as_millis() as u64;

        let latest_signed = signed_prekey_store.lock().await.get_any_signed_pre_key();
        let rotate_signed = latest_signed
            .as_ref()
            .and_then(|(_, record)| record.timestamp().ok())
            .map(|timestamp| now_ms.saturating_sub(timestamp.epoch_millis()) >= PREKEY_ROTATION_MS)
            .unwrap_or(true);
        let retention_cutoff = now_ms.saturating_sub(PREKEY_RETENTION_MS);
        signed_prekey_store
            .lock()
            .await
            .prune_older_than(retention_cutoff);
        if rotate_signed {
            let next_id = latest_signed
                .as_ref()
                .map(|(id, _)| u32::from(*id))
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| {
                    QorError::SignalProtocol("Signed pre-key ID exhausted".to_string())
                })?;
            self.generate_signed_prekey(username, next_id).await?;
        }

        let latest_kyber = kyber_prekey_store.lock().await.get_any_kyber_pre_key();
        let rotate_kyber = latest_kyber
            .as_ref()
            .and_then(|(_, record)| record.timestamp().ok())
            .map(|timestamp| now_ms.saturating_sub(timestamp.epoch_millis()) >= PREKEY_ROTATION_MS)
            .unwrap_or(true);
        kyber_prekey_store
            .lock()
            .await
            .prune_older_than(retention_cutoff);
        if rotate_kyber {
            let next_id = latest_kyber
                .as_ref()
                .map(|(id, _)| u32::from(*id))
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| {
                    QorError::SignalProtocol("Kyber pre-key ID exhausted".to_string())
                })?;
            self.generate_ml_kem_prekey(username, next_id).await?;
        }

        let pq_kyber_public = self
            .static_mlkem_keys
            .read()
            .get(username)
            .map(|(public_key, _)| public_key.clone())
            .ok_or_else(|| {
                QorError::NotInitialized("Static account ML-KEM key unavailable".to_string())
            })?;

        let identity_store = identity_store.lock().await;
        let signed_prekey_store = signed_prekey_store.lock().await;
        let kyber_prekey_store = kyber_prekey_store.lock().await;

        let identity_key_pair = identity_store
            .get_identity_key_pair()
            .ok_or_else(|| QorError::NotInitialized("No identity key pair".to_string()))?;

        let registration_id = identity_store
            .get_local_registration_id()
            .ok_or_else(|| QorError::NotInitialized("No registration ID".to_string()))?;

        let (signed_prekey_id, signed_prekey) = signed_prekey_store
            .get_any_signed_pre_key()
            .ok_or_else(|| QorError::SignalProtocol("No signed pre-keys available".to_string()))?;

        let (kyber_prekey_id, kyber_prekey) = kyber_prekey_store
            .get_any_kyber_pre_key()
            .ok_or_else(|| QorError::SignalProtocol("No Kyber pre-keys available".to_string()))?;
        let local_device_id = signal_device_id_for_identity(identity_key_pair.identity_key());
        let static_ml_kem_payload = static_ml_kem_binding_payload(
            username,
            registration_id,
            local_device_id,
            &pq_kyber_public,
        )?;
        let mut signature_rng = signal_rng()?;
        let static_ml_kem_signature = identity_key_pair
            .private_key()
            .calculate_signature(&static_ml_kem_payload, &mut signature_rng)
            .map_err(|e| QorError::SignalProtocol(e.to_string()))?;

        Ok(PreKeyBundle {
            registration_id,
            device_id: local_device_id,
            identity_key_base64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                identity_key_pair.public_key().serialize(),
            ),
            signed_pre_key: SignedPreKeyInfo {
                key_id: u32::from(signed_prekey_id),
                public_key_base64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    signed_prekey
                        .public_key()
                        .map_err(|e| QorError::SignalProtocol(e.to_string()))?
                        .serialize(),
                ),
                signature_base64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    signed_prekey
                        .signature()
                        .map_err(|e| QorError::SignalProtocol(e.to_string()))?,
                ),
            },
            ml_kem_pre_key: MlKemPreKeyInfo {
                key_id: u32::from(kyber_prekey_id),
                public_key_base64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    kyber_prekey
                        .public_key()
                        .map_err(|e| QorError::SignalProtocol(e.to_string()))?
                        .serialize(),
                ),
                signature_base64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    kyber_prekey
                        .signature()
                        .map_err(|e| QorError::SignalProtocol(e.to_string()))?,
                ),
            },
            static_ml_kem: StaticMlKemKey {
                public_key_base64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &pq_kyber_public,
                ),
                signature_base64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    static_ml_kem_signature,
                ),
            },
        })
    }

    /// Process incoming pre-key bundle and establish session
    pub async fn process_prekey_bundle(
        &self,
        self_username: &str,
        peer_username: &str,
        bundle: PreKeyBundle,
    ) -> QorResult<bool> {
        Self::validate_username(self_username)?;
        Self::validate_username(peer_username)?;
        if !(1..=16_380).contains(&bundle.registration_id) {
            return Err(QorError::InvalidArgument(
                "Invalid peer Signal registration ID".to_string(),
            ));
        }

        let peer_device_id = bundle.device_id;
        let peer_device = signal_device_id(peer_device_id, "peer")?;
        let session_key = format!("{}:{}.{}", self_username, peer_username, peer_device_id);
        let _lock = self.acquire_session_lock(&session_key).await;

        let (session_store, identity_store, _, _, _) = self.get_or_create_stores(self_username);
        let mut session_store = session_store.lock().await;
        let mut identity_store = identity_store.lock().await;

        let peer_address = ProtocolAddress::new(peer_username.to_string(), peer_device);
        let local_device_id = identity_store
            .get_identity_key_pair()
            .map(|identity| signal_device_id_for_identity(identity.identity_key()))
            .ok_or_else(|| QorError::NotInitialized("No identity key pair".to_string()))?;
        let local_device = signal_device_id(local_device_id, "local")?;
        let local_address = ProtocolAddress::new(self_username.to_string(), local_device);
        let peer_identity_key = IdentityKey::decode(&decode_exact_signal_base64(
            &bundle.identity_key_base64,
            SIGNAL_CURVE_PUBLIC_KEY_BYTES,
            "identity key",
        )?)
        .map_err(|_| QorError::InvalidArgument("Invalid identity key".to_string()))?;
        validate_signal_device_identity_binding(&peer_identity_key, peer_device_id)?;

        let existing_session = session_store.has_session(&peer_address);
        if existing_session {
            let stored_identity =
                <InMemoryIdentityKeyStore as libsignal_protocol::IdentityKeyStore>::get_identity(
                    &*identity_store,
                    &peer_address,
                )
                .await
                .map_err(|_| {
                    QorError::SignalProtocol("Failed to read pinned identity".to_string())
                })?
                .ok_or_else(|| {
                    QorError::SignalProtocol(
                        "Session exists without a pinned peer identity".to_string(),
                    )
                })?;
            if stored_identity != peer_identity_key {
                return Err(QorError::SignalProtocol(
                    "untrusted identity key change".to_string(),
                ));
            }
        }

        let peer_signed_prekey = PublicKey::deserialize(&decode_exact_signal_base64(
            &bundle.signed_pre_key.public_key_base64,
            SIGNAL_CURVE_PUBLIC_KEY_BYTES,
            "signed pre-key",
        )?)
        .map_err(|_| QorError::InvalidArgument("Invalid signed pre-key".to_string()))?;

        let signature = decode_exact_signal_base64(
            &bundle.signed_pre_key.signature_base64,
            SIGNAL_IDENTITY_SIGNATURE_BYTES,
            "signed pre-key signature",
        )?;

        // Verify signed pre-key signature
        if !peer_identity_key
            .public_key()
            .verify_signature(&peer_signed_prekey.serialize(), &signature)
        {
            return Err(QorError::SignalProtocol(
                "Invalid signed pre-key signature".to_string(),
            ));
        }

        let kpk = &bundle.ml_kem_pre_key;
        let kyber_pk = KemPublicKey::deserialize(&decode_exact_signal_base64(
            &kpk.public_key_base64,
            SIGNAL_ML_KEM_PUBLIC_KEY_BYTES,
            "ML-KEM pre-key",
        )?)
        .map_err(|_| QorError::InvalidArgument("Invalid ML-KEM pre-key".to_string()))?;
        if kyber_pk.key_type() != KemKeyType::MLKEM1024 {
            return Err(QorError::SignalProtocol(
                "Non-ML-KEM Signal pre-key rejected".to_string(),
            ));
        }
        let kyber_sig = decode_exact_signal_base64(
            &kpk.signature_base64,
            SIGNAL_IDENTITY_SIGNATURE_BYTES,
            "ML-KEM pre-key signature",
        )?;
        if !peer_identity_key
            .public_key()
            .verify_signature(&kyber_pk.serialize(), &kyber_sig)
        {
            return Err(QorError::SignalProtocol(
                "Invalid ML-KEM pre-key signature".to_string(),
            ));
        }
        let kyber_id = KyberPreKeyId::from(kpk.key_id);

        // Build Signal pre-key bundle
        let static_ml_kem = &bundle.static_ml_kem;
        let static_ml_kem_key = decode_exact_signal_base64(
            &static_ml_kem.public_key_base64,
            post_quantum::ML_KEM_PUBLIC_KEY_SIZE,
            "static ML-KEM key",
        )?;
        post_quantum::validate_ml_kem_public_key(&static_ml_kem_key)?;
        let static_ml_kem_signature = decode_exact_signal_base64(
            &static_ml_kem.signature_base64,
            SIGNAL_IDENTITY_SIGNATURE_BYTES,
            "static ML-KEM key signature",
        )?;
        let static_ml_kem_payload = static_ml_kem_binding_payload(
            peer_username,
            bundle.registration_id,
            peer_device_id,
            &static_ml_kem_key,
        )?;
        if !peer_identity_key
            .public_key()
            .verify_signature(&static_ml_kem_payload, &static_ml_kem_signature)
        {
            return Err(QorError::SignalProtocol(
                "Invalid static ML-KEM key signature".to_string(),
            ));
        }

        let signal_bundle = libsignal_protocol::PreKeyBundle::new(
            bundle.registration_id,
            peer_device,
            None,
            SignedPreKeyId::from(bundle.signed_pre_key.key_id),
            peer_signed_prekey,
            signature,
            kyber_id,
            kyber_pk,
            kyber_sig,
            peer_identity_key,
        )
        .map_err(|e| QorError::SignalProtocol(e.to_string()))?;

        if existing_session {
            let record = session_store.load_session(&peer_address).ok_or_else(|| {
                QorError::SignalProtocol("Signal session disappeared during validation".to_string())
            })?;
            validate_pq_ratchet_state(&record).map_err(QorError::SignalProtocol)?;
            self.set_authenticated_peer_ml_kem_key(
                self_username,
                peer_username,
                static_ml_kem_key,
            )?;
            return Ok(true);
        }

        let mut rng = signal_rng()?;

        // Process the bundle to create session
        let result = libsignal_protocol::process_prekey_bundle(
            &peer_address,
            &local_address,
            &mut *session_store,
            &mut *identity_store,
            &signal_bundle,
            SystemTime::now(),
            &mut rng,
        )
        .await;

        match result {
            Ok(_) => {
                let record = session_store.load_session(&peer_address).ok_or_else(|| {
                    QorError::SignalProtocol(
                        "Signal session was not stored after bundle processing".to_string(),
                    )
                })?;
                validate_pq_ratchet_state(&record).map_err(QorError::SignalProtocol)?;
                self.set_authenticated_peer_ml_kem_key(
                    self_username,
                    peer_username,
                    static_ml_kem_key,
                )?;
                Ok(true)
            }
            
            Err(e) => Err(QorError::SignalProtocol(e.to_string())),
        }
    }

    /// Check if session exists
    pub async fn has_session(&self, self_username: &str, peer_username: &str) -> QorResult<bool> {
        Self::validate_username(self_username)?;
        Self::validate_username(peer_username)?;

        let (session_store, _, _, _, _) = self.get_or_create_stores(self_username);
        let session_store = session_store.lock().await;
        Ok(first_session_device_id(&session_store, peer_username).is_some())
    }

    pub async fn encrypt(
        &self,
        from_username: &str,
        to_username: &str,
        plaintext: &[u8],
    ) -> QorResult<EncryptedMessage> {
        Self::validate_username(from_username)?;
        Self::validate_username(to_username)?;
        if plaintext.len() > MAX_SIGNAL_PLAINTEXT_BYTES {
            return Err(QorError::InvalidArgument(
                "Signal plaintext exceeds size limit".to_string(),
            ));
        }

        let session_key = format!("{}:{}", from_username, to_username);
        let _lock = self.acquire_session_lock(&session_key).await;

        self.peer_static_ml_kem_key(from_username, to_username)?;

        let signal_encrypted = self
            .encrypt_with_signal_protocol(from_username, to_username, plaintext)
            .await?;

        let wrapped = self
            .wrap_with_pq_hybrid(&signal_encrypted, from_username, to_username)
            .await?;

        Ok(EncryptedMessage {
            message_type: signal_encrypted.message_type,
            pq_envelope: wrapped,
        })
    }

    async fn encrypt_with_signal_protocol(
        &self,
        from_username: &str,
        to_username: &str,
        plaintext: &[u8],
    ) -> QorResult<SignalEncryptedMessage> {
        let (session_store, identity_store, _, _, _) = self.get_or_create_stores(from_username);
        let mut session_store = session_store.lock().await;
        let mut identity_store = identity_store.lock().await;
        let sender_device_id = identity_store
            .get_identity_key_pair()
            .map(|identity| signal_device_id_for_identity(identity.identity_key()))
            .ok_or_else(|| QorError::NotInitialized("No identity key pair".to_string()))?;
        let target_device_id =
            first_session_device_id(&session_store, to_username).ok_or_else(|| {
                QorError::NotInitialized(
                    "No authenticated Signal session for recipient".to_string(),
                )
            })?;
        let to_device = signal_device_id(target_device_id, "target")?;
        let to_address = ProtocolAddress::new(to_username.to_string(), to_device);
        let from_device = signal_device_id(sender_device_id, "sender")?;
        let from_address = ProtocolAddress::new(from_username.to_string(), from_device);
        let mut rng = signal_rng()?;

        let message = libsignal_protocol::message_encrypt(
            plaintext,
            &to_address,
            &from_address,
            &mut *session_store,
            &mut *identity_store,
            SystemTime::now(),
            &mut rng,
        )
        .await
        .map_err(|e| QorError::SignalProtocol(e.to_string()))?;

        let updated_session = session_store.load_session(&to_address).ok_or_else(|| {
            QorError::SignalProtocol("Signal session missing after encryption".to_string())
        })?;
        validate_pq_ratchet_state(&updated_session).map_err(QorError::SignalProtocol)?;

        let message_type = message.message_type() as u8;
        if message_type != 2 && message_type != 3 {
            return Err(QorError::SignalProtocol(
                "Unsupported outgoing Signal message type".to_string(),
            ));
        }
        Ok(SignalEncryptedMessage {
            message_type,
            ciphertext: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                message.serialize(),
            ),
            sender_device_id,
            recipient_device_id: target_device_id,
        })
    }

    /// Wrap Signal message with PQ hybrid envelope
    async fn wrap_with_pq_hybrid(
        &self,
        signal_message: &SignalEncryptedMessage,
        from_username: &str,
        to_username: &str,
    ) -> QorResult<PQEnvelope> {
        let peer_pq_key = self.peer_static_ml_kem_key(from_username, to_username)?;

        let kem_result = post_quantum::ml_kem_encapsulate(&peer_pq_key)?;

        let salt = random::random_bytes(32)?;
        let info = format!("pq-envelope:{}->{}", from_username, to_username);

        let mut kdf_input = Zeroizing::new(Vec::new());
        kdf_input.extend_from_slice(&kem_result.shared_secret);
        kdf_input.extend_from_slice(&salt);
        kdf_input.extend_from_slice(info.as_bytes());

        let key_material = Zeroizing::new(hash::blake3(&kdf_input));

        let extended_key = Zeroizing::new(hash::sha3_512(&key_material[..]));
        let aes_key = Zeroizing::new(<[u8; 32]>::try_from(&extended_key[..32]).unwrap());
        let nonce = random::random_bytes(24)?;
        let aad = info.as_bytes();
        let payload = Zeroizing::new(serde_json::to_vec(signal_message)?);

        let encrypted = crate::crypto::aead::xchacha_encrypt(
            &aes_key,
            nonce[..24].try_into().unwrap(),
            &payload,
            aad,
        )?;

        Ok(PQEnvelope {
            version: crate::protocol_keys::SIGNAL_PQ_ENVELOPE_VERSION.to_string(),
            algorithms: PQEnvelopeAlgorithms {
                kem: SIGNAL_PQ_KEM_ALGORITHM.to_string(),
                kdf: SIGNAL_PQ_KDF_ALGORITHM.to_string(),
                aead: SIGNAL_PQ_AEAD_ALGORITHM.to_string(),
            },
            kem_ciphertext: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &kem_result.ciphertext,
            ),
            nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &nonce),
            ciphertext: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &encrypted,
            ),
            salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &salt),
        })
    }

    pub(crate) async fn decrypt_with_mutation_status(
        &self,
        from_username: &str,
        to_username: &str,
        encrypted: &EncryptedMessage,
    ) -> (QorResult<SignalDecryptOutput>, bool) {
        if let Err(error) = Self::validate_username(from_username) {
            return (Err(error), false);
        }
        if let Err(error) = Self::validate_username(to_username) {
            return (Err(error), false);
        }

        let session_key = format!("{}:{}", to_username, from_username);
        let _lock = self.acquire_session_lock(&session_key).await;

        let envelope = &encrypted.pq_envelope;
        let local_device_id = match self.own_signal_device_id(to_username).await {
            Ok(device_id) => device_id,
            Err(error) => return (Err(error), false),
        };
        let signal_message = match self
            .unwrap_pq_hybrid(envelope, from_username, to_username)
            .await
        {
            Ok(message) => message,
            Err(error) => return (Err(error), false),
        };
        if encrypted.message_type != signal_message.message_type {
            return (
                Err(QorError::DecryptionFailed(
                    "Signal message type binding mismatch".to_string(),
                )),
                false,
            );
        }
        if signal_message.recipient_device_id != local_device_id {
            return (
                Err(QorError::DecryptionFailed(
                    "Signal recipient device mismatch".to_string(),
                )),
                false,
            );
        }

        (
            self.decrypt_with_signal_protocol(
                from_username,
                to_username,
                &signal_message,
                signal_message.sender_device_id,
            )
            .await,
            true,
        )
    }

    /// Unwrap PQ hybrid envelope
    async fn unwrap_pq_hybrid(
        &self,
        envelope: &PQEnvelope,
        from_username: &str,
        to_username: &str,
    ) -> QorResult<SignalEncryptedMessage> {
        if envelope.version != crate::protocol_keys::SIGNAL_PQ_ENVELOPE_VERSION {
            return Err(QorError::DecryptionFailed(
                "Unsupported Signal PQ envelope version".to_string(),
            ));
        }
        if envelope.algorithms.kem != SIGNAL_PQ_KEM_ALGORITHM
            || envelope.algorithms.kdf != SIGNAL_PQ_KDF_ALGORITHM
            || envelope.algorithms.aead != SIGNAL_PQ_AEAD_ALGORITHM
        {
            return Err(QorError::DecryptionFailed(
                "Signal PQ envelope algorithm policy mismatch".to_string(),
            ));
        }

        let our_secret_key = self
            .static_mlkem_keys
            .read()
            .get(to_username)
            .map(|(_, secret_key)| secret_key.clone())
            .ok_or_else(|| {
                QorError::NotInitialized("Static account ML-KEM key unavailable".to_string())
            })?;

        let kem_ciphertext = decode_exact_signal_base64(
            &envelope.kem_ciphertext,
            post_quantum::ML_KEM_CIPHERTEXT_SIZE,
            "KEM ciphertext",
        )?;
        let salt = decode_exact_signal_base64(&envelope.salt, 32, "KDF salt")?;
        let nonce = decode_exact_signal_base64(&envelope.nonce, 24, "nonce")?;
        let ciphertext = decode_bounded_signal_base64(
            &envelope.ciphertext,
            16,
            MAX_SIGNAL_CIPHERTEXT_BYTES,
            "ciphertext",
        )?;

        let shared_secret = post_quantum::ml_kem_decapsulate(&kem_ciphertext, &our_secret_key)?;

        let info = format!("pq-envelope:{}->{}", from_username, to_username);

        let mut kdf_input = Zeroizing::new(Vec::new());
        kdf_input.extend_from_slice(&shared_secret);
        kdf_input.extend_from_slice(&salt);
        kdf_input.extend_from_slice(info.as_bytes());

        let key_material = Zeroizing::new(hash::blake3(&kdf_input));
        let extended_key = Zeroizing::new(hash::sha3_512(&key_material[..]));
        let aes_key = Zeroizing::new(<[u8; 32]>::try_from(&extended_key[..32]).unwrap());
        let aad = info.as_bytes();

        // Decrypt
        let nonce_array: [u8; 24] = nonce
            .try_into()
            .map_err(|_| QorError::DecryptionFailed("Invalid nonce length".to_string()))?;

        let plaintext = Zeroizing::new(crate::crypto::aead::xchacha_decrypt(
            &aes_key,
            &nonce_array,
            &ciphertext,
            aad,
        )?);

        let signal_message: SignalEncryptedMessage = serde_json::from_slice(&plaintext)
            .map_err(|e| QorError::DecryptionFailed(format!("Invalid Signal message: {}", e)))?;

        Ok(signal_message)
    }

    async fn decrypt_with_signal_protocol(
        &self,
        from_username: &str,
        to_username: &str,
        signal_message: &SignalEncryptedMessage,
        from_device_id: u32,
    ) -> QorResult<SignalDecryptOutput> {
        let (session_store, identity_store, prekey_store, signed_prekey_store, kyber_prekey_store) =
            self.get_or_create_stores(to_username);
        let mut session_store = session_store.lock().await;
        let mut identity_store = identity_store.lock().await;
        let mut prekey_store = prekey_store.lock().await;
        let signed_prekey_store = signed_prekey_store.lock().await;
        let mut kyber_prekey_store = kyber_prekey_store.lock().await;

        let from_device = signal_device_id(from_device_id, "sender")?;
        let from_address = ProtocolAddress::new(from_username.to_string(), from_device);
        let local_device_id = identity_store
            .get_identity_key_pair()
            .map(|identity| signal_device_id_for_identity(identity.identity_key()))
            .ok_or_else(|| QorError::NotInitialized("No identity key pair".to_string()))?;
        let local_device = signal_device_id(local_device_id, "local")?;
        let local_address = ProtocolAddress::new(to_username.to_string(), local_device);

        let message_bytes = Zeroizing::new(decode_bounded_signal_base64(
            &signal_message.ciphertext,
            1,
            MAX_SIGNAL_CIPHERTEXT_BYTES,
            "Signal message",
        )?);

        let mut rng = signal_rng()?;

        let mut plaintext = match signal_message.message_type {
            3 => {
                let prekey_message = PreKeySignalMessage::try_from(message_bytes.as_slice())
                    .map_err(|e| QorError::SignalProtocol(e.to_string()))?;
                validate_signal_device_identity_binding(
                    prekey_message.identity_key(),
                    from_device_id,
                )?;

                libsignal_protocol::message_decrypt_prekey(
                    &prekey_message,
                    &from_address,
                    &local_address,
                    &mut *session_store,
                    &mut *identity_store,
                    &mut *prekey_store,
                    &*signed_prekey_store,
                    &mut *kyber_prekey_store,
                    &mut rng,
                )
                .await
                .map_err(|e| QorError::SignalProtocol(e.to_string()))?
            }
            2 => {
                let signal_msg = SignalMessage::try_from(message_bytes.as_slice())
                    .map_err(|e| QorError::SignalProtocol(e.to_string()))?;

                let pinned_identity =
                    identity_store.get_identity(from_username).ok_or_else(|| {
                        QorError::SignalProtocol(
                            "Signal session exists without a pinned peer identity".to_string(),
                        )
                    })?;
                validate_signal_device_identity_binding(&pinned_identity, from_device_id)?;

                if !session_store.has_session(&from_address) {
                    return Err(QorError::SignalProtocol(
                        "No Signal session for decryption".to_string(),
                    ));
                }

                libsignal_protocol::message_decrypt_signal(
                    &signal_msg,
                    &from_address,
                    &local_address,
                    &mut *session_store,
                    &mut *identity_store,
                    &mut rng,
                )
                .await
                .map_err(|e| QorError::SignalProtocol(e.to_string()))?
            }
            _ => {
                return Err(QorError::DecryptionFailed(
                    "Unsupported Signal message type".to_string(),
                ));
            }
        };

        if plaintext.len() > MAX_SIGNAL_PLAINTEXT_BYTES {
            plaintext.zeroize();
            return Ok(SignalDecryptOutput::AuthenticatedPlaintextRejected);
        }

        let updated_session = session_store.load_session(&from_address).ok_or_else(|| {
            QorError::SignalProtocol("Signal session missing after decryption".to_string())
        })?;
        validate_pq_ratchet_state(&updated_session).map_err(QorError::SignalProtocol)?;

        Ok(SignalDecryptOutput::Plaintext(plaintext))
    }

    /// Delete all sessions with peer
    pub async fn delete_all_sessions(
        &self,
        self_username: &str,
        peer_username: &str,
    ) -> QorResult<bool> {
        Self::validate_username(self_username)?;
        Self::validate_username(peer_username)?;

        let (session_store, _, _, _, _) = self.get_or_create_stores(self_username);
        session_store
            .lock()
            .await
            .delete_all_sessions(peer_username);
        self.peer_ml_kem_keys
            .write()
            .remove(&(self_username.to_string(), peer_username.to_string()));
        Ok(true)
    }

    async fn persist_transparency_peer_identity(
        &self,
        db: &crate::database::DatabaseManager,
        self_username: &str,
        peer_username: &str,
        replacement: Option<IdentityKey>,
    ) -> QorResult<bool> {
        Self::validate_username(self_username)?;
        Self::validate_username(peer_username)?;

        let (session_store, identity_store, _, _, _) = self.get_or_create_stores(self_username);

        let sessions = session_store.lock().await;
        let identities = identity_store.lock().await;
        if replacement.is_some() && !identities.can_insert_identity(peer_username) {
            return Err(QorError::SignalProtocol(
                "Known peer identity limit exceeded".to_string(),
            ));
        }
        let old_identity = identities.get_identity(peer_username);
        if replacement
            .as_ref()
            .is_some_and(|identity| old_identity.as_ref() == Some(identity))
        {
            return Ok(true);
        }
        let mut pending_decrypts = Self::load_pending_decrypts(db, self_username)?;
        pending_decrypts.retain(|entry| entry.from_username != peer_username);
        let old_sessions = (1..=SIGNAL_DEVICE_ID_MAX)
            .filter_map(|candidate| {
                let device = DeviceId::try_from(candidate).ok()?;
                let address = ProtocolAddress::new(peer_username.to_string(), device);
                sessions
                    .load_session(&address)
                    .map(|record| (address, record))
            })
            .collect::<Vec<_>>();
        let peer_map_key = (self_username.to_string(), peer_username.to_string());
        let old_peer_ml_kem_key = self.peer_ml_kem_keys.read().get(&peer_map_key).cloned();
        match replacement {
            Some(identity) => identities.replace_identity(peer_username, identity),
            None => identities.remove_identity(peer_username),
        }
        sessions.delete_all_sessions(peer_username);
        self.peer_ml_kem_keys.write().remove(&peer_map_key);

        let prepared = (|| -> QorResult<SerializedSignalState> {
            let session_blob = serialize_signal_records(
                sessions.dump().map_err(QorError::SignalProtocol)?,
                "session",
            )?;
            let mut identity_data = identities
                .dump()
                .ok_or_else(|| QorError::NotInitialized("No local identity state".to_string()))?;
            let serialized = serde_json::to_vec(&identity_data);
            identity_data.2.zeroize();
            let identity_blob = Zeroizing::new(serialized.map_err(|_| {
                QorError::SignalProtocol("Failed to serialize identity store".to_string())
            })?);
            let peer_ml_kem_blob = self.serialize_peer_ml_kem_keys(self_username)?;
            let pending_decrypt_blob = Self::serialize_pending_decrypts(&pending_decrypts)?;
            Ok((
                session_blob,
                identity_blob,
                peer_ml_kem_blob,
                pending_decrypt_blob,
            ))
        })();
        let (session_blob, identity_blob, peer_ml_kem_blob, pending_decrypt_blob) = match prepared {
            Ok(blobs) => blobs,
            Err(error) => {
                match old_identity {
                    Some(identity) => identities.replace_identity(peer_username, identity),
                    None => identities.remove_identity(peer_username),
                }
                sessions.delete_all_sessions(peer_username);
                for (address, record) in &old_sessions {
                    sessions.store_session(address, record);
                }
                if let Some(key) = old_peer_ml_kem_key.as_ref() {
                    self.peer_ml_kem_keys
                        .write()
                        .insert(peer_map_key.clone(), key.clone());
                }
                return Err(error);
            }
        };
        drop(identities);
        drop(sessions);
        if let Err(error) = db.set_secure_batch(&[
            (
                "signal_session_store_v1",
                self_username,
                session_blob.as_slice(),
            ),
            (
                "signal_identity_store_v1",
                self_username,
                identity_blob.as_slice(),
            ),
            (
                "signal_peer_mlkem_store_v1",
                self_username,
                peer_ml_kem_blob.as_slice(),
            ),
            (
                "signal_pending_decrypt_store_v4",
                self_username,
                pending_decrypt_blob.as_slice(),
            ),
        ]) {
            let sessions = session_store.lock().await;
            let identities = identity_store.lock().await;
            match old_identity {
                Some(identity) => identities.replace_identity(peer_username, identity),
                None => identities.remove_identity(peer_username),
            }
            sessions.delete_all_sessions(peer_username);
            for (address, record) in &old_sessions {
                sessions.store_session(address, record);
            }
            if let Some(key) = old_peer_ml_kem_key.as_ref() {
                self.peer_ml_kem_keys
                    .write()
                    .insert(peer_map_key, key.clone());
            }
            return Err(error);
        }

        Ok(true)
    }

    pub async fn install_transparency_verified_peer_identity(
        &self,
        db: &crate::database::DatabaseManager,
        self_username: &str,
        peer_username: &str,
        new_identity_key_base64: &str,
    ) -> QorResult<bool> {
        let decoded = decode_exact_signal_base64(
            new_identity_key_base64,
            SIGNAL_CURVE_PUBLIC_KEY_BYTES,
            "identity key",
        )?;
        let new_identity = IdentityKey::decode(&decoded)
            .map_err(|_| QorError::InvalidArgument("Invalid identity key".to_string()))?;
        self.persist_transparency_peer_identity(
            db,
            self_username,
            peer_username,
            Some(new_identity),
        )
        .await
    }

    pub async fn revoke_transparency_peer_identity(
        &self,
        db: &crate::database::DatabaseManager,
        self_username: &str,
        peer_username: &str,
    ) -> QorResult<bool> {
        self.persist_transparency_peer_identity(db, self_username, peer_username, None)
            .await
    }

    pub async fn get_peer_identity_key(
        &self,
        self_username: &str,
        peer_username: &str,
    ) -> QorResult<String> {
        Self::validate_username(self_username)?;
        Self::validate_username(peer_username)?;
        let (_, identity_store, _, _, _) = self.get_or_create_stores(self_username);
        let identity_store = identity_store.lock().await;
        let identity = identity_store.get_identity(peer_username).ok_or_else(|| {
            QorError::NotInitialized("No transparency-verified peer identity".to_string())
        })?;
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            identity.serialize(),
        ))
    }

    pub async fn peek_prekey_identity(
        &self,
        from_username: &str,
        to_username: &str,
        encrypted: &EncryptedMessage,
    ) -> QorResult<Option<String>> {
        Self::validate_username(from_username)?;
        Self::validate_username(to_username)?;

        let envelope = &encrypted.pq_envelope;
        let local_device_id = self.own_signal_device_id(to_username).await?;
        let signal_message = self
            .unwrap_pq_hybrid(envelope, from_username, to_username)
            .await?;
        if encrypted.message_type != signal_message.message_type
            || signal_message.recipient_device_id != local_device_id
        {
            return Err(QorError::DecryptionFailed(
                "Signal envelope binding mismatch".to_string(),
            ));
        }
        if signal_message.message_type != 3 {
            return Ok(None);
        }
        let message_bytes = Zeroizing::new(decode_bounded_signal_base64(
            &signal_message.ciphertext,
            1,
            MAX_SIGNAL_CIPHERTEXT_BYTES,
            "Signal message",
        )?);
        let prekey_message = PreKeySignalMessage::try_from(message_bytes.as_slice())
            .map_err(|e| QorError::SignalProtocol(e.to_string()))?;
        validate_signal_device_identity_binding(
            prekey_message.identity_key(),
            signal_message.sender_device_id,
        )?;
        Ok(Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            prekey_message.identity_key().serialize(),
        )))
    }

    pub async fn set_static_mlkem_keys(
        &self,
        username: &str,
        public_key: Vec<u8>,
        secret_key: Vec<u8>,
    ) -> QorResult<bool> {
        let secret_key = Zeroizing::new(secret_key);
        Self::validate_username(username)?;

        if public_key.len() != post_quantum::ML_KEM_PUBLIC_KEY_SIZE {
            log::error!("[set_static_mlkem_keys] Invalid public key length");
            return Err(QorError::InvalidKeyLength {
                expected: post_quantum::ML_KEM_PUBLIC_KEY_SIZE,
                actual: public_key.len(),
            });
        }

        if secret_key.len() != post_quantum::ML_KEM_SECRET_KEY_SIZE {
            log::error!("[set_static_mlkem_keys] Invalid secret key length");
            return Err(QorError::InvalidKeyLength {
                expected: post_quantum::ML_KEM_SECRET_KEY_SIZE,
                actual: secret_key.len(),
            });
        }

        post_quantum::validate_ml_kem_keypair(&public_key, &secret_key)?;

        let mut keys = self.static_mlkem_keys.write();
        if let Some((existing_public, existing_secret)) = keys.get(username) {
            let same_keypair = existing_public == &public_key
                && crate::crypto::utils::constant_time_eq(existing_secret, &secret_key);
            if !same_keypair {
                return Err(QorError::Verification(
                    "Refusing to replace the loaded account static ML-KEM key".to_string(),
                ));
            }
            return Ok(true);
        }

        keys.insert(username.to_string(), (public_key, secret_key));

        Ok(true)
    }

    pub(crate) fn pending_decrypt_id(
        from_username: &str,
        to_username: &str,
        transport_message_id: &str,
        application_type: &str,
        sender_identity_key: &str,
        identity_root_fingerprint: &str,
        identity_bundle_fingerprint: &str,
        encrypted: &EncryptedMessage,
    ) -> QorResult<String> {
        Self::validate_username(from_username)?;
        Self::validate_username(to_username)?;
        Self::validate_pending_transport_metadata(transport_message_id, application_type)?;
        decode_exact_signal_base64(
            sender_identity_key,
            SIGNAL_CURVE_PUBLIC_KEY_BYTES,
            "pending decrypt sender identity",
        )?;
        Self::validate_transparency_fingerprint(
            identity_root_fingerprint,
            "pending decrypt identity root",
        )?;
        Self::validate_transparency_fingerprint(
            identity_bundle_fingerprint,
            "pending decrypt identity bundle",
        )?;
        let serialized = Zeroizing::new(
            serde_json::to_vec(&(
                crate::protocol_keys::SIGNAL_PENDING_DECRYPT,
                from_username,
                to_username,
                transport_message_id,
                application_type,
                sender_identity_key,
                identity_root_fingerprint,
                identity_bundle_fingerprint,
                encrypted,
            ))
            .map_err(|_| {
                QorError::SignalProtocol("Failed to identify encrypted Signal message".to_string())
            })?,
        );
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            hash::blake3(&serialized),
        ))
    }

    pub(crate) fn validate_pending_decrypt_id(value: &str) -> QorResult<()> {
        decode_exact_signal_base64(value, 32, "pending decrypt identifier").map(|_| ())
    }

    fn validate_transparency_fingerprint(value: &str, label: &str) -> QorResult<()> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(QorError::InvalidArgument(format!("Invalid {}", label)));
        }
        Ok(())
    }

    fn validate_pending_transport_metadata(
        transport_message_id: &str,
        application_type: &str,
    ) -> QorResult<()> {
        if transport_message_id.is_empty()
            || transport_message_id.len() > MAX_PENDING_TRANSPORT_MESSAGE_ID_BYTES
            || !transport_message_id.is_ascii()
            || !transport_message_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b'~' | b':' | b'+' | b'/' | b'=' | b'-')
            })
        {
            return Err(QorError::InvalidArgument(
                "Invalid pending decrypt transport message identifier".to_string(),
            ));
        }
        if application_type.is_empty()
            || application_type.len() > MAX_PENDING_APPLICATION_TYPE_BYTES
            || !application_type.is_ascii()
            || !application_type
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(QorError::InvalidArgument(
                "Invalid pending decrypt application type".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_pending_decrypted_message(entry: &PendingDecryptedMessage) -> QorResult<usize> {
        Self::validate_username(&entry.from_username)?;
        Self::validate_pending_decrypt_id(&entry.pending_id)?;
        decode_exact_signal_base64(
            &entry.sender_identity_key,
            SIGNAL_CURVE_PUBLIC_KEY_BYTES,
            "pending decrypt sender identity",
        )?;
        Self::validate_transparency_fingerprint(
            &entry.identity_root_fingerprint,
            "pending decrypt identity root",
        )?;
        Self::validate_transparency_fingerprint(
            &entry.identity_bundle_fingerprint,
            "pending decrypt identity bundle",
        )?;
        Self::validate_pending_transport_metadata(
            &entry.transport_message_id,
            &entry.application_type,
        )?;
        if entry.plaintext.len() > MAX_PENDING_DECRYPT_PLAINTEXT_BYTES {
            return Err(QorError::SignalProtocol(
                "Pending decrypt plaintext limit exceeded".to_string(),
            ));
        }
        [
            entry.pending_id.len(),
            entry.from_username.len(),
            entry.sender_identity_key.len(),
            entry.identity_root_fingerprint.len(),
            entry.identity_bundle_fingerprint.len(),
            entry.transport_message_id.len(),
            entry.application_type.len(),
            entry.plaintext.len(),
        ]
        .into_iter()
        .try_fold(0usize, |total, length| total.checked_add(length))
        .ok_or_else(|| QorError::SignalProtocol("Pending decrypt size overflow".to_string()))
    }

    pub(crate) fn load_pending_decrypts(
        db: &crate::database::DatabaseManager,
        username: &str,
    ) -> QorResult<Vec<PendingDecryptedMessage>> {
        Self::validate_username(username)?;
        let pending: Vec<PendingDecryptedMessage> =
            read_signal_store(db, "signal_pending_decrypt_store_v4", username)?.unwrap_or_default();
        if pending.len() > MAX_PENDING_DECRYPTS {
            return Err(QorError::SignalProtocol(
                "Pending decrypt store record limit exceeded".to_string(),
            ));
        }

        let mut ids = std::collections::HashSet::with_capacity(pending.len());
        let mut total_bytes = 0usize;
        for entry in &pending {
            let entry_bytes = Self::validate_pending_decrypted_message(entry)?;
            if !ids.insert(entry.pending_id.as_str()) {
                return Err(QorError::SignalProtocol(
                    "Duplicate pending decrypt identifier".to_string(),
                ));
            }
            total_bytes = total_bytes.checked_add(entry_bytes).ok_or_else(|| {
                QorError::SignalProtocol("Pending decrypt size overflow".to_string())
            })?;
            if total_bytes > MAX_PENDING_DECRYPT_TOTAL_BYTES {
                return Err(QorError::SignalProtocol(
                    "Pending decrypt total size limit exceeded".to_string(),
                ));
            }
        }
        Ok(pending)
    }

    pub(crate) fn serialize_pending_decrypts(
        pending: &[PendingDecryptedMessage],
    ) -> QorResult<Zeroizing<Vec<u8>>> {
        if pending.len() > MAX_PENDING_DECRYPTS {
            return Err(QorError::SignalProtocol(
                "Pending decrypt store is full".to_string(),
            ));
        }
        let mut ids = std::collections::HashSet::with_capacity(pending.len());
        let mut total_bytes = 0usize;
        for entry in pending {
            let entry_bytes = Self::validate_pending_decrypted_message(entry)?;
            if !ids.insert(entry.pending_id.as_str()) {
                return Err(QorError::SignalProtocol(
                    "Invalid or duplicate pending decrypt identifier".to_string(),
                ));
            }
            total_bytes = total_bytes.checked_add(entry_bytes).ok_or_else(|| {
                QorError::SignalProtocol("Pending decrypt size overflow".to_string())
            })?;
            if total_bytes > MAX_PENDING_DECRYPT_TOTAL_BYTES {
                return Err(QorError::SignalProtocol(
                    "Pending decrypt total size limit exceeded".to_string(),
                ));
            }
        }
        serde_json::to_vec(pending)
            .map(Zeroizing::new)
            .map_err(|_| {
                QorError::SignalProtocol("Failed to serialize pending decrypt store".to_string())
            })
    }

    pub async fn persist_to_db(
        &self,
        db: &crate::database::DatabaseManager,
        username: &str,
    ) -> QorResult<()> {
        Self::validate_username(username)?;
        let (session_store, identity_store, _prekey_store, signed_prekey_store, kyber_prekey_store) =
            self.get_or_create_stores(username);

        let sessions_blob = serialize_signal_records(
            session_store
                .lock()
                .await
                .dump()
                .map_err(QorError::SignalProtocol)?,
            "session",
        )?;
        let signed_prekeys_blob = serialize_signal_records(
            signed_prekey_store
                .lock()
                .await
                .dump()
                .map_err(QorError::SignalProtocol)?,
            "signed pre-key",
        )?;
        let kyber_prekeys_blob = serialize_signal_records(
            kyber_prekey_store
                .lock()
                .await
                .dump()
                .map_err(QorError::SignalProtocol)?,
            "Kyber pre-key",
        )?;
        let kyber_replay_state = kyber_prekey_store.lock().await.dump_replay_state();
        let kyber_replay_blob =
            Zeroizing::new(serde_json::to_vec(&kyber_replay_state).map_err(|_| {
                QorError::SignalProtocol("Failed to serialize Kyber replay state".to_string())
            })?);

        let identity_blob = identity_store
            .lock()
            .await
            .dump()
            .map(|mut identity_data| {
                let serialized = serde_json::to_vec(&identity_data);
                identity_data.2.zeroize();
                serialized.map(Zeroizing::new).map_err(|_| {
                    QorError::SignalProtocol("Failed to serialize identity store".to_string())
                })
            })
            .transpose()?;

        let static_keys_map = self.static_mlkem_keys.read();
        let static_key = static_keys_map
            .get(username)
            .map(|(public_key, secret_key)| (public_key.clone(), secret_key.to_vec()));
        drop(static_keys_map);
        let static_keys_blob = static_key
            .map(|mut keypair| {
                let serialized = serde_json::to_vec(&keypair);
                keypair.1.zeroize();
                serialized.map(Zeroizing::new).map_err(|_| {
                    QorError::SignalProtocol("Failed to serialize static ML-KEM store".to_string())
                })
            })
            .transpose()?;
        let peer_ml_kem_blob = self.serialize_peer_ml_kem_keys(username)?;

        let mut entries = vec![
            (
                "signal_session_store_v1",
                username,
                sessions_blob.as_slice(),
            ),
            (
                "signal_signed_prekey_store_v1",
                username,
                signed_prekeys_blob.as_slice(),
            ),
            (
                "signal_mlkem_prekey_store_v1",
                username,
                kyber_prekeys_blob.as_slice(),
            ),
            (
                "signal_mlkem_replay_store_v1",
                username,
                kyber_replay_blob.as_slice(),
            ),
            (
                "signal_peer_mlkem_store_v1",
                username,
                peer_ml_kem_blob.as_slice(),
            ),
        ];
        let mut deletions = Vec::new();
        if let Some(blob) = identity_blob.as_ref() {
            entries.push(("signal_identity_store_v1", username, blob.as_slice()));
        } else {
            deletions.push(("signal_identity_store_v1", username));
        }
        if let Some(blob) = static_keys_blob.as_ref() {
            entries.push(("signal_static_mlkem_store_v1", username, blob.as_slice()));
        } else {
            deletions.push(("signal_static_mlkem_store_v1", username));
        }
        db.mutate_secure_batch(&entries, &deletions)
    }

    /// save only state that changes during normal messaging
    pub async fn persist_messaging_state(
        &self,
        db: &crate::database::DatabaseManager,
        username: &str,
        full: bool,
    ) -> QorResult<()> {
        self.persist_messaging_state_inner(db, username, full, None)
            .await
    }

    pub(crate) async fn persist_decrypt_state(
        &self,
        db: &crate::database::DatabaseManager,
        username: &str,
        pending_decrypt_blob: &[u8],
    ) -> QorResult<()> {
        self.persist_messaging_state_inner(db, username, true, Some(pending_decrypt_blob))
            .await
    }

    async fn persist_messaging_state_inner(
        &self,
        db: &crate::database::DatabaseManager,
        username: &str,
        full: bool,
        pending_decrypt_blob: Option<&[u8]>,
    ) -> QorResult<()> {
        Self::validate_username(username)?;
        let (session_store, identity_store, _prekey_store, _signed, kyber_prekey_store) =
            self.get_or_create_stores(username);

        let sessions_blob = serialize_signal_records(
            session_store
                .lock()
                .await
                .dump()
                .map_err(QorError::SignalProtocol)?,
            "session",
        )?;

        if full {
            let identity_blob = identity_store
                .lock()
                .await
                .dump()
                .map(|mut identity_data| {
                    let serialized = serde_json::to_vec(&identity_data);
                    identity_data.2.zeroize();
                    serialized.map(Zeroizing::new).map_err(|_| {
                        QorError::SignalProtocol("Failed to serialize identity store".to_string())
                    })
                })
                .transpose()?;
            let kyber_replay_state = kyber_prekey_store.lock().await.dump_replay_state();
            let kyber_replay_blob =
                Zeroizing::new(serde_json::to_vec(&kyber_replay_state).map_err(|_| {
                    QorError::SignalProtocol("Failed to serialize Kyber replay state".to_string())
                })?);
            let peer_ml_kem_blob = self.serialize_peer_ml_kem_keys(username)?;
            let mut entries = vec![
                (
                    "signal_session_store_v1",
                    username,
                    sessions_blob.as_slice(),
                ),
                (
                    "signal_mlkem_replay_store_v1",
                    username,
                    kyber_replay_blob.as_slice(),
                ),
                (
                    "signal_peer_mlkem_store_v1",
                    username,
                    peer_ml_kem_blob.as_slice(),
                ),
            ];
            let mut deletions = Vec::new();
            if let Some(blob) = identity_blob.as_ref() {
                entries.push(("signal_identity_store_v1", username, blob.as_slice()));
            } else {
                deletions.push(("signal_identity_store_v1", username));
            }
            if let Some(blob) = pending_decrypt_blob {
                entries.push(("signal_pending_decrypt_store_v4", username, blob));
            }
            db.mutate_secure_batch(&entries, &deletions)
        } else {
            db.set_secure_batch(&[(
                "signal_session_store_v1",
                username,
                sessions_blob.as_slice(),
            )])
        }
    }

    /// Load all Signal stores for a user from the database
    pub async fn load_from_db(
        &self,
        db: &crate::database::DatabaseManager,
        username: &str,
    ) -> QorResult<()> {
        Self::validate_username(username)?;

        let session_store = InMemorySessionStore::new();
        let sessions: Vec<(String, Vec<u8>)> =
            read_signal_store(db, "signal_session_store_v1", username)?.unwrap_or_default();
        session_store
            .load(sessions)
            .map_err(QorError::SignalProtocol)?;

        let identity_store = InMemoryIdentityKeyStore::new();
        if let Some((reg_id, identity_key, private_key, known_identities)) =
            read_signal_store::<(u32, Vec<u8>, Vec<u8>, Vec<(String, Vec<u8>)>)>(
                db,
                "signal_identity_store_v1",
                username,
            )?
        {
            identity_store
                .load(reg_id, identity_key, private_key, known_identities)
                .map_err(QorError::SignalProtocol)?;
        }

        let prekey_store = InMemoryPreKeyStore::new();

        let signed_prekey_store = InMemorySignedPreKeyStore::new();
        let signed_prekeys: Vec<(u32, Vec<u8>)> =
            read_signal_store(db, "signal_signed_prekey_store_v1", username)?.unwrap_or_default();
        signed_prekey_store
            .load(signed_prekeys)
            .map_err(QorError::SignalProtocol)?;

        let kyber_prekey_store = InMemoryKyberPreKeyStore::new();
        let kyber_prekeys: Vec<(u32, Vec<u8>)> =
            read_signal_store(db, "signal_mlkem_prekey_store_v1", username)?.unwrap_or_default();
        kyber_prekey_store
            .load(kyber_prekeys)
            .map_err(QorError::SignalProtocol)?;
        if signed_prekey_store.get_any_signed_pre_key().is_some()
            || kyber_prekey_store.get_any_kyber_pre_key().is_some()
        {
            let identity = identity_store.get_identity_key_pair().ok_or_else(|| {
                QorError::SignalProtocol(
                    "Signal pre-key stores exist without a local identity".to_string(),
                )
            })?;
            signed_prekey_store
                .validate_signatures(identity.identity_key())
                .map_err(QorError::SignalProtocol)?;
            kyber_prekey_store
                .validate_signatures(identity.identity_key())
                .map_err(QorError::SignalProtocol)?;
        }
        let replay_state: Vec<(u32, u32, Vec<Vec<u8>>)> =
            read_signal_store(db, "signal_mlkem_replay_store_v1", username)?.unwrap_or_default();
        kyber_prekey_store
            .load_replay_state(replay_state)
            .map_err(QorError::SignalProtocol)?;

        let peer_ml_kem_entries: Vec<(String, Vec<u8>)> =
            read_signal_store(db, "signal_peer_mlkem_store_v1", username)?.unwrap_or_default();
        if peer_ml_kem_entries.len() > MAX_PEER_ML_KEM_KEYS {
            return Err(QorError::SignalProtocol(
                "Peer ML-KEM key store record limit exceeded".to_string(),
            ));
        }
        let mut loaded_peer_ml_kem_keys = HashMap::with_capacity(peer_ml_kem_entries.len());
        for (peer, key) in peer_ml_kem_entries {
            Self::validate_username(&peer)?;
            post_quantum::validate_ml_kem_public_key(&key).map_err(|_| {
                QorError::SignalProtocol("Invalid peer ML-KEM public key store".to_string())
            })?;
            if loaded_peer_ml_kem_keys.insert(peer, key).is_some() {
                return Err(QorError::SignalProtocol(
                    "Duplicate peer ML-KEM public key".to_string(),
                ));
            }
        }

        let static_key =
            read_signal_store::<(Vec<u8>, Vec<u8>)>(db, "signal_static_mlkem_store_v1", username)?
                .map(|(public_key, secret_key)| {
                    let secret_key = Zeroizing::new(secret_key);
                    if public_key.len() != post_quantum::ML_KEM_PUBLIC_KEY_SIZE
                        || secret_key.len() != post_quantum::ML_KEM_SECRET_KEY_SIZE
                    {
                        return Err(QorError::SignalProtocol(
                            "Invalid static ML-KEM keypair store".to_string(),
                        ));
                    }
                    post_quantum::validate_ml_kem_keypair(&public_key, &secret_key).map_err(
                        |_| {
                            QorError::SignalProtocol(
                                "Invalid static ML-KEM keypair store".to_string(),
                            )
                        },
                    )?;
                    Ok((public_key, secret_key))
                })
                .transpose()?;

        self.session_stores
            .write()
            .insert(username.to_string(), Arc::new(Mutex::new(session_store)));
        self.identity_stores
            .write()
            .insert(username.to_string(), Arc::new(Mutex::new(identity_store)));
        self.prekey_stores
            .write()
            .insert(username.to_string(), Arc::new(Mutex::new(prekey_store)));
        self.signed_prekey_stores.write().insert(
            username.to_string(),
            Arc::new(Mutex::new(signed_prekey_store)),
        );
        self.kyber_prekey_stores.write().insert(
            username.to_string(),
            Arc::new(Mutex::new(kyber_prekey_store)),
        );
        let session_prefix = format!("{}:", username);
        self.session_locks
            .write()
            .retain(|key, _| !key.starts_with(&session_prefix));
        let mut peer_ml_kem_keys = self.peer_ml_kem_keys.write();
        peer_ml_kem_keys.retain(|(owner, _), _| owner != username);
        peer_ml_kem_keys.extend(
            loaded_peer_ml_kem_keys
                .into_iter()
                .map(|(peer, key)| ((username.to_string(), peer), key)),
        );
        drop(peer_ml_kem_keys);

        let mut static_keys = self.static_mlkem_keys.write();
        static_keys.remove(username);
        if let Some(keypair) = static_key {
            static_keys.insert(username.to_string(), keypair);
        }
        Ok(())
    }
}

/// Session lock guard
pub(crate) struct SessionLockGuard {
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
    key: String,
    lock_identity: Weak<tokio::sync::Mutex<()>>,
    registry: Arc<RwLock<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
}

impl Drop for SessionLockGuard {
    fn drop(&mut self) {
        drop(self.guard.take());

        let mut locks = self.registry.write();
        let remove = locks.get(&self.key).is_some_and(|current| {
            Weak::ptr_eq(&Arc::downgrade(current), &self.lock_identity)
                && Arc::strong_count(current) == 1
        });
        if remove {
            locks.remove(&self.key);
        }
    }
}

pub(crate) struct AccountStateLockGuard {
    _lifecycle_guard: tokio::sync::OwnedMutexGuard<()>,
    _account_guard: SessionLockGuard,
}

/// Generate random registration ID
fn generate_registration_id() -> QorResult<u32> {
    loop {
        let bytes = random::random_bytes(2)?;
        let candidate = u16::from_le_bytes([bytes[0], bytes[1]]) as u32 & 0x3fff;
        if (1..=16_380).contains(&candidate) {
            return Ok(candidate);
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IdentityBundle {
    pub identity_key_public: String,
    pub registration_id: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedPreKey {
    pub key_id: u32,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MlKemPreKey {
    pub key_id: u32,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedPreKeyInfo {
    pub key_id: u32,
    pub public_key_base64: String,
    pub signature_base64: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlKemPreKeyInfo {
    pub key_id: u32,
    pub public_key_base64: String,
    pub signature_base64: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StaticMlKemKey {
    pub public_key_base64: String,
    pub signature_base64: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreKeyBundle {
    pub registration_id: u32,
    pub device_id: u32,
    pub identity_key_base64: String,
    pub signed_pre_key: SignedPreKeyInfo,
    pub ml_kem_pre_key: MlKemPreKeyInfo,
    pub static_ml_kem: StaticMlKemKey,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignalEncryptedMessage {
    pub message_type: u8,
    pub ciphertext: String,
    pub sender_device_id: u32,
    pub recipient_device_id: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptedMessage {
    pub message_type: u8,
    pub pq_envelope: PQEnvelope,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PQEnvelope {
    pub version: String,
    pub algorithms: PQEnvelopeAlgorithms,
    pub kem_ciphertext: String,
    pub nonce: String,
    pub ciphertext: String,
    pub salt: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PQEnvelopeAlgorithms {
    pub kem: String,
    pub kdf: String,
    pub aead: String,
}

pub async fn init(state: &AppState) -> QorResult<()> {
    let handler = SignalHandler::new();
    *state.signal_handler.write() = Some(Arc::new(handler));

    Ok(())
}
