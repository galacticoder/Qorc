//! Signal Protocol Handler

use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use libsignal_protocol::kem::{KeyType as KemKeyType, PublicKey as KemPublicKey};
use libsignal_protocol::{
    DeviceId, GenericSignedPreKey, IdentityKey, IdentityKeyPair, KeyPair, KyberPreKeyId,
    KyberPreKeyRecord, PreKeyId, PreKeyRecord, PreKeySignalMessage, ProtocolAddress, PublicKey,
    SignalMessage, SignedPreKeyId, SignedPreKeyRecord, Timestamp,
};

use parking_lot::RwLock;
use rand::{SeedableRng, rngs::StdRng};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::crypto::{hash, post_quantum, random};
use crate::error::{QorError, QorResult};
use crate::state::AppState;
use crate::storage::SecureStorage;

mod store;
pub use store::*;

const SIGNAL_PQ_ENVELOPE_VERSION: &str = "signal-pq-v1";
const SIGNAL_PQ_KEM_ALGORITHM: &str = "ML-KEM-1024";
const SIGNAL_PQ_KDF_ALGORITHM: &str = "BLAKE3-SHA3-512-DOMAIN-SEPARATED";
const SIGNAL_PQ_AEAD_ALGORITHM: &str = "XCHACHA20-POLY1305";
const SIGNAL_PQ_MAC_ALGORITHM: &str = "BLAKE3-KEYED";
const SIGNAL_DEVICE_ID_MAX: u32 = 127;

fn local_signal_device_id() -> u32 {
    let instance_id = crate::system::get_instance_id();
    if let Ok(id) = instance_id.parse::<u32>() {
        if (1..=SIGNAL_DEVICE_ID_MAX).contains(&id) {
            return id;
        }
    }

    let digest = hash::blake3(format!("qor-signal-device-id:{}", instance_id).as_bytes());
    (u32::from(digest[0]) % SIGNAL_DEVICE_ID_MAX) + 1
}

fn signal_device_id(value: u32, label: &str) -> QorResult<DeviceId> {
    DeviceId::try_from(value).map_err(|_| {
        QorError::InvalidArgument(format!("Invalid {} Signal device id: {}", label, value))
    })
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
    _storage: Arc<SecureStorage>,
    session_stores: RwLock<HashMap<String, Arc<Mutex<InMemorySessionStore>>>>,
    identity_stores: RwLock<HashMap<String, Arc<Mutex<InMemoryIdentityKeyStore>>>>,
    prekey_stores: RwLock<HashMap<String, Arc<Mutex<InMemoryPreKeyStore>>>>,
    signed_prekey_stores: RwLock<HashMap<String, Arc<Mutex<InMemorySignedPreKeyStore>>>>,
    kyber_prekey_stores: RwLock<HashMap<String, Arc<Mutex<InMemoryKyberPreKeyStore>>>>,
    session_locks: RwLock<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    peer_kyber_keys: RwLock<HashMap<String, Vec<u8>>>,
    static_mlkem_keys: RwLock<HashMap<String, (Vec<u8>, Zeroizing<Vec<u8>>)>>,
    pq_kyber_keypairs: RwLock<HashMap<String, (Vec<u8>, Zeroizing<Vec<u8>>)>>,
}

impl SignalHandler {
    /// Create new Signal handler
    pub fn new(storage: Arc<SecureStorage>) -> Self {
        Self {
            _storage: storage,
            session_stores: RwLock::new(HashMap::new()),
            identity_stores: RwLock::new(HashMap::new()),
            prekey_stores: RwLock::new(HashMap::new()),
            signed_prekey_stores: RwLock::new(HashMap::new()),
            kyber_prekey_stores: RwLock::new(HashMap::new()),
            session_locks: RwLock::new(HashMap::new()),
            peer_kyber_keys: RwLock::new(HashMap::new()),
            static_mlkem_keys: RwLock::new(HashMap::new()),
            pq_kyber_keypairs: RwLock::new(HashMap::new()),
        }
    }

    /// Validate username format
    fn validate_username(username: &str) -> QorResult<()> {
        if username.is_empty() {
            return Err(QorError::InvalidArgument(
                "Username cannot be empty".to_string(),
            ));
        }
        if username.len() > 128 {
            return Err(QorError::InvalidArgument("Username too long".to_string()));
        }

        // Allow hex pseudonyms or alphanumeric usernames
        let is_pseudonym = username.len() >= 32 && username.chars().all(|c| c.is_ascii_hexdigit());

        if !is_pseudonym
            && !username
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(QorError::InvalidArgument(
                "Username contains invalid characters".to_string(),
            ));
        }

        Ok(())
    }

    /// Acquire session lock
    async fn acquire_session_lock(&self, key: &str) -> SessionLockGuard {
        let lock = {
            let mut locks = self.session_locks.write();
            locks
                .entry(key.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };

        let guard = lock.lock_owned().await;

        SessionLockGuard { _guard: guard }
    }

    /// Get or create stores for a username
    fn get_or_create_stores(
        &self,
        username: &str,
    ) -> (
        Arc<Mutex<InMemorySessionStore>>,
        Arc<Mutex<InMemoryIdentityKeyStore>>,
        Arc<Mutex<InMemoryPreKeyStore>>,
        Arc<Mutex<InMemorySignedPreKeyStore>>,
        Arc<Mutex<InMemoryKyberPreKeyStore>>,
    ) {
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

    /// Generate identity keys for a user
    pub async fn generate_identity(&self, username: &str) -> QorResult<IdentityBundle> {
        Self::validate_username(username)?;

        let (_, identity_store, _, _, _) = self.get_or_create_stores(username);
        let identity_store = identity_store.lock().await;

        // Check for existing identity
        if let Some(existing) = identity_store.get_identity_key_pair() {
            let reg_id = identity_store
                .get_local_registration_id()
                .unwrap_or_else(|| {
                    let new_id = generate_registration_id();
                    identity_store.set_local_registration_id(new_id);
                    new_id
                });

            return Ok(IdentityBundle {
                identity_key_public: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    existing.public_key().serialize(),
                ),
                registration_id: reg_id,
                kyber_public_key: None,
            });
        }

        // Generate new identity
        let mut rng = StdRng::from_os_rng();
        let identity_key_pair = IdentityKeyPair::generate(&mut rng);
        let registration_id = generate_registration_id();

        identity_store.set_identity_key_pair(identity_key_pair.clone());
        identity_store.set_local_registration_id(registration_id);

        Ok(IdentityBundle {
            identity_key_public: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                identity_key_pair.public_key().serialize(),
            ),
            registration_id,
            kyber_public_key: None,
        })
    }

    /// Generate pre-keys
    pub async fn generate_prekeys(
        &self,
        username: &str,
        start_id: u32,
        count: u32,
    ) -> QorResult<Vec<PreKey>> {
        Self::validate_username(username)?;

        let (_, _, prekey_store, _, _) = self.get_or_create_stores(username);
        let prekey_store = &mut *prekey_store.lock().await;

        let mut prekeys = Vec::with_capacity(count as usize);
        let mut rng = StdRng::from_os_rng();

        for i in 0..count {
            let key_id = start_id + i;
            let key_pair = KeyPair::generate(&mut rng);

            let prekey_record = PreKeyRecord::new(key_id.into(), &key_pair);
            prekey_store.store_pre_key(key_id.into(), &prekey_record);

            prekeys.push(PreKey {
                key_id,
                public_key: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    key_pair.public_key.serialize(),
                ),
            });
        }

        Ok(prekeys)
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

        let mut rng = StdRng::from_os_rng();
        let key_pair = KeyPair::generate(&mut rng);
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
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

        signed_prekey_store.store_signed_pre_key(key_id.into(), &signed_prekey_record);

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

    /// Generate Kyber pre-key
    pub async fn generate_kyber_prekey(
        &self,
        username: &str,
        key_id: u32,
    ) -> QorResult<KyberPreKey> {
        Self::validate_username(username)?;

        let (_, identity_store, _, _, kyber_prekey_store) = self.get_or_create_stores(username);
        let identity_store = identity_store.lock().await;
        let kyber_prekey_store = &mut *kyber_prekey_store.lock().await;

        let identity_key_pair = identity_store
            .get_identity_key_pair()
            .ok_or_else(|| QorError::NotInitialized("No identity key pair".to_string()))?;

        // Generate Kyber record
        let kyber_record = KyberPreKeyRecord::generate(
            KemKeyType::Kyber1024,
            key_id.into(),
            identity_key_pair.private_key(),
        )
        .map_err(|e| QorError::SignalProtocol(e.to_string()))?;

        // Extract the public key from the record
        let public_key_bytes = kyber_record
            .public_key()
            .map_err(|e| QorError::SignalProtocol(e.to_string()))?
            .serialize();

        let signature = kyber_record
            .signature()
            .map_err(|e| QorError::SignalProtocol(e.to_string()))?
            .to_vec();

        kyber_prekey_store.store_kyber_pre_key(key_id.into(), &kyber_record);

        Ok(KyberPreKey {
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

    /// Generate standalone ML-KEM-1024 pre-key
    pub async fn generate_pq_kyber_prekey(
        &self,
        username: &str,
        key_id: u32,
    ) -> QorResult<PQKyberPreKey> {
        Self::validate_username(username)?;

        let keypair = post_quantum::kyber_generate_keypair()?;

        let key = format!("{}:{}", username, key_id);
        self.pq_kyber_keypairs.write().insert(
            key,
            (
                keypair.public_key.clone(),
                Zeroizing::new(keypair.secret_key),
            ),
        );

        Ok(PQKyberPreKey {
            key_id,
            public_key_base64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &keypair.public_key,
            ),
        })
    }

    /// Create pre-key bundle for distribution
    pub async fn create_prekey_bundle(&self, username: &str) -> QorResult<PreKeyBundle> {
        Self::validate_username(username)?;

        let (_, identity_store, prekey_store, signed_prekey_store, kyber_prekey_store) =
            self.get_or_create_stores(username);

        // Ensure identity exists
        self.generate_identity(username).await?;

        // Ensure pre-keys exist
        let (prekey_count, max_prekey_id) = {
            let store = prekey_store.lock().await;
            let count = store.prekey_count();
            let max_id = store.dump().iter().map(|(id, _)| *id).max().unwrap_or(0);
            (count, max_id)
        };

        if prekey_count < 100 {
            let start_id = max_prekey_id + 1;
            let count = 100 - prekey_count;
            self.generate_prekeys(username, start_id, count).await?;
        }

        // Ensure signed pre-key exists
        if signed_prekey_store
            .lock()
            .await
            .get_signed_pre_key(1.into())
            .is_none()
        {
            self.generate_signed_prekey(username, 1).await?;
        }

        // Ensure Kyber pre-key exists
        if kyber_prekey_store
            .lock()
            .await
            .get_kyber_pre_key(1.into())
            .is_none()
        {
            self.generate_kyber_prekey(username, 1).await?;
        }

        // check PQ Kyber keypair exists prefering static key and falling to pre key
        let pq_kyber_public = if let Some((pk, _)) = self.static_mlkem_keys.read().get(username) {
            pk.clone()
        } else {
            let pq_key = format!("{}:1", username);
            if self.pq_kyber_keypairs.read().get(&pq_key).is_none() {
                self.generate_pq_kyber_prekey(username, 1).await?;
            }
            self.pq_kyber_keypairs
                .read()
                .get(&pq_key)
                .map(|(pk, _)| pk.clone())
                .ok_or_else(|| QorError::SignalProtocol("Missing PQ Kyber pre-key".to_string()))?
        };

        let identity_store = identity_store.lock().await;
        let prekey_store = prekey_store.lock().await;
        let signed_prekey_store = signed_prekey_store.lock().await;
        let kyber_prekey_store = kyber_prekey_store.lock().await;

        let identity_key_pair = identity_store
            .get_identity_key_pair()
            .ok_or_else(|| QorError::NotInitialized("No identity key pair".to_string()))?;

        let registration_id = identity_store
            .get_local_registration_id()
            .ok_or_else(|| QorError::NotInitialized("No registration ID".to_string()))?;

        let (prekey_id, prekey) = prekey_store
            .get_any_pre_key()
            .ok_or_else(|| QorError::SignalProtocol("No pre-keys available".to_string()))?;

        let (signed_prekey_id, signed_prekey) = signed_prekey_store
            .get_any_signed_pre_key()
            .ok_or_else(|| QorError::SignalProtocol("No signed pre-keys available".to_string()))?;

        let (kyber_prekey_id, kyber_prekey) = kyber_prekey_store
            .get_any_kyber_pre_key()
            .ok_or_else(|| QorError::SignalProtocol("No Kyber pre-keys available".to_string()))?;
        let local_device_id = local_signal_device_id();

        Ok(PreKeyBundle {
            registration_id,
            device_id: local_device_id,
            identity_key_base64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                identity_key_pair.public_key().serialize(),
            ),
            pre_key: Some(PreKeyInfo {
                key_id: u32::from(prekey_id),
                public_key_base64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    prekey
                        .public_key()
                        .map_err(|e| QorError::SignalProtocol(e.to_string()))?
                        .serialize(),
                ),
            }),
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
            kyber_pre_key: Some(KyberPreKeyInfo {
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
            }),
            pq_kyber: Some(PQKyberPreKey {
                key_id: 1, // Note: PQ Kyber static/pre-key ID is currently semantic in the name format
                public_key_base64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &pq_kyber_public,
                ),
            }),
        })
    }

    /// Process incoming pre-key bundle and establish session
    pub async fn process_prekey_bundle(
        &self,
        self_username: &str,
        peer_username: &str,
        bundle: PreKeyBundleInput,
    ) -> QorResult<bool> {
        Self::validate_username(self_username)?;
        Self::validate_username(peer_username)?;

        let peer_device_id = bundle.device_id;
        let peer_device = signal_device_id(peer_device_id, "peer")?;
        let session_key = format!("{}:{}.{}", self_username, peer_username, peer_device_id);
        let _lock = self.acquire_session_lock(&session_key).await;

        let (session_store, identity_store, _, _, _) = self.get_or_create_stores(self_username);
        let mut session_store = session_store.lock().await;
        let mut identity_store = identity_store.lock().await;

        let peer_address = ProtocolAddress::new(peer_username.to_string(), peer_device);

        // If session already exists with peer, check if identity key matches
        if session_store.has_session(&peer_address) {
            let incoming_identity_key = IdentityKey::decode(
                &base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &bundle.identity_key_base64,
                )
                .unwrap_or_default(),
            );

            let should_replace = match incoming_identity_key {
                Ok(incoming_ik) => {
                    let stored_ik = <InMemoryIdentityKeyStore as libsignal_protocol::IdentityKeyStore>::get_identity(
                        &*identity_store,
                        &peer_address,
                    ).await.ok().flatten();
                    match stored_ik {
                        Some(existing) => existing != incoming_ik,
                        None => false,
                    }
                }
                Err(_) => false,
            };

            if should_replace {
                session_store.delete_session(&peer_address);
            } else {
                return Ok(true);
            }
        }

        let peer_identity_key = IdentityKey::decode(
            &base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &bundle.identity_key_base64,
            )
            .map_err(|e| QorError::InvalidArgument(format!("Invalid identity key: {}", e)))?,
        )
        .map_err(|e| QorError::SignalProtocol(e.to_string()))?;

        let peer_signed_prekey = PublicKey::deserialize(
            &base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &bundle.signed_pre_key.public_key_base64,
            )
            .map_err(|e| QorError::InvalidArgument(format!("Invalid signed pre-key: {}", e)))?,
        )
        .map_err(|e| QorError::SignalProtocol(e.to_string()))?;

        let signature = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &bundle.signed_pre_key.signature_base64,
        )
        .map_err(|e| QorError::InvalidArgument(format!("Invalid signature: {}", e)))?;

        // Verify signed pre-key signature
        if !peer_identity_key
            .public_key()
            .verify_signature(&peer_signed_prekey.serialize(), &signature)
        {
            return Err(QorError::SignalProtocol(
                "Invalid signed pre-key signature".to_string(),
            ));
        }

        let peer_prekey = if let Some(pk) = &bundle.pre_key {
            Some((
                pk.key_id.into(),
                PublicKey::deserialize(
                    &base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        &pk.public_key_base64,
                    )
                    .map_err(|e| QorError::InvalidArgument(format!("Invalid pre-key: {}", e)))?,
                )
                .map_err(|e| QorError::SignalProtocol(e.to_string()))?,
            ))
        } else {
            None
        };

        let kyber_prekey = if let Some(kpk) = &bundle.kyber_pre_key {
            let kyber_pk = KemPublicKey::deserialize(
                &base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &kpk.public_key_base64,
                )
                .map_err(|e| QorError::InvalidArgument(format!("Invalid kyber pre-key: {}", e)))?,
            )
            .map_err(|e| QorError::SignalProtocol(e.to_string()))?;

            let kyber_sig = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &kpk.signature_base64,
            )
            .map_err(|e| {
                QorError::InvalidArgument(format!("Invalid kyber pre-key signature: {}", e))
            })?;

            Some((KyberPreKeyId::from(kpk.key_id), kyber_pk, kyber_sig))
        } else {
            None
        };

        // Build Signal pre-key bundle
        let (kyber_id, kyber_pk, kyber_sig) = kyber_prekey
            .ok_or_else(|| QorError::InvalidArgument("Missing kyber pre-key".to_string()))?;

        let signal_bundle = libsignal_protocol::PreKeyBundle::new(
            bundle.registration_id,
            peer_device,
            peer_prekey
                .as_ref()
                .map(|(id, pk): &(u32, PublicKey)| (PreKeyId::from(*id), pk.clone())),
            SignedPreKeyId::from(bundle.signed_pre_key.key_id),
            peer_signed_prekey.clone(),
            signature,
            kyber_id,
            kyber_pk,
            kyber_sig,
            peer_identity_key.clone(),
        )
        .map_err(|e| QorError::SignalProtocol(e.to_string()))?;

        let mut rng = StdRng::from_os_rng();

        // Process the bundle to create session
        let result = libsignal_protocol::process_prekey_bundle(
            &peer_address,
            &mut *session_store,
            &mut *identity_store,
            &signal_bundle,
            SystemTime::now(),
            &mut rng,
        )
        .await;

        match result {
            Ok(_) => Ok(true),
            Err(e) => {
                // Handle untrusted identity by trusting and retrying
                if e.to_string().contains("untrusted") || e.to_string().contains("Untrusted") {
                    <InMemoryIdentityKeyStore as libsignal_protocol::IdentityKeyStore>::save_identity(
                        &mut *identity_store,
                        &peer_address,
                        &peer_identity_key,
                    ).await
                        .map_err(|e| QorError::SignalProtocol(e.to_string()))?;
                    identity_store.trust_identity(peer_username);

                    libsignal_protocol::process_prekey_bundle(
                        &peer_address,
                        &mut *session_store,
                        &mut *identity_store,
                        &signal_bundle,
                        SystemTime::now(),
                        &mut rng,
                    )
                    .await
                    .map(|_| true)
                    .map_err(|e| QorError::SignalProtocol(e.to_string()))
                } else {
                    Err(QorError::SignalProtocol(e.to_string()))
                }
            }
        }
    }

    /// Check if session exists
    pub async fn has_session(
        &self,
        self_username: &str,
        peer_username: &str,
        device_id: u32,
    ) -> QorResult<bool> {
        Self::validate_username(self_username)?;
        Self::validate_username(peer_username)?;

        let (session_store, _, _, _, _) = self.get_or_create_stores(self_username);
        let session_store = session_store.lock().await;
        let device = signal_device_id(device_id, "peer")?;
        let address = ProtocolAddress::new(peer_username.to_string(), device);

        if session_store.load_session(&address).is_some() {
            return Ok(true);
        }

        if device_id == 1 {
            return Ok(first_session_device_id(&*session_store, peer_username).is_some());
        }

        Ok(false)
    }

    /// Encrypt
    pub async fn encrypt(
        &self,
        from_username: &str,
        to_username: &str,
        plaintext: &[u8],
    ) -> QorResult<EncryptedMessage> {
        Self::validate_username(from_username)?;
        Self::validate_username(to_username)?;

        let session_key = format!("{}:{}", from_username, to_username);
        let _lock = self.acquire_session_lock(&session_key).await;

        // Encrypt with Signal Protocol
        let signal_encrypted = self
            .encrypt_with_signal_protocol(from_username, to_username, plaintext)
            .await?;

        // Wrap with PQ hybrid envelope
        let wrapped = self
            .wrap_with_pq_hybrid(&signal_encrypted, from_username, to_username)
            .await?;

        Ok(EncryptedMessage {
            message_type: signal_encrypted.message_type,
            ciphertext: signal_encrypted.ciphertext,
            registration_id: signal_encrypted.registration_id,
            sender_device_id: signal_encrypted.sender_device_id,
            recipient_device_id: signal_encrypted.recipient_device_id,
            pq_envelope: Some(wrapped),
        })
    }

    /// Encrypt with Signal Protocol only
    async fn encrypt_with_signal_protocol(
        &self,
        from_username: &str,
        to_username: &str,
        plaintext: &[u8],
    ) -> QorResult<SignalEncryptedMessage> {
        let (session_store, identity_store, _, _, _) = self.get_or_create_stores(from_username);
        let mut session_store = session_store.lock().await;
        let mut identity_store = identity_store.lock().await;
        let target_device_id = first_session_device_id(&*session_store, to_username).unwrap_or(1);
        let to_device = signal_device_id(target_device_id, "target")?;
        let to_address = ProtocolAddress::new(to_username.to_string(), to_device);
        let mut rng = StdRng::from_os_rng();

        let message = libsignal_protocol::message_encrypt(
            plaintext,
            &to_address,
            &mut *session_store,
            &mut *identity_store,
            SystemTime::now(),
            &mut rng,
        )
        .await
        .map_err(|e| QorError::SignalProtocol(e.to_string()))?;

        Ok(SignalEncryptedMessage {
            message_type: message.message_type() as u8,
            ciphertext: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                message.serialize(),
            ),
            registration_id: None,
            sender_device_id: Some(local_signal_device_id()),
            recipient_device_id: Some(target_device_id),
        })
    }

    /// Wrap Signal message with PQ hybrid envelope
    async fn wrap_with_pq_hybrid(
        &self,
        signal_message: &SignalEncryptedMessage,
        from_username: &str,
        to_username: &str,
    ) -> QorResult<PQEnvelope> {
        // Get recipient PQ public key
        let peer_pq_key = self
            .peer_kyber_keys
            .read()
            .get(to_username)
            .cloned()
            .ok_or_else(|| {
                QorError::NotInitialized(format!(
                    "No static ML-KEM public key for recipient: {}",
                    to_username
                ))
            })?;

        // Encapsulate to get shared secret
        let kem_result = post_quantum::kyber_encapsulate(&peer_pq_key)?;

        // Derive encryption keys using BLAKE3
        let salt = random::random_bytes(32);
        let info = format!("pq-envelope:{}->{}", from_username, to_username);

        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(&kem_result.shared_secret);
        kdf_input.extend_from_slice(&salt);
        kdf_input.extend_from_slice(info.as_bytes());

        let key_material = hash::blake3(&kdf_input);

        let extended_key = hash::sha3_512(&key_material);
        let aes_key: [u8; 32] = extended_key[..32].try_into().unwrap();
        let mac_key: [u8; 32] = extended_key[32..64].try_into().unwrap();

        // Encrypt the Signal message
        let nonce = random::random_bytes(24);
        let aad = info.as_bytes();
        let payload = serde_json::to_vec(signal_message)?;

        let encrypted = crate::crypto::aead::xchacha_encrypt(
            &aes_key,
            nonce[..24].try_into().unwrap(),
            &payload,
            aad,
        )?;

        // Compute MAC
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&kem_result.ciphertext);
        mac_input.extend_from_slice(&nonce);
        mac_input.extend_from_slice(&encrypted);
        mac_input.extend_from_slice(aad);

        let mac = hash::blake3_keyed(&mac_key, &mac_input);

        Ok(PQEnvelope {
            version: SIGNAL_PQ_ENVELOPE_VERSION.to_string(),
            algorithms: PQEnvelopeAlgorithms {
                kem: SIGNAL_PQ_KEM_ALGORITHM.to_string(),
                kdf: SIGNAL_PQ_KDF_ALGORITHM.to_string(),
                aead: SIGNAL_PQ_AEAD_ALGORITHM.to_string(),
                mac: SIGNAL_PQ_MAC_ALGORITHM.to_string(),
            },
            pq_key_id: 1,
            kem_ciphertext: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &kem_result.ciphertext,
            ),
            nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &nonce),
            ciphertext: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &encrypted,
            ),
            tag: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[]),
            mac: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &mac),
            aad: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, aad),
            salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &salt),
        })
    }

    /// Decrypt message
    pub async fn decrypt(
        &self,
        from_username: &str,
        to_username: &str,
        encrypted: &EncryptedMessage,
    ) -> QorResult<Vec<u8>> {
        Self::validate_username(from_username)?;
        Self::validate_username(to_username)?;

        let session_key = format!("{}:{}", to_username, from_username);
        let _lock = self.acquire_session_lock(&session_key).await;

        let envelope = encrypted.pq_envelope.as_ref().ok_or_else(|| {
            QorError::SignalProtocol("Post-quantum Signal envelope required".to_string())
        })?;
        let signal_message = self
            .unwrap_pq_hybrid(envelope, from_username, to_username)
            .await?;
        let sender_device_id = encrypted
            .sender_device_id
            .or(signal_message.sender_device_id)
            .unwrap_or(1);

        // Decrypt with Signal Protocol
        self.decrypt_with_signal_protocol(
            from_username,
            to_username,
            &signal_message,
            sender_device_id,
        )
        .await
    }

    /// Unwrap PQ hybrid envelope
    async fn unwrap_pq_hybrid(
        &self,
        envelope: &PQEnvelope,
        from_username: &str,
        to_username: &str,
    ) -> QorResult<SignalEncryptedMessage> {
        if envelope.version != SIGNAL_PQ_ENVELOPE_VERSION {
            return Err(QorError::DecryptionFailed(
                "Unsupported Signal PQ envelope version".to_string(),
            ));
        }
        if envelope.algorithms.kem != SIGNAL_PQ_KEM_ALGORITHM
            || envelope.algorithms.kdf != SIGNAL_PQ_KDF_ALGORITHM
            || envelope.algorithms.aead != SIGNAL_PQ_AEAD_ALGORITHM
            || envelope.algorithms.mac != SIGNAL_PQ_MAC_ALGORITHM
        {
            return Err(QorError::DecryptionFailed(
                "Signal PQ envelope algorithm policy mismatch".to_string(),
            ));
        }

        // Use the key ID to find the correct secret key
        let pq_key_id = envelope.pq_key_id;
        let username = to_username;

        let our_secret_key = if pq_key_id == 1 {
            self.static_mlkem_keys
                .read()
                .get(username)
                .map(|(_, sk)| sk.clone())
                .or_else(|| {
                    let pq_key = format!("{}:1", username);
                    self.pq_kyber_keypairs
                        .read()
                        .get(&pq_key)
                        .map(|(_, sk)| sk.clone())
                })
        } else {
            let pq_key = format!("{}:{}", username, pq_key_id);
            self.pq_kyber_keypairs
                .read()
                .get(&pq_key)
                .map(|(_, sk)| sk.clone())
        }
        .ok_or_else(|| {
            log::error!(
                "[unwrap_pq_hybrid] Missing PQ Kyber secret key for id {} for user {}",
                pq_key_id,
                username
            );
            QorError::SignalProtocol(format!("Missing PQ Kyber secret key for id {}", pq_key_id))
        })?;

        // Decode envelope components
        let kem_ciphertext = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &envelope.kem_ciphertext,
        )
        .map_err(|e| QorError::DecryptionFailed(format!("Invalid KEM ciphertext: {}", e)))?;

        let salt =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &envelope.salt)
                .map_err(|e| QorError::DecryptionFailed(format!("Invalid salt: {}", e)))?;

        let nonce =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &envelope.nonce)
                .map_err(|e| QorError::DecryptionFailed(format!("Invalid nonce: {}", e)))?;

        let ciphertext = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &envelope.ciphertext,
        )
        .map_err(|e| QorError::DecryptionFailed(format!("Invalid ciphertext: {}", e)))?;

        let mac = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &envelope.mac)
            .map_err(|e| QorError::DecryptionFailed(format!("Invalid MAC: {}", e)))?;

        let aad = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &envelope.aad)
            .map_err(|e| QorError::DecryptionFailed(format!("Invalid AAD: {}", e)))?;

        if kem_ciphertext.len() != post_quantum::KYBER_CIPHERTEXT_SIZE {
            return Err(QorError::InvalidKeyLength {
                expected: post_quantum::KYBER_CIPHERTEXT_SIZE,
                actual: kem_ciphertext.len(),
            });
        }

        // Decapsulate to get shared secret
        let shared_secret = post_quantum::kyber_decapsulate(&kem_ciphertext, &our_secret_key)?;

        // Derive keys
        let info = format!("pq-envelope:{}->{}", from_username, to_username);

        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(&shared_secret);
        kdf_input.extend_from_slice(&salt);
        kdf_input.extend_from_slice(info.as_bytes());

        let key_material = hash::blake3(&kdf_input);
        let extended_key = hash::sha3_512(&key_material);
        let aes_key: [u8; 32] = extended_key[..32].try_into().unwrap();
        let mac_key: [u8; 32] = extended_key[32..64].try_into().unwrap();

        // Verify MAC
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&kem_ciphertext);
        mac_input.extend_from_slice(&nonce);
        mac_input.extend_from_slice(&ciphertext);
        mac_input.extend_from_slice(&aad);

        let computed_mac = hash::blake3_keyed(&mac_key, &mac_input);

        if !crate::crypto::utils::constant_time_eq(&mac, &computed_mac) {
            return Err(QorError::DecryptionFailed("PQ MAC mismatch".to_string()));
        }

        // Decrypt
        let nonce_array: [u8; 24] = nonce
            .try_into()
            .map_err(|_| QorError::DecryptionFailed("Invalid nonce length".to_string()))?;

        let plaintext =
            crate::crypto::aead::xchacha_decrypt(&aes_key, &nonce_array, &ciphertext, &aad)?;

        // Parse Signal message
        let signal_message: SignalEncryptedMessage = serde_json::from_slice(&plaintext)
            .map_err(|e| QorError::DecryptionFailed(format!("Invalid Signal message: {}", e)))?;

        Ok(signal_message)
    }

    /// Decrypt with Signal Protocol
    async fn decrypt_with_signal_protocol(
        &self,
        from_username: &str,
        to_username: &str,
        signal_message: &SignalEncryptedMessage,
        from_device_id: u32,
    ) -> QorResult<Vec<u8>> {
        let (session_store, identity_store, prekey_store, signed_prekey_store, kyber_prekey_store) =
            self.get_or_create_stores(to_username);
        let mut session_store = session_store.lock().await;
        let mut identity_store = identity_store.lock().await;
        let mut prekey_store = prekey_store.lock().await;
        let mut signed_prekey_store = signed_prekey_store.lock().await;
        let mut kyber_prekey_store = kyber_prekey_store.lock().await;

        let from_device = signal_device_id(from_device_id, "sender")?;
        let from_address = ProtocolAddress::new(from_username.to_string(), from_device);

        let message_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &signal_message.ciphertext,
        )
        .map_err(|e| QorError::DecryptionFailed(format!("Invalid message: {}", e)))?;
        let msg_fp = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &blake3::hash(&message_bytes).as_bytes()[..8],
        );

        let mut rng = StdRng::from_os_rng();

        let plaintext = match signal_message.message_type {
            3 => {
                // PreKey message
                let prekey_message = PreKeySignalMessage::try_from(message_bytes.as_slice())
                    .map_err(|e| {
                        log::error!(
                            "[decrypt_with_signal_protocol] Failed to parse PreKey message from {}: {} (msg_fp={}, len={})",
                            from_username, e, msg_fp, message_bytes.len()
                        );
                        QorError::SignalProtocol(e.to_string())
                    })?;

                libsignal_protocol::message_decrypt_prekey(
                    &prekey_message,
                    &from_address,
                    &mut *session_store,
                    &mut *identity_store,
                    &mut *prekey_store,
                    &mut *signed_prekey_store,
                    &mut *kyber_prekey_store,
                    &mut rng,
                ).await
                    .map_err(|e| {
                        log::error!(
                            "[decrypt_with_signal_protocol] PreKey decryption failed from {}: {} (msg_fp={}, len={})",
                            from_username, e, msg_fp, message_bytes.len()
                        );
                        QorError::SignalProtocol(e.to_string())
                    })?
            }
            _ => {
                // Regular Signal message
                let signal_msg = SignalMessage::try_from(message_bytes.as_slice())
                    .map_err(|e| {
                        log::error!(
                            "[decrypt_with_signal_protocol] Failed to parse Signal message from {}: {} (msg_fp={}, len={})",
                            from_username, e, msg_fp, message_bytes.len()
                        );
                        QorError::SignalProtocol(e.to_string())
                    })?;

                // Check if session exists before attempting decryption
                if !session_store.has_session(&from_address) {
                    log::error!(
                        "[decrypt_with_signal_protocol] No session exists for {} when trying to decrypt message type {} (msg_fp={}, len={})",
                        from_username,
                        signal_message.message_type,
                        msg_fp,
                        message_bytes.len()
                    );
                    return Err(QorError::SignalProtocol(format!(
                        "No session with {} for decryption",
                        from_username
                    )));
                }

                libsignal_protocol::message_decrypt_signal(
                    &signal_msg,
                    &from_address,
                    &mut *session_store,
                    &mut *identity_store,
                    &mut rng,
                ).await
                    .map_err(|e| {
                        log::error!(
                            "[decrypt_with_signal_protocol] Signal decryption failed from {}: {} (msg_fp={}, len={})",
                            from_username, e, msg_fp, message_bytes.len()
                        );
                        QorError::SignalProtocol(e.to_string())
                    })?
            }
        };

        Ok(plaintext)
    }

    /// Delete session with peer
    pub async fn delete_session(
        &self,
        self_username: &str,
        peer_username: &str,
        device_id: u32,
    ) -> QorResult<bool> {
        Self::validate_username(self_username)?;
        Self::validate_username(peer_username)?;

        let (session_store, _, _, _, _) = self.get_or_create_stores(self_username);
        let session_store = session_store.lock().await;
        let device = signal_device_id(device_id, "peer")?;
        let address = ProtocolAddress::new(peer_username.to_string(), device);

        session_store.delete_session(&address);
        if device_id == 1 {
            for other_device_id in 2..=SIGNAL_DEVICE_ID_MAX {
                if let Ok(other_device) = DeviceId::try_from(other_device_id) {
                    let other_address =
                        ProtocolAddress::new(peer_username.to_string(), other_device);
                    session_store.delete_session(&other_address);
                }
            }
        }
        Ok(true)
    }

    /// Delete all sessions with peer
    pub async fn delete_all_sessions(
        &self,
        self_username: &str,
        peer_username: &str,
    ) -> QorResult<bool> {
        Self::validate_username(self_username)?;
        Self::validate_username(peer_username)?;

        for device_id in 1..=SIGNAL_DEVICE_ID_MAX {
            self.delete_session(self_username, peer_username, device_id)
                .await?;
        }
        Ok(true)
    }

    /// Set peer Kyber public key
    pub fn set_peer_kyber_key(&self, peer: &str, key: Vec<u8>) {
        self.peer_kyber_keys.write().insert(peer.to_string(), key);
    }

    /// Check if peer Kyber key exists
    pub fn has_peer_kyber_key(&self, peer: &str) -> bool {
        self.peer_kyber_keys.read().contains_key(peer)
    }

    /// Trust peer identity
    pub async fn trust_peer_identity(
        &self,
        self_username: &str,
        peer_username: &str,
        _device_id: u32,
    ) -> QorResult<bool> {
        Self::validate_username(self_username)?;
        Self::validate_username(peer_username)?;

        let (_, identity_store, _, _, _) = self.get_or_create_stores(self_username);
        let identity_store = &mut *identity_store.lock().await;
        identity_store.trust_identity(peer_username);
        Ok(true)
    }

    /// Set static ML-KEM keys for user
    pub async fn set_static_mlkem_keys(
        &self,
        username: &str,
        public_key: Vec<u8>,
        secret_key: Vec<u8>,
    ) -> QorResult<bool> {
        Self::validate_username(username)?;

        if public_key.len() != post_quantum::KYBER_PUBLIC_KEY_SIZE {
            log::error!(
                "[set_static_mlkem_keys] Invalid public key length: expected {}, got {}",
                post_quantum::KYBER_PUBLIC_KEY_SIZE,
                public_key.len()
            );
            return Err(QorError::InvalidKeyLength {
                expected: post_quantum::KYBER_PUBLIC_KEY_SIZE,
                actual: public_key.len(),
            });
        }

        if secret_key.len() != post_quantum::KYBER_SECRET_KEY_SIZE {
            log::error!(
                "[set_static_mlkem_keys] Invalid secret key length: expected {}, got {}",
                post_quantum::KYBER_SECRET_KEY_SIZE,
                secret_key.len()
            );
            return Err(QorError::InvalidKeyLength {
                expected: post_quantum::KYBER_SECRET_KEY_SIZE,
                actual: secret_key.len(),
            });
        }

        self.static_mlkem_keys.write().insert(
            username.to_string(),
            (public_key, Zeroizing::new(secret_key)),
        );

        Ok(true)
    }

    /// Persist all Signal stores for a user to the database
    pub async fn persist_to_db(
        &self,
        db: &crate::database::DatabaseManager,
        username: &str,
    ) -> QorResult<()> {
        let (session_store, identity_store, prekey_store, signed_prekey_store, kyber_prekey_store) =
            self.get_or_create_stores(username);

        // Sessions
        let sessions = session_store.lock().await.dump();
        let sessions_blob = serde_json::to_vec(&sessions).map_err(|e| {
            QorError::SignalProtocol(format!("Failed to serialize sessions: {}", e))
        })?;
        db.set_secure("signal_session_store_v1", username, &sessions_blob)?;

        // Identity
        if let Some(identity_data) = identity_store.lock().await.dump() {
            let identity_blob = serde_json::to_vec(&identity_data).map_err(|e| {
                QorError::SignalProtocol(format!("Failed to serialize identity: {}", e))
            })?;
            db.set_secure("signal_identity_store_v1", username, &identity_blob)?;
        }

        // PreKeys
        let prekeys = prekey_store.lock().await.dump();
        let prekeys_blob = serde_json::to_vec(&prekeys)
            .map_err(|e| QorError::SignalProtocol(format!("Failed to serialize prekeys: {}", e)))?;
        db.set_secure("signal_prekey_store_v1", username, &prekeys_blob)?;

        // Signed PreKeys
        let signed_prekeys = signed_prekey_store.lock().await.dump();
        let signed_prekeys_blob = serde_json::to_vec(&signed_prekeys).map_err(|e| {
            QorError::SignalProtocol(format!("Failed to serialize signed prekeys: {}", e))
        })?;
        db.set_secure(
            "signal_signed_prekey_store_v1",
            username,
            &signed_prekeys_blob,
        )?;

        // Kyber PreKeys
        let kyber_prekeys = kyber_prekey_store.lock().await.dump();
        let kyber_prekeys_blob = serde_json::to_vec(&kyber_prekeys).map_err(|e| {
            QorError::SignalProtocol(format!("Failed to serialize kyber prekeys: {}", e))
        })?;
        db.set_secure(
            "signal_kyber_prekey_store_v1",
            username,
            &kyber_prekeys_blob,
        )?;

        // PQ Kyber Keypairs
        let pq_keys_map = self.pq_kyber_keypairs.read();
        let pq_keys_serializable: HashMap<String, (Vec<u8>, Vec<u8>)> = pq_keys_map
            .iter()
            .map(|(k, (pk, sk))| (k.clone(), (pk.clone(), sk.to_vec())))
            .collect();

        let pq_keys_blob = serde_json::to_vec(&pq_keys_serializable).map_err(|e| {
            QorError::SignalProtocol(format!("Failed to serialize pq kyber keys: {}", e))
        })?;
        db.set_secure("signal_pq_kyber_store_v1", username, &pq_keys_blob)?;

        // Static ML-KEM Keys
        let static_keys_map = self.static_mlkem_keys.read();
        if let Some((pk, sk)) = static_keys_map.get(username) {
            let static_keys_serializable = (pk.clone(), sk.to_vec());
            let static_keys_blob = serde_json::to_vec(&static_keys_serializable).map_err(|e| {
                QorError::SignalProtocol(format!("Failed to serialize static mlkem keys: {}", e))
            })?;
            db.set_secure("signal_static_mlkem_store_v1", username, &static_keys_blob)?;
        }

        Ok(())
    }

    /// save only state that changes during normal messaging
    pub async fn persist_messaging_state(
        &self,
        db: &crate::database::DatabaseManager,
        username: &str,
        full: bool,
    ) -> QorResult<()> {
        let (session_store, identity_store, prekey_store, _signed, _kyber) =
            self.get_or_create_stores(username);

        let sessions = session_store.lock().await.dump();
        let sessions_blob = serde_json::to_vec(&sessions).map_err(|e| {
            QorError::SignalProtocol(format!("Failed to serialize sessions: {}", e))
        })?;
        db.set_secure("signal_session_store_v1", username, &sessions_blob)?;

        if full {
            if let Some(identity_data) = identity_store.lock().await.dump() {
                let identity_blob = serde_json::to_vec(&identity_data).map_err(|e| {
                    QorError::SignalProtocol(format!("Failed to serialize identity: {}", e))
                })?;
                db.set_secure("signal_identity_store_v1", username, &identity_blob)?;
            }
            let prekeys = prekey_store.lock().await.dump();
            let prekeys_blob = serde_json::to_vec(&prekeys).map_err(|e| {
                QorError::SignalProtocol(format!("Failed to serialize prekeys: {}", e))
            })?;
            db.set_secure("signal_prekey_store_v1", username, &prekeys_blob)?;
        }

        Ok(())
    }

    /// Load all Signal stores for a user from the database
    pub async fn load_from_db(
        &self,
        db: &crate::database::DatabaseManager,
        username: &str,
    ) -> QorResult<()> {
        let (session_store, identity_store, prekey_store, signed_prekey_store, kyber_prekey_store) =
            self.get_or_create_stores(username);

        // Sessions
        if let Some(blob) = db.get_secure("signal_session_store_v1", username)? {
            let data: Vec<(String, Vec<u8>)> = serde_json::from_slice(&blob).map_err(|e| {
                QorError::SignalProtocol(format!("Failed to deserialize sessions: {}", e))
            })?;
            session_store.lock().await.load(data);
        }

        // Identity
        if let Some(blob) = db.get_secure("signal_identity_store_v1", username)? {
            let (reg_id, ik_bytes, pk_bytes, known_identities): (
                u32,
                Vec<u8>,
                Vec<u8>,
                Vec<(String, Vec<u8>)>,
            ) = serde_json::from_slice(&blob).map_err(|e| {
                QorError::SignalProtocol(format!("Failed to deserialize identity: {}", e))
            })?;
            identity_store
                .lock()
                .await
                .load(reg_id, ik_bytes, pk_bytes, known_identities);
        }

        // PreKeys
        if let Some(blob) = db.get_secure("signal_prekey_store_v1", username)? {
            let data: Vec<(u32, Vec<u8>)> = serde_json::from_slice(&blob).map_err(|e| {
                QorError::SignalProtocol(format!("Failed to deserialize prekeys: {}", e))
            })?;
            prekey_store.lock().await.load(data);
        }

        // Signed PreKeys
        if let Some(blob) = db.get_secure("signal_signed_prekey_store_v1", username)? {
            let data: Vec<(u32, Vec<u8>)> = serde_json::from_slice(&blob).map_err(|e| {
                QorError::SignalProtocol(format!("Failed to deserialize signed prekeys: {}", e))
            })?;
            signed_prekey_store.lock().await.load(data);
        }

        // Kyber PreKeys
        if let Some(blob) = db.get_secure("signal_kyber_prekey_store_v1", username)? {
            let data: Vec<(u32, Vec<u8>)> = serde_json::from_slice(&blob).map_err(|e| {
                QorError::SignalProtocol(format!("Failed to deserialize kyber prekeys: {}", e))
            })?;
            kyber_prekey_store.lock().await.load(data);
        }

        // PQ Kyber Keypairs
        if let Some(blob) = db.get_secure("signal_pq_kyber_store_v1", username)? {
            let data: HashMap<String, (Vec<u8>, Vec<u8>)> =
                serde_json::from_slice(&blob).map_err(|e| {
                    QorError::SignalProtocol(format!("Failed to deserialize pq kyber keys: {}", e))
                })?;

            let mut pq_map = self.pq_kyber_keypairs.write();
            for (k, (pk, sk)) in data {
                pq_map.insert(k, (pk, Zeroizing::new(sk)));
            }
        }

        // Static ML-KEM Keys
        if let Some(blob) = db.get_secure("signal_static_mlkem_store_v1", username)? {
            let (pk, sk): (Vec<u8>, Vec<u8>) = serde_json::from_slice(&blob).map_err(|e| {
                QorError::SignalProtocol(format!("Failed to deserialize static mlkem keys: {}", e))
            })?;

            self.static_mlkem_keys
                .write()
                .insert(username.to_string(), (pk, Zeroizing::new(sk)));
        }

        Ok(())
    }
}

/// Session lock guard
struct SessionLockGuard {
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

/// Generate random registration ID
fn generate_registration_id() -> u32 {
    let bytes = random::random_bytes(4);
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) & 0x3FFF
}

/// Identity bundle containing keys
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IdentityBundle {
    pub identity_key_public: String,
    pub registration_id: u32,
    pub kyber_public_key: Option<String>,
}

/// Pre-key data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PreKey {
    pub key_id: u32,
    pub public_key: String,
}

/// Signed pre-key data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedPreKey {
    pub key_id: u32,
    pub public_key: String,
    pub signature: String,
}

/// Kyber pre-key data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KyberPreKey {
    pub key_id: u32,
    pub public_key: String,
    pub signature: String,
}

/// PQ Kyber pre-key standalone ML-KEM-1024
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyInfo {
    pub key_id: u32,
    pub public_key_base64: String,
}

/// Signed pre-key data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPreKeyInfo {
    pub key_id: u32,
    pub public_key_base64: String,
    pub signature_base64: String,
}

/// Kyber pre-key data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KyberPreKeyInfo {
    pub key_id: u32,
    pub public_key_base64: String,
    pub signature_base64: String,
}

/// PQ Kyber pre-key ML-KEM-1024
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PQKyberPreKey {
    pub key_id: u32,
    pub public_key_base64: String,
}

/// Pre-key bundle for key exchange
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyBundle {
    pub registration_id: u32,
    pub device_id: u32,
    pub identity_key_base64: String,
    pub pre_key: Option<PreKeyInfo>,
    pub signed_pre_key: SignedPreKeyInfo,
    pub kyber_pre_key: Option<KyberPreKeyInfo>,
    pub pq_kyber: Option<PQKyberPreKey>,
}

/// Pre-key bundle input for processing
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyBundleInput {
    pub registration_id: u32,
    pub device_id: u32,
    pub identity_key_base64: String,
    pub pre_key: Option<PreKeyInfo>,
    pub signed_pre_key: SignedPreKeyInfo,
    pub kyber_pre_key: Option<KyberPreKeyInfo>,
    pub pq_kyber: Option<PQKyberPreKey>,
}

/// Signal encrypted message
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalEncryptedMessage {
    pub message_type: u8,
    pub ciphertext: String,
    pub registration_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_device_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_device_id: Option<u32>,
}

/// Encrypted message structure PQ envelope
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedMessage {
    pub message_type: u8,
    pub ciphertext: String,
    pub registration_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_device_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_device_id: Option<u32>,
    pub pq_envelope: Option<PQEnvelope>,
}

/// Post-quantum envelope for hybrid encryption
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PQEnvelope {
    pub version: String,
    pub algorithms: PQEnvelopeAlgorithms,
    pub pq_key_id: u32,
    pub kem_ciphertext: String,
    pub nonce: String,
    pub ciphertext: String,
    pub tag: String,
    pub mac: String,
    pub aad: String,
    pub salt: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PQEnvelopeAlgorithms {
    pub kem: String,
    pub kdf: String,
    pub aead: String,
    pub mac: String,
}

/// Initialize Signal Protocol handler
pub async fn init(state: &AppState) -> QorResult<()> {
    let storage = state
        .storage()
        .ok_or_else(|| QorError::NotInitialized("Storage not initialized".to_string()))?;

    let handler = SignalHandler::new(storage);
    *state.signal_handler.write() = Some(Arc::new(handler));

    Ok(())
}
