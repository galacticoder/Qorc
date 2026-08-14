//! Signal Protocol Storage

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use libsignal_protocol::{
    CiphertextMessageType, Direction, GenericSignedPreKey, IdentityKey, IdentityKeyPair,
    KyberPreKeyId, KyberPreKeyRecord, PreKeyId, PreKeyRecord, PrivateKey, ProtocolAddress,
    SessionRecord, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord,
};
use parking_lot::RwLock;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::post_quantum;

const MAX_STORED_SIGNAL_RECORDS: usize = 10_000;
const MAX_STORED_ROTATING_PREKEY_RECORDS: usize = 16;
const MAX_SIGNAL_DEVICE_ID: u32 = 127;
const SIGNAL_SIGNATURE_BYTES: usize = 64;

pub type IdentityStoreDump = (u32, Vec<u8>, Vec<u8>, Vec<(String, Vec<u8>)>);
type KyberReplayPair = (KyberPreKeyId, SignedPreKeyId);
type KyberReplayIndex = HashMap<KyberReplayPair, HashSet<Vec<u8>>>;

fn is_canonical_signal_username(value: &str) -> bool {
    (3..=100).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn is_canonical_session_key(value: &str) -> bool {
    let Some((username, device)) = value.rsplit_once('.') else {
        return false;
    };
    if !is_canonical_signal_username(username)
        || device.is_empty()
        || !device.bytes().all(|b| b.is_ascii_digit())
    {
        return false;
    }
    let Ok(device_id) = device.parse::<u32>() else {
        return false;
    };
    (1..=MAX_SIGNAL_DEVICE_ID).contains(&device_id) && device == device_id.to_string()
}

pub(crate) fn validate_pq_ratchet_state(record: &SessionRecord) -> Result<(), String> {
    let state = record
        .current_pq_state()
        .ok_or_else(|| "Signal session has no post-quantum ratchet state".to_string())?;
    match spqr::current_version(state)
        .map_err(|_| "Invalid Signal post-quantum ratchet state".to_string())?
    {
        spqr::CurrentVersion::StillNegotiating {
            version: spqr::Version::V1,
            ..
        }
        | spqr::CurrentVersion::NegotiationComplete(spqr::Version::V1) => Ok(()),
        _ => Err("Signal post-quantum ratchet downgrade rejected".to_string()),
    }
}

pub struct InMemorySessionStore {
    sessions: RwLock<HashMap<String, SessionRecord>>,
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    fn session_key(address: &ProtocolAddress) -> String {
        format!("{}.{}", address.name(), address.device_id())
    }

    pub fn load_session(&self, address: &ProtocolAddress) -> Option<SessionRecord> {
        self.sessions
            .read()
            .get(&Self::session_key(address))
            .cloned()
    }

    pub fn store_session(&self, address: &ProtocolAddress, record: &SessionRecord) {
        self.sessions
            .write()
            .insert(Self::session_key(address), record.clone());
    }

    pub fn delete_all_sessions(&self, name: &str) {
        self.sessions.write().retain(|key, _| {
            key.rsplit_once('.')
                .is_none_or(|(session_name, _)| session_name != name)
        });
    }

    pub fn has_session(&self, address: &ProtocolAddress) -> bool {
        self.sessions
            .read()
            .contains_key(&Self::session_key(address))
    }

    pub fn dump(&self) -> Result<Vec<(String, Vec<u8>)>, String> {
        self.sessions
            .read()
            .iter()
            .map(|(key, record)| {
                record
                    .serialize()
                    .map(|bytes| (key.clone(), bytes))
                    .map_err(|_| "failed to serialize session record".to_string())
            })
            .collect()
    }

    pub fn load(&self, data: Vec<(String, Vec<u8>)>) -> Result<(), String> {
        if data.len() > MAX_STORED_SIGNAL_RECORDS {
            return Err("session store record limit exceeded".to_string());
        }

        let data = data
            .into_iter()
            .map(|(key, serialized)| (key, Zeroizing::new(serialized)))
            .collect::<Vec<_>>();
        let mut loaded = HashMap::with_capacity(data.len());
        for (key, serialized) in data {
            if !is_canonical_session_key(&key) {
                return Err("invalid session record address".to_string());
            }
            let decoded = SessionRecord::deserialize(&serialized)
                .map_err(|_| "invalid serialized session record".to_string());
            let record = decoded?;
            validate_pq_ratchet_state(&record)?;
            if loaded.insert(key, record).is_some() {
                return Err("duplicate session record".to_string());
            }
        }
        *self.sessions.write() = loaded;
        Ok(())
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl libsignal_protocol::SessionStore for InMemorySessionStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, libsignal_protocol::SignalProtocolError> {
        Ok(self.load_session(address))
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), libsignal_protocol::SignalProtocolError> {
        let key = Self::session_key(address);
        if !is_canonical_session_key(&key) {
            return Err(libsignal_protocol::SignalProtocolError::InvalidState(
                "SessionStore",
                "invalid session record address".to_string(),
            ));
        }
        let mut sessions = self.sessions.write();
        if !sessions.contains_key(&key) && sessions.len() >= MAX_STORED_SIGNAL_RECORDS {
            return Err(libsignal_protocol::SignalProtocolError::InvalidState(
                "SessionStore",
                "session store record limit exceeded".to_string(),
            ));
        }
        sessions.insert(key, record.clone());
        Ok(())
    }
}

pub struct InMemoryIdentityKeyStore {
    identity_key_pair: RwLock<Option<IdentityKeyPair>>,
    registration_id: RwLock<Option<u32>>,
    known_identities: RwLock<HashMap<String, IdentityKey>>,
}

impl InMemoryIdentityKeyStore {
    pub fn new() -> Self {
        Self {
            identity_key_pair: RwLock::new(None),
            registration_id: RwLock::new(None),
            known_identities: RwLock::new(HashMap::new()),
        }
    }

    pub fn get_identity_key_pair(&self) -> Option<IdentityKeyPair> {
        *self.identity_key_pair.read()
    }

    pub fn set_identity_key_pair(&self, key_pair: IdentityKeyPair) {
        *self.identity_key_pair.write() = Some(key_pair);
    }

    pub fn get_local_registration_id(&self) -> Option<u32> {
        *self.registration_id.read()
    }

    pub fn set_local_registration_id(&self, id: u32) {
        *self.registration_id.write() = Some(id);
    }

    pub fn get_identity(&self, name: &str) -> Option<IdentityKey> {
        self.known_identities.read().get(name).cloned()
    }

    pub fn can_insert_identity(&self, name: &str) -> bool {
        let identities = self.known_identities.read();
        identities.contains_key(name) || identities.len() < MAX_STORED_SIGNAL_RECORDS
    }

    pub fn replace_identity(&self, name: &str, identity: IdentityKey) {
        self.known_identities
            .write()
            .insert(name.to_string(), identity);
    }

    pub fn remove_identity(&self, name: &str) {
        self.known_identities.write().remove(name);
    }

    pub fn dump(&self) -> Option<IdentityStoreDump> {
        let registration_id = (*self.registration_id.read())?;
        let guard = self.identity_key_pair.read();
        let ikp = guard.as_ref()?;
        let identity_key = ikp.identity_key().serialize().to_vec();
        let private_key = ikp.private_key().serialize().to_vec();
        let known_identities = self
            .known_identities
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.serialize().to_vec()))
            .collect();
        Some((registration_id, identity_key, private_key, known_identities))
    }

    pub fn load(
        &self,
        registration_id: u32,
        identity_key_bytes: Vec<u8>,
        mut private_key_bytes: Vec<u8>,
        known_identities_data: Vec<(String, Vec<u8>)>,
    ) -> Result<(), String> {
        if known_identities_data.len() > MAX_STORED_SIGNAL_RECORDS {
            private_key_bytes.zeroize();
            return Err("known identity record limit exceeded".to_string());
        }
        if !(1..=16_380).contains(&registration_id) {
            private_key_bytes.zeroize();
            return Err("invalid local Signal registration id".to_string());
        }

        let identity_key = IdentityKey::decode(&identity_key_bytes)
            .map_err(|_| "invalid local identity public key".to_string());
        let private_key = PrivateKey::deserialize(&private_key_bytes)
            .map_err(|_| "invalid local identity private key".to_string());
        private_key_bytes.zeroize();
        let identity_key = identity_key?;
        let private_key = private_key?;
        let derived_public_key = private_key
            .public_key()
            .map_err(|_| "invalid local identity private key".to_string())?;
        if identity_key.public_key() != &derived_public_key {
            return Err("local identity keypair mismatch".to_string());
        }
        let identity_pair = IdentityKeyPair::new(identity_key, private_key);

        let mut known = HashMap::with_capacity(known_identities_data.len());
        for (name, serialized) in known_identities_data {
            if !is_canonical_signal_username(&name) {
                return Err("invalid known identity address".to_string());
            }
            let identity = IdentityKey::decode(&serialized)
                .map_err(|_| "invalid known identity key".to_string())?;
            if known.insert(name, identity).is_some() {
                return Err("duplicate known identity".to_string());
            }
        }

        *self.registration_id.write() = Some(registration_id);
        *self.identity_key_pair.write() = Some(identity_pair);
        *self.known_identities.write() = known;
        Ok(())
    }
}

impl Default for InMemoryIdentityKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl libsignal_protocol::IdentityKeyStore for InMemoryIdentityKeyStore {
    async fn get_identity_key_pair(
        &self,
    ) -> Result<IdentityKeyPair, libsignal_protocol::SignalProtocolError> {
        self.get_identity_key_pair()
            .ok_or(libsignal_protocol::SignalProtocolError::InvalidState(
                "IdentityKeyStore",
                "No identity key pair".to_string(),
            ))
    }

    async fn get_local_registration_id(
        &self,
    ) -> Result<u32, libsignal_protocol::SignalProtocolError> {
        self.get_local_registration_id().ok_or(
            libsignal_protocol::SignalProtocolError::InvalidState(
                "IdentityKeyStore",
                "No registration ID".to_string(),
            ),
        )
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<libsignal_protocol::IdentityChange, libsignal_protocol::SignalProtocolError> {
        if !is_canonical_signal_username(address.name()) {
            return Err(libsignal_protocol::SignalProtocolError::InvalidState(
                "IdentityKeyStore",
                "invalid known identity address".to_string(),
            ));
        }
        let mut identities = self.known_identities.write();
        let existing = identities.get(address.name()).cloned();
        if existing.is_none() && identities.len() >= MAX_STORED_SIGNAL_RECORDS {
            return Err(libsignal_protocol::SignalProtocolError::InvalidState(
                "IdentityKeyStore",
                "known identity record limit exceeded".to_string(),
            ));
        }
        identities.insert(address.name().to_string(), *identity);

        let changed = existing.is_none_or(|known| &known != identity);
        Ok(libsignal_protocol::IdentityChange::from_changed(changed))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, libsignal_protocol::SignalProtocolError> {
        let known = self.known_identities.read().get(address.name()).cloned();
        match known {
            None => Ok(false),
            Some(existing) => Ok(&existing == identity),
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, libsignal_protocol::SignalProtocolError> {
        Ok(InMemoryIdentityKeyStore::get_identity(self, address.name()))
    }
}

pub struct InMemoryPreKeyStore {
    pre_keys: RwLock<HashMap<PreKeyId, PreKeyRecord>>,
}

impl InMemoryPreKeyStore {
    pub fn new() -> Self {
        Self {
            pre_keys: RwLock::new(HashMap::new()),
        }
    }

    pub fn store_pre_key(&self, id: PreKeyId, record: &PreKeyRecord) {
        self.pre_keys.write().insert(id, record.clone());
    }

    pub fn get_pre_key(&self, id: PreKeyId) -> Option<PreKeyRecord> {
        self.pre_keys.read().get(&id).cloned()
    }

    pub fn remove_pre_key(&self, id: PreKeyId) {
        self.pre_keys.write().remove(&id);
    }
}

impl Default for InMemoryPreKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl libsignal_protocol::PreKeyStore for InMemoryPreKeyStore {
    async fn get_pre_key(
        &self,
        id: PreKeyId,
    ) -> Result<PreKeyRecord, libsignal_protocol::SignalProtocolError> {
        InMemoryPreKeyStore::get_pre_key(self, id)
            .ok_or(libsignal_protocol::SignalProtocolError::InvalidPreKeyId)
    }

    async fn save_pre_key(
        &mut self,
        id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), libsignal_protocol::SignalProtocolError> {
        InMemoryPreKeyStore::store_pre_key(self, id, record);
        Ok(())
    }

    async fn remove_pre_key(
        &mut self,
        id: PreKeyId,
    ) -> Result<(), libsignal_protocol::SignalProtocolError> {
        InMemoryPreKeyStore::remove_pre_key(self, id);
        Ok(())
    }
}

pub struct InMemorySignedPreKeyStore {
    signed_pre_keys: RwLock<HashMap<SignedPreKeyId, SignedPreKeyRecord>>,
}

impl InMemorySignedPreKeyStore {
    pub fn new() -> Self {
        Self {
            signed_pre_keys: RwLock::new(HashMap::new()),
        }
    }

    pub fn store_signed_pre_key(
        &self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), String> {
        let mut keys = self.signed_pre_keys.write();
        if !keys.contains_key(&id) && keys.len() >= MAX_STORED_ROTATING_PREKEY_RECORDS {
            return Err("signed pre-key store record limit exceeded".to_string());
        }
        keys.insert(id, record.clone());
        Ok(())
    }

    pub fn get_signed_pre_key(&self, id: SignedPreKeyId) -> Option<SignedPreKeyRecord> {
        self.signed_pre_keys.read().get(&id).cloned()
    }

    pub fn get_any_signed_pre_key(&self) -> Option<(SignedPreKeyId, SignedPreKeyRecord)> {
        let guard = self.signed_pre_keys.read();
        guard
            .iter()
            .max_by_key(|(id, _)| u32::from(**id))
            .map(|(id, record)| (*id, record.clone()))
    }

    pub fn prune_older_than(&self, cutoff_ms: u64) {
        let mut keys = self.signed_pre_keys.write();
        let latest = keys.keys().max_by_key(|id| u32::from(**id)).copied();
        keys.retain(|id, record| {
            Some(*id) == latest
                || record
                    .timestamp()
                    .map(|timestamp| timestamp.epoch_millis() >= cutoff_ms)
                    .unwrap_or(true)
        });
    }

    pub fn validate_signatures(&self, identity: &IdentityKey) -> Result<(), String> {
        for record in self.signed_pre_keys.read().values() {
            let public_key = record
                .public_key()
                .map_err(|_| "invalid signed pre-key public key".to_string())?;
            let signature = record
                .signature()
                .map_err(|_| "invalid signed pre-key signature".to_string())?;
            if !identity
                .public_key()
                .verify_signature(&public_key.serialize(), &signature)
            {
                return Err("signed pre-key identity signature mismatch".to_string());
            }
        }
        Ok(())
    }

    pub fn dump(&self) -> Result<Vec<(u32, Vec<u8>)>, String> {
        self.signed_pre_keys
            .read()
            .iter()
            .map(|(id, record)| {
                record
                    .serialize()
                    .map(|bytes| (u32::from(*id), bytes))
                    .map_err(|_| "failed to serialize signed pre-key record".to_string())
            })
            .collect()
    }

    pub fn load(&self, data: Vec<(u32, Vec<u8>)>) -> Result<(), String> {
        if data.len() > MAX_STORED_ROTATING_PREKEY_RECORDS {
            return Err("signed pre-key store record limit exceeded".to_string());
        }

        let data = data
            .into_iter()
            .map(|(id, serialized)| (id, Zeroizing::new(serialized)))
            .collect::<Vec<_>>();
        let mut loaded = HashMap::with_capacity(data.len());
        for (id, serialized) in data {
            let decoded = SignedPreKeyRecord::deserialize(&serialized)
                .map_err(|_| "invalid serialized signed pre-key record".to_string());
            let record = decoded?;
            let record_id = record
                .id()
                .map_err(|_| "invalid signed pre-key record id".to_string())?;
            if u32::from(record_id) != id {
                return Err("signed pre-key record id mismatch".to_string());
            }
            let public_key = record
                .public_key()
                .map_err(|_| "invalid signed pre-key public key".to_string())?;
            let private_key = record
                .private_key()
                .map_err(|_| "invalid signed pre-key private key".to_string())?;
            let derived_public_key = private_key
                .public_key()
                .map_err(|_| "invalid signed pre-key private key".to_string())?;
            if public_key != derived_public_key {
                return Err("signed pre-key keypair mismatch".to_string());
            }
            if record
                .signature()
                .map_err(|_| "invalid signed pre-key signature".to_string())?
                .len()
                != SIGNAL_SIGNATURE_BYTES
            {
                return Err("invalid signed pre-key signature".to_string());
            }
            if loaded.insert(id.into(), record).is_some() {
                return Err("duplicate signed pre-key record".to_string());
            }
        }
        *self.signed_pre_keys.write() = loaded;
        Ok(())
    }
}

impl Default for InMemorySignedPreKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl libsignal_protocol::SignedPreKeyStore for InMemorySignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, libsignal_protocol::SignalProtocolError> {
        InMemorySignedPreKeyStore::get_signed_pre_key(self, id)
            .ok_or(libsignal_protocol::SignalProtocolError::InvalidSignedPreKeyId)
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), libsignal_protocol::SignalProtocolError> {
        InMemorySignedPreKeyStore::store_signed_pre_key(self, id, record).map_err(|message| {
            libsignal_protocol::SignalProtocolError::InvalidState("SignedPreKeyStore", message)
        })
    }
}

pub struct InMemoryKyberPreKeyStore {
    kyber_pre_keys: RwLock<HashMap<KyberPreKeyId, KyberPreKeyRecord>>,
    base_keys_seen: RwLock<KyberReplayIndex>,
    base_key_count: AtomicUsize,
}

const MAX_BASE_KEYS_PER_KYBER_PAIR: usize = 16_384;
const MAX_KYBER_REPLAY_PAIRS: usize = 4_096;
const MAX_KYBER_REPLAY_KEYS: usize = 100_000;

impl InMemoryKyberPreKeyStore {
    pub fn new() -> Self {
        Self {
            kyber_pre_keys: RwLock::new(HashMap::new()),
            base_keys_seen: RwLock::new(HashMap::new()),
            base_key_count: AtomicUsize::new(0),
        }
    }

    pub fn store_kyber_pre_key(
        &self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), String> {
        let mut keys = self.kyber_pre_keys.write();
        if !keys.contains_key(&id) && keys.len() >= MAX_STORED_ROTATING_PREKEY_RECORDS {
            return Err("ML-KEM pre-key store record limit exceeded".to_string());
        }
        keys.insert(id, record.clone());
        Ok(())
    }

    pub fn get_kyber_pre_key(&self, id: KyberPreKeyId) -> Option<KyberPreKeyRecord> {
        self.kyber_pre_keys.read().get(&id).cloned()
    }

    pub fn get_any_kyber_pre_key(&self) -> Option<(KyberPreKeyId, KyberPreKeyRecord)> {
        let guard = self.kyber_pre_keys.read();
        guard
            .iter()
            .max_by_key(|(id, _)| u32::from(**id))
            .map(|(id, record)| (*id, record.clone()))
    }

    pub fn prune_older_than(&self, cutoff_ms: u64) {
        let retained_ids = {
            let mut keys = self.kyber_pre_keys.write();
            let latest = keys.keys().max_by_key(|id| u32::from(**id)).copied();
            keys.retain(|id, record| {
                Some(*id) == latest
                    || record
                        .timestamp()
                        .map(|timestamp| timestamp.epoch_millis() >= cutoff_ms)
                        .unwrap_or(true)
            });
            keys.keys().copied().collect::<HashSet<_>>()
        };
        let mut replay_state = self.base_keys_seen.write();
        replay_state.retain(|(kyber_id, _), _| retained_ids.contains(kyber_id));
        self.base_key_count.store(
            replay_state.values().map(HashSet::len).sum(),
            Ordering::Relaxed,
        );
    }

    pub fn validate_signatures(&self, identity: &IdentityKey) -> Result<(), String> {
        for record in self.kyber_pre_keys.read().values() {
            let public_key = record
                .public_key()
                .map_err(|_| "invalid ML-KEM pre-key public key".to_string())?;
            let signature = record
                .signature()
                .map_err(|_| "invalid ML-KEM pre-key signature".to_string())?;
            if !identity
                .public_key()
                .verify_signature(&public_key.serialize(), &signature)
            {
                return Err("ML-KEM pre-key identity signature mismatch".to_string());
            }
        }
        Ok(())
    }

    pub fn dump(&self) -> Result<Vec<(u32, Vec<u8>)>, String> {
        self.kyber_pre_keys
            .read()
            .iter()
            .map(|(id, record)| {
                record
                    .serialize()
                    .map(|bytes| (u32::from(*id), bytes))
                    .map_err(|_| "failed to serialize Kyber pre-key record".to_string())
            })
            .collect()
    }

    pub fn load(&self, data: Vec<(u32, Vec<u8>)>) -> Result<(), String> {
        if data.len() > MAX_STORED_ROTATING_PREKEY_RECORDS {
            return Err("Kyber pre-key store record limit exceeded".to_string());
        }

        let data = data
            .into_iter()
            .map(|(id, serialized)| (id, Zeroizing::new(serialized)))
            .collect::<Vec<_>>();
        let mut loaded = HashMap::with_capacity(data.len());
        for (id, serialized) in data {
            let decoded = KyberPreKeyRecord::deserialize(&serialized)
                .map_err(|_| "invalid serialized Kyber pre-key record".to_string());
            let record = decoded?;
            let record_id = record
                .id()
                .map_err(|_| "invalid ML-KEM pre-key record id".to_string())?;
            if u32::from(record_id) != id {
                return Err("ML-KEM pre-key record id mismatch".to_string());
            }
            let public_key = record
                .public_key()
                .map_err(|_| "invalid ML-KEM pre-key record".to_string())?;
            let secret_key = record
                .secret_key()
                .map_err(|_| "invalid ML-KEM pre-key secret key".to_string())?;
            if public_key.key_type() != libsignal_protocol::kem::KeyType::MLKEM1024
                || secret_key.key_type() != libsignal_protocol::kem::KeyType::MLKEM1024
            {
                return Err("non-ML-KEM Signal pre-key rejected".to_string());
            }
            let serialized_public_key = public_key.serialize();
            let serialized_secret_key = Zeroizing::new(secret_key.serialize().into_vec());
            if serialized_public_key.len() != post_quantum::ML_KEM_PUBLIC_KEY_SIZE + 1
                || serialized_secret_key.len() != post_quantum::ML_KEM_SECRET_KEY_SIZE + 1
                || serialized_public_key[0] != serialized_secret_key[0]
            {
                return Err("invalid ML-KEM pre-key keypair".to_string());
            }
            post_quantum::validate_ml_kem_keypair(
                &serialized_public_key[1..],
                &serialized_secret_key[1..],
            )
            .map_err(|_| "ML-KEM pre-key keypair mismatch".to_string())?;
            if record
                .signature()
                .map_err(|_| "invalid ML-KEM pre-key signature".to_string())?
                .len()
                != SIGNAL_SIGNATURE_BYTES
            {
                return Err("invalid ML-KEM pre-key signature".to_string());
            }
            if loaded.insert(id.into(), record).is_some() {
                return Err("duplicate Kyber pre-key record".to_string());
            }
        }
        *self.kyber_pre_keys.write() = loaded;
        Ok(())
    }

    pub fn dump_replay_state(&self) -> Vec<(u32, u32, Vec<Vec<u8>>)> {
        self.base_keys_seen
            .read()
            .iter()
            .map(|((kyber_id, signed_id), keys)| {
                (
                    u32::from(*kyber_id),
                    u32::from(*signed_id),
                    keys.iter().cloned().collect(),
                )
            })
            .collect()
    }

    pub fn load_replay_state(&self, data: Vec<(u32, u32, Vec<Vec<u8>>)>) -> Result<(), String> {
        if data.len() > MAX_KYBER_REPLAY_PAIRS {
            return Err("Kyber replay-state pair limit exceeded".to_string());
        }

        let valid_kyber_ids = self
            .kyber_pre_keys
            .read()
            .keys()
            .copied()
            .collect::<HashSet<_>>();
        let mut loaded = HashMap::with_capacity(data.len());
        let mut total_keys = 0usize;

        for (kyber_id, signed_id, keys) in data {
            let kyber_id = KyberPreKeyId::from(kyber_id);
            if !valid_kyber_ids.contains(&kyber_id) {
                return Err("Kyber replay state references an unknown pre-key".to_string());
            }
            if keys.len() > MAX_BASE_KEYS_PER_KYBER_PAIR {
                return Err("Kyber replay-state key limit exceeded".to_string());
            }
            total_keys = total_keys
                .checked_add(keys.len())
                .ok_or_else(|| "Kyber replay-state size overflow".to_string())?;
            if total_keys > MAX_KYBER_REPLAY_KEYS {
                return Err("Kyber replay-state total key limit exceeded".to_string());
            }

            let mut valid_keys = HashSet::with_capacity(keys.len());
            for key in keys {
                libsignal_protocol::PublicKey::deserialize(&key)
                    .map_err(|_| "invalid Kyber replay-state public key".to_string())?;
                if !valid_keys.insert(key) {
                    return Err("duplicate Kyber replay-state public key".to_string());
                }
            }
            if loaded
                .insert((kyber_id, SignedPreKeyId::from(signed_id)), valid_keys)
                .is_some()
            {
                return Err("duplicate Kyber replay-state pair".to_string());
            }
        }
        *self.base_keys_seen.write() = loaded;
        self.base_key_count.store(total_keys, Ordering::Relaxed);
        Ok(())
    }
}

impl Default for InMemoryKyberPreKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl libsignal_protocol::KyberPreKeyStore for InMemoryKyberPreKeyStore {
    async fn get_kyber_pre_key(
        &self,
        id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, libsignal_protocol::SignalProtocolError> {
        InMemoryKyberPreKeyStore::get_kyber_pre_key(self, id)
            .ok_or(libsignal_protocol::SignalProtocolError::InvalidKyberPreKeyId)
    }

    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), libsignal_protocol::SignalProtocolError> {
        InMemoryKyberPreKeyStore::store_kyber_pre_key(self, id, record).map_err(|message| {
            libsignal_protocol::SignalProtocolError::InvalidState("KyberPreKeyStore", message)
        })
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        id: KyberPreKeyId,
        signed_id: SignedPreKeyId,
        public_key: &libsignal_protocol::PublicKey,
    ) -> Result<(), libsignal_protocol::SignalProtocolError> {
        let serialized = public_key.serialize().into_vec();
        let mut replay_state = self.base_keys_seen.write();
        let pair = (id, signed_id);
        if replay_state
            .get(&pair)
            .is_some_and(|base_keys| base_keys.contains(&serialized))
        {
            return Err(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "reused base key",
            ));
        }
        if !replay_state.contains_key(&pair) && replay_state.len() >= MAX_KYBER_REPLAY_PAIRS {
            return Err(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "last-resort key replay pair cache exhausted",
            ));
        }
        if self.base_key_count.load(Ordering::Relaxed) >= MAX_KYBER_REPLAY_KEYS {
            return Err(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "last-resort key replay cache exhausted",
            ));
        }
        let base_keys = replay_state.entry(pair).or_default();
        if base_keys.len() >= MAX_BASE_KEYS_PER_KYBER_PAIR {
            return Err(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "last-resort key replay cache exhausted",
            ));
        }
        if base_keys.insert(serialized) {
            self.base_key_count.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_protocol::{DeviceId, KeyPair};
    use rand::{SeedableRng, rngs::StdRng};

    fn address(name: &str) -> ProtocolAddress {
        ProtocolAddress::new(name.to_string(), DeviceId::try_from(1).unwrap())
    }

    #[test]
    fn session_load_replaces_the_existing_snapshot() {
        let store = InMemorySessionStore::new();
        let peer = address("peer");
        store.store_session(&peer, &SessionRecord::new_fresh());
        assert!(store.has_session(&peer));

        store.load(Vec::new()).unwrap();
        assert!(!store.has_session(&peer));
    }

    #[test]
    fn session_deletion_does_not_match_dotted_username_prefixes() {
        let store = InMemorySessionStore::new();
        let exact_peer = address("alice");
        let dotted_peer = address("alice.smith");
        store.store_session(&exact_peer, &SessionRecord::new_fresh());
        store.store_session(&dotted_peer, &SessionRecord::new_fresh());

        store.delete_all_sessions("alice");

        assert!(!store.has_session(&exact_peer));
        assert!(store.has_session(&dotted_peer));
    }

    #[test]
    fn malformed_session_snapshot_does_not_partially_replace_state() {
        let store = InMemorySessionStore::new();
        let peer = address("peer");
        store.store_session(&peer, &SessionRecord::new_fresh());

        assert!(
            store
                .load(vec![("attacker.1".to_string(), vec![0xff, 0x00])])
                .is_err()
        );
        assert!(store.has_session(&peer));
        assert!(!store.has_session(&address("attacker")));
    }

    #[test]
    fn duplicate_session_records_are_rejected_without_mutation() {
        let store = InMemorySessionStore::new();
        let existing = address("existing");
        store.store_session(&existing, &SessionRecord::new_fresh());
        let serialized = SessionRecord::new_fresh().serialize().unwrap();

        assert!(
            store
                .load(vec![
                    ("peer.1".to_string(), serialized.clone()),
                    ("peer.1".to_string(), serialized),
                ])
                .is_err()
        );
        assert!(store.has_session(&existing));
        assert!(!store.has_session(&address("peer")));
    }

    #[test]
    fn malformed_session_address_is_rejected_without_mutation() {
        let store = InMemorySessionStore::new();
        let existing = address("existing");
        store.store_session(&existing, &SessionRecord::new_fresh());
        let serialized = SessionRecord::new_fresh().serialize().unwrap();

        assert!(
            store
                .load(vec![("Peer.1".to_string(), serialized)])
                .is_err()
        );
        assert!(store.has_session(&existing));
    }

    #[test]
    fn identity_restore_rejects_a_mismatched_keypair_without_mutation() {
        let mut rng = StdRng::from_seed([29u8; 32]);
        let existing = IdentityKeyPair::generate(&mut rng);
        let mismatched = IdentityKeyPair::generate(&mut rng);
        let store = InMemoryIdentityKeyStore::new();
        store.set_identity_key_pair(existing);
        store.set_local_registration_id(7);

        let error = store
            .load(
                8,
                existing.identity_key().serialize().to_vec(),
                mismatched.private_key().serialize(),
                Vec::new(),
            )
            .expect_err("a mismatched local identity keypair must fail closed");
        assert!(error.contains("keypair mismatch"));
        assert_eq!(
            store
                .get_identity_key_pair()
                .expect("existing identity remains")
                .identity_key()
                .serialize(),
            existing.identity_key().serialize()
        );
        assert_eq!(store.get_local_registration_id(), Some(7));
    }

    #[test]
    fn signed_prekey_restore_binds_the_index_to_the_serialized_record_id() {
        let mut rng = StdRng::from_seed([31u8; 32]);
        let identity = IdentityKeyPair::generate(&mut rng);
        let key_pair = KeyPair::generate(&mut rng);
        let signature = identity
            .private_key()
            .calculate_signature(&key_pair.public_key.serialize(), &mut rng)
            .expect("signature");
        let record = SignedPreKeyRecord::new(
            SignedPreKeyId::from(4),
            libsignal_protocol::Timestamp::from_epoch_millis(1),
            &key_pair,
            &signature,
        );
        let store = InMemorySignedPreKeyStore::new();

        let error = store
            .load(vec![(5, record.serialize().expect("serialized pre-key"))])
            .expect_err("an index/record id mismatch must fail closed");
        assert!(error.contains("id mismatch"));
        assert!(store.get_any_signed_pre_key().is_none());
    }

    #[test]
    fn mlkem_prekey_restore_rejects_a_mismatched_public_private_pair() {
        let mut rng = StdRng::from_seed([37u8; 32]);
        let first = libsignal_protocol::kem::KeyPair::generate(
            libsignal_protocol::kem::KeyType::MLKEM1024,
            &mut rng,
        );
        let second = libsignal_protocol::kem::KeyPair::generate(
            libsignal_protocol::kem::KeyType::MLKEM1024,
            &mut rng,
        );
        let mismatched = libsignal_protocol::kem::KeyPair::new(first.public_key, second.secret_key);
        let record = KyberPreKeyRecord::new(
            KyberPreKeyId::from(9),
            libsignal_protocol::Timestamp::from_epoch_millis(1),
            &mismatched,
            &[0u8; SIGNAL_SIGNATURE_BYTES],
        );
        let store = InMemoryKyberPreKeyStore::new();

        let error = store
            .load(vec![(
                9,
                record.serialize().expect("serialized ML-KEM pre-key"),
            )])
            .expect_err("a mismatched ML-KEM keypair must fail closed");
        assert!(error.contains("keypair mismatch"));
        assert!(store.get_any_kyber_pre_key().is_none());
    }

    #[test]
    fn restored_prekey_signatures_are_bound_to_the_local_identity() {
        let mut rng = StdRng::from_seed([41u8; 32]);
        let expected_identity = IdentityKeyPair::generate(&mut rng);
        let wrong_identity = IdentityKeyPair::generate(&mut rng);

        let signed_pair = KeyPair::generate(&mut rng);
        let signed_signature = wrong_identity
            .private_key()
            .calculate_signature(&signed_pair.public_key.serialize(), &mut rng)
            .expect("signed pre-key signature");
        let signed_record = SignedPreKeyRecord::new(
            SignedPreKeyId::from(3),
            libsignal_protocol::Timestamp::from_epoch_millis(1),
            &signed_pair,
            &signed_signature,
        );
        let signed_store = InMemorySignedPreKeyStore::new();
        signed_store
            .load(vec![(
                3,
                signed_record.serialize().expect("signed pre-key"),
            )])
            .expect("structurally valid signed pre-key");
        assert!(
            signed_store
                .validate_signatures(expected_identity.identity_key())
                .is_err()
        );

        let mlkem_pair = libsignal_protocol::kem::KeyPair::generate(
            libsignal_protocol::kem::KeyType::MLKEM1024,
            &mut rng,
        );
        let mlkem_signature = wrong_identity
            .private_key()
            .calculate_signature(&mlkem_pair.public_key.serialize(), &mut rng)
            .expect("ML-KEM pre-key signature");
        let mlkem_record = KyberPreKeyRecord::new(
            KyberPreKeyId::from(4),
            libsignal_protocol::Timestamp::from_epoch_millis(1),
            &mlkem_pair,
            &mlkem_signature,
        );
        let mlkem_store = InMemoryKyberPreKeyStore::new();
        mlkem_store
            .load(vec![(4, mlkem_record.serialize().expect("ML-KEM pre-key"))])
            .expect("structurally valid ML-KEM pre-key");
        assert!(
            mlkem_store
                .validate_signatures(expected_identity.identity_key())
                .is_err()
        );
    }

    #[tokio::test]
    async fn live_session_store_rejects_new_peers_at_restore_limit() {
        let mut store = InMemorySessionStore::new();
        {
            let mut sessions = store.sessions.write();
            for index in 0..MAX_STORED_SIGNAL_RECORDS {
                sessions.insert(format!("peer{index}.1"), SessionRecord::new_fresh());
            }
        }

        let overflow = address("overflow");
        let error = libsignal_protocol::SessionStore::store_session(
            &mut store,
            &overflow,
            &SessionRecord::new_fresh(),
        )
        .await
        .expect_err("a live store must never outgrow its restorable snapshot");
        assert!(error.to_string().contains("record limit exceeded"));

        let existing = address("peer0");
        libsignal_protocol::SessionStore::store_session(
            &mut store,
            &existing,
            &SessionRecord::new_fresh(),
        )
        .await
        .expect("ratchet updates remain allowed at capacity");
    }

    #[tokio::test]
    async fn live_kyber_replay_state_obeys_persisted_global_limits() {
        let mut rng = StdRng::from_seed([17u8; 32]);
        let public_key = KeyPair::generate(&mut rng).public_key;

        let mut pair_limited = InMemoryKyberPreKeyStore::new();
        {
            let mut state = pair_limited.base_keys_seen.write();
            for index in 0..MAX_KYBER_REPLAY_PAIRS {
                state.insert(
                    (KyberPreKeyId::from(index as u32), SignedPreKeyId::from(1)),
                    HashSet::new(),
                );
            }
        }
        let pair_error = libsignal_protocol::KyberPreKeyStore::mark_kyber_pre_key_used(
            &mut pair_limited,
            KyberPreKeyId::from(MAX_KYBER_REPLAY_PAIRS as u32),
            SignedPreKeyId::from(1),
            &public_key,
        )
        .await
        .expect_err("live replay pairs must remain restorable");
        assert!(pair_error.to_string().contains("pair cache exhausted"));

        let mut total_limited = InMemoryKyberPreKeyStore::new();
        {
            let mut state = total_limited.base_keys_seen.write();
            let mut remaining = MAX_KYBER_REPLAY_KEYS;
            for pair_index in 0u32.. {
                if remaining == 0 {
                    break;
                }
                let count = remaining.min(MAX_BASE_KEYS_PER_KYBER_PAIR);
                let keys = (0..count)
                    .map(|key_index| {
                        let mut key = pair_index.to_be_bytes().to_vec();
                        key.extend_from_slice(&(key_index as u32).to_be_bytes());
                        key
                    })
                    .collect();
                state.insert(
                    (KyberPreKeyId::from(pair_index), SignedPreKeyId::from(1)),
                    keys,
                );
                remaining -= count;
            }
        }
        total_limited
            .base_key_count
            .store(MAX_KYBER_REPLAY_KEYS, Ordering::Relaxed);
        let total_error = libsignal_protocol::KyberPreKeyStore::mark_kyber_pre_key_used(
            &mut total_limited,
            KyberPreKeyId::from(6),
            SignedPreKeyId::from(1),
            &public_key,
        )
        .await
        .expect_err("live replay keys must remain restorable");
        assert!(total_error.to_string().contains("replay cache exhausted"));
    }
}
