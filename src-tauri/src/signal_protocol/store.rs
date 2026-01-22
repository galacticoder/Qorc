//! Signal Protocol Storage

use std::collections::HashMap;

use async_trait::async_trait;
use parking_lot::RwLock;
use libsignal_protocol::{
    Direction, IdentityKey, IdentityKeyPair, PreKeyId, PreKeyRecord,
    ProtocolAddress, SessionRecord, SignedPreKeyId, SignedPreKeyRecord,
    KyberPreKeyId, KyberPreKeyRecord, PrivateKey, GenericSignedPreKey,
};

// Session Store

/// In-memory session store
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
        self.sessions.read().get(&Self::session_key(address)).cloned()
    }

    pub fn store_session(&self, address: &ProtocolAddress, record: &SessionRecord) {
        self.sessions.write().insert(Self::session_key(address), record.clone());
    }

    pub fn delete_session(&self, address: &ProtocolAddress) {
        self.sessions.write().remove(&Self::session_key(address));
    }

    #[allow(dead_code)]
    pub fn has_session(&self, address: &ProtocolAddress) -> bool {
        self.sessions.read().contains_key(&Self::session_key(address))
    }

    pub fn dump(&self) -> Vec<(String, Vec<u8>)> {
        self.sessions.read().iter()
            .filter_map(|(k, v)| v.serialize().ok().map(|b| (k.clone(), b)))
            .collect()
    }

    pub fn load(&self, data: Vec<(String, Vec<u8>)>) {
        let mut sessions = self.sessions.write();
        for (k, v) in data {
            if let Ok(record) = SessionRecord::deserialize(&v) {
                sessions.insert(k, record);
            }
        }
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl libsignal_protocol::SessionStore for InMemorySessionStore {
    async fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>, libsignal_protocol::SignalProtocolError> {
        Ok(self.load_session(address))
    }

    async fn store_session(&mut self, address: &ProtocolAddress, record: &SessionRecord) -> Result<(), libsignal_protocol::SignalProtocolError> {
        InMemorySessionStore::store_session(self, address, record);
        Ok(())
    }
}

// Identity Key Store

/// In-memory identity key store
pub struct InMemoryIdentityKeyStore {
    identity_key_pair: RwLock<Option<IdentityKeyPair>>,
    registration_id: RwLock<Option<u32>>,
    known_identities: RwLock<HashMap<String, IdentityKey>>,
    trusted_identities: RwLock<std::collections::HashSet<String>>,
}

impl InMemoryIdentityKeyStore {
    pub fn new() -> Self {
        Self {
            identity_key_pair: RwLock::new(None),
            registration_id: RwLock::new(None),
            known_identities: RwLock::new(HashMap::new()),
            trusted_identities: RwLock::new(std::collections::HashSet::new()),
        }
    }

    pub fn get_identity_key_pair(&self) -> Option<IdentityKeyPair> {
        self.identity_key_pair.read().clone()
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

    pub fn save_identity(&self, address: &ProtocolAddress, identity: &IdentityKey) {
        self.known_identities.write().insert(address.name().to_string(), identity.clone());
    }

    pub fn get_identity(&self, name: &str) -> Option<IdentityKey> {
        self.known_identities.read().get(name).cloned()
    }

    pub fn trust_identity(&self, name: &str) {
        self.trusted_identities.write().insert(name.to_string());
    }

    pub fn is_trusted(&self, name: &str) -> bool {
        self.trusted_identities.read().contains(name)
    }

    pub fn dump(&self) -> Option<(u32, Vec<u8>, Vec<u8>, Vec<(String, Vec<u8>)>)> {
        let registration_id = self.registration_id.read().clone()?;
        let guard = self.identity_key_pair.read();
        let ikp = guard.as_ref()?;
        let identity_key = ikp.identity_key().serialize().to_vec();
        let private_key = ikp.private_key().serialize().to_vec();
        let known_identities = self.known_identities.read().iter()
            .map(|(k, v)| (k.clone(), v.serialize().to_vec()))
            .collect();
        Some((registration_id, identity_key, private_key, known_identities))
    }

    pub fn load(&self, registration_id: u32, identity_key_bytes: Vec<u8>, private_key_bytes: Vec<u8>, known_identities_data: Vec<(String, Vec<u8>)>) {
        *self.registration_id.write() = Some(registration_id);
        if let (Ok(ik), Ok(pk)) = (IdentityKey::decode(&identity_key_bytes), PrivateKey::deserialize(&private_key_bytes)) {
            *self.identity_key_pair.write() = Some(IdentityKeyPair::new(ik, pk));
        } else {
            log::warn!("[InMemoryIdentityKeyStore] Failed to decode identity key pair");
        }
        let mut known = self.known_identities.write();
        for (k, v) in known_identities_data {
            if let Ok(ik) = IdentityKey::decode(&v) {
                known.insert(k, ik);
            }
        }
    }
}

impl Default for InMemoryIdentityKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl libsignal_protocol::IdentityKeyStore for InMemoryIdentityKeyStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, libsignal_protocol::SignalProtocolError> {
        self.get_identity_key_pair()
            .ok_or(libsignal_protocol::SignalProtocolError::InvalidState(
                "IdentityKeyStore",
                "No identity key pair".to_string(),
            ))
    }

    async fn get_local_registration_id(&self) -> Result<u32, libsignal_protocol::SignalProtocolError> {
        self.get_local_registration_id()
            .ok_or(libsignal_protocol::SignalProtocolError::InvalidState(
                "IdentityKeyStore",
                "No registration ID".to_string(),
            ))
    }

    async fn save_identity(&mut self, address: &ProtocolAddress, identity: &IdentityKey) -> Result<libsignal_protocol::IdentityChange, libsignal_protocol::SignalProtocolError> {
        let existing = self.known_identities.read().get(address.name()).cloned();
        InMemoryIdentityKeyStore::save_identity(self, address, identity);
        
        let changed = existing.map_or(true, |known| &known != identity);
        Ok(libsignal_protocol::IdentityChange::from_changed(changed))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, libsignal_protocol::SignalProtocolError> {
        // If explicitly trusted then allow
        if self.is_trusted(address.name()) {
            return Ok(true);
        }
        
        // If no known identity then tofu
        let known = self.known_identities.read().get(address.name()).cloned();
        match known {
            None => Ok(true),
            Some(existing) => Ok(&existing == identity),
        }
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>, libsignal_protocol::SignalProtocolError> {
        Ok(InMemoryIdentityKeyStore::get_identity(self, address.name()))
    }
}

// Pre-Key Store

/// In-memory pre-key store
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

    pub fn dump(&self) -> Vec<(u32, Vec<u8>)> {
        self.pre_keys.read().iter()
            .filter_map(|(k, v)| v.serialize().ok().map(|b| (u32::from(*k), b)))
            .collect()
    }

    pub fn load(&self, data: Vec<(u32, Vec<u8>)>) {
        let mut pre_keys = self.pre_keys.write();
        for (k, v) in data {
            if let Ok(record) = PreKeyRecord::deserialize(&v) {
                pre_keys.insert(k.into(), record);
            }
        }
    }
}

impl Default for InMemoryPreKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl libsignal_protocol::PreKeyStore for InMemoryPreKeyStore {
    async fn get_pre_key(&self, id: PreKeyId) -> Result<PreKeyRecord, libsignal_protocol::SignalProtocolError> {
        InMemoryPreKeyStore::get_pre_key(self, id)
            .ok_or(libsignal_protocol::SignalProtocolError::InvalidPreKeyId)
    }

    async fn save_pre_key(&mut self, id: PreKeyId, record: &PreKeyRecord) -> Result<(), libsignal_protocol::SignalProtocolError> {
        InMemoryPreKeyStore::store_pre_key(self, id, record);
        Ok(())
    }

    async fn remove_pre_key(&mut self, id: PreKeyId) -> Result<(), libsignal_protocol::SignalProtocolError> {
        InMemoryPreKeyStore::remove_pre_key(self, id);
        Ok(())
    }
}

// Signed Pre-Key Store

/// In-memory signed pre-key store
pub struct InMemorySignedPreKeyStore {
    signed_pre_keys: RwLock<HashMap<SignedPreKeyId, SignedPreKeyRecord>>,
}

impl InMemorySignedPreKeyStore {
    pub fn new() -> Self {
        Self {
            signed_pre_keys: RwLock::new(HashMap::new()),
        }
    }

    pub fn store_signed_pre_key(&self, id: SignedPreKeyId, record: &SignedPreKeyRecord) {
        self.signed_pre_keys.write().insert(id, record.clone());
    }

    pub fn get_signed_pre_key(&self, id: SignedPreKeyId) -> Option<SignedPreKeyRecord> {
        self.signed_pre_keys.read().get(&id).cloned()
    }

    pub fn dump(&self) -> Vec<(u32, Vec<u8>)> {
        self.signed_pre_keys.read().iter()
            .filter_map(|(k, v)| v.serialize().ok().map(|b| (u32::from(*k), b)))
            .collect()
    }

    pub fn load(&self, data: Vec<(u32, Vec<u8>)>) {
        let mut signed_pre_keys = self.signed_pre_keys.write();
        for (k, v) in data {
            if let Ok(record) = SignedPreKeyRecord::deserialize(&v) {
                signed_pre_keys.insert(k.into(), record);
            }
        }
    }
}

impl Default for InMemorySignedPreKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl libsignal_protocol::SignedPreKeyStore for InMemorySignedPreKeyStore {
    async fn get_signed_pre_key(&self, id: SignedPreKeyId) -> Result<SignedPreKeyRecord, libsignal_protocol::SignalProtocolError> {
        InMemorySignedPreKeyStore::get_signed_pre_key(self, id)
            .ok_or(libsignal_protocol::SignalProtocolError::InvalidSignedPreKeyId)
    }

    async fn save_signed_pre_key(&mut self, id: SignedPreKeyId, record: &SignedPreKeyRecord) -> Result<(), libsignal_protocol::SignalProtocolError> {
        InMemorySignedPreKeyStore::store_signed_pre_key(self, id, record);
        Ok(())
    }
}

// Kyber Pre-Key Store

/// In-memory Kyber pre-key store
pub struct InMemoryKyberPreKeyStore {
    kyber_pre_keys: RwLock<HashMap<KyberPreKeyId, KyberPreKeyRecord>>,
    #[allow(dead_code)]
    used_kyber_pre_keys: RwLock<std::collections::HashSet<KyberPreKeyId>>,
}

impl InMemoryKyberPreKeyStore {
    pub fn new() -> Self {
        Self {
            kyber_pre_keys: RwLock::new(HashMap::new()),
            used_kyber_pre_keys: RwLock::new(std::collections::HashSet::new()),
        }
    }

    pub fn store_kyber_pre_key(&self, id: KyberPreKeyId, record: &KyberPreKeyRecord) {
        self.kyber_pre_keys.write().insert(id, record.clone());
    }

    pub fn get_kyber_pre_key(&self, id: KyberPreKeyId) -> Option<KyberPreKeyRecord> {
        self.kyber_pre_keys.read().get(&id).cloned()
    }

    #[allow(dead_code)]
    pub fn mark_kyber_pre_key_used(&self, id: KyberPreKeyId) {
        self.used_kyber_pre_keys.write().insert(id);
    }

    pub fn dump(&self) -> Vec<(u32, Vec<u8>)> {
        self.kyber_pre_keys.read().iter()
             .filter_map(|(k, v)| v.serialize().ok().map(|b| (u32::from(*k), b)))
            .collect()
    }

    pub fn load(&self, data: Vec<(u32, Vec<u8>)>) {
        let mut kyber_pre_keys = self.kyber_pre_keys.write();
        for (k, v) in data {
            if let Ok(record) = KyberPreKeyRecord::deserialize(&v) {
                kyber_pre_keys.insert(k.into(), record);
            }
        }
    }
}

impl Default for InMemoryKyberPreKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl libsignal_protocol::KyberPreKeyStore for InMemoryKyberPreKeyStore {
    async fn get_kyber_pre_key(&self, id: KyberPreKeyId) -> Result<KyberPreKeyRecord, libsignal_protocol::SignalProtocolError> {
        InMemoryKyberPreKeyStore::get_kyber_pre_key(self, id)
            .ok_or(libsignal_protocol::SignalProtocolError::InvalidKyberPreKeyId)
    }

    async fn save_kyber_pre_key(&mut self, id: KyberPreKeyId, record: &KyberPreKeyRecord) -> Result<(), libsignal_protocol::SignalProtocolError> {
        InMemoryKyberPreKeyStore::store_kyber_pre_key(self, id, record);
        Ok(())
    }

    async fn mark_kyber_pre_key_used(&mut self, _id: KyberPreKeyId, _signed_id: SignedPreKeyId, _public_key: &libsignal_protocol::PublicKey) -> Result<(), libsignal_protocol::SignalProtocolError> {
        Ok(())
    }
}
