//! Native ownership of account secrets

use std::sync::Arc;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use libcrux_ml_kem::mlkem1024;
use ml_dsa::{KeyExport, KeyInit as _, Keypair as _, MlDsa87, SigningKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::post_quantum;
use crate::error::{QorcError, QorcResult};
use crate::protocol_keys;
use crate::storage::SecureStorage;
use crate::storage_keys;

const VAULT_VERSION: u8 = 1;
const MASTER_BYTES: usize = 32;
const ML_KEM_SEED_BYTES: usize = 64;
const ML_DSA_SEED_BYTES: usize = 32;
const X25519_SECRET_BYTES: usize = 32;
const VAULT_SALT_BYTES: usize = 32;
const VAULT_NONCE_BYTES: usize = 24;
const VAULT_TAG_BYTES: usize = 16;
const ML_DSA_87_PUBLIC_BYTES: usize = 2592;
const MAX_VAULT_JSON_CHARS: usize = 24 * 1024;
const PAYLOAD_BYTES: usize = protocol_keys::ACCOUNT_VAULT_PAYLOAD_MAGIC.len()
    + MASTER_BYTES
    + ML_KEM_SEED_BYTES
    + ML_DSA_SEED_BYTES
    + X25519_SECRET_BYTES
    + ML_DSA_SEED_BYTES
    + ML_DSA_SEED_BYTES;
const MAX_CREDENTIAL_BYTES: usize = 4096;
const TOKEN_VAULT_VERSION: u8 = 1;
const TOKEN_VAULT_MAX_PLAINTEXT_BYTES: usize = 7 * 1024 * 1024;

const ARGON_MEMORY_KIB: u32 = 512 * 1024;
const ARGON_ITERATIONS: u32 = 6;
const ARGON_LANES: u32 = 4;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountPublicKeys {
    pub kyber_public_base64: String,
    pub dilithium_public_base64: String,
    pub x25519_public_base64: String,
    pub account_root_public_base64: String,
    pub recovery_public_base64: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedAccountVault {
    version: u8,
    account_owner: String,
    username: String,
    salt_base64: String,
    nonce_base64: String,
    ciphertext_base64: String,
    public_keys: AccountPublicKeys,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedTokenVault {
    version: u8,
    nonce_base64: String,
    ciphertext_base64: String,
}

pub struct AccountSession {
    account_owner: String,
    username: String,
    master_key: Zeroizing<[u8; MASTER_BYTES]>,
    ml_kem_seed: Zeroizing<[u8; ML_KEM_SEED_BYTES]>,
    device_ml_dsa_seed: Zeroizing<[u8; ML_DSA_SEED_BYTES]>,
    x25519_secret: Zeroizing<[u8; X25519_SECRET_BYTES]>,
    account_root_seed: Zeroizing<[u8; ML_DSA_SEED_BYTES]>,
    recovery_seed: Zeroizing<[u8; ML_DSA_SEED_BYTES]>,
    public_keys: AccountPublicKeys,
}

impl AccountSession {
    pub fn account_owner(&self) -> &str {
        &self.account_owner
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn public_keys(&self) -> AccountPublicKeys {
        self.public_keys.clone()
    }

    pub(crate) fn master_key(&self) -> &[u8; MASTER_BYTES] {
        &self.master_key
    }

    pub(crate) fn ml_kem_private_key(&self) -> Zeroizing<Vec<u8>> {
        let pair = mlkem1024::generate_key_pair(*self.ml_kem_seed);
        let bytes = Zeroizing::new(pair.private_key().as_ref().to_vec());
        drop(pair);
        bytes
    }

    pub(crate) fn ml_kem_decapsulate(&self, ciphertext: &[u8]) -> QorcResult<Zeroizing<Vec<u8>>> {
        let private_key = self.ml_kem_private_key();
        post_quantum::ml_kem_decapsulate(ciphertext, private_key.as_slice())
    }

    pub(crate) fn x25519_shared_secret(
        &self,
        peer_public: &[u8; X25519_SECRET_BYTES],
    ) -> QorcResult<Zeroizing<[u8; X25519_SECRET_BYTES]>> {
        let shared = x25519_dalek::x25519(*self.x25519_secret, *peer_public);
        if shared.iter().all(|byte| *byte == 0) {
            return Err(QorcError::Verification(
                "X25519 peer public key was rejected".to_string(),
            ));
        }
        Ok(Zeroizing::new(shared))
    }

    pub(crate) fn sign_device(&self, message: &[u8]) -> QorcResult<Vec<u8>> {
        sign_ml_dsa(&self.device_ml_dsa_seed, message)
    }

    pub(crate) fn sign_account_root(&self, message: &[u8]) -> QorcResult<Vec<u8>> {
        sign_ml_dsa(&self.account_root_seed, message)
    }

    pub(crate) fn sign_recovery(&self, message: &[u8]) -> QorcResult<Vec<u8>> {
        sign_ml_dsa(&self.recovery_seed, message)
    }

    fn token_vault_key(
        &self,
        server_scope: &str,
        vault_kind: &str,
    ) -> QorcResult<Zeroizing<[u8; 32]>> {
        if !valid_account_owner(server_scope) || !valid_token_vault_kind(vault_kind) {
            return Err(QorcError::InvalidArgument(
                "Invalid token-vault server scope".to_string(),
            ));
        }
        let mut transcript = Zeroizing::new(Vec::with_capacity(
            protocol_keys::TOKEN_VAULT_DOMAIN.len() + server_scope.len() + vault_kind.len() + 5,
        ));
        transcript.extend_from_slice(protocol_keys::TOKEN_VAULT_DOMAIN);
        transcript.extend_from_slice(protocol_keys::VAULT_KEY_PURPOSE);
        transcript.extend_from_slice(vault_kind.as_bytes());
        transcript.push(0);
        transcript.extend_from_slice(server_scope.as_bytes());
        Ok(Zeroizing::new(
            *blake3::keyed_hash(&*self.master_key, transcript.as_slice()).as_bytes(),
        ))
    }

    pub(crate) fn token_vault_storage_key(
        &self,
        server_scope: &str,
        vault_kind: &str,
    ) -> QorcResult<String> {
        if !valid_account_owner(server_scope) || !valid_token_vault_kind(vault_kind) {
            return Err(QorcError::InvalidArgument(
                "Invalid token-vault server scope".to_string(),
            ));
        }
        let mut transcript = Zeroizing::new(Vec::with_capacity(
            protocol_keys::TOKEN_VAULT_DOMAIN.len() + server_scope.len() + vault_kind.len() + 4,
        ));
        transcript.extend_from_slice(protocol_keys::TOKEN_VAULT_DOMAIN);
        transcript.extend_from_slice(protocol_keys::TOKEN_VAULT_ID_PURPOSE);
        transcript.extend_from_slice(vault_kind.as_bytes());
        transcript.push(0);
        transcript.extend_from_slice(server_scope.as_bytes());
        let id = blake3::keyed_hash(&*self.master_key, transcript.as_slice());
        Ok(format!(
            "{}{}",
            storage_keys::NATIVE_TOKEN_VAULT_PREFIX,
            hex::encode(id.as_bytes())
        ))
    }

    pub(crate) fn seal_token_vault(
        &self,
        server_scope: &str,
        vault_kind: &str,
        plaintext: &[u8],
    ) -> QorcResult<String> {
        if plaintext.len() > TOKEN_VAULT_MAX_PLAINTEXT_BYTES {
            return Err(QorcError::InvalidArgument(
                "Token vault exceeds its size limit".to_string(),
            ));
        }
        let key = self.token_vault_key(server_scope, vault_kind)?;
        let nonce = Zeroizing::new(crate::crypto::random::random_bytes(VAULT_NONCE_BYTES)?);
        let mut aad = Zeroizing::new(Vec::with_capacity(
            protocol_keys::TOKEN_VAULT_DOMAIN.len()
                + self.account_owner.len()
                + server_scope.len()
                + vault_kind.len()
                + 3,
        ));
        aad.extend_from_slice(protocol_keys::TOKEN_VAULT_DOMAIN);
        aad.extend_from_slice(self.account_owner.as_bytes());
        aad.push(0);
        aad.extend_from_slice(vault_kind.as_bytes());
        aad.push(0);
        aad.extend_from_slice(server_scope.as_bytes());
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| QorcError::EncryptionFailed("Token-vault key setup failed".to_string()))?;
        let ciphertext = Zeroizing::new(
            cipher
                .encrypt(
                    XNonce::from_slice(nonce.as_slice()),
                    Payload {
                        msg: plaintext,
                        aad: aad.as_slice(),
                    },
                )
                .map_err(|_| {
                    QorcError::EncryptionFailed("Token-vault encryption failed".to_string())
                })?,
        );
        serde_json::to_string(&PersistedTokenVault {
            version: TOKEN_VAULT_VERSION,
            nonce_base64: BASE64.encode(nonce.as_slice()),
            ciphertext_base64: BASE64.encode(ciphertext.as_slice()),
        })
        .map_err(|_| QorcError::EncryptionFailed("Token-vault encoding failed".to_string()))
    }

    pub(crate) fn open_token_vault(
        &self,
        server_scope: &str,
        vault_kind: &str,
        encoded: &str,
    ) -> QorcResult<Zeroizing<Vec<u8>>> {
        if encoded.len() > TOKEN_VAULT_MAX_PLAINTEXT_BYTES + 64 * 1024 {
            return Err(QorcError::InvalidArgument(
                "Token vault exceeds its size limit".to_string(),
            ));
        }
        crate::json_bounds::enforce_bounded_json_structure(
            encoded.as_bytes(),
            2,
            8,
            TOKEN_VAULT_MAX_PLAINTEXT_BYTES + 32 * 1024,
        )
        .map_err(|_| QorcError::DecryptionFailed("Invalid token-vault format".to_string()))?;
        let persisted: PersistedTokenVault = serde_json::from_str(encoded)
            .map_err(|_| QorcError::DecryptionFailed("Invalid token-vault format".to_string()))?;
        if persisted.version != TOKEN_VAULT_VERSION {
            return Err(QorcError::DecryptionFailed(
                "Unsupported token-vault version".to_string(),
            ));
        }
        let nonce =
            Zeroizing::new(BASE64.decode(&persisted.nonce_base64).map_err(|_| {
                QorcError::DecryptionFailed("Invalid token-vault nonce".to_string())
            })?);
        let ciphertext =
            Zeroizing::new(BASE64.decode(&persisted.ciphertext_base64).map_err(|_| {
                QorcError::DecryptionFailed("Invalid token-vault ciphertext".to_string())
            })?);
        if nonce.len() != VAULT_NONCE_BYTES
            || BASE64.encode(nonce.as_slice()) != persisted.nonce_base64
            || ciphertext.len() < VAULT_TAG_BYTES
            || ciphertext.len() > TOKEN_VAULT_MAX_PLAINTEXT_BYTES + VAULT_TAG_BYTES
            || BASE64.encode(ciphertext.as_slice()) != persisted.ciphertext_base64
        {
            return Err(QorcError::DecryptionFailed(
                "Invalid token-vault encoding".to_string(),
            ));
        }
        let key = self.token_vault_key(server_scope, vault_kind)?;
        let mut aad = Zeroizing::new(Vec::with_capacity(
            protocol_keys::TOKEN_VAULT_DOMAIN.len()
                + self.account_owner.len()
                + server_scope.len()
                + vault_kind.len()
                + 3,
        ));
        aad.extend_from_slice(protocol_keys::TOKEN_VAULT_DOMAIN);
        aad.extend_from_slice(self.account_owner.as_bytes());
        aad.push(0);
        aad.extend_from_slice(vault_kind.as_bytes());
        aad.push(0);
        aad.extend_from_slice(server_scope.as_bytes());
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| QorcError::DecryptionFailed("Token-vault key setup failed".to_string()))?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(nonce.as_slice()),
                    Payload {
                        msg: ciphertext.as_slice(),
                        aad: aad.as_slice(),
                    },
                )
                .map_err(|_| {
                    QorcError::DecryptionFailed("Token-vault authentication failed".to_string())
                })?,
        );
        if plaintext.len() > TOKEN_VAULT_MAX_PLAINTEXT_BYTES {
            return Err(QorcError::DecryptionFailed(
                "Token vault exceeds its size limit".to_string(),
            ));
        }
        Ok(plaintext)
    }

    pub(crate) fn discovery_publication_hex(
        &self,
        server_scope: &str,
        publication_window: u64,
        purpose: &str,
        counter: u16,
    ) -> QorcResult<String> {
        if !valid_account_owner(server_scope) || !matches!(purpose, "id" | "padding") {
            return Err(QorcError::InvalidArgument(
                "Invalid discovery publication context".to_string(),
            ));
        }
        let mut key_input = Zeroizing::new(Vec::with_capacity(40 + self.account_root_seed.len()));
        key_input.extend_from_slice(protocol_keys::DISCOVERY_PUBLICATION_KEY);
        key_input.extend_from_slice(self.account_root_seed.as_slice());
        let publication_key = Zeroizing::new(*blake3::hash(key_input.as_slice()).as_bytes());
        let transcript = Zeroizing::new(format!(
            "{}\0{server_scope}\0{publication_window}\0{purpose}\0{counter}",
            protocol_keys::DISCOVERY_PUBLICATION
        ));
        let digest = blake3::keyed_hash(&publication_key, transcript.as_bytes());
        Ok(hex::encode(digest.as_bytes()))
    }
}

fn sign_ml_dsa(seed: &[u8; ML_DSA_SEED_BYTES], message: &[u8]) -> QorcResult<Vec<u8>> {
    use ml_dsa::signature::{SignatureEncoding, Signer};

    let signing_key = SigningKey::<MlDsa87>::new_from_slice(seed)
        .map_err(|_| QorcError::EncryptionFailed("ML-DSA key initialization failed".to_string()))?;
    let signature = signing_key.sign(message);
    let bytes = signature.to_vec();
    drop(signing_key);
    Ok(bytes)
}

fn valid_account_owner(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_token_vault_kind(value: &str) -> bool {
    matches!(value, "working" | "resume")
}

fn valid_username(value: &str) -> bool {
    (3..=100).contains(&value.len())
        && value == value.trim().to_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn storage_key(account_owner: &str) -> QorcResult<String> {
    if !valid_account_owner(account_owner) {
        return Err(QorcError::InvalidArgument(
            "Invalid native account owner".to_string(),
        ));
    }
    Ok(format!(
        "{}{account_owner}",
        storage_keys::NATIVE_ACCOUNT_VAULT_PREFIX
    ))
}

fn put_len_prefixed(target: &mut Zeroizing<Vec<u8>>, value: &[u8]) -> QorcResult<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| QorcError::InvalidArgument("Credential input is too large".to_string()))?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

fn credential_input(
    username: &str,
    password: &str,
    passphrase: &str,
) -> QorcResult<Zeroizing<Vec<u8>>> {
    if !valid_username(username)
        || password.is_empty()
        || passphrase.is_empty()
        || password.len() > MAX_CREDENTIAL_BYTES
        || passphrase.len() > MAX_CREDENTIAL_BYTES
    {
        return Err(QorcError::InvalidArgument(
            "Invalid native account credentials".to_string(),
        ));
    }

    let mut input = Zeroizing::new(Vec::with_capacity(
        protocol_keys::ACCOUNT_VAULT_UNLOCK_DOMAIN.len()
            + username.len()
            + password.len()
            + passphrase.len()
            + 12,
    ));
    input.extend_from_slice(protocol_keys::ACCOUNT_VAULT_UNLOCK_DOMAIN);
    put_len_prefixed(&mut input, username.as_bytes())?;
    put_len_prefixed(&mut input, password.as_bytes())?;
    put_len_prefixed(&mut input, passphrase.as_bytes())?;
    Ok(input)
}

fn derive_unlock_key(
    input: &[u8],
    salt: &[u8; VAULT_SALT_BYTES],
) -> QorcResult<Zeroizing<[u8; 32]>> {
    let params = Params::new(ARGON_MEMORY_KIB, ARGON_ITERATIONS, ARGON_LANES, Some(32))
        .map_err(|_| QorcError::EncryptionFailed("Native account KDF setup failed".to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(input, salt, output.as_mut())
        .map_err(|_| QorcError::EncryptionFailed("Native account KDF failed".to_string()))?;
    Ok(output)
}

fn public_keys_from_seeds(
    ml_kem_seed: &[u8; ML_KEM_SEED_BYTES],
    device_seed: &[u8; ML_DSA_SEED_BYTES],
    x25519_secret: &[u8; X25519_SECRET_BYTES],
    account_root_seed: &[u8; ML_DSA_SEED_BYTES],
    recovery_seed: &[u8; ML_DSA_SEED_BYTES],
) -> QorcResult<AccountPublicKeys> {
    let kem_pair = mlkem1024::generate_key_pair(*ml_kem_seed);
    let device_key = SigningKey::<MlDsa87>::new_from_slice(device_seed)
        .map_err(|_| QorcError::EncryptionFailed("ML-DSA key initialization failed".to_string()))?;
    let root_key = SigningKey::<MlDsa87>::new_from_slice(account_root_seed)
        .map_err(|_| QorcError::EncryptionFailed("ML-DSA key initialization failed".to_string()))?;
    let recovery_key = SigningKey::<MlDsa87>::new_from_slice(recovery_seed)
        .map_err(|_| QorcError::EncryptionFailed("ML-DSA key initialization failed".to_string()))?;
    let x25519_public = x25519_dalek::x25519(*x25519_secret, x25519_dalek::X25519_BASEPOINT_BYTES);

    let public = AccountPublicKeys {
        kyber_public_base64: BASE64.encode(kem_pair.public_key().as_ref()),
        dilithium_public_base64: BASE64.encode(device_key.verifying_key().to_bytes()),
        x25519_public_base64: BASE64.encode(x25519_public),
        account_root_public_base64: BASE64.encode(root_key.verifying_key().to_bytes()),
        recovery_public_base64: BASE64.encode(recovery_key.verifying_key().to_bytes()),
    };
    drop(kem_pair);
    drop(device_key);
    drop(root_key);
    drop(recovery_key);
    Ok(public)
}

fn validate_public_keys(keys: &AccountPublicKeys) -> QorcResult<()> {
    let mut kem = decode_exact::<{ post_quantum::ML_KEM_PUBLIC_KEY_SIZE }>(
        &keys.kyber_public_base64,
        "native ML-KEM public key",
    )?;
    let mut device = decode_exact::<ML_DSA_87_PUBLIC_BYTES>(
        &keys.dilithium_public_base64,
        "native device ML-DSA public key",
    )?;
    let mut x25519 = decode_exact::<X25519_SECRET_BYTES>(
        &keys.x25519_public_base64,
        "native X25519 public key",
    )?;
    let mut root = decode_exact::<ML_DSA_87_PUBLIC_BYTES>(
        &keys.account_root_public_base64,
        "native account-root ML-DSA public key",
    )?;
    let mut recovery = decode_exact::<ML_DSA_87_PUBLIC_BYTES>(
        &keys.recovery_public_base64,
        "native recovery ML-DSA public key",
    )?;
    let result = if device == root || device == recovery || root == recovery {
        Err(QorcError::Verification(
            "Native signing roles must use distinct keys".to_string(),
        ))
    } else {
        Ok(())
    };
    kem.zeroize();
    device.zeroize();
    x25519.zeroize();
    root.zeroize();
    recovery.zeroize();
    result
}

fn vault_aad(
    account_owner: &str,
    username: &str,
    public_keys: &AccountPublicKeys,
) -> Zeroizing<Vec<u8>> {
    let mut aad = Zeroizing::new(Vec::with_capacity(
        protocol_keys::ACCOUNT_VAULT_DOMAIN.len()
            + account_owner.len()
            + username.len()
            + public_keys.kyber_public_base64.len()
            + public_keys.dilithium_public_base64.len()
            + public_keys.x25519_public_base64.len()
            + public_keys.account_root_public_base64.len()
            + public_keys.recovery_public_base64.len()
            + 7,
    ));
    aad.extend_from_slice(protocol_keys::ACCOUNT_VAULT_DOMAIN);
    for value in [
        account_owner,
        username,
        &public_keys.kyber_public_base64,
        &public_keys.dilithium_public_base64,
        &public_keys.x25519_public_base64,
        &public_keys.account_root_public_base64,
        &public_keys.recovery_public_base64,
    ] {
        aad.extend_from_slice(value.as_bytes());
        aad.push(0);
    }
    aad
}

fn decode_exact<const N: usize>(value: &str, label: &str) -> QorcResult<[u8; N]> {
    let mut decoded = BASE64
        .decode(value)
        .map_err(|_| QorcError::DecryptionFailed(format!("Invalid {label}")))?;
    if decoded.len() != N || BASE64.encode(&decoded) != value {
        decoded.zeroize();
        return Err(QorcError::DecryptionFailed(format!("Invalid {label}")));
    }
    let mut output = [0u8; N];
    output.copy_from_slice(&decoded);
    decoded.zeroize();
    Ok(output)
}

fn encode_payload(
    master_key: &[u8; MASTER_BYTES],
    ml_kem_seed: &[u8; ML_KEM_SEED_BYTES],
    device_seed: &[u8; ML_DSA_SEED_BYTES],
    x25519_secret: &[u8; X25519_SECRET_BYTES],
    account_root_seed: &[u8; ML_DSA_SEED_BYTES],
    recovery_seed: &[u8; ML_DSA_SEED_BYTES],
) -> Zeroizing<Vec<u8>> {
    let mut payload = Zeroizing::new(Vec::with_capacity(PAYLOAD_BYTES));
    payload.extend_from_slice(protocol_keys::ACCOUNT_VAULT_PAYLOAD_MAGIC);
    payload.extend_from_slice(master_key);
    payload.extend_from_slice(ml_kem_seed);
    payload.extend_from_slice(device_seed);
    payload.extend_from_slice(x25519_secret);
    payload.extend_from_slice(account_root_seed);
    payload.extend_from_slice(recovery_seed);
    payload
}

fn decode_payload(
    payload: &[u8],
) -> QorcResult<(
    Zeroizing<[u8; MASTER_BYTES]>,
    Zeroizing<[u8; ML_KEM_SEED_BYTES]>,
    Zeroizing<[u8; ML_DSA_SEED_BYTES]>,
    Zeroizing<[u8; X25519_SECRET_BYTES]>,
    Zeroizing<[u8; ML_DSA_SEED_BYTES]>,
    Zeroizing<[u8; ML_DSA_SEED_BYTES]>,
)> {
    if payload.len() != PAYLOAD_BYTES
        || &payload[..protocol_keys::ACCOUNT_VAULT_PAYLOAD_MAGIC.len()]
            != protocol_keys::ACCOUNT_VAULT_PAYLOAD_MAGIC
    {
        return Err(QorcError::DecryptionFailed(
            "Invalid native account vault payload".to_string(),
        ));
    }
    let mut offset = protocol_keys::ACCOUNT_VAULT_PAYLOAD_MAGIC.len();
    macro_rules! take {
        ($size:expr) => {{
            let mut output = [0u8; $size];
            output.copy_from_slice(&payload[offset..offset + $size]);
            offset += $size;
            Zeroizing::new(output)
        }};
    }
    let result = (
        take!(MASTER_BYTES),
        take!(ML_KEM_SEED_BYTES),
        take!(ML_DSA_SEED_BYTES),
        take!(X25519_SECRET_BYTES),
        take!(ML_DSA_SEED_BYTES),
        take!(ML_DSA_SEED_BYTES),
    );
    debug_assert_eq!(offset, PAYLOAD_BYTES);
    Ok(result)
}

fn session_from_payload(
    account_owner: String,
    username: String,
    payload: &[u8],
    expected_public: &AccountPublicKeys,
) -> QorcResult<Arc<AccountSession>> {
    let (master_key, ml_kem_seed, device_seed, x25519_secret, account_root_seed, recovery_seed) =
        decode_payload(payload)?;
    let derived_public = public_keys_from_seeds(
        &ml_kem_seed,
        &device_seed,
        &x25519_secret,
        &account_root_seed,
        &recovery_seed,
    )?;
    if &derived_public != expected_public {
        return Err(QorcError::Verification(
            "Native account public/private key binding failed".to_string(),
        ));
    }
    Ok(Arc::new(AccountSession {
        account_owner,
        username,
        master_key,
        ml_kem_seed,
        device_ml_dsa_seed: device_seed,
        x25519_secret,
        account_root_seed,
        recovery_seed,
        public_keys: derived_public,
    }))
}

pub async fn create(
    storage: Arc<SecureStorage>,
    account_owner: String,
    username: String,
    password: Zeroizing<String>,
    passphrase: Zeroizing<String>,
) -> QorcResult<Arc<AccountSession>> {
    let key = storage_key(&account_owner)?;
    if storage.has(&key).await? {
        return Err(QorcError::InvalidArgument(
            "Native account vault already exists".to_string(),
        ));
    }
    if !valid_username(&username) {
        return Err(QorcError::InvalidArgument(
            "Invalid native account username".to_string(),
        ));
    }

    let credential_bytes = credential_input(&username, &password, &passphrase)?;
    let mut salt = Zeroizing::new([0u8; VAULT_SALT_BYTES]);
    let mut nonce = Zeroizing::new([0u8; VAULT_NONCE_BYTES]);
    let mut master_key = Zeroizing::new([0u8; MASTER_BYTES]);
    let mut ml_kem_seed = Zeroizing::new([0u8; ML_KEM_SEED_BYTES]);
    let mut device_seed = Zeroizing::new([0u8; ML_DSA_SEED_BYTES]);
    let mut x25519_secret = Zeroizing::new([0u8; X25519_SECRET_BYTES]);
    let mut account_root_seed = Zeroizing::new([0u8; ML_DSA_SEED_BYTES]);
    let mut recovery_seed = Zeroizing::new([0u8; ML_DSA_SEED_BYTES]);
    for target in [
        salt.as_mut_slice(),
        nonce.as_mut_slice(),
        master_key.as_mut_slice(),
        ml_kem_seed.as_mut_slice(),
        device_seed.as_mut_slice(),
        x25519_secret.as_mut_slice(),
        account_root_seed.as_mut_slice(),
        recovery_seed.as_mut_slice(),
    ] {
        getrandom::fill(target)
            .map_err(|_| QorcError::EncryptionFailed("Secure randomness failed".to_string()))?;
    }

    let public_keys = public_keys_from_seeds(
        &ml_kem_seed,
        &device_seed,
        &x25519_secret,
        &account_root_seed,
        &recovery_seed,
    )?;
    let aad = vault_aad(&account_owner, &username, &public_keys);
    let payload = encode_payload(
        &master_key,
        &ml_kem_seed,
        &device_seed,
        &x25519_secret,
        &account_root_seed,
        &recovery_seed,
    );
    let salt_for_kdf = *salt;
    let input_for_kdf = Zeroizing::new(credential_bytes.to_vec());
    let unlock_key =
        tokio::task::spawn_blocking(move || derive_unlock_key(&input_for_kdf, &salt_for_kdf))
            .await
            .map_err(|_| {
                QorcError::EncryptionFailed("Native account KDF task failed".to_string())
            })??;
    let cipher = XChaCha20Poly1305::new_from_slice(unlock_key.as_slice())
        .map_err(|_| QorcError::EncryptionFailed("Native vault key setup failed".to_string()))?;
    let ciphertext = Zeroizing::new(
        cipher
            .encrypt(
                XNonce::from_slice(nonce.as_slice()),
                Payload {
                    msg: payload.as_slice(),
                    aad: aad.as_slice(),
                },
            )
            .map_err(|_| {
                QorcError::EncryptionFailed("Native vault encryption failed".to_string())
            })?,
    );

    let persisted = PersistedAccountVault {
        version: VAULT_VERSION,
        account_owner: account_owner.clone(),
        username: username.clone(),
        salt_base64: BASE64.encode(salt.as_slice()),
        nonce_base64: BASE64.encode(nonce.as_slice()),
        ciphertext_base64: BASE64.encode(ciphertext.as_slice()),
        public_keys: public_keys.clone(),
    };
    let serialized = Zeroizing::new(serde_json::to_string(&persisted).map_err(|_| {
        QorcError::EncryptionFailed("Native vault serialization failed".to_string())
    })?);
    storage.set(&key, &serialized).await?;
    let verified = storage.get(&key).await?.ok_or_else(|| {
        QorcError::StorageInitFailed("Native vault persistence failed".to_string())
    })?;
    if verified != *serialized {
        return Err(QorcError::StorageInitFailed(
            "Native vault persistence verification failed".to_string(),
        ));
    }

    session_from_payload(account_owner, username, payload.as_slice(), &public_keys)
}

pub async fn unlock(
    storage: Arc<SecureStorage>,
    account_owner: String,
    username: String,
    password: Zeroizing<String>,
    passphrase: Zeroizing<String>,
) -> QorcResult<Arc<AccountSession>> {
    let key = storage_key(&account_owner)?;
    let raw = Zeroizing::new(storage.get(&key).await?.ok_or_else(|| {
        QorcError::DecryptionFailed("Native account vault is unavailable".to_string())
    })?);
    if raw.is_empty() || raw.len() > MAX_VAULT_JSON_CHARS {
        return Err(QorcError::DecryptionFailed(
            "Invalid native account vault".to_string(),
        ));
    }
    let persisted: PersistedAccountVault = serde_json::from_str(&raw)
        .map_err(|_| QorcError::DecryptionFailed("Invalid native account vault".to_string()))?;
    if persisted.version != VAULT_VERSION
        || persisted.account_owner != account_owner
        || persisted.username != username
        || !valid_username(&persisted.username)
    {
        return Err(QorcError::DecryptionFailed(
            "Invalid native account vault".to_string(),
        ));
    }
    validate_public_keys(&persisted.public_keys)?;

    let credential_bytes = credential_input(&username, &password, &passphrase)?;
    let salt = Zeroizing::new(decode_exact::<VAULT_SALT_BYTES>(
        &persisted.salt_base64,
        "native vault salt",
    )?);
    let nonce = Zeroizing::new(decode_exact::<VAULT_NONCE_BYTES>(
        &persisted.nonce_base64,
        "native vault nonce",
    )?);
    let mut ciphertext =
        Zeroizing::new(BASE64.decode(&persisted.ciphertext_base64).map_err(|_| {
            QorcError::DecryptionFailed("Invalid native vault ciphertext".to_string())
        })?);
    if ciphertext.len() != PAYLOAD_BYTES + VAULT_TAG_BYTES
        || BASE64.encode(ciphertext.as_slice()) != persisted.ciphertext_base64
    {
        ciphertext.zeroize();
        return Err(QorcError::DecryptionFailed(
            "Invalid native vault ciphertext".to_string(),
        ));
    }
    let aad = vault_aad(&account_owner, &username, &persisted.public_keys);
    let salt_for_kdf = *salt;
    let input_for_kdf = Zeroizing::new(credential_bytes.to_vec());
    let unlock_key =
        tokio::task::spawn_blocking(move || derive_unlock_key(&input_for_kdf, &salt_for_kdf))
            .await
            .map_err(|_| {
                QorcError::DecryptionFailed("Native account KDF task failed".to_string())
            })??;
    let cipher = XChaCha20Poly1305::new_from_slice(unlock_key.as_slice())
        .map_err(|_| QorcError::DecryptionFailed("Native vault key setup failed".to_string()))?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(nonce.as_slice()),
                Payload {
                    msg: ciphertext.as_slice(),
                    aad: aad.as_slice(),
                },
            )
            .map_err(|_| QorcError::DecryptionFailed("Incorrect account credentials".to_string()))?,
    );
    session_from_payload(
        account_owner,
        username,
        plaintext.as_slice(),
        &persisted.public_keys,
    )
}

pub async fn exists(storage: &SecureStorage, account_owner: &str) -> QorcResult<bool> {
    storage.has(&storage_key(account_owner)?).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_owner_and_username_are_canonical() {
        assert!(valid_account_owner(&"a".repeat(64)));
        assert!(!valid_account_owner(&"A".repeat(64)));
        assert!(valid_username("alice.test-1"));
        assert!(!valid_username("Alice"));
        assert!(!valid_username("a"));
    }

    #[test]
    fn credential_encoding_is_unambiguous() {
        let first = credential_input("alice", "a\0b", "c").unwrap();
        let second = credential_input("alice", "a", "b\0c").unwrap();
        assert_ne!(first.as_slice(), second.as_slice());
    }
}
