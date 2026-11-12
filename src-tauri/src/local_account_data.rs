use crate::{account_vault::AccountSession, state::AppState, storage::SecureStorage};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use tauri::State;

const PREFIX: &str = "native-local-account-data:";
const PENDING_KEY: &str = "native-pending-local-account-deletions";
const MAX_KEYS: usize = 32_768;
const CACHE_PREFIXES: &[&str] = &[
    "kt-authorizations:",
    "kt-contact:",
    "kt-monitors:",
    "kt-records:",
    "kt-warnings:",
    "peercert:",
    "spoolconsumed:",
    "spooldet:",
    "spoolpeerdet:",
    "discmat:",
];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountStorageOwnership {
    account_owner: String,
    domain: String,
    parts: Vec<String>,
}

fn valid_ownership(
    key: &str,
    ownership: &AccountStorageOwnership,
    session: &AccountSession,
) -> bool {
    let domains = [
        (
            "kt-authorizations:",
            "qorc-key-transparency-authorization-storage",
        ),
        ("kt-contact:", "qorc-kt-contact-storage"),
        ("kt-monitors:", "qorc-key-transparency-monitor-storage"),
        ("kt-records:", "qorc-key-transparency-record-storage"),
        ("kt-warnings:", "qorc-key-transparency-warning-storage"),
        ("peercert:", "qorc-peer-certificate-cache"),
        ("spoolconsumed:", "qorc-spool-consumed-probes"),
        ("spooldet:", "qorc-spool-detection-key"),
        ("spoolpeerdet:", "qorc-spool-peer-detection"),
        ("discmat:", "qorc-discovery-material-cache"),
    ];
    if ownership.account_owner != session.account_owner()
        || ownership.parts.len() > 4
        || ownership
            .parts
            .iter()
            .any(|part| part.len() > 256 || part.contains('\0'))
    {
        return false;
    }
    let parts = ownership
        .parts
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    domains.iter().any(|(prefix, domain)| {
        ownership.domain == *domain
            && scoped(prefix, domain, session.account_owner(), &parts) == key
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    version: u8,
    owner: String,
    database_id: String,
    keys: BTreeSet<String>,
    deleting: bool,
}

fn hex_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn is_account_cache_key(key: &str) -> bool {
    CACHE_PREFIXES
        .iter()
        .any(|prefix| key.strip_prefix(prefix).is_some_and(hex_id))
}

fn inventory_key(owner: &str) -> Result<String, String> {
    if !hex_id(owner) {
        return Err("Invalid local account owner".into());
    }
    Ok(format!("{PREFIX}{owner}"))
}

fn scoped(prefix: &str, domain: &str, owner: &str, parts: &[&str]) -> String {
    if prefix.starts_with("kt-") {
        let mut hasher = Sha3_512::new();
        hasher.update(domain.as_bytes());
        hasher.update(b"\0");
        hasher.update(owner.as_bytes());
        for part in parts {
            hasher.update(b"\0");
            hasher.update(part.as_bytes());
        }
        return format!("{prefix}{}", hex::encode(&hasher.finalize()[..32]));
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(b"\0");
    hasher.update(owner.as_bytes());
    for part in parts {
        hasher.update(b"\0");
        hasher.update(part.as_bytes());
    }
    format!("{prefix}{}", blake3::Hasher::finalize(&hasher).to_hex())
}

async fn load(storage: &SecureStorage, owner: &str) -> Result<Option<Inventory>, String> {
    let Some(raw) = storage
        .get_text(&inventory_key(owner)?)
        .await
        .map_err(|error| error.safe_message())?
    else {
        return Ok(None);
    };
    let inventory: Inventory =
        serde_json::from_str(&raw).map_err(|_| "Local account inventory is invalid")?;
    if inventory.version != 1
        || inventory.owner != owner
        || !hex_id(&inventory.database_id)
        || inventory.keys.len() > MAX_KEYS
        || inventory.keys.iter().any(|key| !valid_inventory_entry(key))
    {
        return Err("Local account inventory is invalid".into());
    }
    Ok(Some(inventory))
}

fn valid_inventory_entry(key: &str) -> bool {
    is_account_cache_key(key)
        || [
            "native-token-vault:",
            "private_auth_slot_",
            "registration_attempt_",
            "last-auth-user:",
            "last-auth-display:",
        ]
        .iter()
        .any(|prefix| key.strip_prefix(prefix).is_some_and(hex_id))
}

async fn save(storage: &SecureStorage, inventory: &Inventory) -> Result<(), String> {
    if inventory.keys.len() > MAX_KEYS {
        return Err("Account inventory limit exceeded".into());
    }
    let encoded = serde_json::to_string(inventory)
        .map_err(|_| "Local account inventory could not be encoded")?;
    storage
        .set_text(&inventory_key(&inventory.owner)?, &encoded)
        .await
        .map_err(|error| error.safe_message())
}

async fn pending(storage: &SecureStorage) -> Result<BTreeMap<String, Inventory>, String> {
    let Some(raw) = storage
        .get_text(PENDING_KEY)
        .await
        .map_err(|error| error.safe_message())?
    else {
        return Ok(BTreeMap::new());
    };
    let entries: BTreeMap<String, Inventory> =
        serde_json::from_str(&raw).map_err(|_| "Local deletion journal is invalid")?;
    if entries.len() > 256
        || entries
            .values()
            .map(|entry| entry.keys.len())
            .sum::<usize>()
            > MAX_KEYS
        || entries.iter().any(|(owner, entry)| {
            !hex_id(owner)
                || owner != &entry.owner
                || entry.version != 1
                || !entry.deleting
                || !hex_id(&entry.database_id)
                || entry.keys.iter().any(|key| !valid_inventory_entry(key))
        })
    {
        return Err("Local deletion journal is invalid".into());
    }
    Ok(entries)
}

async fn save_pending(storage: &SecureStorage, inventory: &Inventory) -> Result<(), String> {
    let mut entries = pending(storage).await?;
    entries.insert(
        inventory.owner.clone(),
        Inventory {
            version: inventory.version,
            owner: inventory.owner.clone(),
            database_id: inventory.database_id.clone(),
            keys: inventory.keys.clone(),
            deleting: true,
        },
    );
    if entries.len() > 256
        || entries
            .values()
            .map(|entry| entry.keys.len())
            .sum::<usize>()
            > MAX_KEYS
    {
        return Err("Local deletion journal is full".into());
    }
    let raw = serde_json::to_string(&entries)
        .map_err(|_| "Local deletion journal could not be encoded")?;
    storage
        .set_text(PENDING_KEY, &raw)
        .await
        .map_err(|error| error.safe_message())
}

async fn forget_pending(storage: &SecureStorage, owner: &str) -> Result<(), String> {
    let mut entries = pending(storage).await?;
    entries.remove(owner);
    if entries.is_empty() {
        return storage
            .remove_item(PENDING_KEY)
            .await
            .map_err(|error| error.safe_message());
    }
    storage
        .set_text(
            PENDING_KEY,
            &serde_json::to_string(&entries)
                .map_err(|_| "Local deletion journal could not be encoded")?,
        )
        .await
        .map_err(|error| error.safe_message())
}

pub(crate) async fn ensure_session(
    storage: &SecureStorage,
    session: &AccountSession,
) -> Result<(), String> {
    if pending(storage)
        .await?
        .contains_key(session.account_owner())
    {
        return Err("Local account deletion is pending".into());
    }
    let expected = crate::database::account_file_id(session.master_key(), session.account_owner());
    if let Some(inventory) = load(storage, session.account_owner()).await? {
        if inventory.deleting || inventory.database_id != expected {
            return Err("Local account deletion must finish before this account can open".into());
        }
    } else {
        save(
            storage,
            &Inventory {
                version: 1,
                owner: session.account_owner().into(),
                database_id: expected,
                keys: BTreeSet::new(),
                deleting: false,
            },
        )
        .await?;
    }
    Ok(())
}

pub(crate) async fn record_key(
    storage: &SecureStorage,
    session: &AccountSession,
    key: &str,
) -> Result<(), String> {
    if pending(storage)
        .await?
        .contains_key(session.account_owner())
    {
        return Err("Local account deletion is pending".into());
    }
    if !valid_inventory_entry(key) {
        return Err("Invalid account-owned storage key".into());
    }
    let mut inventory = load(storage, session.account_owner())
        .await?
        .unwrap_or_else(|| Inventory {
            version: 1,
            owner: session.account_owner().into(),
            database_id: crate::database::account_file_id(
                session.master_key(),
                session.account_owner(),
            ),
            keys: BTreeSet::new(),
            deleting: false,
        });
    if inventory.deleting {
        return Err("Local account deletion is pending".into());
    }
    if inventory.keys.insert(key.into()) {
        save(storage, &inventory).await?;
    }
    Ok(())
}

pub(crate) async fn cache_guard(
    state: &AppState,
    key: &str,
    ownership: Option<&AccountStorageOwnership>,
) -> Result<Option<tokio::sync::OwnedMutexGuard<()>>, String> {
    if !is_account_cache_key(key) {
        return Ok(None);
    }
    let session = state.account_session().ok_or("Native account is locked")?;
    if !ownership.is_some_and(|ownership| valid_ownership(key, ownership, session.as_ref())) {
        return Err("Storage selector does not belong to the unlocked account".into());
    }
    let guard = state.database_lifecycle_lock.clone().lock_owned().await;
    if !state
        .account_session()
        .is_some_and(|current| Arc::ptr_eq(&current, &session))
    {
        return Err("Native account changed during storage operation".into());
    }
    let storage = state.storage().ok_or("Storage not initialized")?;
    record_key(storage.as_ref(), session.as_ref(), key).await?;
    Ok(Some(guard))
}

async fn include_account_credentials(
    storage: &SecureStorage,
    session: &AccountSession,
    server_scope: &str,
    inventory: &mut Inventory,
) -> Result<(), String> {
    if !hex_id(server_scope)
        || scoped(
            "",
            "qorc-local-account-scope",
            server_scope,
            &[session.username()],
        ) != session.account_owner()
    {
        return Err("Account server scope does not match the unlocked account".into());
    }
    let auth_id = scoped(
        "",
        "qorc-private-auth-slot",
        server_scope,
        &[session.username()],
    );
    for prefix in ["private_auth_slot_", "registration_attempt_"] {
        inventory.keys.insert(format!("{prefix}{auth_id}"));
    }
    for kind in ["working", "resume"] {
        inventory.keys.insert(
            session
                .token_vault_storage_key(server_scope, kind)
                .map_err(|error| error.safe_message())?,
        );
    }
    let last_user = format!("last-auth-user:{server_scope}");
    if storage
        .get_text(&last_user)
        .await
        .map_err(|error| error.safe_message())?
        .as_deref()
        == Some(session.username())
    {
        inventory.keys.insert(last_user);
        inventory
            .keys
            .insert(format!("last-auth-display:{server_scope}"));
    }
    Ok(())
}

async fn finish(storage: &SecureStorage, inventory: &Inventory) -> Result<(), String> {
    if !inventory.deleting {
        return Err("Local account deletion was not confirmed".into());
    }
    for key in &inventory.keys {
        storage
            .remove_item(key)
            .await
            .map_err(|error| error.safe_message())?;
        if storage
            .has(key)
            .await
            .map_err(|error| error.safe_message())?
        {
            return Err("Local record deletion could not be verified".into());
        }
    }
    let path = storage
        .config_dir()
        .join(format!("qorc_{}.db", inventory.database_id));
    for suffix in ["-wal", "-shm", "-journal", ""] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let path = std::path::PathBuf::from(name);
        match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) => {
                crate::storage::file::validate_private_file_metadata(&metadata)
                    .map_err(|error| error.safe_message())?;
                crate::storage::file::remove_file(&path)
                    .await
                    .map_err(|error| error.safe_message())?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("Account database file could not be removed".into()),
        }
        match tokio::fs::symlink_metadata(&path).await {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("Account database deletion could not be verified".into()),
        }
    }
    let vault = format!("native-account-vault:{}", inventory.owner);
    storage
        .remove_item(&vault)
        .await
        .map_err(|error| error.safe_message())?;
    if storage
        .has(&vault)
        .await
        .map_err(|error| error.safe_message())?
    {
        return Err("Account vault deletion could not be verified".into());
    }
    storage
        .remove_item(&inventory_key(&inventory.owner)?)
        .await
        .map_err(|error| error.safe_message())
}

pub(crate) async fn resume_pending(storage: &SecureStorage, owner: &str) -> Result<(), String> {
    if let Some(inventory) = pending(storage).await?.remove(owner) {
        finish(storage, &inventory).await?;
        return forget_pending(storage, owner).await;
    }
    if let Some(inventory) = load(storage, owner).await? {
        if inventory.deleting {
            finish(storage, &inventory).await?;
        }
    }
    Ok(())
}

pub(crate) async fn resume_all_pending(storage: &SecureStorage) -> Result<(), String> {
    for (owner, inventory) in pending(storage).await? {
        if finish(storage, &inventory).await.is_ok() {
            forget_pending(storage, &owner).await?;
        } else {
            log::warn!("A confirmed local account deletion is still pending");
        }
    }
    Ok(())
}

async fn clear(state: &AppState, owner: &str, server_scope: &str) -> Result<bool, String> {
    inventory_key(owner)?;
    let initial = state.account_session();
    if initial
        .as_ref()
        .is_some_and(|session| session.account_owner() != owner)
    {
        return Err("The active account changed".into());
    }
    if let Some(session) = initial.as_ref() {
        if !hex_id(server_scope)
            || scoped(
                "",
                "qorc-local-account-scope",
                server_scope,
                &[session.username()],
            ) != owner
        {
            return Err("Account server scope does not match the unlocked account".into());
        }
        state.account_lifecycle.cancel_open(owner)?;
    }
    let _guard = state.database_lifecycle_lock.clone().lock_owned().await;
    let storage = state.storage().ok_or("Storage not initialized")?;
    let current = state.account_session();
    let unchanged = match (&initial, &current) {
        (Some(before), Some(after)) => Arc::ptr_eq(before, after) && after.account_owner() == owner,
        (None, None) => true,
        _ => false,
    };
    if !unchanged {
        return Err("The active account changed".into());
    }
    let Some(session) = current else {
        let inventory = if let Some(inventory) = pending(storage.as_ref()).await?.remove(owner) {
            inventory
        } else {
            load(storage.as_ref(), owner)
                .await?
                .filter(|inventory| inventory.deleting)
                .ok_or("Native account is locked")?
        };
        finish(storage.as_ref(), &inventory).await?;
        forget_pending(storage.as_ref(), owner).await?;
        return Ok(true);
    };
    let mut inventory = load(storage.as_ref(), owner)
        .await?
        .unwrap_or_else(|| Inventory {
            version: 1,
            owner: owner.into(),
            database_id: crate::database::account_file_id(session.master_key(), owner),
            keys: BTreeSet::new(),
            deleting: false,
        });
    let database = state.database();
    include_account_credentials(
        storage.as_ref(),
        session.as_ref(),
        server_scope,
        &mut inventory,
    )
    .await?;
    inventory.deleting = true;
    save_pending(storage.as_ref(), &inventory).await?;
    save(storage.as_ref(), &inventory).await?;
    if let Some(handler) = state.signal_handler() {
        let _signal_guard = handler.acquire_lifecycle_lock().await;
        handler.clear_all();
    }
    *state.account_session.write() = None;
    *state.database.write() = None;
    if let Some(database) = database {
        database
            .close_for_local_deletion()
            .map_err(|error| error.safe_message())?;
    }
    finish(storage.as_ref(), &inventory).await?;
    forget_pending(storage.as_ref(), owner).await?;
    Ok(true)
}

#[tauri::command]
pub async fn account_clear_local_data(
    account_owner: String,
    server_scope: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    clear(state.inner(), &account_owner, &server_scope).await
}
