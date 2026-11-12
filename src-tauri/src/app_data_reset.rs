use crate::state::AppState;
use std::{
    path::{Path, PathBuf},
    sync::atomic::Ordering,
};
use tauri::{AppHandle, State};
#[cfg(not(target_os = "android"))]
use tauri::Manager;

#[cfg(not(target_os = "android"))]
const RESET_MAGIC: &[u8] = b"qorc-local-app-reset-v1";

fn erase_owned_tree(path: &Path, depth: usize) -> Result<(), String> {
    if depth > 64 || path.parent().is_none() || path.file_name().is_none() {
        return Err("Invalid app profile directory".into());
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("App profile metadata is unavailable".into()),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("App profile root is not a directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err("App profile has an invalid owner".into());
        }
    }
    for entry in std::fs::read_dir(path).map_err(|_| "App profile cannot be read")? {
        let entry = entry.map_err(|_| "App profile entry is unavailable")?;
        let child = entry.path();
        let metadata =
            std::fs::symlink_metadata(&child).map_err(|_| "App profile entry is unavailable")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() } {
                return Err("App profile entry has an invalid owner".into());
            }
        }
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            erase_owned_tree(&child, depth + 1)?;
        } else {
            std::fs::remove_file(&child).map_err(|_| "App profile file could not be deleted")?;
        }
    }
    std::fs::remove_dir(path).map_err(|_| "App profile directory could not be deleted".to_string())
}

async fn erase_profiles(config: PathBuf, data: PathBuf) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        erase_owned_tree(&config, 0)?;
        if data != config {
            erase_owned_tree(&data, 0)?;
        }
        Ok(())
    })
    .await
    .map_err(|_| "App reset task failed")?
}

#[cfg(not(target_os = "android"))]
fn marker_path(app: &AppHandle) -> Result<PathBuf, String> {
    let root = app
        .path()
        .app_config_dir()
        .map_err(|_| "App configuration directory is unavailable")?;
    let instance = crate::system::get_instance_id().map_err(|error| error.safe_message())?;
    Ok(root.join(format!("reset-local-data-{instance}.pending")))
}

#[cfg(not(target_os = "android"))]
pub(crate) async fn resume_if_pending(
    app: &AppHandle,
    config: &Path,
    data: &Path,
) -> Result<(), String> {
    let marker = marker_path(app)?;
    match crate::storage::file::read_file_bounded(&marker, 64).await {
        Ok(value) if value == RESET_MAGIC => {}
        Err(crate::error::QorcError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(())
        }
        _ => return Err("App reset marker is invalid".into()),
    }
    for window in app.webview_windows().into_values() {
        window
            .clear_all_browsing_data()
            .map_err(|_| "Browser data could not be cleared")?;
    }
    erase_profiles(config.to_owned(), data.to_owned()).await?;
    crate::storage::file::remove_file(&marker)
        .await
        .map_err(|error| error.safe_message())
}

#[cfg(target_os = "android")]
fn android_clear_application_data() -> Result<bool, String> {
    use jni::objects::{JObject, JValue};
    let context = ndk_context::android_context();
    let vm = unsafe { jni::JavaVM::from_raw(context.vm().cast()) }
        .map_err(|_| "Android runtime is unavailable")?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|_| "Android runtime is unavailable")?;
    let context = unsafe { JObject::from_raw(context.context().cast()) };
    let result = (|| -> Result<bool, jni::errors::Error> {
        let name = env.new_string("activity")?;
        let manager = env
            .call_method(
                &context,
                "getSystemService",
                "(Ljava/lang/String;)Ljava/lang/Object;",
                &[JValue::Object(name.as_ref())],
            )?
            .l()?;
        env.call_method(manager, "clearApplicationUserData", "()Z", &[])?
            .z()
    })();
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
    result.map_err(|_| "Android could not reset Qorc's local data".into())
}

#[tauri::command]
pub async fn app_reset_all_local_data(
    app_handle: AppHandle,
    account_owner: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let session = state
        .account_session()
        .filter(|session| session.account_owner() == account_owner)
        .ok_or("The active account changed")?;
    let _guard = state.database_lifecycle_lock.clone().lock_owned().await;
    if !state
        .account_session()
        .is_some_and(|current| std::sync::Arc::ptr_eq(&current, &session))
    {
        return Err("The active account changed".into());
    }
    if state.resetting_local_data.load(Ordering::SeqCst) {
        return Err("Local app data is already being reset".into());
    }

    #[cfg(target_os = "android")]
    {
        let _ = app_handle;
        state.resetting_local_data.store(true, Ordering::SeqCst);
        let accepted = tokio::task::spawn_blocking(android_clear_application_data)
            .await
            .unwrap_or_else(|_| Err("Android reset task failed".into()));
        if accepted != Ok(true) {
            state.resetting_local_data.store(false, Ordering::SeqCst);
        }
        return accepted.and_then(|accepted| {
            if accepted {
                Ok(true)
            } else {
                Err("Android rejected the app data reset".into())
            }
        });
    }

    #[cfg(not(target_os = "android"))]
    {
        let storage = state.storage().ok_or("Storage not initialized")?;
        let config = storage.config_dir().to_owned();
        let tor = state
            .tor_manager
            .read()
            .clone()
            .ok_or("Tor runtime is unavailable")?;
        let data = tor.managed_app_data_dir();
        let marker = marker_path(&app_handle)?;
        crate::storage::file::atomic_write(&marker, RESET_MAGIC, 0o600)
            .await
            .map_err(|error| error.safe_message())?;
        state.resetting_local_data.store(true, Ordering::SeqCst);
        state.account_lifecycle.cancel_all_open()?;
        if let Some(signal) = state.signal_handler() {
            let _signal_guard = signal.acquire_lifecycle_lock().await;
            signal.clear_all();
        }
        let database = state.database();
        *state.database.write() = None;
        *state.account_session.write() = None;
        if let Some(database) = database {
            database
                .close_for_local_deletion()
                .map_err(|error| error.safe_message())?;
        }
        tor.stop().await.map_err(|error| error.safe_message())?;
        let pir_tor = state.pir_tor_manager.read().clone();
        if let Some(pir_tor) = pir_tor {
            pir_tor.stop().await.map_err(|error| error.safe_message())?;
        }
        tokio::task::spawn_blocking(crate::commands::pir::stop_for_local_reset)
            .await
            .map_err(|_| "PIR reset task failed")??;
        storage.revoke().await;
        *state.storage.write() = None;
        for window in app_handle.webview_windows().into_values() {
            window
                .clear_all_browsing_data()
                .map_err(|_| "Browser data could not be cleared")?;
        }
        erase_profiles(config, data).await?;
        crate::storage::file::remove_file(&marker)
            .await
            .map_err(|error| error.safe_message())?;
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            app_handle.restart();
        });
        Ok(true)
    }
}
