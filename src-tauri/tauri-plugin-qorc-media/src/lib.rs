use serde::de::DeserializeOwned;
use std::sync::RwLock;
use tauri::{
    Wry,
    plugin::{PluginHandle, TauriPlugin},
};
static HANDLE: RwLock<Option<PluginHandle<Wry>>> = RwLock::new(None);

pub fn init() -> TauriPlugin<Wry> {
    tauri::plugin::Builder::new("qorc-media")
        .setup(|_, api| {
            let handle = api.register_android_plugin("com.qorc.media", "MediaPlugin")?;
            *HANDLE
                .write()
                .map_err(|_| "Android media state unavailable")? = Some(handle);
            Ok(())
        })
        .build()
}

pub fn call<T: DeserializeOwned>(op: &str, mut args: serde_json::Value) -> Result<T, String> {
    args.as_object_mut()
        .ok_or("Invalid media arguments")?
        .insert("op".into(), op.into());
    let handle = HANDLE
        .read()
        .map_err(|_| "Android media state unavailable")?
        .clone()
        .ok_or("Android media is not initialized")?;
    handle
        .run_mobile_plugin("execute", args)
        .map_err(|_| format!("Android media operation failed: {op}"))
}
