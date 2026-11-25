//! Tauri command handlers
//!
//! All IPC commands exposed to frontend

pub mod account;
pub mod audio;
pub mod callback_bytes;
pub mod camera;
pub mod crypto;
pub mod discovery;
pub mod message_content;
pub mod microphone;
pub mod notification;
pub mod p2p;
pub mod pir;
pub mod screen_capture;
pub mod session;
pub mod signal;
pub mod storage;
pub mod system;
pub mod tor;
pub mod websocket;

#[cfg(target_os = "android")]
mod android_bytes;

use std::borrow::Cow;

fn binary_body<'a>(
    request: &'a tauri::ipc::Request<'_>,
    max_bytes: usize,
) -> Result<Cow<'a, [u8]>, ()> {
    match request.body() {
        tauri::ipc::InvokeBody::Raw(bytes) if bytes.len() <= max_bytes => Ok(Cow::Borrowed(bytes)),
        #[cfg(target_os = "android")]
        tauri::ipc::InvokeBody::Json(value) => {
            android_bytes::decode(value, max_bytes).map(Cow::Owned)
        }
        _ => Err(()),
    }
}
