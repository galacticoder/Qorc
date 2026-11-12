use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};

pub fn action(op: &str, args: Value) -> Result<(), String> {
    let accepted: bool = tauri_plugin_qorc_media::call(op, args)?;
    if accepted {
        Ok(())
    } else {
        Err(format!("Android media action rejected: {op}"))
    }
}
pub fn devices<T: serde::de::DeserializeOwned>(op: &str) -> Result<Vec<T>, String> {
    #[derive(Deserialize)]
    struct Devices<T> {
        devices: Vec<T>,
    }
    let result: Devices<T> = tauri_plugin_qorc_media::call(op, json!({}))?;
    if result.devices.len() > 32 {
        return Err("Too many Android media devices".into());
    }
    Ok(result.devices)
}
pub fn permission(kind: &str) -> Result<bool, String> {
    tauri_plugin_qorc_media::call("permission", json!({"kind": kind}))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Frame {
    pub sequence: u64,
    pub captured_at: u64,
    pub enabled: bool,
    pub width: u16,
    pub height: u16,
    pub frame_rate: u16,
    bytes: String,
}
impl Frame {
    pub fn decode(&mut self, max: usize) -> Result<Vec<u8>, String> {
        if self.bytes.len() > max.div_ceil(3) * 4 || self.sequence == 0 || self.captured_at == 0 {
            return Err("Invalid Android media frame".into());
        }
        let mut bytes = STANDARD
            .decode(&self.bytes)
            .map_err(|_| "Invalid Android media encoding")?;
            
        use zeroize::Zeroize;
        self.bytes.zeroize();
        if bytes.len() > max {
            bytes.zeroize();
            return Err("Android media frame exceeds its limit".into());
        }
        Ok(bytes)
    }
}
impl Drop for Frame {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.zeroize();
    }
}
pub struct Capture {
    pub id: String,
    kind: &'static str,
    stopped: std::sync::atomic::AtomicBool,
}
impl Capture {
    pub fn start(
        kind: &'static str,
        device_id: Option<&str>,
        width: u32,
        height: u32,
        fps: u32,
    ) -> Result<Self, String> {
        if device_id.is_some_and(|id| id.contains("-bt:")) && !permission("bluetooth")? {
            return Err("Bluetooth permission was not granted".into());
        }
        let handle = Self::pending(kind);
        handle.begin(device_id, width, height, fps)?;
        Ok(handle)
    }
    pub fn pending(kind: &'static str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().simple().to_string(),
            kind,
            stopped: std::sync::atomic::AtomicBool::new(false),
        }
    }
    pub fn begin(
        &self,
        device_id: Option<&str>,
        width: u32,
        height: u32,
        fps: u32,
    ) -> Result<(), String> {
        let kind = self.kind;
        action(
            &format!("{kind}Start"),
            json!({"id":self.id,"deviceId":device_id.unwrap_or(""),"width":width,"height":height,"frameRate":fps}),
        )
    }
    pub fn poll(&self) -> Result<Option<Frame>, String> {
        #[derive(Deserialize)]
        struct Reply {
            frame: Option<Frame>,
        }
        let reply: Reply =
            tauri_plugin_qorc_media::call(&format!("{}Poll", self.kind), json!({"id":self.id}))?;
        Ok(reply.frame)
    }
    pub fn enabled(&self, enabled: bool) -> Result<(), String> {
        action(
            &format!("{}Enabled", self.kind),
            json!({"id":self.id,"enabled":enabled}),
        )
    }
    pub fn write(&self, bytes: &[u8]) -> Result<(), String> {
        action(
            "playbackWrite",
            json!({"id":self.id,"bytes":STANDARD.encode(bytes)}),
        )
    }
}
impl Capture {
    pub fn finish(&self) -> Result<(), String> {
        if self.stopped.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return Ok(());
        }
        action(&format!("{}Stop", self.kind), json!({"id":self.id}))
    }
    pub fn cancel(&self) {
        if self.stopped.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        
        let kind = self.kind;
        let id = self.id.clone();
        let _ = std::thread::Builder::new()
            .name("qorc-android-media-stop".into())
            .spawn(move || {
                let _ = action(&format!("{kind}Stop"), json!({"id":id}));
            });
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.cancel();
    }
}
