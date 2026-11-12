use crate::error::{QorcError, QorcResult};

pub fn copy_text(_app: &tauri::AppHandle, text: &str) -> QorcResult<()> {
    #[cfg(target_os = "android")]
    {
        use tauri_plugin_clipboard_manager::ClipboardExt;
        _app.clipboard()
            .write_text(text)
            .map_err(|_| QorcError::Internal("System clipboard write failed".to_string()))
    }
    #[cfg(desktop)]
    {
        let mut clipboard = arboard::Clipboard::new()
            .map_err(|_| QorcError::Internal("System clipboard is unavailable".to_string()))?;
        clipboard
            .set_text(text)
            .map_err(|_| QorcError::Internal("System clipboard write failed".to_string()))
    }
}

pub fn open_url(_app: &tauri::AppHandle, url: &str) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        use tauri_plugin_opener::OpenerExt;
        _app.opener()
            .open_url(url, None::<&str>)
            .map_err(|_| "Failed to open URL".to_string())
    }
    #[cfg(desktop)]
    open::that(url)
        .map(|_| ())
        .map_err(|_| "Failed to open URL".to_string())
}
