//! screen source enumeration for screen share picker

use crate::error::QorResult;
use serde::Serialize;

const MAX_SCREEN_SOURCES: usize = 128;
const MAX_SOURCE_NAME_CHARS: usize = 256;

#[derive(Debug, Clone, Serialize)]
pub struct ScreenSource {
    pub id: String,
    pub name: String,
    pub source_type: String,
}

pub async fn get_sources() -> QorResult<Vec<ScreenSource>> {
    #[cfg(target_os = "linux")]
    {
        get_sources_linux().await
    }

    #[cfg(target_os = "macos")]
    {
        get_sources_macos().await
    }

    #[cfg(target_os = "windows")]
    {
        get_sources_windows().await
    }
}

fn clean_source_name(value: &str, fallback: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(MAX_SOURCE_NAME_CHARS)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn append_displays(sources: &mut Vec<ScreenSource>) {
    if let Ok(displays) = scrap::Display::all() {
        for (index, display) in displays.iter().take(MAX_SCREEN_SOURCES).enumerate() {
            sources.push(ScreenSource {
                id: format!("screen:{index}"),
                name: format!(
                    "Display {} ({}x{})",
                    index + 1,
                    display.width(),
                    display.height()
                ),
                source_type: "screen".to_string(),
            });
        }
    }

    if sources.is_empty() {
        sources.push(ScreenSource {
            id: "screen:0".to_string(),
            name: "Entire Screen".to_string(),
            source_type: "screen".to_string(),
        });
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn run_bounded_command(path: &str, args: &[&str]) -> Option<Vec<u8>> {
    use std::process::Stdio;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::process::Command;
    use tokio::time::timeout;

    const MAX_COMMAND_OUTPUT_BYTES: usize = 512 * 1024;
    const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);

    let mut child = Command::new(path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;

    let output = timeout(COMMAND_TIMEOUT, async move {
        let mut limited = stdout.take((MAX_COMMAND_OUTPUT_BYTES + 1) as u64);
        let mut bytes = Vec::new();
        limited.read_to_end(&mut bytes).await.map(|_| bytes)
    })
    .await;

    let bytes = match output {
        Ok(Ok(bytes)) if bytes.len() <= MAX_COMMAND_OUTPUT_BYTES => bytes,
        _ => {
            let _ = child.kill().await;
            return None;
        }
    };

    match timeout(COMMAND_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) if status.success() => Some(bytes),
        _ => {
            let _ = child.kill().await;
            None
        }
    }
}

#[cfg(target_os = "linux")]
async fn get_sources_linux() -> QorResult<Vec<ScreenSource>> {
    use std::path::Path;

    let mut sources = Vec::new();
    append_displays(&mut sources);

    let executable = ["/usr/bin/wmctrl", "/bin/wmctrl", "/usr/local/bin/wmctrl"]
        .into_iter()
        .find(|candidate| Path::new(candidate).is_file());

    if let Some(executable) = executable
        && let Some(output) = run_bounded_command(executable, &["-l"]).await
    {
        let stdout = String::from_utf8_lossy(&output);
        for line in stdout.lines() {
            if sources.len() >= MAX_SCREEN_SOURCES {
                break;
            }
            let mut parts = line.split_whitespace();
            let Some(window_id) = parts.next() else {
                continue;
            };
            let _desktop = parts.next();
            let _host = parts.next();
            let digits = window_id.strip_prefix("0x").unwrap_or("");
            if digits.is_empty()
                || digits.len() > 16
                || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                continue;
            }
            let title = parts.collect::<Vec<_>>().join(" ");
            let name = clean_source_name(&title, "Window");
            if name == "N/A" {
                continue;
            }
            sources.push(ScreenSource {
                id: format!("window:{window_id}"),
                name,
                source_type: "window".to_string(),
            });
        }
    }

    Ok(sources)
}

#[cfg(target_os = "macos")]
async fn get_sources_macos() -> QorResult<Vec<ScreenSource>> {
    let mut sources = Vec::new();
    append_displays(&mut sources);

    const SCRIPT: &str = r#"
        set maxItems to 128
        set windowList to {}
        tell application "System Events"
            repeat with proc in (every process whose background only is false)
                if (count windowList) < maxItems then
                    repeat with w in (every window of proc)
                        if (count windowList) >= maxItems then exit repeat
                        try
                            set recordText to ((id of w) as text) & (character id 31) & (name of proc) & " - " & (name of w)
                            set end of windowList to recordText
                        end try
                    end repeat
                end if
            end repeat
        end tell
        set oldDelimiters to AppleScript's text item delimiters
        set AppleScript's text item delimiters to character id 30
        set outputText to windowList as text
        set AppleScript's text item delimiters to oldDelimiters
        return outputText
    "#;

    if let Some(output) = run_bounded_command("/usr/bin/osascript", &["-e", SCRIPT]).await {
        let stdout = String::from_utf8_lossy(&output);
        for record in stdout.trim().split('\u{1e}') {
            if sources.len() >= MAX_SCREEN_SOURCES {
                break;
            }
            let Some((window_id, title)) = record.split_once('\u{1f}') else {
                continue;
            };
            if window_id.is_empty()
                || window_id.len() > 20
                || !window_id.bytes().all(|byte| byte.is_ascii_digit())
            {
                continue;
            }
            sources.push(ScreenSource {
                id: format!("window:{window_id}"),
                name: clean_source_name(title, "Window"),
                source_type: "window".to_string(),
            });
        }
    }

    Ok(sources)
}

#[cfg(target_os = "windows")]
async fn get_sources_windows() -> QorResult<Vec<ScreenSource>> {
    use std::sync::{Arc, Mutex};
    use windows::Win32::Foundation::{BOOL, HWND, LPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowTextW, IsWindowVisible};

    struct WindowInfo {
        id: String,
        name: String,
    }

    let mut sources = Vec::new();
    append_displays(&mut sources);
    let remaining = MAX_SCREEN_SOURCES.saturating_sub(sources.len());
    if remaining == 0 {
        return Ok(sources);
    }

    let windows_list: Arc<Mutex<Vec<WindowInfo>>> = Arc::new(Mutex::new(Vec::new()));
    unsafe {
        extern "system" fn enum_window(hwnd: HWND, lparam: LPARAM) -> BOOL {
            let list = unsafe { &*(lparam.0 as *const Mutex<Vec<WindowInfo>>) };
            let Ok(mut list) = list.lock() else {
                return false.into();
            };
            if list.len() >= MAX_SCREEN_SOURCES {
                return false.into();
            }
            if unsafe { IsWindowVisible(hwnd).as_bool() } {
                let mut text: [u16; 512] = [0; 512];
                let length = unsafe { GetWindowTextW(hwnd, &mut text) };
                if length > 0 {
                    let title = String::from_utf16_lossy(&text[..length as usize]);
                    if !title.is_empty() && title != "Program Manager" {
                        list.push(WindowInfo {
                            id: format!("window:{}", hwnd.0 as usize),
                            name: clean_source_name(&title, "Window"),
                        });
                    }
                }
            }
            true.into()
        }

        let _ = EnumWindows(
            Some(enum_window),
            LPARAM(Arc::as_ptr(&windows_list) as isize),
        );
    }

    if let Ok(list) = windows_list.lock() {
        for info in list.iter().take(remaining) {
            sources.push(ScreenSource {
                id: info.id.clone(),
                name: info.name.clone(),
                source_type: "window".to_string(),
            });
        }
    }

    Ok(sources)
}
