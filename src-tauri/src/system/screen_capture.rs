//! Screen Capture
//!
//! Platform-specific screen capture for screen sharing

use crate::error::{QorError, QorResult};
use serde::{Deserialize, Serialize};

/// Screen source information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenSource {
    pub id: String,
    pub name: String,
    pub thumbnail: Option<String>,
    pub source_type: String,
    pub app_icon: Option<String>,
    pub display_size: Option<(u32, u32)>,
}

/// Screen capture options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaptureOptions {
    /// Include screen sources (monitors)
    pub types: Vec<String>, // ["screen", "window"]
    /// Maximum thumbnail size
    pub thumbnail_size: Option<(u32, u32)>,
    /// Fetch window thumbnails  
    pub fetch_window_icons: bool,
}

/// Get available screen sources for sharing
pub async fn get_sources(options: Option<CaptureOptions>) -> QorResult<Vec<ScreenSource>> {
    let opts = options.unwrap_or_else(|| CaptureOptions {
        types: vec!["screen".to_string(), "window".to_string()],
        thumbnail_size: Some((320, 180)),
        fetch_window_icons: true,
    });

    #[cfg(target_os = "linux")]
    {
        get_sources_linux(&opts).await
    }

    #[cfg(target_os = "macos")]
    {
        get_sources_macos(&opts).await
    }

    #[cfg(target_os = "windows")]
    {
        get_sources_windows(&opts).await
    }
}

// Linux

#[cfg(target_os = "linux")]
async fn get_sources_linux(options: &CaptureOptions) -> QorResult<Vec<ScreenSource>> {
    use std::process::Command;
    
    let mut sources = Vec::new();
    
    // Get screens
    if options.types.contains(&"screen".to_string()) {
        if let Ok(output) = Command::new("xrandr").arg("--query").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            let mut screen_idx = 0;
            for line in stdout.lines() {
                if line.contains(" connected") {
                    // Parse monitor name and resolution
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    let name = parts.first().unwrap_or(&"Screen");
                    
                    // Extract resolution if present
                    let mut width = 1920u32;
                    let mut height = 1080u32;
                    for part in &parts {
                        if part.contains('x') && part.contains('+') {
                            if let Some(res) = part.split('+').next() {
                                let dims: Vec<&str> = res.split('x').collect();
                                if dims.len() == 2 {
                                    width = dims[0].parse().unwrap_or(1920);
                                    height = dims[1].parse().unwrap_or(1080);
                                }
                            }
                        }
                    }
                    
                    sources.push(ScreenSource {
                        id: format!("screen:{}", screen_idx),
                        name: format!("Screen {} ({})", screen_idx + 1, name),
                        thumbnail: None,
                        source_type: "screen".to_string(),
                        app_icon: None,
                        display_size: Some((width, height)),
                    });
                    screen_idx += 1;
                }
            }
        }
        
        // Fallback add at least one screen
        if sources.is_empty() {
            sources.push(ScreenSource {
                id: "screen:0".to_string(),
                name: "Entire Screen".to_string(),
                thumbnail: None,
                source_type: "screen".to_string(),
                app_icon: None,
                display_size: None,
            });
        }
    }
    
    // Get windows
    if options.types.contains(&"window".to_string()) {
        if let Ok(output) = Command::new("wmctrl").arg("-l").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let window_id = parts[0];
                    let name = parts[3..].join(" ");
                    
                    if !name.is_empty() && !name.starts_with("N/A") {
                        sources.push(ScreenSource {
                            id: format!("window:{}", window_id),
                            name: name.clone(),
                            thumbnail: None,
                            source_type: "window".to_string(),
                            app_icon: None,
                            display_size: None,
                        });
                    }
                }
            }
        }
    }
    
    Ok(sources)
}

// macOS

#[cfg(target_os = "macos")]
async fn get_sources_macos(options: &CaptureOptions) -> QorResult<Vec<ScreenSource>> {
    use std::process::Command;
    
    let mut sources = Vec::new();
    
    // Get screens
    if options.types.contains(&"screen".to_string()) {
        sources.push(ScreenSource {
            id: "screen:0".to_string(),
            name: "Entire Screen".to_string(),
            thumbnail: None,
            source_type: "screen".to_string(),
            app_icon: None,
            display_size: None,
        });
        
        // Try to get display info
        if let Ok(output) = Command::new("system_profiler")
            .args(["SPDisplaysDataType", "-json"])
            .output()
        {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                if let Some(displays) = json.get("SPDisplaysDataType")
                    .and_then(|d| d.as_array())
                {
                    for (idx, display) in displays.iter().enumerate() {
                        if idx == 0 { continue; }
                        
                        let name = display.get("_name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("Display");
                        
                        sources.push(ScreenSource {
                            id: format!("screen:{}", idx),
                            name: format!("Display {}: {}", idx + 1, name),
                            thumbnail: None,
                            source_type: "screen".to_string(),
                            app_icon: None,
                            display_size: None,
                        });
                    }
                }
            }
        }
    }
    
    // Get windows
    if options.types.contains(&"window".to_string()) {
        let script = r#"
            tell application "System Events"
                set windowList to {}
                repeat with proc in (every process whose background only is false)
                    repeat with w in (every window of proc)
                        try
                            set end of windowList to (name of proc) & "|" & (name of w) & "|" & (id of w)
                        end try
                    end repeat
                end repeat
                return windowList
            end tell
        "#;
        
        if let Ok(output) = Command::new("osascript")
            .arg("-e")
            .arg(script)
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            for (idx, item) in stdout.trim().split(", ").enumerate() {
                let parts: Vec<&str> = item.split('|').collect();
                if parts.len() >= 2 {
                    let app_name = parts[0];
                    let window_name = parts[1];
                    
                    sources.push(ScreenSource {
                        id: format!("window:{}", idx),
                        name: format!("{} - {}", app_name, window_name),
                        thumbnail: None,
                        source_type: "window".to_string(),
                        app_icon: None,
                        display_size: None,
                    });
                }
            }
        }
    }
    
    Ok(sources)
}

// Windows

#[cfg(target_os = "windows")]
async fn get_sources_windows(options: &CaptureOptions) -> QorResult<Vec<ScreenSource>> {
    use windows::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowTextW, IsWindowVisible, GetWindowThreadProcessId};
    use windows::Win32::Foundation::{HWND, LPARAM, BOOL};
    use std::sync::Mutex;

    let mut sources = Vec::new();
    
    // Get displays
    if options.types.contains(&"screen".to_string()) {
        let displays = scrap::Display::all().unwrap_or_default();
        for (idx, display) in displays.iter().enumerate() {
            sources.push(ScreenSource {
                id: format!("screen:{}", idx),
                name: format!("Display {} ({}x{})", idx + 1, display.width(), display.height()),
                thumbnail: None,
                source_type: "screen".to_string(),
                app_icon: None,
                display_size: Some((display.width() as u32, display.height() as u32)),
            });
        }
    }
    
    // Get windows using EnumWindows
    if options.types.contains(&"window".to_string()) {
        struct WindowInfo {
            id: String,
            name: String,
        }
        let windows_list = Arc::new(Mutex::new(Vec::new()));
        
        unsafe {
            extern "system" fn enum_window(hwnd: HWND, lparam: LPARAM) -> BOOL {
                let list = unsafe { &*(lparam.0 as *const Mutex<Vec<WindowInfo>>) };
                
                if unsafe { IsWindowVisible(hwnd).as_bool() } {
                    let mut text: [u16; 512] = [0; 512];
                    let len = unsafe { GetWindowTextW(hwnd, &mut text) };
                    if len > 0 {
                        let title = String::from_utf16_lossy(&text[..len as usize]);
                        if !title.is_empty() && title != "Program Manager" {
                            let mut list = list.lock().unwrap();
                            list.push(WindowInfo {
                                id: format!("window:{}", hwnd.0 as usize),
                                name: title,
                            });
                        }
                    }
                }
                true.into()
            }
            
            let _ = EnumWindows(Some(enum_window), LPARAM(Arc::as_ptr(&windows_list) as isize));
        }
        
        let list = windows_list.lock().unwrap();
        for info in list.iter() {
            sources.push(ScreenSource {
                id: info.id.clone(),
                name: info.name.clone(),
                thumbnail: None,
                source_type: "window".to_string(),
                app_icon: None,
                display_size: None,
            });
        }
    }
    
    Ok(sources)
}

/// Capture a specific source (returns raw image data)
pub async fn capture_source(source_id: &str) -> QorResult<Vec<u8>> {
    if source_id.starts_with("screen:") {
        let idx: usize = source_id.split(':').nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
            
        let display = scrap::Display::all()
            .map_err(|_| QorError::Internal("Failed to list displays".to_string()))?
            .into_iter().nth(idx)
            .ok_or_else(|| QorError::NotFound("Display not found".to_string()))?;
            
        let mut capturer = scrap::Capturer::new(display)
            .map_err(|e| QorError::Internal(format!("Failed to create capturer: {}", e)))?;
            
        // Capture a frame (might need retries if WOULDBLOCK)
        let frame = loop {
            match capturer.frame() {
                Ok(f) => break f,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(e) => return Err(QorError::Internal(format!("Capture failed: {}", e))),
            }
        };
        
        // Convert frame to Vec<u8> (BGRA to RGBA if needed, scrap is usually BGRA on Windows)
        return Ok(frame.to_vec());
    }
    
    Err(QorError::NotImplemented("Window capture not yet implemented with scrap".to_string()))
}
