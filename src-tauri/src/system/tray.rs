//! System Tray Handler
//!
//! System tray integration for background

use std::sync::atomic::{AtomicU32, Ordering};
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager,
};

use crate::error::QorResult;

/// Unread message count
static UNREAD_COUNT: AtomicU32 = AtomicU32::new(0);

/// Initialize system tray
pub async fn init(app_handle: &AppHandle) -> QorResult<()> {
    let app = app_handle.clone();
    
    // Build context menu
    let menu = build_tray_menu(&app)?;
    
    // Load tray icon from path
    let icon = app_handle.default_window_icon().cloned()
        .unwrap_or_else(|| tauri::image::Image::new_owned(vec![0, 0, 0, 255], 1, 1));
    
    // Build tray icon
    let app_clone = app.clone();
    let _tray = TrayIconBuilder::with_id("main")
        .icon(icon)
        .tooltip("Qor Chat")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_tray_icon_event(move |_tray, event| {
            match event {
                TrayIconEvent::Click { button, button_state, .. } => {
                    if button == MouseButton::Left && button_state == MouseButtonState::Up {
                        show_main_window(&app_clone);
                    }
                }
                TrayIconEvent::DoubleClick { button, .. } => {
                    if button == MouseButton::Left {
                        show_main_window(&app_clone);
                    }
                }
                _ => {}
            }
        })
        .on_menu_event(move |app, event| {
            match event.id.as_ref() {
                "open" => {
                    show_main_window(app);
                }
                "quit" => {
                    tracing::info!("Quit requested from tray");
                    app.exit(0);
                }
                _ => {}
            }
        })
        .build(&app)?;
    
    tracing::info!("System tray initialized with menu");
    Ok(())
}

/// Build the tray context menu
fn build_tray_menu(app: &AppHandle) -> QorResult<Menu<tauri::Wry>> {
    let unread = UNREAD_COUNT.load(Ordering::Relaxed);
    let unread_label = if unread > 0 {
        format!("{} unread message{}", unread, if unread > 1 { "s" } else { "" })
    } else {
        "No new messages".to_string()
    };
    
    let menu = Menu::with_items(app, &[
        &MenuItem::with_id(app, "unread", &unread_label, false, None::<&str>)?,
        &PredefinedMenuItem::separator(app)?,
        &MenuItem::with_id(app, "open", "Open Qor Chat", true, None::<&str>)?,
        &PredefinedMenuItem::separator(app)?,
        &MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?,
    ])?;
    
    Ok(menu)
}

/// Show the main window
fn show_main_window(app: &AppHandle) {
    // Try to get existing window
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    } else {
        // Create new window
        match tauri::WebviewWindowBuilder::new(
            app,
            "main",
            tauri::WebviewUrl::App("index.html".into())
        )
        .title("Qor Chat")
        .inner_size(1200.0, 800.0)
        .min_inner_size(800.0, 600.0)
        .center()
        .decorations(true)
        .build() {
            Ok(window) => {
                let _ = window.show();
                let _ = window.set_focus();
                tracing::info!("Main window recreated from tray");
            }
            Err(e) => {
                tracing::error!("Failed to create main window: {}", e);
                return;
            }
        }
    }
    
    // Clear background mode when window is shown
    let state = app.state::<crate::state::AppState>();
    state.set_background_mode(false);
    
    // Clear unread count when window is shown
    clear_unread(app);
}

/// Set unread count and update tray menu
pub fn set_unread_count(app: &AppHandle, count: u32) {
    let count = count.min(9999);
    let previous = UNREAD_COUNT.swap(count, Ordering::Relaxed);
    
    // Update menu if count changed
    if previous == count {
        return;
    }
    
    // Update the tray menu
    match app.tray_by_id("main") {
        Some(tray) => {
            match build_tray_menu(app) {
                Ok(menu) => {
                    if let Err(e) = tray.set_menu(Some(menu)) {
                        tracing::warn!("Failed to set tray menu: {}", e);
                    } else {
                        tracing::info!("Tray menu updated: {} unread", count);
                    }
                }
                Err(e) => tracing::warn!("Failed to build tray menu: {}", e),
            }
        }
        None => tracing::warn!("Tray 'main' not found for menu update"),
    }
    
    tracing::debug!("Tray unread count set to: {}", count);
}


/// Increment unread count
pub fn increment_unread(app: &AppHandle) {
    let current = UNREAD_COUNT.load(Ordering::Relaxed);
    set_unread_count(app, current + 1);
}

/// Clear unread count
pub fn clear_unread(app: &AppHandle) {
    set_unread_count(app, 0);
}
