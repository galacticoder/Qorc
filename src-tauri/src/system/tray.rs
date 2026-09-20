//! System Tray Handler
//!
//! System tray integration for background

use std::sync::{
    OnceLock,
    atomic::{AtomicU32, Ordering},
};
use tauri::{
    AppHandle, Manager,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};

use crate::error::QorcResult;

static UNREAD_COUNT: AtomicU32 = AtomicU32::new(0);
static UNREAD_MENU_ITEM: OnceLock<MenuItem<tauri::Wry>> = OnceLock::new();

pub async fn init(app_handle: &AppHandle) -> QorcResult<()> {
    let app = app_handle.clone();
    let unread_item = MenuItem::with_id(
        &app,
        "unread",
        unread_label(UNREAD_COUNT.load(Ordering::Relaxed)),
        false,
        None::<&str>,
    )?;
    let menu = build_tray_menu(&app, &unread_item)?;

    let app_clone = app.clone();
    let _tray = TrayIconBuilder::with_id("main")
        .icon(tauri::include_image!("icons/icon.png"))
        .tooltip("Qorc")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_tray_icon_event(move |_tray, event| match event {
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } => {
                show_main_window(&app_clone);
            }
            TrayIconEvent::DoubleClick {
                button: MouseButton::Left,
                ..
            } => {
                show_main_window(&app_clone);
            }
            _ => {}
        })
        .on_menu_event(move |app, event| match event.id.as_ref() {
            "open" => {
                show_main_window(app);
            }
            "quit" => {
                tracing::info!("Quit requested from tray");
                app.exit(0);
            }
            _ => {}
        })
        .build(&app)?;

    if UNREAD_MENU_ITEM.set(unread_item).is_err() {
        tracing::warn!("Tray unread menu item was already initialized");
    }

    tracing::info!("System tray initialized with menu");
    Ok(())
}

fn unread_label(unread: u32) -> String {
    if unread > 0 {
        format!(
            "{} unread message{}",
            unread,
            if unread > 1 { "s" } else { "" }
        )
    } else {
        "No new messages".to_string()
    }
}

fn build_tray_menu(
    app: &AppHandle,
    unread_item: &MenuItem<tauri::Wry>,
) -> QorcResult<Menu<tauri::Wry>> {
    let menu = Menu::with_items(
        app,
        &[
            unread_item,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "open", "Open Qorc", true, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?,
        ],
    )?;

    Ok(menu)
}

fn show_main_window(app: &AppHandle) {
    let Some(window) = app.get_webview_window("main") else {
        tracing::error!("Main window is unavailable");
        return;
    };
    let _ = window.show();
    let _ = window.set_focus();

    clear_unread();
}

pub fn set_unread_count(count: u32) {
    let count = count.min(9999);
    let previous = UNREAD_COUNT.swap(count, Ordering::Relaxed);

    if previous == count {
        return;
    }

    let Some(unread_item) = UNREAD_MENU_ITEM.get() else {
        tracing::warn!("Tray unread menu item is not initialized");
        return;
    };

    if let Err(e) = unread_item.set_text(unread_label(count)) {
        tracing::warn!("Failed to update tray unread label: {}", e);
    } else {
        tracing::info!("Tray unread label updated: {} unread", count);
    }
}

pub fn increment_unread() {
    let current = UNREAD_COUNT.load(Ordering::Relaxed);
    set_unread_count(current.saturating_add(1));
}

pub fn clear_unread() {
    set_unread_count(0);
}
