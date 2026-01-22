//! Qor-Chat Tauri Application main entry point

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{Emitter, Manager};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use tokio::sync::mpsc;

// Module declarations
mod commands;
mod crypto;
mod database;
mod error;
mod network;
mod signal_protocol;
mod state;
mod storage;
mod system;
mod tor;

use state::AppState;

/// Initialize logging with filters
fn init_logging() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,qor_chat=debug"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}


/// Main entry point
fn main() {
    // Initialize logging
    init_logging();
    info!("Starting Qor-Chat v{}", env!("CARGO_PKG_VERSION"));

    // Build and run Tauri application
    tauri::Builder::default()
        // Manage application state
        .manage(AppState::new())
        // Register plugins
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_process::init())
        // Setup handler for app initialization
        .setup(|app| {
            info!("Application setup starting");

            // Get app handle for async operations
            let app_handle = app.handle().clone();

            // Initialize state asynchronously
            tauri::async_runtime::spawn(async move {
                if let Err(e) = initialize_app(&app_handle).await {
                    tracing::error!("Failed to initialize application: {}", e);
                }
            });

            // Window close check user setting for close to tray
            if let Some(window) = app.get_webview_window("main") {
                let app_handle = app.handle().clone();
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        // Check if close to tray is enabled
                        let state = app_handle.state::<AppState>();
                        if state.get_close_to_tray() {
                            // Hide to tray instead of closing
                            api.prevent_close();
                            if let Some(w) = app_handle.get_webview_window("main") {
                                let _ = w.hide();
                            }
                            // Set background mode
                            state.set_background_mode(true);
                            tracing::info!("Window hidden to tray");
                        }
                    }
                });
            }

            info!("Application setup complete");
            Ok(())
        })
        // Register all commands
        .invoke_handler(tauri::generate_handler![
            // Storage commands
            commands::storage::secure_init,
            commands::storage::secure_get,
            commands::storage::secure_set,
            commands::storage::secure_remove,
            commands::storage::secure_has,
            commands::storage::secure_keys,
            commands::storage::secure_clear,
            // Tor commands
            commands::tor::tor_check_installation,
            commands::tor::tor_download,
            commands::tor::tor_install,
            commands::tor::tor_configure,
            commands::tor::tor_start,
            commands::tor::tor_stop,
            commands::tor::tor_status,
            commands::tor::tor_initialize,
            commands::tor::tor_verify_connection,
            commands::tor::tor_test_connection,
            commands::tor::tor_rotate_circuit,
            commands::tor::tor_new_circuit,
            commands::tor::tor_info,
            commands::tor::tor_uninstall,
            // Signal Protocol commands
            commands::signal::signal_generate_identity,
            commands::signal::signal_generate_prekeys,
            commands::signal::signal_generate_signed_prekey,
            commands::signal::signal_generate_kyber_prekey,
            commands::signal::signal_generate_pq_kyber_prekey,
            commands::signal::signal_create_prekey_bundle,
            commands::signal::signal_process_prekey_bundle,
            commands::signal::signal_has_session,
            commands::signal::signal_encrypt,
            commands::signal::signal_decrypt,
            commands::signal::signal_delete_session,
            commands::signal::signal_delete_all_sessions,
            commands::signal::signal_set_peer_kyber_key,
            commands::signal::signal_has_peer_kyber_key,
            commands::signal::signal_trust_peer_identity,
            commands::signal::signal_set_static_mlkem_keys,
            commands::signal::signal_init_storage,
            commands::signal::signal_set_storage_key,
            // WebSocket commands
            commands::websocket::ws_connect,
            commands::websocket::ws_disconnect,
            commands::websocket::ws_send,
            commands::websocket::ws_probe_connect,
            commands::websocket::ws_set_server_url,
            commands::websocket::ws_get_server_url,
            commands::websocket::ws_get_state,
            commands::websocket::ws_set_background_mode,
            commands::websocket::ws_set_tor_ready,
            // P2P Signaling commands
            commands::p2p::p2p_signaling_connect,
            commands::p2p::p2p_signaling_disconnect,
            commands::p2p::p2p_signaling_send,
            commands::p2p::p2p_signaling_status,
            commands::p2p::p2p_set_background_mode,
            commands::p2p::p2p_set_tor_ready,
            // Notification commands
            commands::notification::notification_show,
            commands::notification::notification_set_enabled,
            commands::notification::notification_is_enabled,
            commands::notification::notification_set_badge,
            commands::notification::notification_clear_badge,
            commands::notification::notification_get_badge,
            // File commands
            commands::file::file_save,
            commands::file::file_get_download_settings,
            commands::file::file_set_download_path,
            commands::file::file_choose_download_path,
            commands::file::file_read_base64,
            commands::file::file_get_info,
            // System commands
            commands::system::get_platform_info,
            commands::system::get_platform,
            commands::system::get_arch,
            commands::system::open_external,
            commands::system::get_screen_sources,
            commands::system::capture_source,
            commands::system::power_save_blocker_start,
            commands::system::power_save_blocker_stop,
            commands::system::power_save_blocker_is_started,
            commands::system::get_user_data_path,
            commands::system::get_app_version,
            commands::system::get_app_name,
            commands::system::is_tauri,
            commands::system::get_close_to_tray,
            commands::system::set_close_to_tray,
            commands::system::tray_set_unread_count,
            commands::system::tray_increment_unread,
            commands::system::tray_clear_unread,
            // Session commands
            commands::session::session_get_background_state,
            commands::session::session_set_background_state,
            commands::session::session_store_pq_keys,
            commands::session::session_get_pq_keys,
            commands::session::session_delete_pq_keys,
            commands::session::session_update_pending_count,
            // Auth commands
            commands::auth::device_get_credentials,
            commands::auth::device_sign_challenge,
            commands::auth::auth_refresh_tokens,
            // Link preview
            commands::link::link_fetch_preview,
            // Database commands
            database::db_init,
            database::db_set_secure,
            database::db_get_secure,
            database::db_list_secure,
            database::db_scan_secure,
            database::db_delete,
            database::db_clear_store,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Initialize application services
async fn initialize_app(app_handle: &tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    info!("Initializing application services");

    // Get state
    let state = app_handle.state::<AppState>();

    // Base directories
    let mut config_dir = app_handle.path().app_config_dir()?;
    let mut data_dir = app_handle.path().app_data_dir()?;

    // Instance isolation
    if let Some(instance_id) = system::get_instance_id() {
        info!("Applying instance isolation: {}", instance_id);
        let suffix = format!("-instance-{}", instance_id);
        
        // Handle config_dir
        let config_name = config_dir.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Qor-chat-client".to_string());
        config_dir.set_file_name(format!("{}{}", config_name, suffix));
        
        // Handle data_dir
        let data_name = data_dir.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "com.qor.chat".to_string());
        data_dir.set_file_name(format!("{}{}", data_name, suffix));
    }

    info!("Config directory: {:?}", config_dir);
    info!("Data directory: {:?}", data_dir);

    // Initialize secure storage
    storage::init(&state, config_dir).await?;
    info!("Secure storage initialized");

    // Initialize Signal Protocol handler
    signal_protocol::init(&state).await?;
    info!("Signal Protocol handler initialized");

    // Initialize Tor manager
    let tor_manager = tor::init(data_dir).await?;
    *state.tor_manager.write() = Some(tor_manager);
    info!("Tor manager initialized");

    // Initialize WebSocket handler
    let ws_handler = network::websocket::init().await?;
    let (ws_tx, mut ws_rx) = mpsc::unbounded_channel();
    ws_handler.set_event_handler(ws_tx);
    *state.websocket_handler.write() = Some(ws_handler);
    info!("WebSocket handler initialized");

    // Start WebSocket event bridge
    let app_handle_ws = app_handle.clone();
    tauri::async_runtime::spawn(async move {
        use crate::network::websocket::WsEvent;
        while let Some(event) = ws_rx.recv().await {
            match event {
                WsEvent::Message { data } => {
                    let _ = app_handle_ws.emit("ws-message", data);
                }
                _ => {
                    let _ = app_handle_ws.emit("ws-message", event);
                }
            }
        }
    });

    // Initialize P2P signaling handler
    let p2p_handler = network::p2p::init().await?;
    let (p2p_tx, mut p2p_rx) = mpsc::unbounded_channel();
    p2p_handler.set_event_handler(p2p_tx);
    *state.p2p_handler.write() = Some(p2p_handler);
    info!("P2P signaling handler initialized");

    // Start P2P event bridge
    let app_handle_p2p = app_handle.clone();
    tauri::async_runtime::spawn(async move {
        // P2P Signal bridging
        while let Some(event) = p2p_rx.recv().await {
            match event {
                _ => {
                    let _ = app_handle_p2p.emit("p2p-message", event);
                }
            }
        }
    });

    // Initialize notification handler
    system::notification::init(&state).await?;
    info!("Notification handler initialized");

    // Initialize tray
    system::tray::init(app_handle).await?;
    info!("System tray initialized");

    // Show main window
    if let Some(window) = app_handle.get_webview_window("main") {
        window.show()?;
    }

    info!("All services initialized successfully");
    Ok(())
}
