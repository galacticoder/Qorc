//! Qor-Chat Tauri Application main entry point

use std::sync::Arc;

use tauri::{Emitter, Manager};
use tokio::sync::mpsc;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

// Module declarations
mod account_vault;
mod commands;
mod crypto;
mod database;
mod error;
mod hybrid_native;
mod json_bounds;
mod message_content;
mod network;
mod protocol_keys;
mod signal_protocol;
mod state;
mod storage;
mod storage_keys;
mod system;
mod tor;

use state::AppState;

#[cfg(target_os = "linux")]
fn set_env_default(key: &str, value: &str) {
    if std::env::var_os(key).is_none() {
        unsafe {
            std::env::set_var(key, value);
        }
    }
}

#[cfg(target_os = "linux")]
fn configure_linux_webview_rendering() {
    set_env_default("WEBKIT_DISABLE_DMABUF_RENDERER", "1");

    if std::env::var_os("QOR_CHAT_SOFTWARE_RENDERING").is_some() {
        set_env_default("LIBGL_ALWAYS_SOFTWARE", "1");
    }
}

#[cfg(not(target_os = "linux"))]
fn configure_linux_webview_rendering() {}

fn is_allowed_app_navigation(url: &url::Url) -> bool {
    match (url.scheme(), url.host_str()) {
        ("tauri", Some("localhost")) => true,
        ("http" | "https", Some("tauri.localhost")) => true,
        ("http", Some("localhost")) if cfg!(debug_assertions) => url.port() == Some(5173),
        _ => false,
    }
}

fn install_rustls_provider() {
    let provider = crypto::tls::strict_post_quantum_provider();
    if provider.install_default().is_ok() {
        info!("Installed hybrid-only Rustls AWS-LC CryptoProvider");
        return;
    }

    let existing = rustls::crypto::CryptoProvider::get_default()
        .expect("Rustls reported an installed provider without exposing it");
    let is_strict_hybrid = existing.kx_groups.len() == 1
        && existing.kx_groups[0].name() == rustls::NamedGroup::X25519MLKEM768;
    if !is_strict_hybrid {
        panic!("A non-hybrid Rustls CryptoProvider was installed before startup");
    }
    info!("Hybrid-only Rustls CryptoProvider was already installed");
}

/// Init logging with filters
fn init_logging() {
    let mut filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("error,qor_chat=error"));

    for directive in [
        "qor_chat_lib::network::websocket=info",
        "qor_chat_lib::commands::websocket=info",
        "libsignal_protocol::session_management=off",
        "netlink_packet_route=error",
        "netlink_packet_route::link::buffer_tool=error",
        "tokio_tungstenite=error",
        "tokio_tungstenite::compat=error",
        "tungstenite=error",
        "tungstenite::protocol::frame=error",
        "netlink_sys=error",
        "netlink_proto=error",
        "hyper_util::client::legacy=warn",
        "reqwest::connect=warn",
        "reqwest::retry=warn",
    ] {
        if let Ok(parsed) = directive.parse() {
            filter = filter.add_directive(parsed);
        }
    }

    if let Err(err) = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .try_init()
    {
        eprintln!("logging init skipped: {err}");
    }
}

/// Main entry point
pub fn run() {
    configure_linux_webview_rendering();
    init_logging();
    std::panic::set_hook(Box::new(|_| {
        error!("[RUST-PANIC] application terminated unexpectedly");
    }));

    install_rustls_provider();
    info!("Starting Qor-Chat v{}", env!("CARGO_PKG_VERSION"));

    // Build and run Tauri application
    let builder = tauri::Builder::default().manage(AppState::new());

    builder
        // Register plugins
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(
            tauri::plugin::Builder::<tauri::Wry>::new("navigation-policy")
                .on_navigation(|_, url| is_allowed_app_navigation(url))
                .build(),
        )
        .setup(|app| {
            info!("Application setup starting");
            
            let app_handle = app.handle().clone();

            #[cfg(target_os = "linux")]
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.with_webview(|webview| {
                    use webkit2gtk::glib::object::Cast;
                    use webkit2gtk::{
                        PermissionRequestExt, UserMediaPermissionRequestExt, WebViewExt,
                    };
                    let wv = webview.inner();
                    wv.connect_permission_request(|_wv, req| {
                        if let Some(media_request) =
                            req.downcast_ref::<webkit2gtk::UserMediaPermissionRequest>()
                        {
                            let allowed = crate::commands::system::consume_media_permission_lease(
                                media_request.is_for_audio_device(),
                                media_request.is_for_video_device(),
                            );
                            if allowed {
                                req.allow();
                            } else {
                                req.deny();
                            }
                            true
                        } else {
                            false
                        }
                    });
                });
            }

            // Window close check user setting for close to tray
            if let Some(window) = app.get_webview_window("main") {
                let app_handle = app.handle().clone();
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        // Check if close to tray is enabled
                        let state = app_handle.state::<AppState>();
                        if state.get_close_to_tray() {
                            api.prevent_close();
                            if let Some(w) = app_handle.get_webview_window("main") {
                                let _ = w.hide();
                            }
                            tracing::info!("Window hidden to tray");
                        }
                    }
                });
            }

            tauri::async_runtime::block_on(initialize_app(&app_handle)).map_err(|_| {
                tracing::error!("Application initialization failed");
                std::io::Error::other("application initialization failed")
            })?;

            info!("Application setup complete");
            Ok(())
        })
        // Register all commands
        .invoke_handler(tauri::generate_handler![
            commands::pir::pir_generate_query,
            commands::pir::pir_decode_response,
            commands::pir::pir_discard_query,
            commands::account::account_open,
            commands::account::account_public_keys,
            commands::account::account_is_unlocked,
            commands::account::account_sign,
            commands::account::account_p2p_handshake_secrets,
            commands::account::account_discovery_publication,
            commands::account::account_decrypt_hybrid,
            commands::account::account_open_sealed_envelope,
            commands::account::account_token_vault_load,
            commands::account::account_token_vault_store,
            commands::account::account_token_vault_remove,
            commands::account::account_lock,
            commands::message_content::message_content_store_outgoing,
            commands::message_content::message_content_commit_pending,
            commands::message_content::message_content_has,
            commands::message_content::message_content_render,
            commands::message_content::message_content_clone_for_display,
            commands::message_content::message_content_copy,
            commands::message_content::message_content_revoke_send,
            commands::message_content::message_content_delete,
            commands::storage::secure_get,
            commands::storage::secure_set,
            commands::storage::secure_remove,
            commands::storage::secure_has,
            commands::crypto::auth_pow_solve_batch,
            commands::tor::tor_configure,
            commands::tor::tor_start,
            commands::tor::tor_stop,
            commands::tor::tor_status,
            commands::tor::tor_verify_connection,
            commands::tor::tor_rotate_circuit,
            commands::tor::tor_info,
            commands::signal::signal_create_prekey_bundle,
            commands::signal::signal_process_prekey_bundle,
            commands::signal::signal_has_session,
            commands::signal::signal_has_peer_static_mlkem_key,
            commands::signal::signal_encrypt,
            commands::signal::signal_encrypt_content_ref,
            commands::signal::signal_decrypt,
            commands::signal::signal_list_pending_decrypts,
            commands::signal::signal_ack_pending_decrypts,
            commands::signal::signal_delete_all_sessions,
            commands::signal::signal_install_transparency_verified_peer_identity,
            commands::signal::signal_revoke_transparency_peer_identity,
            commands::signal::signal_peek_prekey_identity,
            commands::signal::signal_init_storage,
            commands::websocket::ws_connect,
            commands::websocket::ws_disconnect,
            commands::websocket::ws_rotate_socks_identity,
            commands::websocket::ws_send,
            commands::websocket::ws_set_server_url,
            commands::websocket::ws_get_server_url,
            commands::websocket::ws_get_state,
            commands::websocket::ws_sync_tor_state,
            commands::p2p::p2p_connect,
            commands::p2p::p2p_disconnect,
            commands::p2p::p2p_rotate_identity,
            commands::p2p::p2p_send,
            commands::p2p::p2p_authenticate_connection,
            commands::p2p::p2p_local_endpoint,
            commands::discovery::anonymous_api_fetch,
            commands::discovery::prewarm_anonymous_transport,
            commands::notification::notification_show,
            commands::notification::notification_set_enabled,
            commands::system::get_instance_id,
            commands::system::open_external,
            commands::system::request_media_access,
            commands::system::get_screen_sources,
            commands::system::power_save_blocker_start,
            commands::system::power_save_blocker_stop,
            commands::system::get_close_to_tray,
            commands::system::set_close_to_tray,
            commands::system::tray_increment_unread,
            commands::system::tray_clear_unread,
            commands::session::session_get_background_state,
            commands::session::session_set_background_state,
            database::db_lock,
            database::db_set_secure,
            database::db_get_secure,
            database::db_has_secure,
            database::db_list_secure_keys,
            database::db_scan_secure_keys,
            database::db_mutate_secure,
            database::db_delete,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// init application services
async fn initialize_app(app_handle: &tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    info!("Initializing application services");

    let state = app_handle.state::<AppState>();
    let mut config_dir = app_handle.path().app_config_dir()?;
    let mut data_dir = app_handle.path().app_data_dir()?;

    // Instance isolation
    let instance_id = system::get_instance_id()?;
    info!("Applying instance isolation");
    let suffix = format!("-instance-{}", instance_id);

    // Handle config_dir
    let config_name = config_dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "Qor-chat-client".to_string());
    config_dir.set_file_name(format!("{}{}", config_name, suffix));

    // Handle data_dir
    let data_name = data_dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "com.qor.chat".to_string());
    data_dir.set_file_name(format!("{}{}", data_name, suffix));

    // Initialize Tor manager
    let tor_manager = tor::init(data_dir).await?;
    *state.tor_manager.write() = Some(tor_manager);
    info!("Embedded Tor runtime initialized");

    // Initialize secure storage
    storage::init(&state, config_dir).await?;
    info!("Secure storage initialized");

    // Initialize Signal Protocol handler
    signal_protocol::init(&state).await?;
    info!("Signal Protocol handler initialized");

    // Initialize WebSocket handler
    let ws_handler = network::websocket::init().await?;
    if let Some(secure_storage) = state.storage() {
        match secure_storage.get("server_url").await {
            Ok(Some(saved_server_url)) => {
                if ws_handler.set_server_url(&saved_server_url).await.is_err() {
                    tracing::warn!("Stored server endpoint was invalid and was not restored");
                }
            }
            Ok(None) => {}
            Err(_) => {
                tracing::warn!("Stored server endpoint could not be authenticated");
            }
        }
    }
    let (ws_tx, mut ws_rx) = mpsc::channel(network::websocket::WS_EVENT_CHANNEL_CAPACITY);
    ws_handler.set_event_handler(ws_tx);
    let ws_handler_for_bridge = Arc::downgrade(&ws_handler);
    *state.websocket_handler.write() = Some(ws_handler);
    info!("WebSocket handler initialized");

    // Start WebSocket event bridge
    let app_handle_ws = app_handle.clone();
    tauri::async_runtime::spawn(async move {
        use crate::network::websocket::WsEvent;
        while let Some(event) = ws_rx.recv().await {
            match event {
                WsEvent::Message {
                    connection_token,
                    data,
                    byte_len,
                } => {
                    let emitted = app_handle_ws.emit(
                        "ws-message",
                        serde_json::json!({
                            "connectionToken": connection_token,
                            "data": data,
                        }),
                    );
                    
                    crate::network::websocket::release_ws_inbound_bytes(byte_len);
                    if emitted.is_err()
                        && let Some(handler) = ws_handler_for_bridge.upgrade()
                    {
                        let _ = handler.disconnect(Some(connection_token)).await;
                    }
                }
                _ => {
                    let _ = app_handle_ws.emit("ws-lifecycle", event);
                }
            }
        }
    });

    if let Some(tor) = state.tor_manager() {
        network::p2p::set_tor_manager(tor);
    }

    // Initialize P2P transport handler
    let p2p_handler = network::p2p::init().await?;
    let (p2p_tx, mut p2p_rx) = mpsc::channel(network::p2p::P2P_EVENT_CHANNEL_CAPACITY);
    p2p_handler.set_event_handler(p2p_tx);
    let p2p_handler_for_bridge = Arc::downgrade(&p2p_handler);
    *state.p2p_handler.write() = Some(p2p_handler);
    info!("P2P transport handler initialized");

    // Start P2P event bridge
    let app_handle_p2p = app_handle.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = p2p_rx.recv().await {
            let release_bytes = match &event {
                network::p2p::P2PEvent::Message { byte_len, .. } => *byte_len,
                _ => 0,
            };
            let connection = match &event {
                network::p2p::P2PEvent::Connected {
                    connection_id,
                    connection_token,
                }
                | network::p2p::P2PEvent::Closed {
                    connection_id,
                    connection_token,
                    ..
                }
                | network::p2p::P2PEvent::Message {
                    connection_id,
                    connection_token,
                    ..
                } => Some((connection_id.clone(), *connection_token)),
            };
            let emitted = app_handle_p2p.emit("p2p-message", event);
            network::p2p::release_inbound_bytes(release_bytes);
            if emitted.is_err()
                && let (Some(handler), Some((connection_id, connection_token))) =
                    (p2p_handler_for_bridge.upgrade(), connection)
            {
                let _ = handler
                    .disconnect(&connection_id, Some(connection_token))
                    .await;
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
