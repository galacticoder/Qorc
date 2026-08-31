//! qorc Tauri Application main entry point

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
compile_error!("qorc desktop supports only Linux and Windows");

use std::sync::Arc;

#[cfg(target_os = "linux")]
use std::path::PathBuf;

use tauri::{Emitter, Manager};
use tokio::sync::mpsc;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

// Module declarations
mod account_vault;
mod audio_codec;
mod audio_playback;
mod camera_capture;
mod commands;
mod crypto;
mod database;
mod error;
mod hybrid_native;
mod json_bounds;
mod link_preview;
mod message_content;
mod microphone_capture;
mod network;
mod protocol_keys;
mod screen_capture;
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
fn prepend_env_paths(key: &str, candidates: Vec<PathBuf>) {
    let mut paths = candidates
        .into_iter()
        .filter(|candidate| candidate.is_dir())
        .collect::<Vec<_>>();
    if let Some(existing) = std::env::var_os(key) {
        for existing_path in std::env::split_paths(&existing) {
            if !paths.contains(&existing_path) {
                paths.push(existing_path);
            }
        }
    }
    if paths.is_empty() {
        return;
    }
    if let Ok(value) = std::env::join_paths(paths) {
        unsafe {
            std::env::set_var(key, value);
        }
    }
}

#[cfg(target_os = "linux")]
fn configure_linux_media_runtime() {
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let Some(binary_dir) = executable.parent() else {
        return;
    };
    if binary_dir.file_name().and_then(|name| name.to_str()) != Some("bin") {
        return;
    }
    let Some(usr_dir) = binary_dir.parent() else {
        return;
    };
    unsafe {
        std::env::set_var("QORC_GSTREAMER_REQUIRE_BUNDLED", "1");
    }
    let usr_lib = usr_dir.join("lib");
    let packaged_runtime = usr_lib.join("qorc").join("webkitgtk");
    let capture_plugin_path = usr_lib
        .join("qorc")
        .join("screen-capture")
        .join("gstreamer-1.0");
    let private_capture_plugin_path = packaged_runtime.join("capture-plugins");
    let private_plugin_path = packaged_runtime.join("gstreamer-1.0");
    let app_plugin_path = usr_lib.join("gstreamer-1.0");
    let private_library_path = packaged_runtime.join("lib");
    let plugin_paths = vec![private_plugin_path.clone(), app_plugin_path.clone()];
    let library_paths = vec![private_library_path.clone(), usr_lib.clone()];
    prepend_env_paths("GST_PLUGIN_PATH_1_0", plugin_paths);
    prepend_env_paths("LD_LIBRARY_PATH", library_paths);
    if let Some(capture_plugin_path) = [private_capture_plugin_path, capture_plugin_path]
        .into_iter()
        .find(|path| path.is_dir())
    {
        unsafe {
            std::env::set_var("QORC_GSTREAMER_CAPTURE_PLUGINS", capture_plugin_path);
        }
    }
    if private_library_path.is_dir() {
        unsafe {
            std::env::set_var("QORC_GSTREAMER_RUNTIME_LIB", &private_library_path);
        }
    } else if usr_lib.is_dir() {
        unsafe {
            std::env::set_var("QORC_GSTREAMER_RUNTIME_LIB", &usr_lib);
        }
    }

    unsafe {
        std::env::remove_var("SPA_PLUGIN_DIR");
        std::env::remove_var("QORC_GSTREAMER_SPA_PLUGINS");
    }
    let spa_paths = [packaged_runtime.join("spa-0.2"), usr_lib.join("spa-0.2")];
    if let Some(spa_path) = spa_paths
        .into_iter()
        .find(|path| screen_capture::spa_runtime_is_complete(path))
    {
        unsafe {
            std::env::set_var("SPA_PLUGIN_DIR", &spa_path);
            std::env::set_var("QORC_GSTREAMER_SPA_PLUGINS", spa_path);
        }
    }

    let gstreamer_launch = packaged_runtime.join("bin").join("qorc-gst-launch-1.0");
    if gstreamer_launch.is_file() {
        unsafe {
            std::env::set_var("QORC_GSTREAMER_LAUNCH", gstreamer_launch);
        }
    }
    let plugin_scanner = [
        packaged_runtime.join("bin").join("qorc-gst-plugin-scanner"),
        binary_dir.join("qorc-gst-plugin-scanner"),
    ]
    .into_iter()
    .find(|candidate| candidate.is_file());
    if let Some(plugin_scanner) = plugin_scanner {
        unsafe {
            std::env::set_var("GST_PLUGIN_SCANNER_1_0", &plugin_scanner);
            std::env::set_var("QORC_GSTREAMER_PLUGIN_SCANNER", plugin_scanner);
        }
    }
}

#[cfg(target_os = "linux")]
fn configure_linux_webview_rendering() {
    set_env_default("WEBKIT_DMABUF_RENDERER_FORCE_SHM", "1");
    configure_linux_media_runtime();

    if std::env::var_os("QORC_SOFTWARE_RENDERING").is_some() {
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
        .unwrap_or_else(|_| EnvFilter::new("error,qorc=error"));

    for directive in [
        "qorc_lib::network::websocket=info",
        "qorc_lib::commands::websocket=info",
        "qorc_lib::commands::system=info",
        "qorc_lib::commands::camera=info",
        "qorc_lib::camera_capture=info",
        "qorc_lib::commands::microphone=info",
        "qorc_lib::microphone_capture=info",
        "qorc_lib::commands::message_content=info",
        "qorc_lib::link_preview=info",
        "qorc_call_diag=info",
        "pulseaudio::client::reactor=off",
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
    let context = tauri::generate_context!();
    init_logging();
    std::panic::set_hook(Box::new(|panic_info| {
        let message = panic_info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| {
                panic_info
                    .payload()
                    .downcast_ref::<String>()
                    .map(String::as_str)
            })
            .unwrap_or("non-string panic payload");
        if let Some(location) = panic_info.location() {
            error!(
                panic_message = %message,
                panic_file = location.file(),
                panic_line = location.line(),
                panic_column = location.column(),
                "[RUST-PANIC] application terminated unexpectedly"
            );
        } else {
            error!(
                panic_message = %message,
                "[RUST-PANIC] application terminated unexpectedly"
            );
        }
    }));

    install_rustls_provider();
    info!("Starting qorc v{}", env!("CARGO_PKG_VERSION"));
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
                    use webkit2gtk::glib::{object::Cast, translate::ToGlibPtr};
                    use webkit2gtk::{
                        PermissionRequestExt, UserMediaPermissionRequestExt, WebViewExt,
                    };
                    let wv = webview.inner();
                    wv.connect_permission_request(|_wv, req| {
                        info!(target: "qorc_call_diag", "[CALL-DIAG] webkit-permission-callback-enter");
                        if let Some(media_request) =
                            req.downcast_ref::<webkit2gtk::UserMediaPermissionRequest>()
                        {
                            let requests_audio = media_request.is_for_audio_device();
                            let requests_video = media_request.is_for_video_device();
                            info!(
                                target: "qorc_call_diag",
                                requests_audio,
                                requests_video,
                                "[CALL-DIAG] webkit-media-request-classified"
                            );
                            info!(target: "qorc_call_diag", "[CALL-DIAG] webkit-display-check-before");
                            let is_display = unsafe {
                                webkit2gtk::ffi::webkit_user_media_permission_is_for_display_device(
                                    media_request.to_glib_none().0,
                                ) != 0
                            };
                            info!(
                                target: "qorc_call_diag",
                                is_display,
                                "[CALL-DIAG] webkit-display-check-after"
                            );
                            let allowed = is_display
                                || crate::commands::system::consume_media_permission_lease(
                                    requests_audio,
                                    requests_video,
                                );
                            info!(
                                target: "qorc_call_diag",
                                requests_audio,
                                requests_video,
                                is_display,
                                allowed,
                                "[CALL-DIAG] webkit-permission-decision"
                            );
                            if allowed {
                                info!(target: "qorc_call_diag", "[CALL-DIAG] webkit-permission-allow-before");
                                req.allow();
                                info!(target: "qorc_call_diag", "[CALL-DIAG] webkit-permission-allow-after");
                            } else {
                                info!(target: "qorc_call_diag", "[CALL-DIAG] webkit-permission-deny-before");
                                req.deny();
                                info!(target: "qorc_call_diag", "[CALL-DIAG] webkit-permission-deny-after");
                            }
                            true
                        } else {
                            info!(target: "qorc_call_diag", "[CALL-DIAG] webkit-permission-non-media");
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
            commands::pir::pir_generate_batch_query,
            commands::pir::pir_decode_response,
            commands::pir::pir_decode_batch_response,
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
            commands::message_content::message_content_link_targets,
            commands::message_content::message_link_preview_fetch,
            commands::message_content::message_content_clone_for_display,
            commands::message_content::message_content_copy,
            commands::message_content::message_content_revoke_send,
            commands::message_content::message_content_delete,
            commands::audio::audio_opus_start,
            commands::audio::audio_opus_stop,
            commands::audio::audio_opus_encode,
            commands::audio::audio_opus_decode,
            commands::audio::audio_opus_decode_playback,
            commands::audio::audio_playback_start,
            commands::audio::audio_playback_stop,
            commands::camera::camera_devices,
            commands::camera::camera_capture_start,
            commands::camera::camera_capture_set_enabled,
            commands::camera::camera_capture_pull,
            commands::camera::camera_capture_stop,
            commands::screen_capture::screen_capture_start,
            commands::screen_capture::screen_capture_pull,
            commands::screen_capture::screen_capture_stop,
            commands::microphone::microphone_devices,
            commands::microphone::audio_output_devices,
            commands::microphone::microphone_capture_start,
            commands::microphone::microphone_capture_set_enabled,
            commands::microphone::microphone_capture_pull,
            commands::microphone::microphone_capture_stop,
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
            commands::websocket::ws_send_binary,
            commands::websocket::ws_receive_binary,
            commands::websocket::ws_set_server_url,
            commands::websocket::ws_get_server_url,
            commands::websocket::ws_get_state,
            commands::websocket::ws_sync_tor_state,
            commands::p2p::p2p_connect,
            commands::p2p::p2p_disconnect,
            commands::p2p::p2p_rotate_identity,
            commands::p2p::p2p_send,
            commands::p2p::p2p_subscribe,
            commands::p2p::p2p_receive,
            commands::p2p::p2p_unsubscribe,
            commands::p2p::p2p_authenticate_connection,
            commands::p2p::p2p_local_endpoint,
            commands::discovery::anonymous_api_fetch,
            commands::discovery::prewarm_anonymous_transport,
            commands::notification::notification_show,
            commands::notification::notification_set_enabled,
            commands::system::get_instance_id,
            commands::system::forward_client_logs,
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
        .run(context)
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
        .unwrap_or_else(|| "qorc-client".to_string());
    config_dir.set_file_name(format!("{}{}", config_name, suffix));

    // Handle data_dir
    let data_name = data_dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "com.qorc.app".to_string());
    data_dir.set_file_name(format!("{}{}", data_name, suffix));

    // Initialize Tor manager
    let pir_tor_data_dir = data_dir.join("pir-transport");
    let tor_manager = tor::init(data_dir).await?;
    let pir_tor_manager = tor::init(pir_tor_data_dir).await?;
    *state.tor_manager.write() = Some(tor_manager);
    *state.pir_tor_manager.write() = Some(pir_tor_manager);
    info!("Embedded Tor runtimes initialized");

    // Initialize secure storage
    storage::init(&state, config_dir).await?;
    info!("Storage initialized");

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
    let (ws_binary_tx, ws_binary_rx) = mpsc::channel(network::websocket::WS_EVENT_CHANNEL_CAPACITY);
    ws_handler.set_event_handler(ws_tx);
    ws_handler.set_binary_handler(ws_binary_tx);
    let ws_handler_for_bridge = Arc::downgrade(&ws_handler);
    *state.websocket_handler.write() = Some(ws_handler);
    *state.websocket_binary_receiver.lock().await = Some(ws_binary_rx);
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
    let (p2p_tx, p2p_rx) = mpsc::channel(network::p2p::P2P_EVENT_CHANNEL_CAPACITY);
    p2p_handler.set_event_handler(p2p_tx);
    *state.p2p_handler.write() = Some(p2p_handler);
    *state.p2p_event_receiver.lock().await = Some(p2p_rx);
    info!("P2P transport handler initialized");

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
