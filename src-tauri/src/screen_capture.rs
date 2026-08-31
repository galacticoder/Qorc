use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::future::Future;
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
use ashpd::desktop::screencast::{CursorMode, Screencast, SelectSourcesOptions, SourceType};
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
use tokio::sync::Notify;
use tokio::sync::oneshot;

const MAX_SESSIONS: usize = 1;
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_CAPTURE_BUFFER_BYTES: usize = MAX_FRAME_BYTES * 2;
const FRAME_WAIT: Duration = Duration::from_secs(1);
const START_WAIT: Duration = Duration::from_secs(120);
const CAPTURE_WIDTH: u16 = 1280;
const CAPTURE_HEIGHT: u16 = 720;
const CAPTURE_FRAME_RATE: u16 = 60;
#[cfg(target_os = "linux")]
const GSTREAMER_FIRST_FRAME_WAIT: Duration = Duration::from_secs(8);
#[cfg(target_os = "linux")]
const CAPTURE_PLUGINS: [&str; 5] = [
    "libgstcoreelements.so",
    "libgstjpeg.so",
    "libgstpipewire.so",
    "libgstvideoconvertscale.so",
    "libgstvideorate.so",
];
#[cfg(target_os = "linux")]
const REQUIRED_SPA_PLUGINS: [&str; 2] = [
    "support/libspa-support.so",
    "videoconvert/libspa-videoconvert.so",
];

pub struct ScreenFrame {
    pub sequence: u64,
    pub captured_at: u64,
    pub width: u16,
    pub height: u16,
    pub frame_rate: u16,
    pub bytes: Vec<u8>,
}

struct FrameSlot {
    frame: Option<ScreenFrame>,
    stopped: bool,
}

type StartNotifier = Arc<Mutex<Option<oneshot::Sender<Result<(), String>>>>>;

struct ScreenSession {
    stop: AtomicBool,
    slot: Mutex<FrameSlot>,
    ready: Condvar,
    cancel: Notify,
}

impl ScreenSession {
    fn new() -> Self {
        Self {
            stop: AtomicBool::new(false),
            slot: Mutex::new(FrameSlot {
                frame: None,
                stopped: false,
            }),
            ready: Condvar::new(),
            cancel: Notify::new(),
        }
    }

    fn publish(&self, frame: ScreenFrame) -> bool {
        if self.stop.load(Ordering::Acquire) {
            return false;
        }
        if let Ok(mut slot) = self.slot.lock() {
            let overwritten = slot.frame.is_some();
            if let Some(previous) = slot.frame.as_mut() {
                previous.bytes.fill(0);
            }
            slot.frame = Some(frame);
            self.ready.notify_all();
            return overwritten;
        }
        false
    }

    fn pull(&self, after_sequence: u64) -> Result<Option<ScreenFrame>, String> {
        let mut slot = self
            .slot
            .lock()
            .map_err(|_| "screen frame queue unavailable".to_string())?;
        let deadline = Instant::now() + FRAME_WAIT;
        loop {
            if slot
                .frame
                .as_ref()
                .is_some_and(|frame| frame.sequence > after_sequence)
            {
                return Ok(slot.frame.take());
            }
            if slot.stopped {
                return Err("screen capture stopped".to_string());
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let waited = self
                .ready
                .wait_timeout(slot, deadline.saturating_duration_since(now))
                .map_err(|_| "screen frame queue unavailable".to_string())?;
            slot = waited.0;
            if waited.1.timed_out() {
                return Ok(None);
            }
        }
    }

    fn finish(&self) {
        if let Ok(mut slot) = self.slot.lock() {
            if let Some(frame) = slot.frame.as_mut() {
                frame.bytes.fill(0);
            }
            slot.frame = None;
            slot.stopped = true;
            self.ready.notify_all();
        }
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        self.finish();
        self.cancel.notify_waiters();
        self.cancel.notify_one();
    }

    fn is_finished(&self) -> bool {
        self.slot.lock().map_or(true, |slot| slot.stopped)
    }
}

pub struct ScreenCaptureState {
    sessions: Mutex<HashMap<String, Arc<ScreenSession>>>,
}

impl ScreenCaptureState {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub async fn start(self: &Arc<Self>, session_id: &str) -> Result<(), String> {
        validate_session_id(session_id)?;
        self.stop(session_id)?;

        #[cfg(not(target_os = "linux"))]
        {
            return Err("native screen capture is unavailable on this platform".to_string());
        }

        #[cfg(target_os = "linux")]
        {
            let session = Arc::new(ScreenSession::new());
            let replaced = {
                let mut sessions = self
                    .sessions
                    .lock()
                    .map_err(|_| "screen capture unavailable".to_string())?;
                sessions.retain(|_, existing| !existing.is_finished());
                if sessions.len() >= MAX_SESSIONS && !sessions.contains_key(session_id) {
                    return Err("screen capture session limit reached".to_string());
                }
                sessions.insert(session_id.to_string(), session.clone())
            };
            if let Some(replaced) = replaced {
                replaced.stop();
            }

            let (started_tx, started_rx) = oneshot::channel();
            let notifier = Arc::new(Mutex::new(Some(started_tx)));
            let task_session = session.clone();
            let task_notifier = notifier;
            let task_state = Arc::downgrade(self);
            let task_session_id = session_id.to_string();
            let _ = tokio::spawn(async move {
                let result = run_portal_capture(task_session.clone(), task_notifier.clone()).await;
                if let Err(error) = result {
                    notify_start(&task_notifier, Err(error.clone()));
                    tracing::warn!(target: "qorc_call_diag", error = %error, "[CALL-DIAG] native-screen-capture-failed");
                }
                task_session.finish();
                if let Some(state) = task_state.upgrade()
                    && let Ok(mut sessions) = state.sessions.lock()
                    && sessions
                        .get(&task_session_id)
                        .is_some_and(|current| Arc::ptr_eq(current, &task_session))
                {
                    sessions.remove(&task_session_id);
                }
            });

            let result = match tokio::time::timeout(START_WAIT, started_rx).await {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => Err("screen capture startup cancelled".to_string()),
                Err(_) => Err("screen capture startup timed out".to_string()),
            };
            if let Err(error) = result {
                let _ = self.stop_if_current(session_id, &session);
                return Err(error);
            }
            Ok(())
        }
    }

    pub fn pull(
        &self,
        session_id: &str,
        after_sequence: u64,
    ) -> Result<Option<ScreenFrame>, String> {
        self.session(session_id)?.pull(after_sequence)
    }

    pub fn stop(&self, session_id: &str) -> Result<(), String> {
        validate_session_id(session_id)?;
        let session = self
            .sessions
            .lock()
            .map_err(|_| "screen capture unavailable".to_string())?
            .remove(session_id);
        if let Some(session) = session {
            session.stop();
        }
        Ok(())
    }

    fn stop_if_current(
        &self,
        session_id: &str,
        expected: &Arc<ScreenSession>,
    ) -> Result<(), String> {
        validate_session_id(session_id)?;
        let session = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| "screen capture unavailable".to_string())?;
            if sessions
                .get(session_id)
                .is_some_and(|current| Arc::ptr_eq(current, expected))
            {
                sessions.remove(session_id)
            } else {
                None
            }
        };
        if let Some(session) = session {
            session.stop();
        }
        Ok(())
    }

    fn session(&self, session_id: &str) -> Result<Arc<ScreenSession>, String> {
        validate_session_id(session_id)?;
        self.sessions
            .lock()
            .map_err(|_| "screen capture unavailable".to_string())?
            .get(session_id)
            .cloned()
            .ok_or_else(|| "screen capture session unavailable".to_string())
    }
}

impl Default for ScreenCaptureState {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ScreenCaptureState {
    fn drop(&mut self) {
        if let Ok(sessions) = self.sessions.get_mut() {
            for session in sessions.values() {
                session.stop();
            }
            sessions.clear();
        }
    }
}

fn notify_start(notifier: &StartNotifier, result: Result<(), String>) {
    if let Ok(mut notifier) = notifier.lock()
        && let Some(notifier) = notifier.take()
    {
        let _ = notifier.send(result);
    }
}

#[cfg(target_os = "linux")]
async fn run_portal_capture(
    session: Arc<ScreenSession>,
    notifier: StartNotifier,
) -> Result<(), String> {
    let portal_started_at = Instant::now();
    tracing::info!(target: "qorc_call_diag", "[CALL-DIAG] native-screen-portal-create-before");
    let proxy = portal_step(
        &session,
        Screencast::new(),
        "screen capture portal unavailable",
    )
    .await?;
    tracing::info!(
        target: "qorc_call_diag",
        elapsed_ms = portal_started_at.elapsed().as_millis(),
        "[CALL-DIAG] native-screen-portal-create-after"
    );
    let available_sources = portal_step(
        &session,
        proxy.available_source_types(),
        "screen capture source capabilities are unavailable",
    )
    .await?;
    let requested_sources = available_sources & (SourceType::Monitor | SourceType::Window);
    if requested_sources.is_empty() {
        return Err("screen capture portal supports no monitor or window sources".to_string());
    }
    let portal_session = portal_step(
        &session,
        proxy.create_session(Default::default()),
        "screen capture session could not be created",
    )
    .await?;
    let capture_result = async {
        let mut options = SelectSourcesOptions::default()
            .set_sources(requested_sources)
            .set_multiple(false);
        if proxy.version() >= 2 {
            let available_cursor_modes = portal_step(
                &session,
                proxy.available_cursor_modes(),
                "screen capture cursor capabilities are unavailable",
            )
            .await?;
            if available_cursor_modes.contains(CursorMode::Embedded) {
                options = options.set_cursor_mode(CursorMode::Embedded);
            }
        }
        let select_request = portal_step(
            &session,
            proxy.select_sources(&portal_session, options),
            "screen source selection failed",
        )
        .await?;
        select_request
            .response()
            .map_err(|error| format!("screen source selection was not allowed: {error}"))?;
        tracing::info!(
            target: "qorc_call_diag",
            elapsed_ms = portal_started_at.elapsed().as_millis(),
            "[CALL-DIAG] native-screen-portal-select-after"
        );
        tracing::info!(target: "qorc_call_diag", "[CALL-DIAG] native-screen-portal-start-before");
        let start_request = portal_step(
            &session,
            proxy.start(&portal_session, None, Default::default()),
            "screen capture request failed",
        )
        .await?;
        let response = start_request
            .response()
            .map_err(|error| format!("screen capture was not allowed: {error}"))?;
        tracing::info!(
            target: "qorc_call_diag",
            elapsed_ms = portal_started_at.elapsed().as_millis(),
            "[CALL-DIAG] native-screen-portal-start-after"
        );
        let node_id = response
            .streams()
            .first()
            .map(|stream| stream.pipe_wire_node_id())
            .ok_or_else(|| "screen capture returned no stream".to_string())?;
        let remote = portal_step(
            &session,
            proxy.open_pipe_wire_remote(&portal_session, Default::default()),
            "screen capture PipeWire connection failed",
        )
        .await?;
        tracing::info!(
            target: "qorc_call_diag",
            node_id,
            elapsed_ms = portal_started_at.elapsed().as_millis(),
            "[CALL-DIAG] native-screen-pipewire-ready"
        );
        let worker_session = session.clone();
        let worker_notifier = notifier.clone();
        tokio::task::spawn_blocking(move || {
            run_gstreamer_capture(worker_session, remote, node_id, worker_notifier)
        })
        .await
        .map_err(|_| "screen capture worker failed".to_string())?
    }
    .await;
    if let Err(error) = &capture_result {
        notify_start(&notifier, Err(error.clone()));
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), portal_session.close()).await;
    capture_result
}

#[cfg(target_os = "linux")]
async fn portal_step<T, E, F>(
    session: &Arc<ScreenSession>,
    future: F,
    context: &str,
) -> Result<T, String>
where
    F: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    if session.stop.load(Ordering::Acquire) {
        return Err("screen capture cancelled".to_string());
    }
    tokio::select! {
        result = future => result.map_err(|error| format!("{context}: {error}")),
        _ = session.cancel.notified() => Err("screen capture cancelled".to_string()),
    }
}

#[cfg(target_os = "linux")]
fn run_gstreamer_capture(
    session: Arc<ScreenSession>,
    remote: OwnedFd,
    node_id: u32,
    notifier: StartNotifier,
) -> Result<(), String> {
    let capture_started_at = Instant::now();
    let bundled_only = require_bundled_gstreamer();
    let launcher = resolve_gstreamer_launcher()
        .ok_or_else(|| "bundled GStreamer screen capture runtime is unavailable".to_string())?;
    let plugin_path = resolve_gstreamer_plugins(&launcher)
        .ok_or_else(|| "GStreamer screen capture plugins are unavailable".to_string())?;
    let library_path = resolve_gstreamer_library_path(&plugin_path);
    let spa_path = resolve_gstreamer_spa_path(&plugin_path);
    let scanner = resolve_gstreamer_scanner(&launcher);
    if bundled_only && library_path.is_none() {
        return Err("bundled GStreamer screen capture libraries are unavailable".to_string());
    }
    if bundled_only && spa_path.is_none() {
        return Err("bundled PipeWire SPA runtime is unavailable".to_string());
    }
    if let Some(spa_path) = spa_path.as_ref() {
        let missing = missing_spa_plugins(spa_path);
        if !missing.is_empty() {
            return Err(format!(
                "PipeWire SPA runtime is incomplete at {} (missing: {})",
                spa_path.display(),
                missing.join(", ")
            ));
        }
    }
    if bundled_only && scanner.is_none() {
        return Err("bundled GStreamer plugin scanner is unavailable".to_string());
    }
    tracing::info!(
        target: "qorc_call_diag",
        launcher = %launcher.display(),
        plugin_path = %plugin_path.display(),
        target_fps = CAPTURE_FRAME_RATE,
        bundled_only,
        "[CALL-DIAG] native-screen-gstreamer-start-before"
    );
    let max_rate = format!("max-rate={CAPTURE_FRAME_RATE}");
    let output_caps = format!(
        "video/x-raw,format=I420,width=1280,height=720,framerate={CAPTURE_FRAME_RATE}/1,pixel-aspect-ratio=1/1"
    );
    let mut command = Command::new(&launcher);
    command
        .env("GST_PLUGIN_PATH_1_0", &plugin_path)
        .env("GST_PLUGIN_SYSTEM_PATH_1_0", "")
        .env("GST_PLUGIN_PATH", "")
        .env("GST_PLUGIN_SYSTEM_PATH", "")
        .env("GST_REGISTRY_FORK", "no")
        .env_remove("GST_REGISTRY_UPDATE")
        .env_remove("GST_REGISTRY_REUSE_PLUGIN_SCANNER")
        .args([
            "-q",
            "pipewiresrc",
            "fd=0",
            &format!("path={node_id}"),
            "do-timestamp=true",
            "on-disconnect=eos",
            "!",
            "queue",
            "leaky=downstream",
            "max-size-buffers=1",
            "max-size-bytes=0",
            "max-size-time=0",
            "!",
            "videorate",
            "drop-only=true",
            &max_rate,
            "!",
            "videoconvertscale",
            "n-threads=2",
            "add-borders=true",
            "!",
            &output_caps,
            "!",
            "jpegenc",
            "quality=80",
            "idct-method=ifast",
            "!",
            "fdsink",
            "fd=1",
            "sync=false",
        ]);
    if let Some(registry_path) = resolve_gstreamer_registry_path() {
        command
            .env("GST_REGISTRY", &registry_path)
            .env("GST_REGISTRY_1_0", registry_path);
    } else {
        command
            .env_remove("GST_REGISTRY")
            .env_remove("GST_REGISTRY_1_0");
    }
    if let Some(library_path) = library_path {
        command.env("LD_LIBRARY_PATH", library_path);
    } else {
        command.env_remove("LD_LIBRARY_PATH");
    }
    if let Some(spa_path) = spa_path {
        command.env("SPA_PLUGIN_DIR", spa_path);
    } else {
        command.env_remove("SPA_PLUGIN_DIR");
    }
    if let Some(scanner) = scanner {
        command.env("GST_PLUGIN_SCANNER_1_0", scanner);
    } else {
        command.env_remove("GST_PLUGIN_SCANNER_1_0");
    }
    if std::env::var_os("PIPEWIRE_DEBUG").is_none() {
        command.env("PIPEWIRE_DEBUG", "1");
    }
    let parent_pid = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent_pid {
                return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
    let mut child = command
        .stdin(Stdio::from(remote))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("GStreamer screen capture could not start: {error}"))?;
    tracing::info!(
        target: "qorc_call_diag",
        spawn_ms = capture_started_at.elapsed().as_millis(),
        process_id = child.id(),
        "[CALL-DIAG] native-screen-gstreamer-start-after"
    );
    let Some(mut stdout) = child.stdout.take() else {
        terminate_capture_process(&mut child);
        return Err("GStreamer screen capture output is unavailable".to_string());
    };
    let Some(mut stderr) = child.stderr.take() else {
        terminate_capture_process(&mut child);
        return Err("GStreamer screen capture diagnostics are unavailable".to_string());
    };
    if let Err(error) = set_nonblocking(stdout.as_raw_fd()) {
        terminate_capture_process(&mut child);
        return Err(error);
    }
    if let Err(error) = set_nonblocking(stderr.as_raw_fd()) {
        terminate_capture_process(&mut child);
        return Err(error);
    }
    let first_frame_started_at = Instant::now();

    let mut input = [0u8; 64 * 1024];
    let mut buffered = Vec::with_capacity(512 * 1024);
    let mut stderr_input = [0u8; 4 * 1024];
    let mut stderr_output = Vec::new();
    let mut sequence = 0u64;
    let mut total_jpeg_bytes = 0u64;
    let mut overwritten_frames = 0u64;
    let mut largest_jpeg_bytes = 0usize;
    let mut report_started_at = Instant::now();
    let mut report_frames = 0u64;
    let result = loop {
        drain_capture_stderr(&mut stderr, &mut stderr_input, &mut stderr_output);
        if session.stop.load(Ordering::Acquire) {
            break Ok(());
        }
        match stdout.read(&mut input) {
            Ok(0) => break Err(capture_process_exit_error(&mut child)),
            Ok(length) => {
                buffered.extend_from_slice(&input[..length]);
                if buffered.len() > MAX_CAPTURE_BUFFER_BYTES {
                    buffered.fill(0);
                    buffered.clear();
                    break Err("screen capture frame exceeded the size limit".to_string());
                }
                while let Some(mut frame) = take_jpeg_frame(&mut buffered) {
                    if frame.len() > MAX_FRAME_BYTES {
                        frame.fill(0);
                        continue;
                    }
                    sequence = sequence.wrapping_add(1).max(1);
                    let jpeg_bytes = frame.len();
                    total_jpeg_bytes = total_jpeg_bytes.saturating_add(jpeg_bytes as u64);
                    largest_jpeg_bytes = largest_jpeg_bytes.max(jpeg_bytes);
                    report_frames += 1;
                    if session.publish(ScreenFrame {
                        sequence,
                        captured_at: now_ms(),
                        width: CAPTURE_WIDTH,
                        height: CAPTURE_HEIGHT,
                        frame_rate: CAPTURE_FRAME_RATE,
                        bytes: frame,
                    }) {
                        overwritten_frames = overwritten_frames.saturating_add(1);
                    }
                    if sequence == 1 {
                        tracing::info!(
                            target: "qorc_call_diag",
                            startup_ms = capture_started_at.elapsed().as_millis(),
                            jpeg_bytes,
                            "[CALL-DIAG] native-screen-first-frame"
                        );
                    }
                    notify_start(&notifier, Ok(()));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if child
                    .try_wait()
                    .map_err(|error| format!("screen capture process status failed: {error}"))?
                    .is_some()
                {
                    break Err(capture_process_exit_error(&mut child));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => break Err(format!("screen capture output failed: {error}")),
        }
        if sequence == 0 && first_frame_started_at.elapsed() >= GSTREAMER_FIRST_FRAME_WAIT {
            break Err(
                "GStreamer screen capture produced no first frame within 8 seconds".to_string(),
            );
        }
        if report_started_at.elapsed() >= Duration::from_secs(5) {
            let elapsed_seconds = report_started_at.elapsed().as_secs_f64().max(0.001);
            tracing::info!(
                target: "qorc_call_diag",
                frames = report_frames,
                fps = report_frames as f64 / elapsed_seconds,
                overwritten_frames,
                buffered_bytes = buffered.len(),
                largest_jpeg_bytes,
                "[CALL-DIAG] native-screen-capture-window"
            );
            report_started_at = Instant::now();
            report_frames = 0;
        }
    };
    terminate_capture_process(&mut child);
    drain_capture_stderr(&mut stderr, &mut stderr_input, &mut stderr_output);
    let stderr = String::from_utf8_lossy(&stderr_output).into_owned();
    tracing::info!(
        target: "qorc_call_diag",
        frames = sequence,
        total_jpeg_bytes,
        overwritten_frames,
        largest_jpeg_bytes,
        elapsed_ms = capture_started_at.elapsed().as_millis(),
        "[CALL-DIAG] native-screen-capture-ended"
    );
    buffered.fill(0);
    match result {
        Err(error) if !stderr.trim().is_empty() => {
            let detail = stderr
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(1_000)
                .collect::<String>();
            Err(format!("{error}: {detail}"))
        }
        result => result,
    }
}

#[cfg(target_os = "linux")]
fn drain_capture_stderr(stderr: &mut impl Read, input: &mut [u8], output: &mut Vec<u8>) {
    const STDERR_LIMIT: usize = 16 * 1024;
    loop {
        match stderr.read(input) {
            Ok(0) => break,
            Ok(length) => {
                output.extend_from_slice(&input[..length]);
                if output.len() > STDERR_LIMIT {
                    let excess = output.len() - STDERR_LIMIT;
                    output.drain(..excess);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

#[cfg(target_os = "linux")]
fn terminate_capture_process(child: &mut std::process::Child) {
    let process_group = -(child.id() as i32);
    unsafe {
        libc::kill(process_group, libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(target_os = "linux")]
fn capture_process_exit_error(child: &mut std::process::Child) -> String {
    match child.try_wait() {
        Ok(Some(status)) => format!("GStreamer screen capture ended with {status}"),
        Ok(None) => "GStreamer screen capture output closed".to_string(),
        Err(error) => format!("screen capture process status failed: {error}"),
    }
}

#[cfg(target_os = "linux")]
fn take_jpeg_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    let start = buffer.windows(2).position(|bytes| bytes == [0xff, 0xd8]);
    let Some(start) = start else {
        if buffer.last() == Some(&0xff) {
            let last = buffer.pop().unwrap_or_default();
            buffer.fill(0);
            buffer.clear();
            buffer.push(last);
        } else {
            buffer.fill(0);
            buffer.clear();
        }
        return None;
    };
    if start > 0 {
        buffer[..start].fill(0);
        buffer.drain(..start);
    }
    let end = buffer[2..]
        .windows(2)
        .position(|bytes| bytes == [0xff, 0xd9])?
        + 4;
    Some(buffer.drain(..end).collect())
}

#[cfg(target_os = "linux")]
fn set_nonblocking(fd: std::os::fd::RawFd) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        Err("screen capture output could not be configured".to_string())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn resolve_gstreamer_launcher() -> Option<PathBuf> {
    if let Some(configured) = std::env::var_os("QORC_GSTREAMER_LAUNCH") {
        let configured = PathBuf::from(configured);
        if configured.is_file() {
            return Some(configured);
        }
    }
    let mut candidates = Vec::new();
    if let Ok(executable) = std::env::current_exe()
        && let Some(binary_dir) = executable.parent()
    {
        candidates.push(binary_dir.join("qorc-gst-launch-1.0"));
        if let Some(usr_dir) = binary_dir.parent() {
            candidates.push(
                usr_dir
                    .join("lib")
                    .join("qorc")
                    .join("webkitgtk")
                    .join("bin")
                    .join("qorc-gst-launch-1.0"),
            );
        }
    }
    if !require_bundled_gstreamer() {
        candidates.push(PathBuf::from("/usr/bin/gst-launch-1.0"));
        candidates.push(PathBuf::from("/bin/gst-launch-1.0"));
    }
    candidates.into_iter().find(|candidate| candidate.is_file())
}

#[cfg(target_os = "linux")]
fn resolve_gstreamer_plugins(launcher: &std::path::Path) -> Option<PathBuf> {
    let mut candidates = std::env::var_os("QORC_GSTREAMER_CAPTURE_PLUGINS")
        .map(PathBuf::from)
        .into_iter()
        .collect::<Vec<_>>();
    if let Some(bin_dir) = launcher.parent()
        && let Some(runtime_dir) = bin_dir.parent()
    {
        candidates.push(runtime_dir.join("capture-plugins"));
        if !require_bundled_gstreamer() {
            candidates.push(runtime_dir.join("gstreamer-1.0"));
            if runtime_dir.file_name().and_then(|name| name.to_str()) == Some("runtime")
                && let Some(staging_dir) = runtime_dir.parent()
            {
                candidates.push(staging_dir.to_path_buf());
            }
        }
    }
    if let Ok(executable) = std::env::current_exe()
        && let Some(binary_dir) = executable.parent()
        && let Some(usr_dir) = binary_dir.parent()
    {
        candidates.push(
            usr_dir
                .join("lib")
                .join("qorc")
                .join("webkitgtk")
                .join("capture-plugins"),
        );
        candidates.push(
            usr_dir
                .join("lib")
                .join("qorc")
                .join("screen-capture")
                .join("gstreamer-1.0"),
        );
        if !require_bundled_gstreamer() {
            candidates.push(usr_dir.join("lib").join("gstreamer-1.0"));
        }
    }
    if !require_bundled_gstreamer() {
        candidates.extend([
            PathBuf::from("/usr/lib/x86_64-linux-gnu/gstreamer-1.0"),
            PathBuf::from("/usr/lib/aarch64-linux-gnu/gstreamer-1.0"),
            PathBuf::from("/usr/lib64/gstreamer-1.0"),
            PathBuf::from("/usr/lib/gstreamer-1.0"),
        ]);
    }
    candidates.into_iter().find(|candidate| {
        candidate.is_dir()
            && CAPTURE_PLUGINS
                .iter()
                .all(|plugin| candidate.join(plugin).is_file())
    })
}

#[cfg(target_os = "linux")]
fn resolve_gstreamer_library_path(plugin_path: &std::path::Path) -> Option<PathBuf> {
    if let Some(configured) = std::env::var_os("QORC_GSTREAMER_RUNTIME_LIB") {
        let configured = PathBuf::from(configured);
        if configured.is_dir() {
            return Some(configured);
        }
    }
    let runtime_library = plugin_path.join("runtime").join("lib");
    if runtime_library.is_dir() {
        return Some(runtime_library);
    }
    if let Some(runtime_library) = plugin_path.parent().map(|path| path.join("lib"))
        && runtime_library.is_dir()
    {
        return Some(runtime_library);
    }
    if require_bundled_gstreamer() {
        None
    } else {
        plugin_path
            .parent()
            .filter(|path| path.is_dir())
            .map(PathBuf::from)
    }
}

#[cfg(target_os = "linux")]
fn resolve_gstreamer_spa_path(plugin_path: &std::path::Path) -> Option<PathBuf> {
    if let Some(configured) = std::env::var_os("QORC_GSTREAMER_SPA_PLUGINS") {
        let configured = PathBuf::from(configured);
        return configured.is_dir().then_some(configured);
    }
    let mut candidates = vec![
        plugin_path.join("runtime").join("spa-0.2"),
        plugin_path
            .parent()
            .map(|path| path.join("spa-0.2"))
            .unwrap_or_default(),
    ];
    if !require_bundled_gstreamer() {
        candidates.extend([
            PathBuf::from("/usr/lib/x86_64-linux-gnu/spa-0.2"),
            PathBuf::from("/usr/lib/aarch64-linux-gnu/spa-0.2"),
            PathBuf::from("/usr/lib64/spa-0.2"),
            PathBuf::from("/usr/lib/spa-0.2"),
        ]);
    }
    let mut first_existing = None;
    for candidate in candidates {
        if !candidate.is_dir() {
            continue;
        }
        if spa_runtime_is_complete(&candidate) {
            return Some(candidate);
        }
        if first_existing.is_none() {
            first_existing = Some(candidate);
        }
    }
    first_existing
}

#[cfg(target_os = "linux")]
fn missing_spa_plugins(spa_root: &std::path::Path) -> Vec<&'static str> {
    REQUIRED_SPA_PLUGINS
        .iter()
        .copied()
        .filter(|relative_path| !spa_root.join(relative_path).is_file())
        .collect()
}

#[cfg(target_os = "linux")]
pub(crate) fn spa_runtime_is_complete(spa_root: &std::path::Path) -> bool {
    spa_root.is_dir() && missing_spa_plugins(spa_root).is_empty()
}

#[cfg(target_os = "linux")]
fn resolve_gstreamer_scanner(launcher: &std::path::Path) -> Option<PathBuf> {
    if let Some(configured) = std::env::var_os("QORC_GSTREAMER_PLUGIN_SCANNER") {
        let configured = PathBuf::from(configured);
        if configured.is_file() {
            return Some(configured);
        }
    }
    launcher
        .parent()
        .map(|path| path.join("qorc-gst-plugin-scanner"))
        .filter(|candidate| candidate.is_file())
}

#[cfg(target_os = "linux")]
fn require_bundled_gstreamer() -> bool {
    std::env::var_os("QORC_GSTREAMER_REQUIRE_BUNDLED")
        .is_some_and(|value| value == std::ffi::OsStr::new("1"))
}

#[cfg(target_os = "linux")]
fn resolve_gstreamer_registry_path() -> Option<PathBuf> {
    if let Some(configured) = std::env::var_os("QORC_GSTREAMER_REGISTRY") {
        let configured = PathBuf::from(configured);
        if let Some(parent) = configured.parent()
            && std::fs::create_dir_all(parent).is_ok()
        {
            return Some(configured);
        }
    }
    let runtime_dir = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?);
    if !runtime_dir.is_absolute() || !runtime_dir.is_dir() {
        return None;
    }
    let registry_dir = runtime_dir.join("qorc");
    std::fs::create_dir_all(&registry_dir).ok()?;
    Some(registry_dir.join("gstreamer-registry-1.0.bin"))
}

fn validate_session_id(session_id: &str) -> Result<(), String> {
    if (16..=64).contains(&session_id.len())
        && session_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err("invalid screen capture session".to_string())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
