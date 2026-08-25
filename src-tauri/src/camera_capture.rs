use image::{ExtendedColorType, RgbImage, codecs::jpeg::JpegEncoder};
#[cfg(target_os = "windows")]
use nokhwa::{
    Camera,
    pixel_format::RgbFormat,
    query,
    utils::{
        ApiBackend, CameraFormat, CameraIndex, FrameFormat, RequestedFormat, RequestedFormatType,
    },
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(target_os = "linux")]
use v4l::{
    Format, FourCC,
    buffer::Type,
    context,
    frameinterval::FrameIntervalEnum,
    framesize::FrameSizeEnum,
    io::traits::CaptureStream,
    prelude::{Device, MmapStream},
    video::{Capture, capture::Parameters},
};

const MAX_SESSIONS: usize = 2;
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const FRAME_WAIT: Duration = Duration::from_secs(1);
const START_WAIT: Duration = Duration::from_secs(10);

#[derive(Clone, Serialize)]
pub struct CameraDevice {
    pub device_id: String,
    pub label: String,
}

pub struct CameraFrame {
    pub sequence: u64,
    pub captured_at: u64,
    pub width: u16,
    pub height: u16,
    pub frame_rate: u16,
    pub enabled: bool,
    pub bytes: Vec<u8>,
}

struct FrameSlot {
    frame: Option<CameraFrame>,
    stopped: bool,
}

struct CameraSession {
    enabled: AtomicBool,
    stop: AtomicBool,
    slot: Mutex<FrameSlot>,
    ready: Condvar,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl CameraSession {
    fn new() -> Self {
        Self {
            enabled: AtomicBool::new(true),
            stop: AtomicBool::new(false),
            slot: Mutex::new(FrameSlot {
                frame: None,
                stopped: false,
            }),
            ready: Condvar::new(),
            worker: Mutex::new(None),
        }
    }

    fn publish(&self, frame: CameraFrame) -> bool {
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

    fn finish(&self) {
        if let Ok(mut slot) = self.slot.lock() {
            slot.stopped = true;
            self.ready.notify_all();
        }
    }

    fn pull(&self, after_sequence: u64) -> Result<Option<CameraFrame>, String> {
        let mut slot = self
            .slot
            .lock()
            .map_err(|_| "camera frame queue unavailable".to_string())?;
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
                return Err("camera capture stopped".to_string());
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let waited = self
                .ready
                .wait_timeout(slot, deadline.saturating_duration_since(now))
                .map_err(|_| "camera frame queue unavailable".to_string())?;
            slot = waited.0;
            if waited.1.timed_out() {
                return Ok(None);
            }
        }
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        self.ready.notify_all();
        if let Ok(mut worker) = self.worker.lock()
            && let Some(worker) = worker.take()
        {
            let _ = worker.join();
        }
        if let Ok(mut slot) = self.slot.lock() {
            if let Some(frame) = slot.frame.as_mut() {
                frame.bytes.fill(0);
            }
            slot.frame = None;
            slot.stopped = true;
        }
    }
}

pub struct CameraCaptureState {
    sessions: Mutex<HashMap<String, Arc<CameraSession>>>,
    lifecycle: Mutex<()>,
}

impl CameraCaptureState {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            lifecycle: Mutex::new(()),
        }
    }

    pub fn devices(&self) -> Result<Vec<CameraDevice>, String> {
        #[cfg(target_os = "linux")]
        {
            Ok(context::enum_devices()
                .into_iter()
                .filter(|device| linux_camera_has_supported_format(device.path()))
                .take(32)
                .map(|device| CameraDevice {
                    device_id: device.path().to_string_lossy().into_owned(),
                    label: clean_label(&device.name().unwrap_or_else(|| "Camera".to_string())),
                })
                .collect())
        }
        #[cfg(target_os = "windows")]
        {
            let devices =
                query(ApiBackend::Auto).map_err(|_| "camera devices unavailable".to_string())?;
            Ok(devices
                .into_iter()
                .take(32)
                .map(|device| CameraDevice {
                    device_id: device.index().as_string(),
                    label: clean_label(&device.human_name()),
                })
                .collect())
        }
    }

    pub fn start(
        &self,
        session_id: &str,
        device_id: Option<&str>,
        width: u32,
        height: u32,
        frame_rate: u32,
    ) -> Result<(), String> {
        let lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| "camera capture unavailable".to_string())?;
        tracing::info!(
            width,
            height,
            frame_rate,
            selected_device = device_id.is_some(),
            "[CALL-DIAG] camera-state-start-enter"
        );
        validate_session_id(session_id)?;
        if !(2..=1280).contains(&width)
            || !(2..=720).contains(&height)
            || width.saturating_mul(height) > 1280 * 720
            || !(1..=60).contains(&frame_rate)
        {
            return Err("invalid camera capture profile".to_string());
        }
        if let Some(device_id) = device_id {
            validate_device_id(device_id)?;
        }
        tracing::info!("[CALL-DIAG] camera-state-previous-stop-before");
        self.stop_session(session_id)?;
        tracing::info!("[CALL-DIAG] camera-state-previous-stop-after");
        let session = Arc::new(CameraSession::new());
        {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| "camera capture unavailable".to_string())?;
            if sessions.len() >= MAX_SESSIONS {
                return Err("camera capture session limit reached".to_string());
            }
            sessions.insert(session_id.to_string(), session.clone());
        }
        let selected_device = device_id.map(str::to_string);
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let worker_session = session.clone();
        tracing::info!("[CALL-DIAG] camera-worker-spawn-before");
        let worker = thread::Builder::new()
            .name("qor-camera-capture".to_string())
            .spawn(move || {
                run_capture(
                    worker_session.clone(),
                    selected_device.as_deref(),
                    width,
                    height,
                    frame_rate,
                    started_tx,
                );
                worker_session.finish();
            });
        tracing::info!(
            spawned = worker.is_ok(),
            "[CALL-DIAG] camera-worker-spawn-after"
        );
        let worker = match worker {
            Ok(worker) => worker,
            Err(_) => {
                if let Ok(mut sessions) = self.sessions.lock() {
                    sessions.remove(session_id);
                }
                return Err("camera capture failed to start".to_string());
            }
        };
        *session
            .worker
            .lock()
            .map_err(|_| "camera capture unavailable".to_string())? = Some(worker);
        drop(lifecycle);
        tracing::info!("[CALL-DIAG] camera-worker-ready-wait-before");
        match started_rx.recv_timeout(START_WAIT) {
            Ok(Ok(())) => {
                tracing::info!("[CALL-DIAG] camera-worker-ready-wait-after");
                Ok(())
            }
            Ok(Err(error)) => {
                tracing::warn!(error = %error, "[CALL-DIAG] camera-worker-start-reported-error");
                let _ = self.stop_if_current(session_id, &session);
                Err(error)
            }
            Err(_) => {
                tracing::warn!("[CALL-DIAG] camera-worker-ready-wait-timeout");
                let _ = self.stop_if_current(session_id, &session);
                Err("camera capture startup timed out".to_string())
            }
        }
    }

    pub fn set_enabled(&self, session_id: &str, enabled: bool) -> Result<(), String> {
        let session = self.session(session_id)?;
        session.enabled.store(enabled, Ordering::Release);
        Ok(())
    }

    pub fn pull(
        &self,
        session_id: &str,
        after_sequence: u64,
    ) -> Result<Option<CameraFrame>, String> {
        self.session(session_id)?.pull(after_sequence)
    }

    pub fn stop(&self, session_id: &str) -> Result<(), String> {
        validate_session_id(session_id)?;
        let _lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| "camera capture unavailable".to_string())?;
        self.stop_session(session_id)
    }

    fn stop_session(&self, session_id: &str) -> Result<(), String> {
        let session = self
            .sessions
            .lock()
            .map_err(|_| "camera capture unavailable".to_string())?
            .remove(session_id);
        if let Some(session) = session {
            session.stop();
        }
        Ok(())
    }

    fn stop_if_current(
        &self,
        session_id: &str,
        expected: &Arc<CameraSession>,
    ) -> Result<(), String> {
        let _lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| "camera capture unavailable".to_string())?;
        let session = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| "camera capture unavailable".to_string())?;
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

    fn session(&self, session_id: &str) -> Result<Arc<CameraSession>, String> {
        validate_session_id(session_id)?;
        self.sessions
            .lock()
            .map_err(|_| "camera capture unavailable".to_string())?
            .get(session_id)
            .cloned()
            .ok_or_else(|| "camera capture session unavailable".to_string())
    }
}

impl Default for CameraCaptureState {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CameraCaptureState {
    fn drop(&mut self) {
        if let Ok(sessions) = self.sessions.get_mut() {
            for session in sessions.values() {
                session.stop();
            }
            sessions.clear();
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinuxCaptureProfile {
    fourcc: FourCC,
    width: u32,
    height: u32,
    frame_rate: u32,
}

#[cfg(target_os = "linux")]
struct DeliveredCadence {
    advertised_frame_rate: u32,
    effective_frame_rate: u32,
    last_frame_at: Option<Instant>,
    average_interval_ms: f64,
    samples: u32,
    last_adjusted_at: Option<Instant>,
}

#[cfg(target_os = "linux")]
impl DeliveredCadence {
    fn new(advertised_frame_rate: u32) -> Self {
        Self {
            advertised_frame_rate,
            effective_frame_rate: advertised_frame_rate,
            last_frame_at: None,
            average_interval_ms: 0.0,
            samples: 0,
            last_adjusted_at: None,
        }
    }

    fn observe(&mut self, now: Instant) -> u32 {
        if let Some(previous) = self.last_frame_at {
            let interval_ms = now.duration_since(previous).as_secs_f64() * 1_000.0;
            let maximum_interval_ms =
                (3_000.0 / self.advertised_frame_rate.max(1) as f64).clamp(100.0, 1_000.0);
            if (1.0..=maximum_interval_ms).contains(&interval_ms) {
                self.average_interval_ms = if self.average_interval_ms > 0.0 {
                    self.average_interval_ms * 0.9 + interval_ms * 0.1
                } else {
                    interval_ms
                };
                self.samples = self.samples.saturating_add(1);
            }
        }
        self.last_frame_at = Some(now);
        let can_adjust = self.samples >= 20
            && self.last_adjusted_at.map_or(true, |adjusted| {
                now.duration_since(adjusted) >= Duration::from_secs(5)
            });
        if can_adjust && self.average_interval_ms > 0.0 {
            let measured = (1_000.0 / self.average_interval_ms)
                .round()
                .clamp(1.0, 60.0) as u32;
            let candidate =
                if measured.saturating_mul(100) < self.advertised_frame_rate.saturating_mul(85) {
                    measured
                } else {
                    self.advertised_frame_rate
                };
            let cadence_delta = candidate.abs_diff(self.effective_frame_rate);
            let meaningful_change = candidate == self.advertised_frame_rate
                || cadence_delta.saturating_mul(100)
                    >= self.effective_frame_rate.saturating_mul(20);
            if cadence_delta >= 2 && meaningful_change {
                tracing::info!(
                    advertised_frame_rate = self.advertised_frame_rate,
                    previous_frame_rate = self.effective_frame_rate,
                    measured_frame_rate = measured,
                    effective_frame_rate = candidate,
                    "[CALL-DIAG] linux-camera-delivered-cadence-changed"
                );
                self.effective_frame_rate = candidate;
            }
            self.last_adjusted_at = Some(now);
        }
        self.effective_frame_rate
    }

    fn discontinuity(&mut self) {
        self.last_frame_at = None;
    }
}

fn capture_profile_priority(
    candidate_width: u32,
    candidate_height: u32,
    candidate_frame_rate: u32,
    compressed: bool,
    requested_width: u32,
    requested_height: u32,
    requested_frame_rate: u32,
) -> (u32, u8, i64) {
    let width_delta = i64::from(candidate_width) - i64::from(requested_width);
    let height_delta = i64::from(candidate_height) - i64::from(requested_height);
    let resolution_delta =
        width_delta.saturating_mul(width_delta) + height_delta.saturating_mul(height_delta);
    (
        candidate_frame_rate.abs_diff(requested_frame_rate),
        u8::from(!compressed),
        resolution_delta,
    )
}

#[cfg(target_os = "linux")]
fn run_capture(
    session: Arc<CameraSession>,
    device_id: Option<&str>,
    width: u32,
    height: u32,
    frame_rate: u32,
    started: std::sync::mpsc::SyncSender<Result<(), String>>,
) {
    let capture_started_at = Instant::now();
    tracing::info!("[CALL-DIAG] linux-camera-resolve-before");
    let paths = match resolve_linux_cameras(device_id) {
        Ok(paths) => paths,
        Err(error) => {
            tracing::warn!(error = %error, "[CALL-DIAG] linux-camera-resolve-failed");
            let _ = started.send(Err(error));
            return;
        }
    };
    tracing::info!(
        device_count = paths.len(),
        "[CALL-DIAG] linux-camera-resolve-after"
    );
    let mut saw_device = false;
    let mut saw_profiles = false;
    let mut saw_busy = false;
    let mut configured = None;
    'devices: for (device_index, path) in paths.into_iter().enumerate() {
        tracing::info!(device_index, "[CALL-DIAG] linux-camera-open-before");
        let device = match Device::with_path(path) {
            Ok(device) => {
                tracing::info!(device_index, "[CALL-DIAG] linux-camera-open-after");
                device
            }
            Err(error) => {
                tracing::warn!(
                    device_index,
                    busy = error.kind() == std::io::ErrorKind::ResourceBusy,
                    "[CALL-DIAG] linux-camera-open-failed"
                );
                saw_busy |= error.kind() == std::io::ErrorKind::ResourceBusy;
                continue;
            }
        };
        saw_device = true;
        tracing::info!(device_index, "[CALL-DIAG] linux-camera-profiles-before");
        let profiles = linux_capture_profiles(&device, width, height, frame_rate);
        tracing::info!(
            device_index,
            profile_count = profiles.len(),
            "[CALL-DIAG] linux-camera-profiles-after"
        );
        if profiles.is_empty() {
            continue;
        }
        saw_profiles = true;
        let mut configured_profile = None;
        for (profile_index, profile) in profiles.into_iter().enumerate() {
            tracing::info!(
                device_index,
                profile_index,
                width = profile.width,
                height = profile.height,
                frame_rate = profile.frame_rate,
                fourcc = ?profile.fourcc,
                "[CALL-DIAG] linux-camera-format-before"
            );
            let format = match device.set_format(&Format::new(
                profile.width,
                profile.height,
                profile.fourcc,
            )) {
                Ok(format) => {
                    tracing::info!(
                        device_index,
                        profile_index,
                        "[CALL-DIAG] linux-camera-format-after"
                    );
                    format
                }
                Err(error) => {
                    let busy = error.kind() == std::io::ErrorKind::ResourceBusy;
                    tracing::warn!(
                        device_index,
                        profile_index,
                        busy,
                        "[CALL-DIAG] linux-camera-format-failed"
                    );
                    saw_busy |= busy;
                    if busy {
                        continue 'devices;
                    }
                    continue;
                }
            };
            if !linux_format_is_safe(&format) {
                tracing::warn!(
                    device_index,
                    profile_index,
                    "[CALL-DIAG] linux-camera-format-unsafe"
                );
                continue;
            }
            tracing::info!(
                device_index,
                profile_index,
                "[CALL-DIAG] linux-camera-params-before"
            );
            let parameters = match device.set_params(&Parameters::with_fps(profile.frame_rate)) {
                Ok(parameters) => {
                    tracing::info!(
                        device_index,
                        profile_index,
                        "[CALL-DIAG] linux-camera-params-after"
                    );
                    parameters
                }
                Err(error) => {
                    let busy = error.kind() == std::io::ErrorKind::ResourceBusy;
                    tracing::warn!(
                        device_index,
                        profile_index,
                        busy,
                        "[CALL-DIAG] linux-camera-params-failed"
                    );
                    saw_busy |= busy;
                    if busy {
                        continue 'devices;
                    }
                    continue;
                }
            };
            configured_profile = Some((format, parameters));
            break;
        }
        if let Some((format, parameters)) = configured_profile {
            configured = Some((device, format, parameters));
            break;
        }
    }
    let (device, format, parameters) = match configured {
        Some(configured) => configured,
        None => {
            let error = if saw_busy {
                "camera is already in use"
            } else if saw_profiles {
                "camera format could not be configured"
            } else if saw_device {
                "camera has no supported capture format"
            } else {
                "camera could not be initialized"
            };
            let _ = started.send(Err(error.to_string()));
            return;
        }
    };
    let actual_frame_rate = fraction_frame_rate(
        parameters.interval.numerator,
        parameters.interval.denominator,
    )
    .filter(|actual| (1..=60).contains(actual))
    .unwrap_or(frame_rate.clamp(1, 60));
    tracing::info!(
        width = format.width,
        height = format.height,
        frame_rate = actual_frame_rate,
        fourcc = ?format.fourcc,
        "[CALL-DIAG] linux-camera-selected-profile"
    );
    let black = match encode_black_frame(format.width, format.height) {
        Ok(black) => black,
        Err(error) => {
            let _ = started.send(Err(error));
            return;
        }
    };
    tracing::info!("[CALL-DIAG] linux-camera-stream-open-before");
    let mut stream = match MmapStream::with_buffers(&device, Type::VideoCapture, 4) {
        Ok(mut stream) => {
            stream.set_timeout(Duration::from_millis(750));
            tracing::info!("[CALL-DIAG] linux-camera-stream-open-after");
            Some(stream)
        }
        Err(_) => {
            tracing::warn!("[CALL-DIAG] linux-camera-stream-open-failed");
            let _ = started.send(Err("camera stream could not be opened".to_string()));
            return;
        }
    };
    let mut sequence = 0u64;
    let mut startup_signalled = false;
    let mut cadence = DeliveredCadence::new(actual_frame_rate);
    let mut report_started_at = Instant::now();
    let mut report_frames = 0u64;
    let mut report_bytes = 0u64;
    let mut report_overwrites = 0u64;
    let mut report_timeouts = 0u64;
    let mut report_errors = 0u64;
    while !session.stop.load(Ordering::Acquire) {
        if report_started_at.elapsed() >= Duration::from_secs(5) {
            let elapsed_seconds = report_started_at.elapsed().as_secs_f64().max(0.001);
            tracing::info!(
                frames = report_frames,
                fps = report_frames as f64 / elapsed_seconds,
                jpeg_bytes = report_bytes,
                overwrites = report_overwrites,
                timeouts = report_timeouts,
                errors = report_errors,
                advertised_frame_rate = actual_frame_rate,
                effective_frame_rate = cadence.effective_frame_rate,
                "[CALL-DIAG] linux-camera-capture-window"
            );
            report_started_at = Instant::now();
            report_frames = 0;
            report_bytes = 0;
            report_overwrites = 0;
            report_timeouts = 0;
            report_errors = 0;
        }
        let enabled = session.enabled.load(Ordering::Acquire);
        if !enabled {
            stream = None;
            cadence.discontinuity();
            sequence = sequence.wrapping_add(1).max(1);
            session.publish(CameraFrame {
                sequence,
                captured_at: now_ms(),
                width: format.width as u16,
                height: format.height as u16,
                frame_rate: actual_frame_rate as u16,
                enabled: false,
                bytes: black.clone(),
            });
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        if stream.is_none() {
            cadence.discontinuity();
            stream = match MmapStream::with_buffers(&device, Type::VideoCapture, 4) {
                Ok(mut stream) => {
                    stream.set_timeout(Duration::from_millis(750));
                    Some(stream)
                }
                Err(_) => {
                    report_errors = report_errors.saturating_add(1);
                    thread::sleep(Duration::from_millis(250));
                    continue;
                }
            };
        }
        let frame = match stream.as_mut() {
            Some(capture_stream) => match capture_stream.next() {
                Ok((bytes, metadata)) => {
                    let bytes_used = usize::try_from(metadata.bytesused)
                        .unwrap_or(bytes.len())
                        .min(bytes.len());
                    &bytes[..bytes_used]
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    report_timeouts = report_timeouts.saturating_add(1);
                    cadence.discontinuity();
                    continue;
                }
                Err(_) => {
                    report_errors = report_errors.saturating_add(1);
                    cadence.discontinuity();
                    stream = None;
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
            },
            None => {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
        };
        let captured_at = now_ms();
        let effective_frame_rate = cadence.observe(Instant::now());
        let bytes = if format.fourcc == FourCC::new(b"MJPG") {
            match normalize_jpeg(frame.to_vec()) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            }
        } else {
            match encode_yuyv_frame(frame, format.width, format.height, format.stride) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            }
        };
        if bytes.len() > MAX_FRAME_BYTES {
            continue;
        }
        sequence = sequence.wrapping_add(1).max(1);
        let byte_length = bytes.len() as u64;
        if session.publish(CameraFrame {
            sequence,
            captured_at,
            width: format.width as u16,
            height: format.height as u16,
            frame_rate: effective_frame_rate as u16,
            enabled: true,
            bytes,
        }) {
            report_overwrites = report_overwrites.saturating_add(1);
        }
        report_frames = report_frames.saturating_add(1);
        report_bytes = report_bytes.saturating_add(byte_length);
        if !startup_signalled {
            startup_signalled = true;
            tracing::info!(
                startup_ms = capture_started_at.elapsed().as_millis(),
                jpeg_bytes = byte_length,
                "[CALL-DIAG] linux-camera-first-frame"
            );
            let _ = started.send(Ok(()));
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_capture_profiles(
    device: &Device,
    width: u32,
    height: u32,
    frame_rate: u32,
) -> Vec<LinuxCaptureProfile> {
    let mut profiles = Vec::new();
    let available = device.enum_formats().unwrap_or_default();
    for fourcc in [FourCC::new(b"MJPG"), FourCC::new(b"YUYV")] {
        if !available.iter().any(|format| format.fourcc == fourcc) {
            continue;
        }
        for frame_size in device.enum_framesizes(fourcc).unwrap_or_default() {
            let sizes = match frame_size.size {
                FrameSizeEnum::Discrete(size) => vec![(size.width, size.height)],
                FrameSizeEnum::Stepwise(size) => {
                    let candidate_width =
                        nearest_step(width, size.min_width, size.max_width, size.step_width);
                    let candidate_height =
                        nearest_step(height, size.min_height, size.max_height, size.step_height);
                    vec![(candidate_width, candidate_height)]
                }
            };
            for (candidate_width, candidate_height) in sizes {
                if !linux_size_is_safe(candidate_width, candidate_height) {
                    continue;
                }
                let selected_frame_rate = linux_frame_rate(
                    device,
                    fourcc,
                    candidate_width,
                    candidate_height,
                    frame_rate,
                );
                if let Some(selected_frame_rate) = selected_frame_rate {
                    profiles.push(LinuxCaptureProfile {
                        fourcc,
                        width: candidate_width,
                        height: candidate_height,
                        frame_rate: selected_frame_rate,
                    });
                }
            }
        }
    }
    profiles.sort_by_key(|profile| {
        capture_profile_priority(
            profile.width,
            profile.height,
            profile.frame_rate,
            profile.fourcc == FourCC::new(b"MJPG"),
            width,
            height,
            frame_rate,
        )
    });
    profiles.dedup();
    profiles
}

#[cfg(target_os = "linux")]
fn linux_frame_rate(
    device: &Device,
    fourcc: FourCC,
    width: u32,
    height: u32,
    requested: u32,
) -> Option<u32> {
    let intervals = device
        .enum_frameintervals(fourcc, width, height)
        .unwrap_or_default();
    if intervals.is_empty() {
        return Some(requested);
    }
    let mut frame_rates = Vec::new();
    for interval in intervals {
        match interval.interval {
            FrameIntervalEnum::Discrete(interval) => {
                let frame_rate = interval
                    .denominator
                    .saturating_add(interval.numerator / 2)
                    .checked_div(interval.numerator);
                if let Some(frame_rate) = frame_rate
                    && (1..=60).contains(&frame_rate)
                {
                    frame_rates.push(frame_rate);
                }
            }
            FrameIntervalEnum::Stepwise(interval) => {
                let slowest = fraction_frame_rate(interval.max.numerator, interval.max.denominator);
                let fastest = fraction_frame_rate(interval.min.numerator, interval.min.denominator);
                if let (Some(slowest), Some(fastest)) = (slowest, fastest) {
                    frame_rates.push(requested.clamp(slowest.min(fastest), slowest.max(fastest)));
                }
            }
        }
    }
    frame_rates
        .into_iter()
        .filter(|frame_rate| (1..=60).contains(frame_rate))
        .min_by_key(|frame_rate| frame_rate.abs_diff(requested))
}

#[cfg(target_os = "linux")]
fn fraction_frame_rate(numerator: u32, denominator: u32) -> Option<u32> {
    if numerator == 0 {
        return None;
    }
    Some(denominator.saturating_add(numerator / 2) / numerator)
}

#[cfg(target_os = "linux")]
fn nearest_step(requested: u32, minimum: u32, maximum: u32, step: u32) -> u32 {
    let requested = requested.clamp(minimum, maximum);
    if step == 0 {
        return requested;
    }
    let lower = minimum + (requested - minimum) / step * step;
    let upper = lower.saturating_add(step).min(maximum);
    if requested.abs_diff(lower) <= requested.abs_diff(upper) {
        lower
    } else {
        upper
    }
}

#[cfg(target_os = "linux")]
fn linux_size_is_safe(width: u32, height: u32) -> bool {
    width >= 2
        && height >= 2
        && width <= 1280
        && height <= 720
        && width.saturating_mul(height) <= 1280 * 720
}

#[cfg(target_os = "linux")]
fn linux_format_is_safe(format: &Format) -> bool {
    linux_size_is_safe(format.width, format.height)
        && (format.fourcc == FourCC::new(b"MJPG") || format.fourcc == FourCC::new(b"YUYV"))
}

#[cfg(target_os = "linux")]
fn resolve_linux_cameras(device_id: Option<&str>) -> Result<Vec<String>, String> {
    if let Some(device_id) = device_id {
        let exists = context::enum_devices().into_iter().any(|device| {
            device.path().to_string_lossy() == device_id
                && linux_camera_has_supported_format(device.path())
        });
        return exists
            .then(|| vec![device_id.to_string()])
            .ok_or_else(|| "selected camera device is unavailable".to_string());
    }
    let cameras = context::enum_devices()
        .into_iter()
        .filter(|device| linux_camera_has_supported_format(device.path()))
        .map(|device| device.path().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if cameras.is_empty() {
        Err("no camera device is available".to_string())
    } else {
        Ok(cameras)
    }
}

#[cfg(target_os = "linux")]
fn linux_camera_has_supported_format(path: &std::path::Path) -> bool {
    Device::with_path(path)
        .and_then(|device| device.enum_formats())
        .is_ok_and(|formats| {
            formats.iter().any(|format| {
                format.fourcc == FourCC::new(b"MJPG") || format.fourcc == FourCC::new(b"YUYV")
            })
        })
}

#[cfg(target_os = "windows")]
fn run_capture(
    session: Arc<CameraSession>,
    device_id: Option<&str>,
    width: u32,
    height: u32,
    frame_rate: u32,
    started: std::sync::mpsc::SyncSender<Result<(), String>>,
) {
    let camera_index = match resolve_camera(device_id) {
        Ok(index) => index,
        Err(error) => {
            let _ = started.send(Err(error));
            return;
        }
    };
    let requested =
        RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestResolution);
    let mut camera = match Camera::new(camera_index, requested) {
        Ok(camera) => camera,
        Err(_) => {
            let _ = started.send(Err("camera could not be initialized".to_string()));
            return;
        }
    };
    let selected_format = camera
        .compatible_camera_formats()
        .ok()
        .and_then(|formats| select_camera_format(&formats, width, height, frame_rate));
    let Some(selected_format) = selected_format else {
        let _ = started.send(Err("camera has no supported capture format".to_string()));
        return;
    };
    let selected_resolution = selected_format.resolution();
    let selected_frame_rate = selected_format.frame_rate().clamp(1, 60);
    tracing::info!(
        width = selected_resolution.width_x,
        height = selected_resolution.height_y,
        frame_rate = selected_frame_rate,
        format = ?selected_format.format(),
        "[CALL-DIAG] windows-camera-selected-profile"
    );
    if camera
        .set_camera_requset(RequestedFormat::new::<RgbFormat>(
            RequestedFormatType::Exact(selected_format),
        ))
        .is_err()
    {
        let _ = started.send(Err("camera format could not be configured".to_string()));
        return;
    }
    if camera.open_stream().is_err() {
        let _ = started.send(Err("camera stream could not be opened".to_string()));
        return;
    }
    let mut stream_open = true;
    let mut sequence = 0u64;
    let black = encode_black_frame(selected_resolution.width_x, selected_resolution.height_y);
    if black.is_err() {
        let _ = started.send(Err("camera frame encoder unavailable".to_string()));
        return;
    }
    let black = black.unwrap_or_default();
    let _ = started.send(Ok(()));
    while !session.stop.load(Ordering::Acquire) {
        let enabled = session.enabled.load(Ordering::Acquire);
        if !enabled {
            if stream_open {
                let _ = camera.stop_stream();
                stream_open = false;
            }
            sequence = sequence.wrapping_add(1).max(1);
            session.publish(CameraFrame {
                sequence,
                captured_at: now_ms(),
                width: selected_resolution.width_x as u16,
                height: selected_resolution.height_y as u16,
                frame_rate: selected_frame_rate as u16,
                enabled: false,
                bytes: black.clone(),
            });
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        if !stream_open {
            if camera.open_stream().is_err() {
                thread::sleep(Duration::from_millis(250));
                continue;
            }
            stream_open = true;
        }
        let captured_at = now_ms();
        let frame = match camera.frame() {
            Ok(frame) => frame,
            Err(_) => {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
        };
        let resolution = frame.resolution();
        if resolution.width_x < 2
            || resolution.height_y < 2
            || resolution.width_x > 1280
            || resolution.height_y > 720
        {
            continue;
        }
        let bytes = if frame.source_frame_format() == FrameFormat::MJPEG
            && frame.buffer().len() <= MAX_FRAME_BYTES
        {
            match normalize_jpeg(frame.buffer().to_vec()) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            }
        } else {
            match frame
                .decode_image::<RgbFormat>()
                .ok()
                .and_then(|image| encode_rgb_frame(&image).ok())
            {
                Some(bytes) => bytes,
                None => continue,
            }
        };
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            continue;
        }
        sequence = sequence.wrapping_add(1).max(1);
        session.publish(CameraFrame {
            sequence,
            captured_at,
            width: resolution.width_x as u16,
            height: resolution.height_y as u16,
            frame_rate: selected_frame_rate as u16,
            enabled: true,
            bytes,
        });
    }
}

#[cfg(target_os = "windows")]
fn select_camera_format(
    formats: &[CameraFormat],
    width: u32,
    height: u32,
    frame_rate: u32,
) -> Option<CameraFormat> {
    formats
        .iter()
        .copied()
        .filter(|format| {
            let resolution = format.resolution();
            resolution.width_x >= 2
                && resolution.height_y >= 2
                && resolution.width_x <= 1280
                && resolution.height_y <= 720
                && resolution.width_x.saturating_mul(resolution.height_y) <= 1280 * 720
        })
        .min_by_key(|format| {
            let resolution = format.resolution();
            capture_profile_priority(
                resolution.width_x,
                resolution.height_y,
                format.frame_rate(),
                format.format() == FrameFormat::MJPEG,
                width,
                height,
                frame_rate,
            )
        })
}

#[cfg(target_os = "windows")]
fn resolve_camera(device_id: Option<&str>) -> Result<CameraIndex, String> {
    let devices = query(ApiBackend::Auto).map_err(|_| "camera devices unavailable".to_string())?;
    if devices.is_empty() {
        return Err("no camera device is available".to_string());
    }
    if let Some(device_id) = device_id {
        return devices
            .into_iter()
            .find(|device| device.index().as_string() == device_id)
            .map(|device| device.index().clone())
            .ok_or_else(|| "selected camera device is unavailable".to_string());
    }
    Ok(devices[0].index().clone())
}

fn encode_black_frame(width: u32, height: u32) -> Result<Vec<u8>, String> {
    encode_rgb_frame(&RgbImage::new(width, height))
}

#[cfg(target_os = "linux")]
fn encode_yuyv_frame(
    frame: &[u8],
    width: u32,
    height: u32,
    stride: u32,
) -> Result<Vec<u8>, String> {
    let pixel_count = usize::try_from(width.saturating_mul(height))
        .map_err(|_| "invalid camera frame".to_string())?;
    if width % 2 != 0 || pixel_count == 0 {
        return Err("invalid camera frame".to_string());
    }
    let row_bytes = usize::try_from(width)
        .map_err(|_| "invalid camera frame".to_string())?
        .checked_mul(2)
        .ok_or_else(|| "invalid camera frame".to_string())?;
    let stride = if stride == 0 {
        row_bytes
    } else {
        usize::try_from(stride).map_err(|_| "invalid camera frame".to_string())?
    };
    let height_rows = usize::try_from(height).map_err(|_| "invalid camera frame".to_string())?;
    let required_bytes = stride
        .checked_mul(height_rows.saturating_sub(1))
        .and_then(|bytes| bytes.checked_add(row_bytes))
        .ok_or_else(|| "invalid camera frame".to_string())?;
    if stride < row_bytes || frame.len() < required_bytes {
        return Err("invalid camera frame".to_string());
    }
    let mut rgb = Vec::with_capacity(pixel_count.saturating_mul(3));
    for row_index in 0..height_rows {
        let row_start = row_index.saturating_mul(stride);
        let row = &frame[row_start..row_start + row_bytes];
        for pair in row.chunks_exact(4) {
            let y0 = i32::from(pair[0]);
            let u = i32::from(pair[1]) - 128;
            let y1 = i32::from(pair[2]);
            let v = i32::from(pair[3]) - 128;
            append_yuv_pixel(&mut rgb, y0, u, v);
            append_yuv_pixel(&mut rgb, y1, u, v);
        }
    }
    let image =
        RgbImage::from_raw(width, height, rgb).ok_or_else(|| "invalid camera frame".to_string())?;
    encode_rgb_frame(&image)
}

#[cfg(target_os = "linux")]
fn append_yuv_pixel(output: &mut Vec<u8>, y: i32, u: i32, v: i32) {
    let c = (y - 16).max(0);
    let red = (298 * c + 409 * v + 128) >> 8;
    let green = (298 * c - 100 * u - 208 * v + 128) >> 8;
    let blue = (298 * c + 516 * u + 128) >> 8;
    output.extend_from_slice(&[
        red.clamp(0, 255) as u8,
        green.clamp(0, 255) as u8,
        blue.clamp(0, 255) as u8,
    ]);
}

fn encode_rgb_frame(image: &RgbImage) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    JpegEncoder::new_with_quality(&mut bytes, 82)
        .encode(
            image.as_raw(),
            image.width(),
            image.height(),
            ExtendedColorType::Rgb8,
        )
        .map_err(|_| "camera frame encoding failed".to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        bytes.fill(0);
        return Err("invalid encoded camera frame".to_string());
    }
    normalize_jpeg(bytes)
}

fn normalize_jpeg(mut bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    if bytes.len() < 4 || bytes.len() > MAX_FRAME_BYTES || !bytes.starts_with(&[0xff, 0xd8]) {
        bytes.fill(0);
        return Err("invalid encoded camera frame".to_string());
    }
    let end = bytes
        .windows(2)
        .position(|marker| marker == [0xff, 0xd9])
        .map(|position| position + 2)
        .ok_or_else(|| {
            bytes.fill(0);
            "invalid encoded camera frame".to_string()
        })?;
    bytes.truncate(end);
    Ok(bytes)
}

fn clean_label(value: &str) -> String {
    let label: String = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(256)
        .collect();
    let label = label.trim();
    if label.is_empty() {
        "Camera".to_string()
    } else {
        label.to_string()
    }
}

fn validate_device_id(device_id: &str) -> Result<(), String> {
    if device_id.is_empty() || device_id.len() > 512 || device_id.chars().any(char::is_control) {
        Err("invalid camera device identifier".to_string())
    } else {
        Ok(())
    }
}

fn validate_session_id(session_id: &str) -> Result<(), String> {
    if (16..=64).contains(&session_id.len())
        && session_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err("invalid camera capture session".to_string())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::{
        CameraCaptureState, CameraFrame, CameraSession, capture_profile_priority, normalize_jpeg,
    };
    use std::collections::HashSet;

    #[test]
    fn latest_camera_frame_replaces_and_clears_the_previous_frame() {
        let session = CameraSession::new();
        session.publish(CameraFrame {
            sequence: 1,
            captured_at: 1,
            width: 640,
            height: 360,
            frame_rate: 60,
            enabled: true,
            bytes: vec![1, 2, 3],
        });
        session.publish(CameraFrame {
            sequence: 2,
            captured_at: 2,
            width: 640,
            height: 360,
            frame_rate: 60,
            enabled: true,
            bytes: vec![4, 5, 6],
        });
        let frame = session.pull(0).unwrap().unwrap();
        assert_eq!(frame.sequence, 2);
        assert_eq!(frame.bytes, vec![4, 5, 6]);
        assert!(session.pull(2).unwrap().is_none());
    }

    #[test]
    fn padded_camera_jpeg_is_trimmed_to_its_end_marker() {
        let bytes = normalize_jpeg(vec![0xff, 0xd8, 1, 2, 0xff, 0xd9, 0, 0, 0xff, 0xd9]).unwrap();
        assert_eq!(bytes, vec![0xff, 0xd8, 1, 2, 0xff, 0xd9]);
    }

    #[test]
    fn camera_profile_priority_prefers_requested_frame_rate_before_resolution() {
        let full_resolution_30 = capture_profile_priority(1280, 720, 30, true, 1280, 720, 60);
        let lower_resolution_60 = capture_profile_priority(640, 480, 60, true, 1280, 720, 60);
        assert!(lower_resolution_60 < full_resolution_30);
    }

    #[test]
    #[ignore]
    fn native_camera_produces_advancing_frames() {
        let state = CameraCaptureState::new();
        let devices = state.devices().unwrap();
        assert!(!devices.is_empty());
        for (index, device) in devices.iter().enumerate() {
            let session_id = format!("{:032x}", index + 1);
            state
                .start(&session_id, Some(&device.device_id), 1280, 720, 60)
                .unwrap();
            let mut sequence = 0;
            let mut signatures = HashSet::new();
            for _ in 0..60 {
                let Some(frame) = state.pull(&session_id, sequence).unwrap() else {
                    continue;
                };
                sequence = frame.sequence;
                assert!(frame.bytes.starts_with(&[0xff, 0xd8]));
                assert!(frame.bytes.ends_with(&[0xff, 0xd9]));
                signatures.insert(frame.bytes);
                if sequence >= 20 {
                    break;
                }
            }
            state.set_enabled(&session_id, false).unwrap();
            let mut disabled = false;
            for _ in 0..10 {
                let Some(frame) = state.pull(&session_id, sequence).unwrap() else {
                    continue;
                };
                sequence = frame.sequence;
                if !frame.enabled {
                    disabled = true;
                    break;
                }
            }
            state.set_enabled(&session_id, true).unwrap();
            let mut resumed = false;
            for _ in 0..20 {
                let Some(frame) = state.pull(&session_id, sequence).unwrap() else {
                    continue;
                };
                sequence = frame.sequence;
                if frame.enabled {
                    resumed = true;
                    break;
                }
            }
            state.stop(&session_id).unwrap();
            assert!(sequence >= 20, "{} did not advance", device.label);
            assert!(signatures.len() > 1, "{} repeated one frame", device.label);
            assert!(disabled, "{} did not disable", device.label);
            assert!(resumed, "{} did not resume", device.label);
        }
    }

    #[test]
    #[ignore]
    fn native_camera_default_uses_the_next_available_device() {
        let state = CameraCaptureState::new();
        if state.devices().unwrap().len() < 2 {
            return;
        }
        let first_session = "10000000000000000000000000000000";
        let second_session = "20000000000000000000000000000000";
        state.start(first_session, None, 1280, 720, 60).unwrap();
        state.start(second_session, None, 1280, 720, 60).unwrap();
        for session_id in [first_session, second_session] {
            let mut frame_received = false;
            for _ in 0..10 {
                if state.pull(session_id, 0).unwrap().is_some() {
                    frame_received = true;
                    break;
                }
            }
            assert!(frame_received);
        }
        state.stop(first_session).unwrap();
        state.stop(second_session).unwrap();
    }
}
