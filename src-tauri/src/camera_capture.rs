use image::{DynamicImage, RgbImage, codecs::jpeg::JpegEncoder};
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

    fn publish(&self, frame: CameraFrame) {
        if let Ok(mut slot) = self.slot.lock() {
            if let Some(previous) = slot.frame.as_mut() {
                previous.bytes.fill(0);
            }
            slot.frame = Some(frame);
            self.ready.notify_all();
        }
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
}

impl CameraCaptureState {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
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
        self.stop(session_id)?;
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
        match started_rx.recv_timeout(START_WAIT) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                let _ = self.stop(session_id);
                Err(error)
            }
            Err(_) => {
                let _ = self.stop(session_id);
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
fn run_capture(
    session: Arc<CameraSession>,
    device_id: Option<&str>,
    width: u32,
    height: u32,
    frame_rate: u32,
    started: std::sync::mpsc::SyncSender<Result<(), String>>,
) {
    let path = match resolve_linux_camera(device_id) {
        Ok(path) => path,
        Err(error) => {
            let _ = started.send(Err(error));
            return;
        }
    };
    let device = match Device::with_path(path) {
        Ok(device) => device,
        Err(_) => {
            let _ = started.send(Err("camera could not be initialized".to_string()));
            return;
        }
    };
    let available = device.enum_formats().unwrap_or_default();
    let format_code = if available
        .iter()
        .any(|format| format.fourcc == FourCC::new(b"MJPG"))
    {
        FourCC::new(b"MJPG")
    } else if available
        .iter()
        .any(|format| format.fourcc == FourCC::new(b"YUYV"))
    {
        FourCC::new(b"YUYV")
    } else {
        let _ = started.send(Err("camera has no supported capture format".to_string()));
        return;
    };
    let format = match device.set_format(&Format::new(width, height, format_code)) {
        Ok(format) => format,
        Err(_) => {
            let _ = started.send(Err("camera format could not be configured".to_string()));
            return;
        }
    };
    if format.width < 2
        || format.height < 2
        || format.width > 1280
        || format.height > 720
        || format.width.saturating_mul(format.height) > 1280 * 720
    {
        let _ = started.send(Err("camera selected an unsafe capture size".to_string()));
        return;
    }
    let _ = device.set_params(&Parameters::with_fps(frame_rate));
    let black = match encode_black_frame(format.width, format.height) {
        Ok(black) => black,
        Err(error) => {
            let _ = started.send(Err(error));
            return;
        }
    };
    let mut stream = match MmapStream::with_buffers(&device, Type::VideoCapture, 4) {
        Ok(mut stream) => {
            stream.set_timeout(Duration::from_secs(1));
            Some(stream)
        }
        Err(_) => {
            let _ = started.send(Err("camera stream could not be opened".to_string()));
            return;
        }
    };
    let mut sequence = 0u64;
    let _ = started.send(Ok(()));
    while !session.stop.load(Ordering::Acquire) {
        let enabled = session.enabled.load(Ordering::Acquire);
        if !enabled {
            stream = None;
            sequence = sequence.wrapping_add(1).max(1);
            session.publish(CameraFrame {
                sequence,
                captured_at: now_ms(),
                width: format.width as u16,
                height: format.height as u16,
                enabled: false,
                bytes: black.clone(),
            });
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        if stream.is_none() {
            stream = match MmapStream::with_buffers(&device, Type::VideoCapture, 4) {
                Ok(mut stream) => {
                    stream.set_timeout(Duration::from_secs(1));
                    Some(stream)
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(250));
                    continue;
                }
            };
        }
        let frame = match stream.as_mut() {
            Some(capture_stream) => match capture_stream.next() {
                Ok((bytes, _)) => bytes,
                Err(_) => {
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
        let bytes = if format.fourcc == FourCC::new(b"MJPG") {
            match normalize_jpeg(frame.to_vec()) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            }
        } else {
            match encode_yuyv_frame(frame, format.width, format.height) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            }
        };
        if bytes.len() > MAX_FRAME_BYTES {
            continue;
        }
        sequence = sequence.wrapping_add(1).max(1);
        session.publish(CameraFrame {
            sequence,
            captured_at: now_ms(),
            width: format.width as u16,
            height: format.height as u16,
            enabled: true,
            bytes,
        });
    }
}

#[cfg(target_os = "linux")]
fn resolve_linux_camera(device_id: Option<&str>) -> Result<String, String> {
    if let Some(device_id) = device_id {
        let exists = context::enum_devices().into_iter().any(|device| {
            device.path().to_string_lossy() == device_id
                && linux_camera_has_supported_format(device.path())
        });
        return exists
            .then(|| device_id.to_string())
            .ok_or_else(|| "selected camera device is unavailable".to_string());
    }
    context::enum_devices()
        .into_iter()
        .find(|device| linux_camera_has_supported_format(device.path()))
        .map(|device| device.path().to_string_lossy().into_owned())
        .ok_or_else(|| "no camera device is available".to_string())
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
    let black = encode_black_frame(width, height);
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
                width: width as u16,
                height: height as u16,
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
            let width_delta = i64::from(resolution.width_x) - i64::from(width);
            let height_delta = i64::from(resolution.height_y) - i64::from(height);
            let resolution_delta =
                width_delta.saturating_mul(width_delta) + height_delta.saturating_mul(height_delta);
            (
                u8::from(format.format() != FrameFormat::MJPEG),
                resolution_delta,
                format.frame_rate().abs_diff(frame_rate),
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
fn encode_yuyv_frame(frame: &[u8], width: u32, height: u32) -> Result<Vec<u8>, String> {
    let pixel_count = usize::try_from(width.saturating_mul(height))
        .map_err(|_| "invalid camera frame".to_string())?;
    if pixel_count % 2 != 0 || frame.len() != pixel_count.saturating_mul(2) {
        return Err("invalid camera frame".to_string());
    }
    let mut rgb = Vec::with_capacity(pixel_count.saturating_mul(3));
    for pair in frame.chunks_exact(4) {
        let y0 = i32::from(pair[0]);
        let u = i32::from(pair[1]) - 128;
        let y1 = i32::from(pair[2]);
        let v = i32::from(pair[3]) - 128;
        append_yuv_pixel(&mut rgb, y0, u, v);
        append_yuv_pixel(&mut rgb, y1, u, v);
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
        .encode_image(&DynamicImage::ImageRgb8(image.clone()))
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
    use super::{CameraCaptureState, CameraFrame, CameraSession, normalize_jpeg};
    use std::collections::HashSet;

    #[test]
    fn latest_camera_frame_replaces_and_clears_the_previous_frame() {
        let session = CameraSession::new();
        session.publish(CameraFrame {
            sequence: 1,
            captured_at: 1,
            width: 640,
            height: 360,
            enabled: true,
            bytes: vec![1, 2, 3],
        });
        session.publish(CameraFrame {
            sequence: 2,
            captured_at: 2,
            width: 640,
            height: 360,
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
    #[ignore]
    fn native_camera_produces_advancing_frames() {
        let state = CameraCaptureState::new();
        let session_id = "0123456789abcdef0123456789abcdef";
        state.start(session_id, None, 640, 360, 30).unwrap();
        let mut sequence = 0;
        let mut signatures = HashSet::new();
        for _ in 0..60 {
            let Some(frame) = state.pull(session_id, sequence).unwrap() else {
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
        state.set_enabled(session_id, false).unwrap();
        let mut disabled = false;
        for _ in 0..10 {
            let Some(frame) = state.pull(session_id, sequence).unwrap() else {
                continue;
            };
            sequence = frame.sequence;
            if !frame.enabled {
                disabled = true;
                break;
            }
        }
        state.set_enabled(session_id, true).unwrap();
        let mut resumed = false;
        for _ in 0..20 {
            let Some(frame) = state.pull(session_id, sequence).unwrap() else {
                continue;
            };
            sequence = frame.sequence;
            if frame.enabled {
                resumed = true;
                break;
            }
        }
        state.stop(session_id).unwrap();
        assert!(sequence >= 20);
        assert!(signatures.len() > 1);
        assert!(disabled);
        assert!(resumed);
    }
}
