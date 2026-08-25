#[cfg(target_os = "windows")]
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
#[cfg(target_os = "windows")]
use cpal::{Data, Device, SampleFormat, SampleRate, SupportedStreamConfig};
#[cfg(target_os = "linux")]
use pulseaudio::{Client as PulseClient, RecordSink, protocol};
use serde::Serialize;
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TARGET_SAMPLE_RATE: u32 = 48_000;
const FRAME_SAMPLES: usize = 960;
const FRAME_WAIT: Duration = Duration::from_secs(1);
const START_WAIT: Duration = Duration::from_secs(10);
const MAX_SESSIONS: usize = 2;

#[derive(Clone, Serialize)]
pub struct MicrophoneDevice {
    pub device_id: String,
    pub label: String,
}

pub struct MicrophoneFrame {
    pub sequence: u32,
    pub captured_at: u64,
    pub enabled: bool,
    pub samples: Vec<f32>,
}

struct FrameSlot {
    frame: Option<MicrophoneFrame>,
    stopped: bool,
    failure: Option<String>,
}

struct MicrophoneSession {
    enabled: AtomicBool,
    stop: AtomicBool,
    slot: Mutex<FrameSlot>,
    ready: Condvar,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl MicrophoneSession {
    fn new() -> Self {
        Self {
            enabled: AtomicBool::new(true),
            stop: AtomicBool::new(false),
            slot: Mutex::new(FrameSlot {
                frame: None,
                stopped: false,
                failure: None,
            }),
            ready: Condvar::new(),
            worker: Mutex::new(None),
        }
    }

    fn publish(&self, frame: MicrophoneFrame) {
        if let Ok(mut slot) = self.slot.lock() {
            if let Some(previous) = slot.frame.as_mut() {
                previous.samples.fill(0.0);
            }
            slot.frame = Some(frame);
            self.ready.notify_all();
        }
    }

    fn fail(&self, message: String) {
        self.stop.store(true, Ordering::Release);
        if let Ok(mut slot) = self.slot.lock() {
            slot.failure = Some(message);
            slot.stopped = true;
            self.ready.notify_all();
        }
    }

    fn finish(&self) {
        if let Ok(mut slot) = self.slot.lock() {
            slot.stopped = true;
            self.ready.notify_all();
        }
    }

    fn pull(&self, after_sequence: u32) -> Result<Option<MicrophoneFrame>, String> {
        let mut slot = self
            .slot
            .lock()
            .map_err(|_| "microphone frame queue unavailable".to_string())?;
        let deadline = Instant::now() + FRAME_WAIT;
        loop {
            if slot
                .frame
                .as_ref()
                .is_some_and(|frame| sequence_after(frame.sequence, after_sequence))
            {
                return Ok(slot.frame.take());
            }
            if let Some(failure) = slot.failure.take() {
                return Err(failure);
            }
            if slot.stopped {
                return Err("microphone capture stopped".to_string());
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let waited = self
                .ready
                .wait_timeout(slot, deadline.saturating_duration_since(now))
                .map_err(|_| "microphone frame queue unavailable".to_string())?;
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
                frame.samples.fill(0.0);
            }
            slot.frame = None;
            slot.stopped = true;
        }
    }
}

pub struct MicrophoneCaptureState {
    sessions: Mutex<HashMap<String, Arc<MicrophoneSession>>>,
}

impl MicrophoneCaptureState {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn devices(&self) -> Result<Vec<MicrophoneDevice>, String> {
        enumerate_input_devices()
    }

    pub fn output_devices(&self) -> Result<Vec<MicrophoneDevice>, String> {
        enumerate_output_devices()
    }

    pub fn start(&self, session_id: &str, device_id: Option<&str>) -> Result<(), String> {
        validate_session_id(session_id)?;
        if let Some(device_id) = device_id {
            validate_device_id(device_id)?;
        }
        self.stop(session_id)?;
        let session = Arc::new(MicrophoneSession::new());
        {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| "microphone capture unavailable".to_string())?;
            if sessions.len() >= MAX_SESSIONS {
                return Err("microphone capture session limit reached".to_string());
            }
            sessions.insert(session_id.to_string(), session.clone());
        }
        let selected_device = device_id.map(str::to_string);
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let worker_session = session.clone();
        let worker = thread::Builder::new()
            .name("qor-microphone-capture".to_string())
            .spawn(move || {
                run_capture(
                    worker_session.clone(),
                    selected_device.as_deref(),
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
                return Err("microphone capture failed to start".to_string());
            }
        };
        *session
            .worker
            .lock()
            .map_err(|_| "microphone capture unavailable".to_string())? = Some(worker);
        match started_rx.recv_timeout(START_WAIT) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                self.stop(session_id)?;
                Err(error)
            }
            Err(_) => {
                self.stop(session_id)?;
                Err("microphone capture timed out".to_string())
            }
        }
    }

    pub fn set_enabled(&self, session_id: &str, enabled: bool) -> Result<(), String> {
        validate_session_id(session_id)?;
        let session = self.session(session_id)?;
        session.enabled.store(enabled, Ordering::Release);
        Ok(())
    }

    pub fn pull(
        &self,
        session_id: &str,
        after_sequence: u32,
    ) -> Result<Option<MicrophoneFrame>, String> {
        validate_session_id(session_id)?;
        self.session(session_id)?.pull(after_sequence)
    }

    pub fn stop(&self, session_id: &str) -> Result<(), String> {
        validate_session_id(session_id)?;
        let session = self
            .sessions
            .lock()
            .map_err(|_| "microphone capture unavailable".to_string())?
            .remove(session_id);
        if let Some(session) = session {
            session.stop();
        }
        Ok(())
    }

    fn session(&self, session_id: &str) -> Result<Arc<MicrophoneSession>, String> {
        self.sessions
            .lock()
            .map_err(|_| "microphone capture unavailable".to_string())?
            .get(session_id)
            .cloned()
            .ok_or_else(|| "microphone capture session unavailable".to_string())
    }
}

struct CaptureProcessor {
    session: Arc<MicrophoneSession>,
    source_rate: u32,
    #[cfg(target_os = "windows")]
    channels: usize,
    previous_sample: Option<f32>,
    source_index: u64,
    next_output_position: f64,
    output: Vec<f32>,
    sequence: u32,
}

impl CaptureProcessor {
    #[allow(unused_variables)]
    fn new(session: Arc<MicrophoneSession>, source_rate: u32, channels: usize) -> Self {
        Self {
            session,
            source_rate,
            #[cfg(target_os = "windows")]
            channels,
            previous_sample: None,
            source_index: 0,
            next_output_position: 0.0,
            output: Vec::with_capacity(FRAME_SAMPLES),
            sequence: 0,
        }
    }

    #[cfg(target_os = "windows")]
    fn push_interleaved<T: Copy>(&mut self, samples: &[T], convert: impl Fn(T) -> f32) {
        for frame in samples.chunks_exact(self.channels) {
            let mono = frame.iter().copied().map(&convert).sum::<f32>() / self.channels as f32;
            self.push_mono(mono.clamp(-1.0, 1.0));
        }
    }

    fn push_mono(&mut self, sample: f32) {
        let Some(previous) = self.previous_sample else {
            self.previous_sample = Some(sample);
            self.emit(sample);
            self.next_output_position = self.source_rate as f64 / TARGET_SAMPLE_RATE as f64;
            return;
        };
        self.source_index = self.source_index.wrapping_add(1);
        let current_position = self.source_index as f64;
        while self.next_output_position <= current_position {
            let fraction = (self.next_output_position - (current_position - 1.0)).clamp(0.0, 1.0);
            self.emit(previous + (sample - previous) * fraction as f32);
            self.next_output_position += self.source_rate as f64 / TARGET_SAMPLE_RATE as f64;
        }
        self.previous_sample = Some(sample);
    }

    fn emit(&mut self, sample: f32) {
        let enabled = self.session.enabled.load(Ordering::Acquire);
        self.output.push(if enabled { sample } else { 0.0 });
        if self.output.len() != FRAME_SAMPLES {
            return;
        }
        self.sequence = self.sequence.wrapping_add(1);
        let mut samples = Vec::with_capacity(FRAME_SAMPLES);
        std::mem::swap(&mut samples, &mut self.output);
        self.session.publish(MicrophoneFrame {
            sequence: self.sequence,
            captured_at: now_ms(),
            enabled,
            samples,
        });
    }
}

#[cfg(target_os = "linux")]
struct PulseRecordSink {
    processor: CaptureProcessor,
    pending: Vec<u8>,
    session: Arc<MicrophoneSession>,
}

#[cfg(target_os = "linux")]
impl RecordSink for PulseRecordSink {
    fn write(&mut self, data: &[u8]) {
        if self.pending.len().saturating_add(data.len()) > 1024 * 1024 {
            self.pending.fill(0);
            self.pending.clear();
            self.session
                .fail("microphone capture buffer exceeded its limit".to_string());
            return;
        }
        self.pending.extend_from_slice(data);
        let complete = self.pending.len() / std::mem::size_of::<f32>() * std::mem::size_of::<f32>();
        for bytes in self.pending[..complete].chunks_exact(std::mem::size_of::<f32>()) {
            let sample = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            self.processor
                .push_mono(if sample.is_finite() { sample } else { 0.0 });
        }
        self.pending.copy_within(complete.., 0);
        self.pending.truncate(self.pending.len() - complete);
    }
}

#[cfg(target_os = "linux")]
impl Drop for PulseRecordSink {
    fn drop(&mut self) {
        self.pending.fill(0);
        if !self.session.stop.load(Ordering::Acquire) {
            self.session
                .fail("microphone capture stream disconnected".to_string());
        }
    }
}

#[cfg(target_os = "linux")]
fn pulse_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|_| "microphone runtime unavailable".to_string())
}

#[cfg(target_os = "linux")]
fn pulse_client() -> Result<PulseClient, String> {
    let socket_path = pulseaudio::socket_path_from_env()
        .ok_or_else(|| "PulseAudio-compatible server unavailable".to_string())?;
    let socket = std::os::unix::net::UnixStream::connect(socket_path)
        .map_err(|_| "PulseAudio-compatible server unavailable".to_string())?;
    let timeout = Some(Duration::from_secs(5));
    socket
        .set_read_timeout(timeout)
        .map_err(|_| "microphone server connection failed".to_string())?;
    socket
        .set_write_timeout(timeout)
        .map_err(|_| "microphone server connection failed".to_string())?;
    let cookie = pulseaudio::cookie_path_from_env().and_then(|path| std::fs::read(path).ok());
    PulseClient::new_unix(c"Qor Chat", socket, cookie.as_deref())
        .map_err(|_| "microphone server connection failed".to_string())
}

#[cfg(target_os = "linux")]
fn enumerate_input_devices() -> Result<Vec<MicrophoneDevice>, String> {
    let runtime = pulse_runtime()?;
    let client = pulse_client()?;
    let sources = runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(5), client.list_sources()).await
        })
        .map_err(|_| "microphone device enumeration timed out".to_string())?
        .map_err(|_| "microphone devices unavailable".to_string())?;
    Ok(sources
        .into_iter()
        .filter(|source| source.monitor_of_sink_index.is_none())
        .take(64)
        .map(|source| MicrophoneDevice {
            device_id: format!("pulseaudio:{}", source.name.to_string_lossy()),
            label: clean_label(
                source
                    .description
                    .as_deref()
                    .unwrap_or(source.name.as_c_str())
                    .to_string_lossy()
                    .as_ref(),
            ),
        })
        .collect())
}

#[cfg(target_os = "linux")]
fn enumerate_output_devices() -> Result<Vec<MicrophoneDevice>, String> {
    let runtime = pulse_runtime()?;
    let client = pulse_client()?;
    let sinks = runtime
        .block_on(async { tokio::time::timeout(Duration::from_secs(5), client.list_sinks()).await })
        .map_err(|_| "audio output device enumeration timed out".to_string())?
        .map_err(|_| "audio output devices unavailable".to_string())?;
    Ok(sinks
        .into_iter()
        .take(64)
        .map(|sink| MicrophoneDevice {
            device_id: format!("pulseaudio:{}", sink.name.to_string_lossy()),
            label: clean_label(
                sink.description
                    .as_deref()
                    .unwrap_or(sink.name.as_c_str())
                    .to_string_lossy()
                    .as_ref(),
            ),
        })
        .collect())
}

#[cfg(target_os = "windows")]
fn enumerate_input_devices() -> Result<Vec<MicrophoneDevice>, String> {
    let host = cpal::default_host();
    let devices = host
        .input_devices()
        .map_err(|_| "microphone devices unavailable".to_string())?;
    Ok(devices
        .take(64)
        .filter_map(|device| {
            let device_id = device.id().ok()?.to_string();
            let label = device
                .description()
                .ok()
                .map(|description| clean_label(description.name()))
                .unwrap_or_else(|| "Microphone".to_string());
            Some(MicrophoneDevice { device_id, label })
        })
        .collect())
}

#[cfg(target_os = "windows")]
fn enumerate_output_devices() -> Result<Vec<MicrophoneDevice>, String> {
    let host = cpal::default_host();
    let devices = host
        .output_devices()
        .map_err(|_| "audio output devices unavailable".to_string())?;
    Ok(devices
        .take(64)
        .filter_map(|device| {
            let device_id = device.id().ok()?.to_string();
            let label = device
                .description()
                .ok()
                .map(|description| clean_label(description.name()))
                .unwrap_or_else(|| "Speaker".to_string());
            Some(MicrophoneDevice { device_id, label })
        })
        .collect())
}

#[cfg(target_os = "linux")]
fn run_capture(
    session: Arc<MicrophoneSession>,
    device_id: Option<&str>,
    started: std::sync::mpsc::SyncSender<Result<(), String>>,
) {
    let result = run_pulse_capture(session.clone(), device_id, &started);
    if let Err(error) = result {
        tracing::warn!(error = %error, "[CALL-DIAG] native-microphone-stream-failed");
        let _ = started.send(Err(error));
    }
}

#[cfg(target_os = "linux")]
fn run_pulse_capture(
    session: Arc<MicrophoneSession>,
    device_id: Option<&str>,
    started: &std::sync::mpsc::SyncSender<Result<(), String>>,
) -> Result<(), String> {
    let runtime = pulse_runtime()?;
    let client = pulse_client()?;
    let source_name = match device_id {
        Some(device_id) => {
            let name = device_id
                .strip_prefix("pulseaudio:")
                .ok_or_else(|| "selected microphone is unavailable".to_string())?;
            CString::new(name).map_err(|_| "invalid microphone device identifier".to_string())?
        }
        None => protocol::DEFAULT_SOURCE.to_owned(),
    };
    let source = runtime
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(5),
                client.source_info_by_name(source_name),
            )
            .await
        })
        .map_err(|_| "microphone device selection timed out".to_string())?
        .map_err(|_| "selected microphone is unavailable".to_string())?;
    let sink = PulseRecordSink {
        processor: CaptureProcessor::new(session.clone(), TARGET_SAMPLE_RATE, 1),
        pending: Vec::with_capacity(FRAME_SAMPLES * std::mem::size_of::<f32>() * 2),
        session: session.clone(),
    };
    let params = protocol::RecordStreamParams {
        source_index: Some(source.index),
        sample_spec: protocol::SampleSpec {
            format: protocol::SampleFormat::Float32Le,
            channels: 1,
            sample_rate: TARGET_SAMPLE_RATE,
        },
        channel_map: protocol::ChannelMap::mono(),
        cvolume: Some(protocol::ChannelVolume::norm(1)),
        buffer_attr: protocol::stream::BufferAttr {
            max_length: (FRAME_SAMPLES * std::mem::size_of::<f32>() * 4) as u32,
            fragment_size: (FRAME_SAMPLES * std::mem::size_of::<f32>()) as u32,
            ..Default::default()
        },
        flags: protocol::stream::StreamFlags {
            adjust_latency: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let stream = runtime
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(5),
                client.create_record_stream(params, sink),
            )
            .await
        })
        .map_err(|_| "microphone stream creation timed out".to_string())?
        .map_err(|_| "microphone stream could not be opened".to_string())?;
    if stream.sample_spec().format != protocol::SampleFormat::Float32Le
        || stream.sample_spec().channels != 1
        || stream.sample_spec().sample_rate != TARGET_SAMPLE_RATE
    {
        return Err("microphone stream format negotiation failed".to_string());
    }
    tracing::info!(
        source_rate = source.sample_spec.sample_rate,
        source_channels = source.sample_spec.channels,
        sample_rate = stream.sample_spec().sample_rate,
        channels = stream.sample_spec().channels,
        sample_format = ?stream.sample_spec().format,
        "[CALL-DIAG] native-microphone-selected-profile"
    );
    runtime
        .block_on(async { tokio::time::timeout(Duration::from_secs(5), stream.started()).await })
        .map_err(|_| "microphone stream startup timed out".to_string())?
        .map_err(|_| "microphone stream could not be started".to_string())?;
    let _ = started.send(Ok(()));
    runtime.block_on(async {
        while !session.stop.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
    let _ = runtime
        .block_on(async { tokio::time::timeout(Duration::from_secs(2), stream.delete()).await });
    Ok(())
}

#[cfg(target_os = "windows")]
fn run_capture(
    session: Arc<MicrophoneSession>,
    device_id: Option<&str>,
    started: std::sync::mpsc::SyncSender<Result<(), String>>,
) {
    let host = cpal::default_host();
    let device = match resolve_device(&host, device_id) {
        Ok(device) => device,
        Err(error) => {
            let _ = started.send(Err(error));
            return;
        }
    };
    let selected = match select_config(&device) {
        Ok(config) => config,
        Err(error) => {
            let _ = started.send(Err(error));
            return;
        }
    };
    let config = selected.config();
    let channels = config.channels as usize;
    let sample_rate = config.sample_rate.0;
    tracing::info!(
        sample_rate,
        channels,
        sample_format = %selected.sample_format(),
        "[CALL-DIAG] native-microphone-selected-profile"
    );
    let callback_session = session.clone();
    let mut processor = CaptureProcessor::new(callback_session, sample_rate, channels);
    let error_session = session.clone();
    let stream = device.build_input_stream_raw(
        config,
        selected.sample_format(),
        move |data, _| process_data(&mut processor, data),
        move |error| {
            tracing::warn!(error = %error, "[CALL-DIAG] native-microphone-stream-failed");
            error_session.fail("microphone capture stream failed".to_string());
        },
        Some(Duration::from_secs(5)),
    );
    let stream = match stream {
        Ok(stream) => stream,
        Err(error) => {
            tracing::warn!(error = %error, "[CALL-DIAG] native-microphone-open-failed");
            let _ = started.send(Err("microphone stream could not be opened".to_string()));
            return;
        }
    };
    if let Err(error) = stream.play() {
        tracing::warn!(error = %error, "[CALL-DIAG] native-microphone-play-failed");
        let _ = started.send(Err("microphone stream could not be started".to_string()));
        return;
    }
    let _ = started.send(Ok(()));
    while !session.stop.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(20));
    }
    drop(stream);
}

#[cfg(target_os = "windows")]
fn process_data(processor: &mut CaptureProcessor, data: &Data) {
    match data.sample_format() {
        SampleFormat::F32 => {
            if let Some(samples) = data.as_slice::<f32>() {
                processor.push_interleaved(samples, |sample| sample);
            }
        }
        SampleFormat::F64 => {
            if let Some(samples) = data.as_slice::<f64>() {
                processor.push_interleaved(samples, |sample| sample as f32);
            }
        }
        SampleFormat::I8 => {
            if let Some(samples) = data.as_slice::<i8>() {
                processor.push_interleaved(samples, |sample| sample as f32 / 128.0);
            }
        }
        SampleFormat::I16 => {
            if let Some(samples) = data.as_slice::<i16>() {
                processor.push_interleaved(samples, |sample| sample as f32 / 32_768.0);
            }
        }
        SampleFormat::I32 => {
            if let Some(samples) = data.as_slice::<i32>() {
                processor.push_interleaved(samples, |sample| sample as f32 / 2_147_483_648.0);
            }
        }
        SampleFormat::I64 => {
            if let Some(samples) = data.as_slice::<i64>() {
                processor.push_interleaved(samples, |sample| {
                    (sample as f64 / 9_223_372_036_854_775_808.0) as f32
                });
            }
        }
        SampleFormat::U8 => {
            if let Some(samples) = data.as_slice::<u8>() {
                processor.push_interleaved(samples, |sample| (sample as f32 - 128.0) / 128.0);
            }
        }
        SampleFormat::U16 => {
            if let Some(samples) = data.as_slice::<u16>() {
                processor.push_interleaved(samples, |sample| (sample as f32 - 32_768.0) / 32_768.0);
            }
        }
        SampleFormat::U32 => {
            if let Some(samples) = data.as_slice::<u32>() {
                processor.push_interleaved(samples, |sample| {
                    (sample as f64 - 2_147_483_648.0) as f32 / 2_147_483_648.0
                });
            }
        }
        SampleFormat::U64 => {
            if let Some(samples) = data.as_slice::<u64>() {
                processor.push_interleaved(samples, |sample| {
                    ((sample as f64 - 9_223_372_036_854_775_808.0) / 9_223_372_036_854_775_808.0)
                        as f32
                });
            }
        }
        _ => {}
    }
}

#[cfg(target_os = "windows")]
fn resolve_device(host: &cpal::Host, device_id: Option<&str>) -> Result<Device, String> {
    if let Some(device_id) = device_id {
        let parsed = device_id
            .parse()
            .map_err(|_| "invalid microphone device identifier".to_string())?;
        return host
            .device_by_id(&parsed)
            .filter(DeviceTrait::supports_input)
            .ok_or_else(|| "selected microphone is unavailable".to_string());
    }
    host.default_input_device()
        .ok_or_else(|| "no microphone is available".to_string())
}

#[cfg(target_os = "windows")]
fn select_config(device: &Device) -> Result<SupportedStreamConfig, String> {
    let configs = device
        .supported_input_configs()
        .map_err(|_| "microphone formats unavailable".to_string())?;
    configs
        .filter(|config| {
            config.channels() > 0
                && config.max_sample_rate().0 > 0
                && supported_sample_format(config.sample_format())
        })
        .map(|config| {
            let rate =
                TARGET_SAMPLE_RATE.clamp(config.min_sample_rate().0, config.max_sample_rate().0);
            config.with_sample_rate(SampleRate(rate))
        })
        .min_by_key(|config| {
            (
                config.sample_rate().0.abs_diff(TARGET_SAMPLE_RATE),
                channel_rank(config.channels()),
                sample_format_rank(config.sample_format()),
            )
        })
        .ok_or_else(|| "microphone has no supported PCM format".to_string())
}

#[cfg(target_os = "windows")]
fn supported_sample_format(format: SampleFormat) -> bool {
    matches!(
        format,
        SampleFormat::F32
            | SampleFormat::F64
            | SampleFormat::I8
            | SampleFormat::I16
            | SampleFormat::I32
            | SampleFormat::I64
            | SampleFormat::U8
            | SampleFormat::U16
            | SampleFormat::U32
            | SampleFormat::U64
    )
}

#[cfg(target_os = "windows")]
fn sample_format_rank(format: SampleFormat) -> u8 {
    match format {
        SampleFormat::F32 => 0,
        SampleFormat::I16 => 1,
        SampleFormat::I32 => 2,
        SampleFormat::F64 => 3,
        SampleFormat::U16 => 4,
        SampleFormat::U32 => 5,
        SampleFormat::I8 => 6,
        SampleFormat::U8 => 7,
        SampleFormat::I64 => 8,
        SampleFormat::U64 => 9,
        _ => u8::MAX,
    }
}

#[cfg(target_os = "windows")]
fn channel_rank(channels: u16) -> u16 {
    match channels {
        1 => 0,
        2 => 1,
        value => value.saturating_add(1),
    }
}

fn sequence_after(value: u32, previous: u32) -> bool {
    value != previous && value.wrapping_sub(previous) < (1 << 31)
}

fn validate_session_id(session_id: &str) -> Result<(), String> {
    if session_id.len() != 32
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid microphone capture session".to_string());
    }
    Ok(())
}

fn validate_device_id(device_id: &str) -> Result<(), String> {
    if device_id.is_empty() || device_id.len() > 1024 || device_id.chars().any(char::is_control) {
        return Err("invalid microphone device identifier".to_string());
    }
    Ok(())
}

fn clean_label(label: &str) -> String {
    let cleaned = label
        .chars()
        .filter(|character| !character.is_control())
        .take(160)
        .collect::<String>()
        .trim()
        .to_string();
    if cleaned.is_empty() {
        "Microphone".to_string()
    } else {
        cleaned
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}
