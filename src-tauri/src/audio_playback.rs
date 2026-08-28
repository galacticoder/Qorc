#[cfg(target_os = "linux")]
use pulseaudio::{AsPlaybackSource, Client as PulseClient, protocol};
use std::collections::{HashMap, VecDeque};
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const FRAME_SAMPLES: usize = 960;
const MAX_QUEUE_SAMPLES: usize = FRAME_SAMPLES * 10;
const MAX_SESSIONS: usize = 2;

struct AudioPlaybackSession {
    stop: AtomicBool,
    queue: Mutex<VecDeque<f32>>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl AudioPlaybackSession {
    fn new() -> Self {
        Self {
            stop: AtomicBool::new(false),
            queue: Mutex::new(VecDeque::with_capacity(MAX_QUEUE_SAMPLES)),
            worker: Mutex::new(None),
        }
    }

    fn push(&self, input: &[u8]) -> Result<(), String> {
        if input.len() != FRAME_SAMPLES * std::mem::size_of::<f32>() {
            return Err("invalid audio playback frame".to_string());
        }
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| "audio playback queue unavailable".to_string())?;
        while queue.len() + FRAME_SAMPLES > MAX_QUEUE_SAMPLES {
            for _ in 0..FRAME_SAMPLES.min(queue.len()) {
                queue.pop_front();
            }
        }
        for bytes in input.chunks_exact(4) {
            let sample = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            queue.push_back(if sample.is_finite() {
                sample.clamp(-1.0, 1.0)
            } else {
                0.0
            });
        }
        Ok(())
    }

    fn fill(&self, output: &mut [u8]) -> usize {
        output.fill(0);
        let Ok(mut queue) = self.queue.lock() else {
            return output.len();
        };
        for bytes in output.chunks_exact_mut(4) {
            let sample = queue.pop_front().unwrap_or(0.0);
            bytes.copy_from_slice(&sample.to_le_bytes());
        }
        output.len()
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        if let Ok(mut worker) = self.worker.lock()
            && let Some(worker) = worker.take()
        {
            let _ = worker.join();
        }
        if let Ok(mut queue) = self.queue.lock() {
            for sample in queue.iter_mut() {
                *sample = 0.0;
            }
            queue.clear();
        }
    }
}

pub struct AudioPlaybackState {
    sessions: Mutex<HashMap<String, Arc<AudioPlaybackSession>>>,
}

impl AudioPlaybackState {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn start(&self, session_id: &str, device_id: Option<&str>) -> Result<(), String> {
        validate_session_id(session_id)?;
        if let Some(device_id) = device_id {
            validate_device_id(device_id)?;
        }
        self.stop(session_id)?;
        let session = Arc::new(AudioPlaybackSession::new());
        {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| "audio playback unavailable".to_string())?;
            if sessions.len() >= MAX_SESSIONS {
                return Err("audio playback session limit reached".to_string());
            }
            sessions.insert(session_id.to_string(), session.clone());
        }
        let selected_device = device_id.map(str::to_string);
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let worker_session = session.clone();
        let worker = thread::Builder::new()
            .name("qor-audio-playback".to_string())
            .spawn(move || run_playback(worker_session, selected_device.as_deref(), started_tx));
        let worker = match worker {
            Ok(worker) => worker,
            Err(_) => {
                if let Ok(mut sessions) = self.sessions.lock() {
                    sessions.remove(session_id);
                }
                return Err("audio playback failed to start".to_string());
            }
        };
        *session
            .worker
            .lock()
            .map_err(|_| "audio playback unavailable".to_string())? = Some(worker);
        match started_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                self.stop(session_id)?;
                Err(error)
            }
            Err(_) => {
                self.stop(session_id)?;
                Err("audio playback timed out".to_string())
            }
        }
    }

    pub fn push(&self, session_id: &str, input: &[u8]) -> Result<(), String> {
        validate_session_id(session_id)?;
        let session = self
            .sessions
            .lock()
            .map_err(|_| "audio playback unavailable".to_string())?
            .get(session_id)
            .cloned()
            .ok_or_else(|| "audio playback session unavailable".to_string())?;
        session.push(input)
    }

    pub fn stop(&self, session_id: &str) -> Result<(), String> {
        validate_session_id(session_id)?;
        let session = self
            .sessions
            .lock()
            .map_err(|_| "audio playback unavailable".to_string())?
            .remove(session_id);
        if let Some(session) = session {
            session.stop();
        }
        Ok(())
    }
}

impl Default for AudioPlaybackState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
fn run_playback(
    session: Arc<AudioPlaybackSession>,
    device_id: Option<&str>,
    started: std::sync::mpsc::SyncSender<Result<(), String>>,
) {
    let result = run_pulse_playback(session.clone(), device_id, &started);
    if let Err(error) = result {
        tracing::warn!(error = %error, "[CALL-DIAG] native-audio-playback-failed");
        let _ = started.send(Err(error));
    }
}

#[cfg(target_os = "linux")]
fn run_pulse_playback(
    session: Arc<AudioPlaybackSession>,
    device_id: Option<&str>,
    started: &std::sync::mpsc::SyncSender<Result<(), String>>,
) -> Result<(), String> {
    let runtime = pulse_runtime()?;
    let client = pulse_client()?;
    let sink_name = match device_id {
        Some(device_id) => {
            let name = device_id
                .strip_prefix("pulseaudio:")
                .ok_or_else(|| "selected speaker is unavailable".to_string())?;
            CString::new(name).map_err(|_| "invalid speaker device identifier".to_string())?
        }
        None => protocol::DEFAULT_SINK.to_owned(),
    };
    let sink = runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(5), client.sink_info_by_name(sink_name)).await
        })
        .map_err(|_| "speaker device selection timed out".to_string())?
        .map_err(|_| "selected speaker is unavailable".to_string())?;
    let callback_session = session.clone();
    let callback = move |output: &mut [u8]| callback_session.fill(output);
    let frame_bytes = (FRAME_SAMPLES * std::mem::size_of::<f32>()) as u32;
    let params = protocol::PlaybackStreamParams {
        sample_spec: protocol::SampleSpec {
            format: protocol::SampleFormat::Float32Le,
            channels: 1,
            sample_rate: 48_000,
        },
        channel_map: protocol::ChannelMap::mono(),
        cvolume: Some(protocol::ChannelVolume::norm(1)),
        sink_index: Some(sink.index),
        buffer_attr: protocol::stream::BufferAttr {
            max_length: frame_bytes * 6,
            target_length: frame_bytes * 3,
            pre_buffering: frame_bytes * 2,
            minimum_request_length: frame_bytes,
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
                client.create_playback_stream(params, callback.as_playback_source()),
            )
            .await
        })
        .map_err(|_| "audio playback stream creation timed out".to_string())?
        .map_err(|_| "audio playback stream could not be opened".to_string())?;
    if stream.sample_spec().format != protocol::SampleFormat::Float32Le
        || stream.sample_spec().channels != 1
        || stream.sample_spec().sample_rate != 48_000
    {
        return Err("audio playback stream format negotiation failed".to_string());
    }
    tracing::info!(
        sink_index = sink.index,
        sample_rate = stream.sample_spec().sample_rate,
        channels = stream.sample_spec().channels,
        "[CALL-DIAG] native-audio-playback-started"
    );
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

#[cfg(target_os = "linux")]
fn pulse_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|_| "audio playback runtime unavailable".to_string())
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
        .map_err(|_| "audio playback server connection failed".to_string())?;
    socket
        .set_write_timeout(timeout)
        .map_err(|_| "audio playback server connection failed".to_string())?;
    let cookie = pulseaudio::cookie_path_from_env().and_then(|path| std::fs::read(path).ok());
    PulseClient::new_unix(c"Qor", socket, cookie.as_deref())
        .map_err(|_| "audio playback server connection failed".to_string())
}

#[cfg(target_os = "windows")]
fn run_playback(
    _session: Arc<AudioPlaybackSession>,
    _device_id: Option<&str>,
    started: std::sync::mpsc::SyncSender<Result<(), String>>,
) {
    let _ = started.send(Err("native audio playback is unavailable".to_string()));
}

fn validate_session_id(session_id: &str) -> Result<(), String> {
    if session_id.len() != 32
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid audio playback session".to_string());
    }
    Ok(())
}

fn validate_device_id(device_id: &str) -> Result<(), String> {
    if device_id.is_empty() || device_id.len() > 1024 || device_id.chars().any(char::is_control) {
        return Err("invalid speaker device identifier".to_string());
    }
    Ok(())
}
