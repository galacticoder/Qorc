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
        if self.stop.load(Ordering::Acquire) {
            return Err("audio playback stream stopped".to_string());
        }
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

    #[cfg(target_os = "linux")]
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
            .name("qorc-audio-playback".to_string())
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
    PulseClient::new_unix(c"qorc", socket, cookie.as_deref())
        .map_err(|_| "audio playback server connection failed".to_string())
}

#[cfg(target_os = "windows")]
fn run_playback(
    session: Arc<AudioPlaybackSession>,
    device_id: Option<&str>,
    started: std::sync::mpsc::SyncSender<Result<(), String>>,
) {
    use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
    let open = || -> Result<cpal::Stream, String> {
        let host = cpal::default_host();
        let device = if let Some(device_id) = device_id {
            let id = device_id
                .parse()
                .map_err(|_| "invalid speaker device identifier")?;
            host.device_by_id(&id)
                .filter(DeviceTrait::supports_output)
                .ok_or("selected speaker is unavailable")?
        } else {
            host.default_output_device()
                .ok_or("no speaker is available")?
        };
        let selected = device
            .default_output_config()
            .map_err(|error| format!("speaker format unavailable: {error}"))?;
        let config = selected.config();
        if config.channels == 0 || config.sample_rate == 0 {
            return Err("invalid speaker format".to_string());
        }
        tracing::info!(
            sample_rate = config.sample_rate,
            channels = config.channels,
            sample_format = %selected.sample_format(),
            "[CALL-DIAG] native-audio-playback-selected-profile"
        );
        match selected.sample_format() {
            cpal::SampleFormat::F32 => output_stream::<f32>(&device, config, session.clone()),
            cpal::SampleFormat::F64 => output_stream::<f64>(&device, config, session.clone()),
            cpal::SampleFormat::I8 => output_stream::<i8>(&device, config, session.clone()),
            cpal::SampleFormat::I16 => output_stream::<i16>(&device, config, session.clone()),
            cpal::SampleFormat::I24 => output_stream::<cpal::I24>(&device, config, session.clone()),
            cpal::SampleFormat::I32 => output_stream::<i32>(&device, config, session.clone()),
            cpal::SampleFormat::I64 => output_stream::<i64>(&device, config, session.clone()),
            cpal::SampleFormat::U8 => output_stream::<u8>(&device, config, session.clone()),
            cpal::SampleFormat::U16 => output_stream::<u16>(&device, config, session.clone()),
            cpal::SampleFormat::U24 => output_stream::<cpal::U24>(&device, config, session.clone()),
            cpal::SampleFormat::U32 => output_stream::<u32>(&device, config, session.clone()),
            cpal::SampleFormat::U64 => output_stream::<u64>(&device, config, session.clone()),
            _ => Err("speaker has an unsupported PCM format".to_string()),
        }
    };
    let stream = match open() {
        Ok(stream) => stream,
        Err(error) => {
            tracing::warn!(error = %error, "[CALL-DIAG] native-audio-playback-open-failed");
            let _ = started.send(Err(error));
            return;
        }
    };
    if let Err(error) = stream.play() {
        tracing::warn!(error = %error, "[CALL-DIAG] native-audio-playback-start-failed");
        let _ = started.send(Err("speaker stream could not be started".to_string()));
        return;
    }
    tracing::info!("[CALL-DIAG] native-audio-playback-started");
    let _ = started.send(Ok(()));
    while !session.stop.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(20));
    }
    drop(stream);
}

#[cfg(target_os = "windows")]
fn output_stream<T>(
    device: &cpal::Device,
    config: cpal::StreamConfig,
    session: Arc<AudioPlaybackSession>,
) -> Result<cpal::Stream, String>
where
    T: cpal::SizedSample + cpal::FromSample<f32>,
{
    use cpal::traits::DeviceTrait;
    let channels = config.channels as usize;
    let mut resampler = PlaybackResampler::new(config.sample_rate);
    let error_session = session.clone();
    device
        .build_output_stream::<T, _, _>(
            config,
            move |output, _| {
                output.fill(T::EQUILIBRIUM);
                if session.stop.load(Ordering::Acquire) {
                    return;
                }
                let Ok(mut queue) = session.queue.lock() else {
                    return;
                };
                for frame in output.chunks_exact_mut(channels) {
                    frame.fill(T::from_sample(resampler.next(&mut queue)));
                }
            },
            move |error| {
                tracing::warn!(error = %error, "[CALL-DIAG] native-audio-playback-stream-failed");
                error_session.stop.store(true, Ordering::Release);
            },
            Some(Duration::from_secs(5)),
        )
        .map_err(|error| format!("speaker stream could not be opened: {error}"))
}

#[cfg(any(target_os = "windows", test))]
struct PlaybackResampler {
    step: f64,
    position: f64,
    samples: Option<(f32, f32)>,
}

#[cfg(any(target_os = "windows", test))]
impl PlaybackResampler {
    fn new(sample_rate: u32) -> Self {
        Self {
            step: 48_000.0 / sample_rate as f64,
            position: 0.0,
            samples: None,
        }
    }

    fn next(&mut self, queue: &mut VecDeque<f32>) -> f32 {
        let (mut left, mut right) = self.samples.unwrap_or_else(|| {
            (
                queue.pop_front().unwrap_or(0.0),
                queue.pop_front().unwrap_or(0.0),
            )
        });
        let value = left + (right - left) * self.position as f32;
        self.position += self.step;
        while self.position >= 1.0 {
            self.position -= 1.0;
            left = right;
            right = queue.pop_front().unwrap_or(0.0);
        }
        self.samples = Some((left, right));
        value
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn playback_preserves_48khz_samples_and_outputs_silence_on_underrun() {
        let mut queue = VecDeque::from([0.25, -0.5, 1.0, -1.0]);
        let mut resampler = PlaybackResampler::new(48_000);
        let output: Vec<_> = (0..7).map(|_| resampler.next(&mut queue)).collect();
        assert_eq!(output, [0.25, -0.5, 1.0, -1.0, 0.0, 0.0, 0.0]);
    }

    #[test]
    fn playback_resamples_across_callback_boundaries() {
        for rate in [44_100, 48_000, 96_000, 192_000] {
            let mut queue: VecDeque<_> = (0..48_002).map(|i| i as f32 / 48_000.0).collect();
            let mut resampler = PlaybackResampler::new(rate);
            for index in 0..rate {
                let sample = resampler.next(&mut queue);
                assert!((sample - index as f32 / rate as f32).abs() < 0.00001);
            }
            assert!(queue.len() <= 1);
        }
    }

    #[test]
    fn playback_queue_is_bounded_and_sanitizes_nonfinite_samples() {
        let session = AudioPlaybackSession::new();
        let frame: Vec<_> = [f32::NAN, f32::INFINITY, 2.0, -2.0]
            .into_iter()
            .cycle()
            .take(FRAME_SAMPLES)
            .flat_map(f32::to_le_bytes)
            .collect();
        for _ in 0..20 {
            session.push(&frame).unwrap();
        }
        let queue = session.queue.lock().unwrap();
        assert_eq!(queue.len(), MAX_QUEUE_SAMPLES);
        assert_eq!(
            queue.iter().take(4).copied().collect::<Vec<_>>(),
            [0.0, 0.0, 1.0, -1.0]
        );
        drop(queue);
        session.stop();
        assert!(session.push(&frame).is_err());
        assert!(session.queue.lock().unwrap().is_empty());
    }
}
