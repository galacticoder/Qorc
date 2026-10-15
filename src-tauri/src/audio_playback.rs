#[cfg(target_os = "linux")]
use pulseaudio::{AsPlaybackSource, Client as PulseClient, protocol};
use std::collections::{HashMap, VecDeque};
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const FRAME_SAMPLES: usize = 960;
const MAX_QUEUE_SAMPLES: usize = FRAME_SAMPLES * 10;
const EDGE_FADE_SAMPLES: usize = 240;
const MAX_SESSIONS: usize = 2;

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AudioPlaybackInfo {
    pub queued_ms: f64,
    pub level: f32,
    pub underruns: u64,
    pub underrun_ms: f64,
}

struct PlaybackQueue {
    samples: VecDeque<f32>,
    gain: f32,
    playing: bool,
    starved: bool,
    underruns: u64,
    underrun_samples: u64,
}

impl PlaybackQueue {
    fn new() -> Self {
        Self {
            samples: VecDeque::with_capacity(MAX_QUEUE_SAMPLES),
            gain: 0.0,
            playing: false,
            starved: false,
            underruns: 0,
            underrun_samples: 0,
        }
    }

    fn next(&mut self) -> f32 {
        let remaining = self.samples.len();
        let Some(sample) = self.samples.pop_front() else {
            if self.playing {
                if !self.starved {
                    self.underruns += 1;
                }
                self.underrun_samples += 1;
                self.starved = true;
            }
            self.gain = 0.0;
            return 0.0;
        };
        self.playing = true;
        self.starved = false;
        let target = (remaining as f32 / EDGE_FADE_SAMPLES as f32).min(1.0);
        self.gain = (self.gain + 1.0 / EDGE_FADE_SAMPLES as f32).min(target);
        sample * self.gain
    }
}

struct AudioPlaybackSession {
    stop: AtomicBool,
    queue: Mutex<PlaybackQueue>,
    worker: Mutex<Option<JoinHandle<()>>>,
    level: AtomicU32,
    level_at: AtomicU64,
    started_at: Instant,
}

impl AudioPlaybackSession {
    fn new() -> Self {
        Self {
            stop: AtomicBool::new(false),
            queue: Mutex::new(PlaybackQueue::new()),
            worker: Mutex::new(None),
            level: AtomicU32::new(0),
            level_at: AtomicU64::new(0),
            started_at: Instant::now(),
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
        while queue.samples.len() + FRAME_SAMPLES > MAX_QUEUE_SAMPLES {
            for _ in 0..FRAME_SAMPLES.min(queue.samples.len()) {
                queue.samples.pop_front();
            }
        }
        for bytes in input.chunks_exact(4) {
            let sample = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            queue.samples.push_back(if sample.is_finite() {
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
        let mut energy = 0.0f64;
        for bytes in output.chunks_exact_mut(4) {
            let sample = queue.next();
            energy += f64::from(sample).powi(2);
            bytes.copy_from_slice(&sample.to_le_bytes());
        }
        self.record_level(energy, output.len() / 4);
        output.len()
    }

    fn record_level(&self, energy: f64, samples: usize) {
        let level = if samples == 0 {
            0.0
        } else {
            (energy / samples as f64).sqrt() as f32
        };
        self.level.store(level.to_bits(), Ordering::Release);
        self.level_at.store(
            self.started_at.elapsed().as_millis() as u64,
            Ordering::Release,
        );
    }

    fn info(&self) -> Result<AudioPlaybackInfo, String> {
        let queue = self
            .queue
            .lock()
            .map_err(|_| "audio playback queue unavailable")?;
        let level = if (self.started_at.elapsed().as_millis() as u64)
            .saturating_sub(self.level_at.load(Ordering::Acquire))
            < 200
        {
            f32::from_bits(self.level.load(Ordering::Acquire))
        } else {
            0.0
        };
        Ok(AudioPlaybackInfo {
            queued_ms: queue.samples.len() as f64 / 48.0,
            level,
            underruns: queue.underruns,
            underrun_ms: queue.underrun_samples as f64 / 48.0,
        })
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        self.level.store(0, Ordering::Release);
        if let Ok(mut worker) = self.worker.lock()
            && let Some(worker) = worker.take()
        {
            let _ = worker.join();
        }
        if let Ok(mut queue) = self.queue.lock() {
            for sample in queue.samples.iter_mut() {
                *sample = 0.0;
            }
            queue.samples.clear();
            queue.gain = 0.0;
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

    pub fn info(&self, session_id: &str) -> Result<AudioPlaybackInfo, String> {
        validate_session_id(session_id)?;
        let session = self
            .sessions
            .lock()
            .map_err(|_| "audio playback unavailable")?
            .get(session_id)
            .cloned()
            .ok_or_else(|| "audio playback session unavailable".to_string())?;
        session.info()
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
                let mut energy = 0.0f64;
                for frame in output.chunks_exact_mut(channels) {
                    let sample = resampler.next(&mut queue);
                    energy += f64::from(sample).powi(2);
                    frame.fill(T::from_sample(sample));
                }
                session.record_level(energy, output.len() / channels);
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

    fn next(&mut self, queue: &mut PlaybackQueue) -> f32 {
        let (mut left, mut right) = self.samples.unwrap_or_else(|| (queue.next(), queue.next()));
        let value = left + (right - left) * self.position as f32;
        self.position += self.step;
        while self.position >= 1.0 {
            self.position -= 1.0;
            left = right;
            right = queue.next();
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
        let mut queue = PlaybackQueue::new();
        queue.gain = 1.0;
        queue.samples.extend([0.25, -0.5, 1.0, -1.0]);
        queue.samples.extend(vec![0.0; EDGE_FADE_SAMPLES]);
        let mut resampler = PlaybackResampler::new(48_000);
        let output: Vec<_> = (0..EDGE_FADE_SAMPLES + 7)
            .map(|_| resampler.next(&mut queue))
            .collect();
        assert_eq!(&output[..4], &[0.25, -0.5, 1.0, -1.0]);
        assert!(output[4..].iter().all(|sample| *sample == 0.0));
        assert_eq!(queue.underruns, 1);
    }

    #[test]
    fn playback_resamples_across_callback_boundaries() {
        for rate in [44_100, 48_000, 96_000, 192_000] {
            let mut queue = PlaybackQueue::new();
            queue.gain = 1.0;
            queue
                .samples
                .extend((0..48_002 + EDGE_FADE_SAMPLES).map(|i| i as f32 / 48_000.0));
            let mut resampler = PlaybackResampler::new(rate);
            for index in 0..rate {
                let sample = resampler.next(&mut queue);
                assert!((sample - index as f32 / rate as f32).abs() < 0.00001);
            }
            assert!(queue.samples.len() <= EDGE_FADE_SAMPLES + 1);
            assert_eq!(queue.underruns, 0);
        }
    }

    #[test]
    fn underrun_edges_fade_without_affecting_steady_audio() {
        let mut queue = PlaybackQueue::new();
        for _ in 0..FRAME_SAMPLES {
            assert_eq!(queue.next(), 0.0);
        }
        assert_eq!(queue.underruns, 0);
        queue.samples.extend(vec![0.75; FRAME_SAMPLES]);
        let output: Vec<_> = (0..FRAME_SAMPLES).map(|_| queue.next()).collect();
        let step = 0.75 / EDGE_FADE_SAMPLES as f32;
        assert!(output[0] <= step + 0.00001);
        assert_eq!(output[FRAME_SAMPLES / 2], 0.75);
        assert!(output[FRAME_SAMPLES - 1] <= step + 0.00001);
        assert!(
            output
                .windows(2)
                .all(|pair| (pair[1] - pair[0]).abs() <= step + 0.00001)
        );
        for _ in 0..4800 {
            assert_eq!(queue.next(), 0.0);
        }
        assert_eq!(queue.underruns, 1);
        assert_eq!(queue.underrun_samples, 4800);
        queue.samples.extend(vec![-0.75; FRAME_SAMPLES]);
        assert!(queue.next().abs() <= step + 0.00001);
        for _ in 1..FRAME_SAMPLES {
            queue.next();
        }
        assert_eq!(queue.next(), 0.0);
        assert_eq!(queue.underruns, 2);
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
        assert_eq!(queue.samples.len(), MAX_QUEUE_SAMPLES);
        assert_eq!(
            queue.samples.iter().take(4).copied().collect::<Vec<_>>(),
            [0.0, 0.0, 1.0, -1.0]
        );
        drop(queue);
        session.stop();
        assert!(session.push(&frame).is_err());
        assert!(session.queue.lock().unwrap().samples.is_empty());
    }

    #[test]
    fn output_level_is_measured_from_played_samples_not_queued_samples() {
        let session = AudioPlaybackSession::new();
        let frame: Vec<_> = (0..FRAME_SAMPLES)
            .flat_map(|_| 0.5f32.to_le_bytes())
            .collect();
        session.push(&frame).unwrap();
        let initial = session.info().unwrap();
        assert_eq!(initial.queued_ms, 20.0);
        assert_eq!(initial.level, 0.0);
        let mut queue = session.queue.lock().unwrap();
        let energy = (0..FRAME_SAMPLES)
            .map(|_| f64::from(queue.next()).powi(2))
            .sum();
        session.record_level(energy, FRAME_SAMPLES);
        drop(queue);
        let level = session.info().unwrap().level;
        assert!(level > 0.0 && level < 0.5);
        session.record_level(0.0, FRAME_SAMPLES);
        assert_eq!(session.info().unwrap().level, 0.0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_output_callback_reports_loudness_and_clears_it_on_underrun() {
        let session = AudioPlaybackSession::new();
        let frame: Vec<_> = (0..FRAME_SAMPLES)
            .flat_map(|_| 0.25f32.to_le_bytes())
            .collect();
        session.push(&frame).unwrap();
        let mut output = vec![0; FRAME_SAMPLES * 4];
        session.fill(&mut output);
        let energy: f64 = output
            .chunks_exact(4)
            .map(|bytes| f64::from(f32::from_le_bytes(bytes.try_into().unwrap())).powi(2))
            .sum();
        assert_eq!(
            session.info().unwrap().level,
            (energy / FRAME_SAMPLES as f64).sqrt() as f32
        );
        assert_eq!(session.info().unwrap().queued_ms, 0.0);
        session.fill(&mut output);
        assert!(output.iter().all(|sample| *sample == 0));
        assert_eq!(session.info().unwrap().level, 0.0);
        assert_eq!(session.info().unwrap().underruns, 1);
        assert_eq!(session.info().unwrap().underrun_ms, 20.0);
    }
}
