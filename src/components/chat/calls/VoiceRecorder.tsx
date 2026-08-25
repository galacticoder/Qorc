import { useState, useRef, useEffect } from 'react';
import { MAX_VOICE_NOTE_BYTES, MAX_VOICE_NOTE_DURATION_SECONDS } from '../../../lib/constants';
import { Square, Play, Pause, Trash2, SendHorizontal } from 'lucide-react';
import { requireNativeMediaAccess } from '../../../lib/tauri-bindings';
import { syncEncryptedStorage } from '../../../lib/database/encrypted-storage';
import { isValidMediaDeviceId } from '../../../lib/utils/calling-utils';
import { formatClockDurationSeconds } from '../../../lib/utils/date-utils';
import { STORAGE_KEYS } from '../../../lib/database/storage-keys';

const LEVEL_HISTORY_SIZE = 96;
const MICROPHONE_PERMISSION_ERROR = 'Microphone permission is required';

const isMicrophonePermissionError = (error: unknown): boolean => {
  const name = error instanceof Error ? error.name : '';
  const message = error instanceof Error ? error.message : String(error || '');
  return name === 'NotAllowedError' ||
    name === 'SecurityError' ||
    /permission|not allowed|denied/i.test(message);
};

// Props for the voice recorder control
interface VoiceRecorderProps {
  onSendVoiceNote: (audioBlob: Blob, durationSec: number) => void | Promise<void>;
  onCancel: () => void;
  disabled?: boolean;
}

// Voice recorder component for capturing and previewing voice notes
export function VoiceRecorder({ onSendVoiceNote, onCancel, disabled }: VoiceRecorderProps) {
  const [isRecording, setIsRecording] = useState(false);
  const isRecordingRef = useRef(false);
  const [isPlaying, setIsPlaying] = useState(false);
  const [recordedBlob, setRecordedBlob] = useState<Blob | null>(null);
  const [duration, setDuration] = useState(0);
  const [currentTime, setCurrentTime] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const chunksRef = useRef<Blob[]>([]);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const limitTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const permissionDismissTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const animationRef = useRef<number | null>(null);
  const analyserRef = useRef<AnalyserNode | null>(null);
  const sourceNodeRef = useRef<MediaStreamAudioSourceNode | null>(null);
  const meterSinkRef = useRef<GainNode | null>(null);
  const audioContextRef = useRef<AudioContext | null>(null);
  const blobUrlRef = useRef<string | null>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const recordStartRef = useRef(0);
  const finalDurationRef = useRef(0);
  const recordedBytesRef = useRef(0);
  const recordingRejectedRef = useRef(false);
  const visualizerSamplesRef = useRef<Uint8Array | null>(null);
  const levelHistoryRef = useRef<number[]>(Array.from({ length: LEVEL_HISTORY_SIZE }, () => 0));
  const smoothedLevelRef = useRef(0);
  const lastLevelSampleRef = useRef(0);

  // Release media resources and reset state
  const cleanup = () => {
    const recorder = mediaRecorderRef.current;
    if (recorder) {
      recorder.ondataavailable = null;
      recorder.onstop = null;
      recorder.onerror = null;
      if (recorder.state !== 'inactive') recorder.stop();
      mediaRecorderRef.current = null;
    }
    chunksRef.current = [];
    recordedBytesRef.current = 0;
    recordingRejectedRef.current = false;
    if (streamRef.current) {
      streamRef.current.getTracks().forEach(track => track.stop());
      streamRef.current = null;
    }
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    if (limitTimeoutRef.current) {
      clearTimeout(limitTimeoutRef.current);
      limitTimeoutRef.current = null;
    }
    if (permissionDismissTimeoutRef.current) {
      clearTimeout(permissionDismissTimeoutRef.current);
      permissionDismissTimeoutRef.current = null;
    }
    if (animationRef.current !== null) {
      cancelAnimationFrame(animationRef.current);
      animationRef.current = null;
    }
    analyserRef.current = null;
    if (sourceNodeRef.current) {
      sourceNodeRef.current.disconnect();
      sourceNodeRef.current = null;
    }
    if (meterSinkRef.current) {
      meterSinkRef.current.disconnect();
      meterSinkRef.current = null;
    }
    visualizerSamplesRef.current = null;
    levelHistoryRef.current = Array.from({ length: LEVEL_HISTORY_SIZE }, () => 0);
    smoothedLevelRef.current = 0;
    lastLevelSampleRef.current = 0;
    if (audioContextRef.current) {
      audioContextRef.current.close();
      audioContextRef.current = null;
    }
    if (blobUrlRef.current) {
      URL.revokeObjectURL(blobUrlRef.current);
      blobUrlRef.current = null;
    }
    if (audioRef.current) {
      audioRef.current.pause();
      audioRef.current.src = '';
      audioRef.current = null;
    }
    setIsRecording(false);
    isRecordingRef.current = false;
    setIsPlaying(false);
    setRecordedBlob(null);
  };

  useEffect(() => {
    startRecording();
    return cleanup;
  }, []);

  // Draw live mic level bars on canvas
  const drawVisualizer = (frameTime = performance.now()) => {
    if (!analyserRef.current || !canvasRef.current) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const analyser = analyserRef.current;
    let samples = visualizerSamplesRef.current;
    if (!samples || samples.length !== analyser.fftSize) {
      samples = new Uint8Array(analyser.fftSize);
      visualizerSamplesRef.current = samples;
    }
    analyser.getByteTimeDomainData(samples);

    let squareSum = 0;
    for (let index = 0; index < samples.length; index += 1) {
      const centered = (samples[index] - 128) / 128;
      squareSum += centered * centered;
    }
    const rms = Math.sqrt(squareSum / samples.length);
    const decibels = 20 * Math.log10(Math.max(rms, 0.00001));
    const targetLevel = rms < 0.002
      ? 0
      : Math.max(0, Math.min(1, (decibels + 60) / 45));
    const previousLevel = smoothedLevelRef.current;
    const smoothing = targetLevel > previousLevel ? 0.34 : 0.1;
    const level = previousLevel + (targetLevel - previousLevel) * smoothing;
    smoothedLevelRef.current = level;

    if (frameTime - lastLevelSampleRef.current >= 45) {
      const history = levelHistoryRef.current;
      history.shift();
      history.push(level);
      lastLevelSampleRef.current = frameTime;
    }

    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    const pixelWidth = Math.max(1, Math.round(rect.width * dpr));
    const pixelHeight = Math.max(1, Math.round(rect.height * dpr));
    if (canvas.width !== pixelWidth || canvas.height !== pixelHeight) {
      canvas.width = pixelWidth;
      canvas.height = pixelHeight;
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    ctx.clearRect(0, 0, rect.width, rect.height);

    const gap = 1.5;
    const fullHistory = levelHistoryRef.current;
    const visibleBarCount = Math.max(1, Math.min(
      fullHistory.length,
      Math.floor((rect.width + gap) / (1 + gap)),
    ));
    const history = fullHistory.slice(-visibleBarCount);
    const barWidth = Math.max(1, (rect.width - gap * (history.length - 1)) / history.length);
    const graphWidth = history.length * barWidth + (history.length - 1) * gap;
    const startX = Math.max(0, rect.width - graphWidth);
    ctx.fillStyle = getComputedStyle(canvas).color || '#777780';

    for (let index = 0; index < history.length; index += 1) {
      const liveShape = 0.46 + Math.abs(Math.sin((index + 1) * 1.31)) * 0.54;
      const displayedLevel = Math.max(history[index], level * liveShape);
      const height = Math.max(2, displayedLevel * (rect.height - 6));
      const y = (rect.height - height) / 2;

      ctx.beginPath();
      ctx.roundRect(
        startX + index * (barWidth + gap),
        y,
        barWidth,
        height,
        Math.min(0.6, barWidth * 0.3),
      );
      ctx.fill();
    }

    if (isRecordingRef.current) {
      animationRef.current = requestAnimationFrame(drawVisualizer);
    }
  };

  // Start microphone recording session
  const startRecording = async () => {
    try {
      setError(null);
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        throw new Error('Media devices not supported');
      }

      // Load set microphone from settings
      let micDeviceId: string | undefined;
      try {
        const stored = syncEncryptedStorage.getItem(STORAGE_KEYS.APP_SETTINGS);
        if (stored) {
          const parsed = JSON.parse(stored);
          if (isValidMediaDeviceId(parsed.preferredMicId)) {
            micDeviceId = parsed.preferredMicId;
          }
        }
      } catch { }

      const audioConstraints: MediaTrackConstraints = {
        echoCancellation: true,
        noiseSuppression: true,
        autoGainControl: true,
      };
      if (micDeviceId) {
        audioConstraints.deviceId = { ideal: micDeviceId };
      }

      await requireNativeMediaAccess('audio');
      const stream = await navigator.mediaDevices.getUserMedia({ audio: audioConstraints });
      streamRef.current = stream;

      const AudioCtx: typeof AudioContext = (window as any).AudioContext || (window as any).webkitAudioContext;
      const audioContext = new AudioCtx();

      if (audioContext.state === 'suspended') {
        await audioContext.resume();
      }
      
      const analyser = audioContext.createAnalyser();
      const source = audioContext.createMediaStreamSource(stream);
      const meterSink = audioContext.createGain();
      meterSink.gain.value = 0;
      source.connect(analyser);
      analyser.connect(meterSink);
      meterSink.connect(audioContext.destination);
      analyser.fftSize = 256;
      analyser.smoothingTimeConstant = 0.65;
      audioContextRef.current = audioContext;
      analyserRef.current = analyser;
      sourceNodeRef.current = source;
      meterSinkRef.current = meterSink;

      let mimeType: string | undefined;
      const supportedTypes = [
        'audio/webm;codecs=opus',
        'audio/ogg;codecs=opus',
        'audio/webm',
        'audio/mp4',
        'audio/mpeg'
      ];
      for (const type of supportedTypes) {
        if (MediaRecorder.isTypeSupported(type)) { mimeType = type; break; }
      }
      if (!mimeType) throw new Error('No supported audio format');

      const mediaRecorder = new MediaRecorder(stream, { mimeType, audioBitsPerSecond: 32000 });
      mediaRecorderRef.current = mediaRecorder;
      chunksRef.current = [];
      recordedBytesRef.current = 0;
      recordingRejectedRef.current = false;

      mediaRecorder.ondataavailable = (e) => {
        if (e.data.size === 0 || recordingRejectedRef.current) return;
        if (recordedBytesRef.current + e.data.size > MAX_VOICE_NOTE_BYTES) {
          recordingRejectedRef.current = true;
          chunksRef.current = [];
          recordedBytesRef.current = 0;
          setError('Voice note is too large');
          if (mediaRecorder.state !== 'inactive') mediaRecorder.stop();
          return;
        }
        recordedBytesRef.current += e.data.size;
        chunksRef.current.push(e.data);
      };

      mediaRecorder.onstop = () => {
        const elapsed = recordStartRef.current > 0
          ? (Date.now() - recordStartRef.current) / 1000
          : 0;
        finalDurationRef.current = Math.min(
          finalDurationRef.current || elapsed,
          MAX_VOICE_NOTE_DURATION_SECONDS,
        );
        if (!recordingRejectedRef.current) {
          const blob = new Blob(chunksRef.current, { type: mimeType });
          setRecordedBlob(blob);
        }
        chunksRef.current = [];
        recordedBytesRef.current = 0;
        if (streamRef.current) {
          streamRef.current.getTracks().forEach(track => track.stop());
          streamRef.current = null;
        }
        if (intervalRef.current) {
          clearInterval(intervalRef.current);
          intervalRef.current = null;
        }
        if (limitTimeoutRef.current) {
          clearTimeout(limitTimeoutRef.current);
          limitTimeoutRef.current = null;
        }
        if (animationRef.current !== null) {
          cancelAnimationFrame(animationRef.current);
          animationRef.current = null;
        }
        analyserRef.current = null;
        if (sourceNodeRef.current) {
          sourceNodeRef.current.disconnect();
          sourceNodeRef.current = null;
        }
        if (meterSinkRef.current) {
          meterSinkRef.current.disconnect();
          meterSinkRef.current = null;
        }
        visualizerSamplesRef.current = null;
        if (audioContextRef.current) {
          audioContextRef.current.close();
          audioContextRef.current = null;
        }
        setIsRecording(false);
        isRecordingRef.current = false;
      };

      recordStartRef.current = Date.now();
      finalDurationRef.current = 0;
      mediaRecorder.start(1_000);
      setIsRecording(true);
      isRecordingRef.current = true;
      setDuration(0);
      levelHistoryRef.current = Array.from({ length: LEVEL_HISTORY_SIZE }, () => 0);
      smoothedLevelRef.current = 0;
      lastLevelSampleRef.current = 0;

      const stopAtLimit = () => {
        if (mediaRecorder.state !== 'recording') return;
        finalDurationRef.current = MAX_VOICE_NOTE_DURATION_SECONDS;
        setDuration(MAX_VOICE_NOTE_DURATION_SECONDS);
        mediaRecorder.stop();
      };

      intervalRef.current = setInterval(() => {
        const elapsedMs = Date.now() - recordStartRef.current;
        setDuration(Math.min(Math.floor(elapsedMs / 1000), MAX_VOICE_NOTE_DURATION_SECONDS));
        if (elapsedMs >= MAX_VOICE_NOTE_DURATION_SECONDS * 1000) stopAtLimit();
      }, 250);
      limitTimeoutRef.current = setTimeout(
        stopAtLimit,
        MAX_VOICE_NOTE_DURATION_SECONDS * 1000,
      );

      drawVisualizer();

    } catch (err) {
      console.error(err);
      const permissionDenied = isMicrophonePermissionError(err);
      setError(permissionDenied ? MICROPHONE_PERMISSION_ERROR : 'Failed to access microphone');
      cleanup();
      if (permissionDenied) {
        permissionDismissTimeoutRef.current = setTimeout(onCancel, 3_000);
      }
    }
  };

  // Stop active recording
  const stopRecording = () => {
    const recorder = mediaRecorderRef.current;
    if (recorder?.state === 'recording') {
      recorder.stop();
    }
  };

  // Play back the recorded audio
  const playRecording = () => {
    if (!recordedBlob) return;

    if (!audioRef.current) {
      const blobUrl = URL.createObjectURL(recordedBlob);
      blobUrlRef.current = blobUrl;
      const audio = new Audio(blobUrl);
      audioRef.current = audio;

      audio.onloadedmetadata = () => {
        if (
          Number.isFinite(audio.duration) &&
          audio.duration > 0 &&
          audio.duration <= MAX_VOICE_NOTE_DURATION_SECONDS + 1
        ) {
          setDuration(Math.min(audio.duration, MAX_VOICE_NOTE_DURATION_SECONDS));
          return;
        }
        setDuration(Math.min(
          finalDurationRef.current || duration,
          MAX_VOICE_NOTE_DURATION_SECONDS,
        ));
      };

      audio.ontimeupdate = () => { setCurrentTime(Math.floor(audio.currentTime)); };
      audio.onended = () => {
        setIsPlaying(false);
        setCurrentTime(0);
      };
    }

    audioRef.current.play();
    setIsPlaying(true);
  };

  // Pause playback of the recording
  const pausePlayback = () => {
    if (audioRef.current) {
      audioRef.current.pause();
      setIsPlaying(false);
    }
  };

  // Send the recorded voice note
  const sendVoiceNote = async () => {
    if (recordedBlob && !disabled) {
      try {
        await onSendVoiceNote(recordedBlob, finalDurationRef.current || duration);
      } catch (error) {
        console.error('Error sending voice note:', error);
      }
    }
  };

  return (
    <div className="qor-voice-recorder" role="region" aria-label="Voice note recorder">
      {error ? (
        error === MICROPHONE_PERMISSION_ERROR ? (
          <div className="qor-voice-recorder-error" role="status">{error}</div>
        ) : (
          <>
            <div className="qor-voice-recorder-error">{error}</div>
            <div className="qor-voice-recorder-actions">
              <button
                type="button"
                onClick={onCancel}
                className="qor-voice-recorder-button qor-voice-recorder-cancel"
                title="Discard voice note"
                aria-label="Discard voice note"
              >
                <Trash2 aria-hidden="true" />
              </button>
            </div>
          </>
        )
      ) : !recordedBlob ? (
        <>
          <div className="qor-voice-recorder-status">
            <span className="qor-voice-recorder-dot" aria-hidden="true" />
            <span className="qor-voice-recorder-label">Recording</span>
            <span className="qor-voice-recorder-time">{formatClockDurationSeconds(duration)}</span>
          </div>

          <div className="qor-voice-recorder-meter-wrap">
            <canvas
              ref={canvasRef}
              width={200}
              height={32}
              className="qor-voice-recorder-meter"
              aria-hidden="true"
            />
          </div>

          <div className="qor-voice-recorder-actions">
            <button
              type="button"
              onClick={onCancel}
              className="qor-voice-recorder-button qor-voice-recorder-cancel"
              title="Discard voice note"
              aria-label="Discard voice note"
            >
              <Trash2 aria-hidden="true" />
            </button>
            <button
              type="button"
              onClick={stopRecording}
              disabled={disabled || !isRecording}
              className="qor-voice-recorder-button qor-voice-recorder-stop"
              title="Stop recording"
              aria-label="Stop recording"
            >
              <Square aria-hidden="true" />
            </button>
          </div>
        </>
      ) : (
        <>
          <button
            type="button"
            onClick={isPlaying ? pausePlayback : playRecording}
            className="qor-voice-recorder-button"
            title={isPlaying ? 'Pause voice note' : 'Play voice note'}
            aria-label={isPlaying ? 'Pause voice note' : 'Play voice note'}
          >
            {isPlaying ? <Pause aria-hidden="true" /> : <Play aria-hidden="true" />}
          </button>

          <div className="qor-voice-recorder-review">
            <div className="qor-voice-recorder-progress">
              <div
                className="qor-voice-recorder-progress-fill"
                style={{ width: `${duration > 0 ? (currentTime / duration) * 100 : 0}%` }}
              />
            </div>
            <span className="qor-voice-recorder-review-time">
              {formatClockDurationSeconds(currentTime)} / {formatClockDurationSeconds(duration)}
            </span>
          </div>

          <div className="qor-voice-recorder-actions">
            <button
              type="button"
              onClick={onCancel}
              className="qor-voice-recorder-button qor-voice-recorder-cancel"
              title="Discard voice note"
              aria-label="Discard voice note"
            >
              <Trash2 aria-hidden="true" />
            </button>
            <button
              type="button"
              onClick={sendVoiceNote}
              disabled={disabled}
              className="qor-send-button qor-voice-recorder-send"
              title="Send voice note"
              aria-label="Send voice note"
            >
              <SendHorizontal aria-hidden="true" />
            </button>
          </div>
        </>
      )}
    </div>
  );
}
