import React, { useState, useRef, useEffect } from 'react';
import { Button } from '../ui/button';
import { Square, Play, Pause, Trash2, Send } from 'lucide-react';

interface VoiceRecorderProps {
  onSendVoiceNote: (audioBlob: Blob) => void;
  onCancel: () => void;
  disabled?: boolean;
}

export function VoiceRecorder({ onSendVoiceNote, onCancel, disabled }: VoiceRecorderProps) {
  const [isRecording, setIsRecording] = useState(false);
  const isRecordingRef = useRef(false);
  const [isPlaying, setIsPlaying] = useState(false);
  const [recordedBlob, setRecordedBlob] = useState<Blob | null>(null);
  const [duration, setDuration] = useState(0);
  const [currentTime, setCurrentTime] = useState(0);
  const [audioLevel, setAudioLevel] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const chunksRef = useRef<Blob[]>([]);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const animationRef = useRef<number | null>(null);
  const analyserRef = useRef<AnalyserNode | null>(null);
  const audioContextRef = useRef<AudioContext | null>(null);
  const blobUrlRef = useRef<string | null>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const cleanup = () => {
    if (mediaRecorderRef.current && mediaRecorderRef.current.state === 'recording') {
      mediaRecorderRef.current.stop();
    }
    if (streamRef.current) {
      streamRef.current.getTracks().forEach(track => track.stop());
      streamRef.current = null;
    }
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    if (animationRef.current) {
      cancelAnimationFrame(animationRef.current);
      animationRef.current = null;
    }
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
    setAudioLevel(0);
  };

  useEffect(() => {
    startRecording();
    return cleanup;
  }, []);

  const drawVisualizer = () => {
    if (!analyserRef.current || !canvasRef.current) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const bufferLength = analyserRef.current.frequencyBinCount;
    const dataArray = new Uint8Array(bufferLength);
    analyserRef.current.getByteFrequencyData(dataArray);

    const average = dataArray.reduce((sum, value) => sum + value, 0) / dataArray.length;
    setAudioLevel(average / 255);

    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();

    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;

    ctx.scale(dpr, dpr);

    ctx.clearRect(0, 0, rect.width, rect.height);

    const barWidth = 4;
    const gap = 2;
    const barCount = Math.floor(rect.width / (barWidth + gap));
    const step = Math.floor(bufferLength / barCount);

    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--color-accent-primary') || '#3b82f6';

    for (let i = 0; i < barCount; i++) {
      const value = dataArray[i * step];
      const percent = value / 255;
      const height = Math.max(4, percent * rect.height); // Minimum height of 4px
      const y = (rect.height - height) / 2;

      // Make bars rounded with 2px radius
      ctx.beginPath();
      ctx.roundRect(i * (barWidth + gap), y, barWidth, height, 2);
      ctx.fill();
    }

    if (isRecordingRef.current) {
      animationRef.current = requestAnimationFrame(drawVisualizer);
    }
  };

  const startRecording = async () => {
    try {
      setError(null);
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        throw new Error('Media devices not supported');
      }

      // Load set microphone from settings
      let micDeviceId: string | undefined;
      try {
        const { syncEncryptedStorage } = await import('../../lib/encrypted-storage');
        const stored = syncEncryptedStorage.getItem('app_settings_v1');
        if (stored) {
          const parsed = JSON.parse(stored);
          if (parsed.preferredMicId) {
            const devices = await navigator.mediaDevices.enumerateDevices();
            const micAvailable = devices.some(d => d.kind === 'audioinput' && d.deviceId === parsed.preferredMicId);
            if (micAvailable) {
              micDeviceId = parsed.preferredMicId;
            }
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

      const stream = await navigator.mediaDevices.getUserMedia({ audio: audioConstraints });
      streamRef.current = stream;

      const AudioCtx: typeof AudioContext = (window as any).AudioContext || (window as any).webkitAudioContext;
      const audioContext = new AudioCtx();
      if (audioContext.state === 'suspended') {
        await audioContext.resume();
      }
      const analyser = audioContext.createAnalyser();
      const source = audioContext.createMediaStreamSource(stream);
      source.connect(analyser);
      analyser.fftSize = 256;
      analyser.smoothingTimeConstant = 0.8;
      audioContextRef.current = audioContext;
      analyserRef.current = analyser;

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

      mediaRecorder.ondataavailable = (e) => {
        if (e.data.size > 0) chunksRef.current.push(e.data);
      };

      mediaRecorder.onstop = () => {
        const blob = new Blob(chunksRef.current, { type: mimeType });
        setRecordedBlob(blob);
        if (streamRef.current) {
          streamRef.current.getTracks().forEach(track => track.stop());
          streamRef.current = null;
        }
        if (intervalRef.current) {
          clearInterval(intervalRef.current);
          intervalRef.current = null;
        }
        if (animationRef.current) {
          cancelAnimationFrame(animationRef.current);
          animationRef.current = null;
        }
        if (audioContextRef.current) {
          audioContextRef.current.close();
          audioContextRef.current = null;
        }
        setIsRecording(false);
        isRecordingRef.current = false;
      };

      mediaRecorder.start();
      setIsRecording(true);
      isRecordingRef.current = true;
      setDuration(0);

      intervalRef.current = setInterval(() => {
        setDuration(prev => prev + 1);
      }, 1000);

      drawVisualizer();

    } catch (err) {
      console.error(err);
      setError('Failed to access microphone');
      cleanup();
    }
  };

  const stopRecording = () => {
    if (mediaRecorderRef.current && isRecording) {
      mediaRecorderRef.current.stop();
    }
  };

  const playRecording = () => {
    if (!recordedBlob) return;

    if (!audioRef.current) {
      const blobUrl = URL.createObjectURL(recordedBlob);
      blobUrlRef.current = blobUrl;
      const audio = new Audio(blobUrl);
      audioRef.current = audio;

      audio.onloadedmetadata = () => {
        if (audio.duration === Infinity) {
          audio.currentTime = 1e101;
          audio.ontimeupdate = () => {
            audio.ontimeupdate = null;
            audio.currentTime = 0;
            setDuration(Math.floor(audio.duration));
          }
        } else {
          setDuration(Math.floor(audio.duration));
        }
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

  const pausePlayback = () => {
    if (audioRef.current) {
      audioRef.current.pause();
      setIsPlaying(false);
    }
  };

  const sendVoiceNote = async () => {
    if (recordedBlob && !disabled) {
      try {
        await onSendVoiceNote(recordedBlob);
      } catch (error) {
        console.error('Error sending voice note:', error);
      }
    }
  };

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  return (
    <div className="flex items-center gap-3 w-full h-full animate-in fade-in duration-200">
      <Button
        onClick={onCancel}
        variant="ghost"
        size="icon"
        className="h-8 w-8 text-muted-foreground hover:text-destructive transition-colors"
        title="Cancel recording"
      >
        <Trash2 className="w-5 h-5" />
      </Button>

      {error ? (
        <div className="flex-1 text-destructive text-sm truncate">{error}</div>
      ) : !recordedBlob ? (
        // Recording State
        <>
          <div className="flex items-center gap-2 text-destructive animate-pulse font-mono text-sm min-w-[3rem]">
            <div className="w-2 h-2 rounded-full bg-destructive" style={{ opacity: Math.max(0.25, Math.min(1, 0.25 + audioLevel)) }} />
            {formatTime(duration)}
          </div>

          <div className="flex-1 h-8 flex items-center justify-center overflow-hidden mx-2">
            <canvas
              ref={canvasRef}
              width={200}
              height={32}
              className="w-full h-full opacity-80"
            />
          </div>

          <Button
            onClick={stopRecording}
            variant="default"
            size="icon"
            className="h-8 w-8 rounded-full bg-destructive hover:bg-destructive/90 text-white shadow-sm"
            title="Stop recording"
          >
            <Square className="w-4 h-4 fill-current" />
          </Button>
        </>
      ) : (
        // Review State
        <>
          <Button
            onClick={isPlaying ? pausePlayback : playRecording}
            variant="ghost"
            size="icon"
            className="h-8 w-8 text-primary"
          >
            {isPlaying ? <Pause className="w-5 h-5 fill-current" /> : <Play className="w-5 h-5 fill-current" />}
          </Button>

          <div className="flex-1 flex items-center gap-2">
            <div className="h-1 flex-1 bg-muted rounded-full overflow-hidden relative">
              <div
                className="absolute top-0 left-0 h-full bg-primary transition-all duration-100"
                style={{ width: `${duration > 0 ? (currentTime / duration) * 100 : 0}%` }}
              />
            </div>
            <span className="text-xs font-mono text-muted-foreground min-w-[6rem] text-right whitespace-nowrap">
              {formatTime(currentTime)} / {formatTime(duration)}
            </span>
          </div>

          <Button
            onClick={sendVoiceNote}
            disabled={disabled}
            variant="default"
            size="icon"
            className="h-8 w-8 rounded-full bg-primary hover:bg-primary/90 text-primary-foreground shadow-sm disabled:opacity-50"
            title="Send voice note"
          >
            <Send className="w-4 h-4" />
          </Button>
        </>
      )}
    </div>
  );
}