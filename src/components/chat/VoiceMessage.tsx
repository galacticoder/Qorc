import React, { useState, useRef, useEffect, useCallback } from 'react';
import { Button } from '../ui/button';
import { Play, Pause, Download } from 'lucide-react';
import { format } from 'date-fns';

interface VoiceMessageProps {
  audioUrl: string;
  timestamp: Date;
  isCurrentUser: boolean;
  filename?: string;
  originalBase64Data?: string;
  mimeType?: string;
}

export function VoiceMessage({
  audioUrl,
  timestamp,
  isCurrentUser,
  filename,
  originalBase64Data,
  mimeType,
}: VoiceMessageProps) {
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const audioRef = useRef<HTMLAudioElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const peaksRef = useRef<number[] | null>(null);
  const drawRafRef = useRef<number | null>(null);

  const handleLoadedMetadata = useCallback(() => {
    if (!audioRef.current) return;
    const dur = audioRef.current.duration;
    if (isFinite(dur) && dur > 0) {
      setDuration(dur);
    } else {
      try {
        const el = audioRef.current;
        const onTimeUpdate = () => {
          if (isFinite(el.duration) && el.duration > 0) {
            setDuration(el.duration);
            el.removeEventListener('timeupdate', onTimeUpdate);
          }
        };
        el.addEventListener('timeupdate', onTimeUpdate);
        el.play().then(() => { setTimeout(() => el.pause(), 50); }).catch(() => {});
      } catch {}
    }
    setIsLoading(false);
  }, []);

  const handleTimeUpdate = useCallback(() => {
    if (audioRef.current) {
      setCurrentTime(audioRef.current.currentTime);
    }
  }, []);

  const handleEnded = useCallback(() => {
    setIsPlaying(false);
    setCurrentTime(0);
  }, []);

  const handleError = useCallback(() => {
    setError('Failed to load audio');
    setIsLoading(false);
    setIsPlaying(false);
  }, []);

  useEffect(() => {
    return () => {
      if (audioRef.current) {
        audioRef.current.pause();
        audioRef.current.removeEventListener('loadedmetadata', handleLoadedMetadata);
        audioRef.current.removeEventListener('timeupdate', handleTimeUpdate);
        audioRef.current.removeEventListener('ended', handleEnded);
        audioRef.current.removeEventListener('error', handleError);
        audioRef.current = null;
      }
      if (drawRafRef.current) {
        cancelAnimationFrame(drawRafRef.current);
      }
    };
  }, [handleLoadedMetadata, handleTimeUpdate, handleEnded, handleError]);

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const togglePlayback = async () => {
    try {
      setError(null);
      if (isPlaying) {
        if (audioRef.current) {
          audioRef.current.pause();
          setIsPlaying(false);
        }
        return;
      }
      setIsLoading(true);
      if (!audioRef.current) {
        const audio = new Audio(audioUrl);
        audio.preload = 'metadata';
        audioRef.current = audio;
        audio.addEventListener('loadedmetadata', handleLoadedMetadata);
        audio.addEventListener('timeupdate', handleTimeUpdate);
        audio.addEventListener('ended', handleEnded);
        audio.addEventListener('error', handleError);
      }
      await audioRef.current.play();
      setIsPlaying(true);
      setIsLoading(false);
    } catch (_err) {
      setError('Failed to play audio');
      setIsLoading(false);
      setIsPlaying(false);
    }
  };

  const drawWaveform = () => {
    const canvas = canvasRef.current;
    const peaks = peaksRef.current;
    if (!canvas || !peaks) {
      if (canvas) {
        const ctx = canvas.getContext('2d');
        if (ctx) {
          ctx.clearRect(0, 0, canvas.width, canvas.height);
        }
      }
      return;
    }
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const width = canvas.width;
    const height = canvas.height;
    const centerY = Math.floor(height / 2);

    const baseColor = isCurrentUser ? 'rgba(255,255,255,0.45)' : 'rgba(59,130,246,0.35)';
    const progressColor = isCurrentUser ? 'rgba(255,255,255,0.95)' : 'rgba(59,130,246,0.9)';

    ctx.clearRect(0, 0, width, height);

    ctx.fillStyle = baseColor;
    for (let x = 0; x < width; x++) {
      const amp = peaks[x];
      const y = Math.max(1, Math.round(amp * (height / 2)));
      ctx.fillRect(x, centerY - y, 1, y * 2);
    }

    const progress = duration > 0 ? Math.min(1, currentTime / duration) : 0;
    const progressX = Math.round(progress * width);
    ctx.fillStyle = progressColor;
    for (let x = 0; x < progressX; x++) {
      const amp = peaks[x];
      const y = Math.max(1, Math.round(amp * (height / 2)));
      ctx.fillRect(x, centerY - y, 1, y * 2);
    }
  };

  useEffect(() => {
    let cancelled = false;
    peaksRef.current = null;

    const decodeAndComputePeaks = async () => {
      try {
        // Prefer originalBase64Data when available; this avoids any network/CSP interactions
        // and keeps processing local to memory.
        if (!originalBase64Data) {
          // If we only have a blob: URL, skip waveform generation rather than issuing
          // a Fetch API call that would hit CSP connect-src.
          if (typeof audioUrl === 'string' && audioUrl.startsWith('blob:')) {
            peaksRef.current = null;
            drawWaveform();
            return;
          }
        }

        const arrayBuffer = originalBase64Data
          ? (() => {
              const clean = originalBase64Data.trim().replace(/[^A-Za-z0-9+/=]/g, '');
              const binaryString = atob(clean);
              const bytes = new Uint8Array(binaryString.length);
              for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
              return bytes.buffer;
            })()
          : await (await fetch(audioUrl)).arrayBuffer();

        const AudioCtx: typeof AudioContext = (window as any).AudioContext || (window as any).webkitAudioContext;
        const audioCtx = new AudioCtx();
        const audioBuffer = await audioCtx.decodeAudioData(arrayBuffer.slice(0));

        const canvas = canvasRef.current;
        const width = canvas?.width || 240;
        const channelData = audioBuffer.getChannelData(0);
        const samplesPerPixel = Math.max(1, Math.floor(channelData.length / width));
        const peaks: number[] = new Array(width);
        for (let i = 0; i < width; i++) {
          const start = i * samplesPerPixel;
          const end = Math.min(start + samplesPerPixel, channelData.length);
          let min = 1.0;
          let max = -1.0;
          for (let j = start; j < end; j++) {
            const v = channelData[j];
            if (v < min) min = v;
            if (v > max) max = v;
          }
          const amp = Math.max(-min, max);
          peaks[i] = Math.min(1, amp);
        }

        peaksRef.current = peaks;
        drawWaveform();
        try {
          audioCtx.close();
        } catch {}
      } catch (_e) {
        peaksRef.current = null;
        drawWaveform();
      }
    };

    setTimeout(() => {
      if (!cancelled) decodeAndComputePeaks();
    }, 0);

    return () => {
      cancelled = true;
      if (drawRafRef.current) cancelAnimationFrame(drawRafRef.current);
    };
  }, [audioUrl, originalBase64Data]);

  useEffect(() => {
    drawWaveform();
  }, [currentTime, duration, isCurrentUser]);

  const handleDownload = async () => {
    try {
      if (originalBase64Data) {
        try {
          const cleanBase64 = originalBase64Data.trim().replace(/[^A-Za-z0-9+/=]/g, '');
          const binaryString = atob(cleanBase64);
          const bytes = new Uint8Array(binaryString.length);
          for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
          const blob = new Blob([bytes], { type: mimeType || 'audio/webm' });
          const downloadUrl = URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = downloadUrl;
          link.download = filename || `voice-note-${format(timestamp, 'yyyy-MM-dd-HH-mm-ss')}.webm`;
          link.style.display = 'none';
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
          return;
        } catch (_base64Error) {
        }
      }

      if (!audioUrl || audioUrl === 'File' || audioUrl === 'voice-note') {
        alert('Cannot download voice note: Invalid audio data');
        return;
      }
      if (audioUrl.startsWith('blob:')) {
        const link = document.createElement('a');
        link.href = audioUrl;
        link.download = filename || `voice-note-${format(timestamp, 'yyyy-MM-dd-HH-mm-ss')}.webm`;
        link.style.display = 'none';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
      } else {
        const link = document.createElement('a');
        link.href = audioUrl;
        link.download = filename || `voice-note-${format(timestamp, 'yyyy-MM-dd-HH-mm-ss')}.webm`;
        link.style.display = 'none';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
      }
    } catch (_error) {
      alert('Failed to download voice note.');
    }
  };

  if (error) {
    return <div className="text-xs text-red-500">{error}</div>;
  }

  return (
    <div className="flex items-center gap-3">
      <Button
        onClick={togglePlayback}
        disabled={isLoading}
        variant="ghost"
        size="sm"
        className="h-8 w-8 p-0 rounded-full"
      >
        {isLoading ? (
          <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
        ) : isPlaying ? (
          <Pause className="w-4 h-4" />
        ) : (
          <Play className="w-4 h-4" />
        )}
      </Button>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs font-mono">{formatTime(currentTime)}</span>
          <span className="text-xs opacity-70">/ {formatTime(duration)}</span>
        </div>
        <div className="mt-1">
          <canvas ref={canvasRef} width={240} height={40} className="w-full h-10" />
        </div>
      </div>

      <Button
        onClick={handleDownload}
        variant="ghost"
        size="sm"
        className="h-8 w-8 p-0 rounded-full"
        title="Download voice note"
      >
        <Download className="w-3 h-3" />
      </Button>
    </div>
  );
}
