import React, { useState, useRef, useEffect, useCallback } from 'react';
import { cn } from '../../lib/utils';
import { Button } from '../ui/button';
import { Play, Pause } from 'lucide-react';
import { useFileUrl } from '../../hooks/useFileUrl';
import type { SecureDB } from '../../lib/secureDB';

interface VoiceMessageProps {
  audioUrl: string;
  timestamp: Date;
  isCurrentUser: boolean;
  filename?: string;
  originalBase64Data?: string;
  mimeType?: string;
  messageId?: string;
  secureDB?: SecureDB | null;
}

export function VoiceMessage({
  audioUrl,
  timestamp: _timestamp,
  isCurrentUser,
  filename: _filename,
  originalBase64Data,
  mimeType,
  messageId,
  secureDB,
}: VoiceMessageProps) {
  // Use useFileUrl to resolve the audio source from SecureDB if needed
  const { url: resolvedUrl, loading: _urlLoading, error: urlError } = useFileUrl({
    secureDB: secureDB || null,
    fileId: messageId,
    mimeType: mimeType || 'audio/webm',
    initialUrl: audioUrl,
    originalBase64Data: originalBase64Data || null,
  });

  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(urlError);

  const audioRef = useRef<HTMLAudioElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const peaksRef = useRef<number[] | null>(null);
  const drawRafRef = useRef<number | null>(null);

  const safeAudioUrl = audioUrl && !audioUrl.startsWith('blob:') ? audioUrl : '';
  const effectiveAudioUrl = resolvedUrl || safeAudioUrl;

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
        el.play().then(() => { setTimeout(() => el.pause(), 50); }).catch(() => { });
      } catch { }
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

  const formatDuration = (seconds: number) => {
    return `${Math.round(seconds)}s`;
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
        const audio = new Audio(effectiveAudioUrl);
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
    } catch {
      setError('Failed to play audio');
      setIsLoading(false);
      setIsPlaying(false);
    }
  };

  const handleCanvasClick = useCallback(async (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas || !audioRef.current || duration === 0) return;

    const rect = canvas.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    const progress = Math.max(0, Math.min(1, clickX / rect.width));
    const seekTime = progress * duration;

    try {
      audioRef.current.currentTime = seekTime;
      setCurrentTime(seekTime);

      // If not already playing, start playback
      if (!isPlaying) {
        await audioRef.current.play();
        setIsPlaying(true);
      }
    } catch (err) {
      console.error('Failed to seek:', err);
    }
  }, [duration, isPlaying]);

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
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();

    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    ctx.scale(dpr, dpr);

    const width = rect.width;
    const height = rect.height;
    const centerY = Math.floor(height / 2);

    const styles = getComputedStyle(document.body);
    const surfaceColor = styles.getPropertyValue('--color-text-primary').trim() || '#000000';

    const hexToRgba = (hex: string, alpha: number) => {
      if (hex.length === 4) {
        hex = '#' + hex[1] + hex[1] + hex[2] + hex[2] + hex[3] + hex[3];
      }
      const r = parseInt(hex.slice(1, 3), 16);
      const g = parseInt(hex.slice(3, 5), 16);
      const b = parseInt(hex.slice(5, 7), 16);
      return `rgba(${r}, ${g}, ${b}, ${alpha})`;
    };

    const baseColor = isCurrentUser
      ? 'rgba(255,255,255,0.45)'
      : (surfaceColor.startsWith('#') ? hexToRgba(surfaceColor, 0.35) : 'rgba(59,130,246,0.35)');

    const progressColor = isCurrentUser
      ? 'rgba(255,255,255,0.95)'
      : (surfaceColor.startsWith('#') ? hexToRgba(surfaceColor, 0.9) : 'rgba(59,130,246,0.9)');

    ctx.clearRect(0, 0, width, height);

    ctx.fillStyle = baseColor;
    const barWidth = width / peaks.length;
    const gap = 1;
    const effectiveBarWidth = Math.max(1, barWidth - gap);

    for (let i = 0; i < peaks.length; i++) {
      const x = i * barWidth;
      const amp = peaks[i];
      const y = Math.max(2, Math.round(amp * (height / 2)));

      // Draw rounded bar
      ctx.beginPath();
      ctx.roundRect(x, centerY - y, effectiveBarWidth, y * 2, 2);
      ctx.fill();
    }

    const progress = duration > 0 ? Math.min(1, currentTime / duration) : 0;

    // Create a clipping region for the progress
    ctx.save();
    ctx.beginPath();
    ctx.rect(0, 0, width * progress, height);
    ctx.clip();

    ctx.fillStyle = progressColor;
    for (let i = 0; i < peaks.length; i++) {
      const x = i * barWidth;
      const amp = peaks[i];
      const y = Math.max(2, Math.round(amp * (height / 2)));

      ctx.beginPath();
      ctx.roundRect(x, centerY - y, effectiveBarWidth, y * 2, 2);
      ctx.fill();
    }
    ctx.restore();
  };

  useEffect(() => {
    let cancelled = false;
    peaksRef.current = null;

    const decodeAndComputePeaks = async () => {
      try {
        if (!originalBase64Data) {
          if (!originalBase64Data && typeof audioUrl === 'string' && audioUrl.startsWith('blob:')) {
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
          : await (await fetch(effectiveAudioUrl)).arrayBuffer();

        const AudioCtx: typeof AudioContext = (window as any).AudioContext || (window as any).webkitAudioContext;
        const audioCtx = new AudioCtx();
        const audioBuffer = await audioCtx.decodeAudioData(arrayBuffer.slice(0));

        // Set duration from the decoded buffer if not already set
        if (audioBuffer.duration && audioBuffer.duration > 0) {
          setDuration(audioBuffer.duration);
        }

        const targetWidth = 120;
        const channelData = audioBuffer.getChannelData(0);
        const samplesPerPixel = Math.max(1, Math.floor(channelData.length / targetWidth));
        const peaks: number[] = new Array(targetWidth);
        const minThreshold = 0.05;

        // First pass: calculate raw peaks and find global maximum
        let globalMax = 0;
        for (let i = 0; i < targetWidth; i++) {
          const start = i * samplesPerPixel;
          const end = Math.min(start + samplesPerPixel, channelData.length);
          let min = 1.0;
          let max = -1.0;
          for (let j = start; j < end; j++) {
            const v = channelData[j];
            if (v < min) min = v;
            if (v > max) max = v;
          }
          let amp = Math.max(-min, max);
          if (amp > globalMax) globalMax = amp;
          peaks[i] = amp;
        }

        // Second pass: normalize peaks
        const normalizationFactor = globalMax > 0.01 ? 1 / globalMax : 1;
        for (let i = 0; i < targetWidth; i++) {
          peaks[i] = Math.min(1, Math.max(minThreshold, peaks[i] * normalizationFactor));
        }

        peaksRef.current = peaks;
        drawWaveform();
        try {
          audioCtx.close();
        } catch { }
      } catch {
        peaksRef.current = null;
        setError('Failed to load audio');
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

  if (error) {
    return (
      <div
        className="px-3 py-2 rounded-lg text-sm italic select-none"
        style={{
          backgroundColor: 'var(--color-surface)',
          color: 'var(--color-text-secondary)',
          border: '1px dashed rgba(255,255,255,0.22)'
        }}
      >
        {urlError || error || 'Failed to load audio'}
      </div>
    );
  }

  return (
    <div
      className={cn(
        "flex items-end gap-3 w-full min-w-[160px] max-w-[300px] select-none py-2 px-2 rounded-md",
        isCurrentUser ? "text-primary-foreground" : ""
      )}
      style={{
        backgroundColor: isCurrentUser ? 'var(--color-accent-primary)' : 'var(--chat-bubble-received-bg)',
        color: isCurrentUser ? 'white' : 'var(--color-text-primary)',
        borderRadius: 'var(--message-bubble-radius)',
      }}
    >
      <div className="flex flex-col items-center justify-end gap-1 shrink-0 min-w-[2rem]">
        <span className="text-[10px] font-mono opacity-80 tabular-nums leading-none">
          {formatDuration(isPlaying ? Math.max(0, duration - currentTime) : duration)}
        </span>
        <Button
          onClick={togglePlayback}
          disabled={isLoading}
          variant="ghost"
          size="sm"
          className="h-8 w-8 p-0 rounded-full shrink-0 hover:bg-black/10"
        >
          {isLoading ? (
            <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
          ) : isPlaying ? (
            <Pause className="w-4 h-4" />
          ) : (
            <Play className="w-4 h-4" />
          )}
        </Button>
      </div>

      <div className="flex-1 h-8 relative flex items-center">
        <canvas
          ref={canvasRef}
          className="w-full h-full block cursor-pointer"
          onClick={handleCanvasClick}
          aria-label="Click to seek in voice message"
        />
      </div>
    </div>
  );
}
