import React, { useState, useRef, useEffect, useCallback } from 'react';
import { cn } from '../../../lib/utils/shared-utils';
import { Play, Pause, Mic } from 'lucide-react';
import { useFileUrl } from '../../../hooks/file-handling/useFileUrl';
import type { SecureDB } from '../../../lib/database/secureDB';

interface VoiceMessageProps {
  audioUrl: string;
  timestamp: Date;
  isCurrentUser: boolean;
  filename?: string;
  originalBase64Data?: string;
  mimeType?: string;
  messageId?: string;
  secureDB?: SecureDB | null;
  onRendered?: () => void;
}

const WAVEFORM_BARS = 48;

// Format seconds as M:SS
const formatTime = (seconds: number): string => {
  if (!isFinite(seconds) || seconds < 0) seconds = 0;
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}:${s.toString().padStart(2, '0')}`;
};

const parseFilenameDuration = (filename?: string): number => {
  const m = /voice-note-(\d+)s/i.exec(filename || '');
  return m ? parseInt(m[1], 10) : 0;
};

export function VoiceMessage({
  audioUrl,
  timestamp: _timestamp,
  isCurrentUser,
  filename,
  originalBase64Data,
  mimeType,
  messageId,
  secureDB,
  onRendered
}: VoiceMessageProps) {
  const filenameDuration = parseFilenameDuration(filename);
  const { url: resolvedUrl, error: urlError } = useFileUrl({
    secureDB: secureDB || null,
    fileId: messageId,
    mimeType: mimeType || 'audio/webm',
    initialUrl: audioUrl,
    originalBase64Data: originalBase64Data || null,
  });

  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(filenameDuration);
  const [error, setError] = useState<string | null>(urlError);
  const [peaks, setPeaks] = useState<number[] | null>(null);

  const audioRef = useRef<HTMLAudioElement | null>(null);

  const safeAudioUrl = audioUrl && !audioUrl.startsWith('blob:') ? audioUrl : '';
  const effectiveAudioUrl = resolvedUrl || safeAudioUrl;

  const progress = duration > 0 ? Math.min(1, currentTime / duration) : 0;
  const remaining = isPlaying ? Math.max(0, duration - currentTime) : duration;

  // Play / pause — the <audio> element drives isPlaying via its events
  const togglePlayback = useCallback(async () => {
    const audio = audioRef.current;
    if (!audio || !effectiveAudioUrl) return;
    try {
      setError(null);
      if (audio.paused) {
        if (audio.ended || (isFinite(audio.duration) && audio.currentTime >= audio.duration - 0.05)) {
          audio.load();
          setCurrentTime(0);
        }
        await audio.play();
      } else {
        audio.pause();
      }
    } catch {
      setError('Failed to play audio');
    }
  }, [effectiveAudioUrl]);

  const handleLoadedMetadata = useCallback(() => {
    if (filenameDuration > 0) return;
    const d = audioRef.current?.duration;
    if (d && isFinite(d) && d > 0) setDuration(d);
  }, [filenameDuration]);

  // Seek by clicking the waveform
  const seekTo = useCallback(async (ratio: number) => {
    const audio = audioRef.current;
    if (!audio || duration <= 0) return;
    const t = Math.max(0, Math.min(1, ratio)) * duration;
    audio.currentTime = t;
    setCurrentTime(t);
    if (audio.paused) {
      try { await audio.play(); } catch { /* ignore */ }
    }
  }, [duration]);

  const handleBarsClick = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    void seekTo((e.clientX - rect.left) / rect.width);
  }, [seekTo]);

  // Decode audio once to compute waveform
  useEffect(() => {
    let cancelled = false;
    setPeaks(null);

    const run = async () => {
      try {
        const arrayBuffer = originalBase64Data
          ? (() => {
            const clean = originalBase64Data.trim().replace(/[^A-Za-z0-9+/=]/g, '');
            const bin = atob(clean);
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            return bytes.buffer;
          })()
          : effectiveAudioUrl
            ? await (await fetch(effectiveAudioUrl)).arrayBuffer()
            : null;

        if (!arrayBuffer) return;

        const AudioCtx: typeof AudioContext = (window as any).AudioContext || (window as any).webkitAudioContext;
        const ctx = new AudioCtx();
        const buffer = await ctx.decodeAudioData(arrayBuffer.slice(0));
        try { ctx.close(); } catch { /* ignore */ }
        if (cancelled) return;

        if (!filenameDuration && buffer.duration && buffer.duration > 0) setDuration(buffer.duration);

        const data = buffer.getChannelData(0);
        const per = Math.max(1, Math.floor(data.length / WAVEFORM_BARS));
        const out = new Array<number>(WAVEFORM_BARS);
        let max = 0;
        for (let i = 0; i < WAVEFORM_BARS; i++) {
          const start = i * per;
          const end = Math.min(start + per, data.length);
          let peak = 0;
          for (let j = start; j < end; j++) peak = Math.max(peak, Math.abs(data[j]));
          out[i] = peak;
          if (peak > max) max = peak;
        }
        const norm = max > 0.01 ? 1 / max : 1;
        for (let i = 0; i < WAVEFORM_BARS; i++) out[i] = Math.min(1, Math.max(0.08, out[i] * norm));

        if (!cancelled) setPeaks(out);
      } catch {
        if (!cancelled) setPeaks(new Array(WAVEFORM_BARS).fill(0.18));
      } finally {
        onRendered?.();
      }
    };

    void run();
    return () => { cancelled = true; };
  }, [effectiveAudioUrl, originalBase64Data, onRendered, filenameDuration]);

  const bars = peaks ?? new Array(WAVEFORM_BARS).fill(0.18);
  const playedColor = isCurrentUser ? 'rgba(255,255,255,0.95)' : 'var(--qor-accent)';
  const restColor = isCurrentUser ? 'rgba(255,255,255,0.38)' : 'color-mix(in srgb, var(--qor-accent) 32%, transparent)';

  if (error || urlError) {
    return <div className="qor-file-error">{urlError || error || 'Failed to load audio'}</div>;
  }

  return (
    <div
      className={cn('qor-voice', isCurrentUser && 'is-mine')}
      style={isCurrentUser ? { background: 'var(--qor-accent)' } : undefined}
    >
      <audio
        ref={audioRef}
        src={effectiveAudioUrl || undefined}
        preload="metadata"
        onLoadedMetadata={handleLoadedMetadata}
        onTimeUpdate={() => setCurrentTime(audioRef.current?.currentTime ?? 0)}
        onPlay={() => setIsPlaying(true)}
        onPause={() => setIsPlaying(false)}
        onEnded={() => { setIsPlaying(false); setCurrentTime(0); }}
        onError={() => setError('Failed to load audio')}
        style={{ display: 'none' }}
      />

      <button
        type="button"
        className="qor-voice-play"
        onClick={togglePlayback}
        aria-label={isPlaying ? 'Pause voice message' : 'Play voice message'}
      >
        {isPlaying ? <Pause className="w-[18px] h-[18px]" /> : <Play className="w-[18px] h-[18px] translate-x-[1px]" />}
      </button>

      <div className="qor-voice-body">
        <div className="qor-voice-bars" onClick={handleBarsClick} role="slider" aria-label="Seek voice message" aria-valuenow={Math.round(progress * 100)} tabIndex={0}>
          {bars.map((amp, i) => (
            <span
              key={i}
              style={{
                height: `${Math.round(amp * 100)}%`,
                background: i / bars.length <= progress ? playedColor : restColor,
              }}
            />
          ))}
        </div>
        <div className="qor-voice-foot">
          <Mic className="w-3 h-3 opacity-70" />
          <span className="qor-voice-time">{formatTime(remaining)}</span>
        </div>
      </div>
    </div>
  );
}
