import React, { useState, useRef, useEffect, useCallback } from 'react';
import { cn } from '../../../lib/utils/shared-utils';
import { Play, Pause, Mic, LoaderCircle } from 'lucide-react';
import { useFileUrl } from '../../../hooks/file-handling/useFileUrl';
import type { SecureDB } from '../../../lib/database/secureDB';
import { MAX_VOICE_NOTE_DURATION_SECONDS } from '../../../lib/constants';
import { isSafeFileUrl, parseCurrentVoiceNoteFilename } from '../../../lib/utils/file-utils';
import { formatClockDurationSeconds } from '../../../lib/utils/date-utils';
import { registerVoicePlayback } from '../../../lib/utils/voice-playback';

interface VoiceMessageProps {
  timestamp: Date;
  isCurrentUser: boolean;
  filename: string;
  mimeType: string;
  messageId: string;
  secureDB: SecureDB;
  onRendered: () => void;
  loadFile: boolean;
}

const WAVEFORM_BARS = 48;
const MEDIA_DURATION_TOLERANCE_SECONDS = 1;
const DEFAULT_WAVEFORM = Array.from({ length: WAVEFORM_BARS }, (_, index) => (
  0.2 + Math.abs(Math.sin((index + 1) * 1.37)) * 0.62
));

export function VoiceMessage({
  timestamp: _timestamp,
  isCurrentUser,
  filename,
  mimeType,
  messageId,
  secureDB,
  onRendered,
  loadFile,
}: VoiceMessageProps) {
  const voiceMetadata = parseCurrentVoiceNoteFilename(filename);
  if (!voiceMetadata || voiceMetadata.mimeType !== mimeType) {
    throw new Error('Invalid voice note metadata');
  }
  const filenameDuration = voiceMetadata.durationSeconds;
  const [mediaRequested, setMediaRequested] = useState(false);
  const { url: resolvedUrl, error: urlError, loading: fileLoading } = useFileUrl({
    secureDB,
    fileId: messageId,
    mimeType,
    enabled: loadFile && mediaRequested,
    previewKind: mediaRequested ? 'voice' : undefined,
  });

  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(filenameDuration);
  const [error, setError] = useState<string | null>(urlError);

  const audioRef = useRef<HTMLAudioElement | null>(null);
  const pendingPlayRef = useRef(false);
  const onRenderedRef = useRef(onRendered);
  onRenderedRef.current = onRendered;

  const effectiveAudioUrl = isSafeFileUrl(resolvedUrl);

  useEffect(() => {
    const audio = audioRef.current;
    const unregister = audio ? registerVoicePlayback(audio) : undefined;
    return () => {
      pendingPlayRef.current = false;
      unregister?.();
    };
  }, [messageId, secureDB]);

  useEffect(() => {
    const audio = audioRef.current;
    if (!effectiveAudioUrl || !audio || !pendingPlayRef.current) return;
    pendingPlayRef.current = false;
    let canceled = false;
    void audio.play().catch((error: unknown) => {
      if (!canceled && !(error instanceof Error && error.name === 'NotAllowedError')) {
        setError('Failed to play audio');
      }
    });
    return () => { canceled = true; };
  }, [effectiveAudioUrl]);

  useEffect(() => {
    onRenderedRef.current();
  }, [messageId]);

  const progress = duration > 0 ? Math.min(1, currentTime / duration) : 0;
  const remaining = isPlaying ? Math.max(0, duration - currentTime) : duration;

  // Play / pause — the <audio> element drives isPlaying via its events
  const togglePlayback = useCallback(async () => {
    if (!mediaRequested) {
      pendingPlayRef.current = true;
      setMediaRequested(true);
      return;
    }
    const audio = audioRef.current;
    if (!audio || !effectiveAudioUrl) return;
    try {
      setError(null);
      if (audio.paused) {
        const playbackEnd = duration > 0 ? duration : MAX_VOICE_NOTE_DURATION_SECONDS;
        if (audio.ended || audio.currentTime >= playbackEnd - 0.05) {
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
  }, [effectiveAudioUrl, mediaRequested, duration]);

  const handleLoadedMetadata = useCallback(() => {
    const d = audioRef.current?.duration;

    if (
      typeof d !== 'number' || !Number.isFinite(d) || d <= 0 ||
      d > MAX_VOICE_NOTE_DURATION_SECONDS + MEDIA_DURATION_TOLERANCE_SECONDS
    ) {
      if (filenameDuration > 0) {
        setDuration(filenameDuration);
        setError(null);
        return;
      }

      if (typeof d === 'number' && Number.isFinite(d) &&
        d > MAX_VOICE_NOTE_DURATION_SECONDS + MEDIA_DURATION_TOLERANCE_SECONDS) {
        audioRef.current?.pause();
        setError('Voice message duration is invalid');
      }
      return;
    }

    setDuration(Math.min(d, MAX_VOICE_NOTE_DURATION_SECONDS));
    setError(null);
  }, [filenameDuration]);

  const handleTimeUpdate = useCallback(() => {
    const audio = audioRef.current;
    if (!audio) return;

    if (!Number.isFinite(audio.currentTime) || audio.currentTime < 0) {
      audio.pause();
      setIsPlaying(false);
      setError('Voice message duration is invalid');
      return;
    }

    if (audio.currentTime >= MAX_VOICE_NOTE_DURATION_SECONDS) {
      audio.pause();
      setIsPlaying(false);
      setCurrentTime(MAX_VOICE_NOTE_DURATION_SECONDS);
      return;
    }

    setCurrentTime(audio.currentTime);
  }, []);

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
    if (!mediaRequested) {
      pendingPlayRef.current = true;
      setMediaRequested(true);
      return;
    }
    const rect = e.currentTarget.getBoundingClientRect();
    void seekTo((e.clientX - rect.left) / rect.width);
  }, [mediaRequested, seekTo]);

  const bars = DEFAULT_WAVEFORM;
  const playedColor = isCurrentUser ? 'rgba(255,255,255,0.95)' : 'var(--qorc-accent)';
  const restColor = isCurrentUser ? 'rgba(255,255,255,0.38)' : 'color-mix(in srgb, var(--qorc-accent) 32%, transparent)';

  if (error || urlError) {
    return (
      <div className="qorc-deleted-message-bubble qorc-voice-message-error">
        {urlError || error || 'Failed to load audio'}
      </div>
    );
  }

  return (
    <div
      className={cn('qorc-voice', isCurrentUser && 'is-mine')}
      style={isCurrentUser ? { background: 'var(--qorc-accent)' } : undefined}
    >
      <audio
        ref={audioRef}
        src={effectiveAudioUrl || undefined}
        preload="none"
        onLoadedMetadata={handleLoadedMetadata}
        onDurationChange={handleLoadedMetadata}
        onTimeUpdate={handleTimeUpdate}
        onPlay={() => setIsPlaying(true)}
        onPause={() => setIsPlaying(false)}
        onEnded={() => { setIsPlaying(false); setCurrentTime(0); }}
        onError={() => setError('Failed to load audio')}
        style={{ display: 'none' }}
      />

      <button
        type="button"
        className="qorc-voice-play"
        onClick={togglePlayback}
        aria-label={isPlaying ? 'Pause voice message' : 'Play voice message'}
      >
        {fileLoading && mediaRequested
          ? <LoaderCircle className="w-[18px] h-[18px] animate-spin" />
          : isPlaying
            ? <Pause className="w-[18px] h-[18px]" />
            : <Play className="w-[18px] h-[18px] translate-x-[1px]" />}
      </button>

      <div className="qorc-voice-body">
        <div className="qorc-voice-bars" onClick={handleBarsClick} role="slider" aria-label="Seek voice message" aria-valuenow={Math.round(progress * 100)} tabIndex={0}>
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
        <div className="qorc-voice-foot">
          <Mic className="w-3 h-3 opacity-70" />
          <span className="qorc-voice-time">{formatClockDurationSeconds(remaining)}</span>
        </div>
      </div>
    </div>
  );
}
