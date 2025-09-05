import React, { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Play, Pause, Download } from 'lucide-react';
import { cn } from '@/lib/utils';
import { format } from 'date-fns';

interface VoiceMessageProps {
  audioUrl: string;
  sender: string;
  timestamp: Date;
  isCurrentUser: boolean;
  filename?: string;
  originalBase64Data?: string;
  mimeType?: string;
  onReply?: (message: any) => void;
  onDelete?: (message: any) => void;
  onEdit?: (message: any) => void;
}

export function VoiceMessage({
  audioUrl,
  sender,
  timestamp,
  isCurrentUser,
  filename,
  originalBase64Data,
  mimeType,
  onReply,
  onDelete,
  onEdit
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
    };
  }, []);

  const handleLoadedMetadata = () => {
    if (!audioRef.current) return;
    const dur = audioRef.current.duration;
    if (isFinite(dur) && dur > 0) {
      setDuration(dur);
    } else {
      // Safari/Blob quirk: try a small play-pause to force metadata
      try {
        const el = audioRef.current;
        const onTimeUpdate = () => {
          if (isFinite(el.duration) && el.duration > 0) {
            setDuration(el.duration);
            el.removeEventListener('timeupdate', onTimeUpdate);
          }
        };
        el.addEventListener('timeupdate', onTimeUpdate);
        el.play().then(() => {
          setTimeout(() => el.pause(), 50);
        }).catch(() => {});
      } catch {}
    }
    setIsLoading(false);
  };

  const handleTimeUpdate = () => {
    if (audioRef.current) {
      setCurrentTime(audioRef.current.currentTime);
    }
  };

  const handleEnded = () => {
    setIsPlaying(false);
    setCurrentTime(0);
  };

  const handleError = () => {
    setError('Failed to load audio');
    setIsLoading(false);
    setIsPlaying(false);
  };

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const togglePlayback = async () => {
    try {
      setError(null);
      
      if (isPlaying) {
        // Pause
        if (audioRef.current) {
          audioRef.current.pause();
          setIsPlaying(false);
        }
        return;
      }

      // Play
      setIsLoading(true);

      if (!audioRef.current) {
        const audio = new Audio(audioUrl);
        // HTMLAudioElement has no 'type' property; rely on Blob URL MIME for playback
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

    } catch (err) {
      console.error('Failed to play audio:', err);
      setError('Failed to play audio');
      setIsLoading(false);
      setIsPlaying(false);
    }
  };

  // Generate waveform peaks once per source
  useEffect(() => {
    let cancelled = false;
    peaksRef.current = null;

    const decodeAndComputePeaks = async () => {
      try {
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

        // Compute peaks per pixel
        const canvas = canvasRef.current;
        const width = canvas?.width || 240;
        const height = canvas?.height || 40;
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
          const amp = Math.max(-min, max); // peak amplitude
          peaks[i] = Math.min(1, amp);
        }

        peaksRef.current = peaks;
        drawWaveform();
        try { audioCtx.close(); } catch {}
      } catch (e) {
        // Non-fatal; waveform will be hidden
        peaksRef.current = null;
        drawWaveform();
      }
    };

    // Defer to next tick to allow canvas to mount
    setTimeout(() => { if (!cancelled) decodeAndComputePeaks(); }, 0);

    return () => { cancelled = true; if (drawRafRef.current) cancelAnimationFrame(drawRafRef.current); };
  }, [audioUrl, originalBase64Data]);

  // Redraw on progress
  useEffect(() => {
    drawWaveform();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentTime, duration, isCurrentUser]);

  const drawWaveform = () => {
    const canvas = canvasRef.current;
    const peaks = peaksRef.current;
    if (!canvas || !peaks) {
      // Clear canvas if no peaks
      if (canvas) {
        const ctx = canvas.getContext('2d');
        if (ctx) { ctx.clearRect(0, 0, canvas.width, canvas.height); }
      }
      return;
    }

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const width = canvas.width;
    const height = canvas.height;
    const centerY = Math.floor(height / 2);

    // Colors depending on bubble theme
    const baseColor = isCurrentUser ? 'rgba(255,255,255,0.45)' : 'rgba(59,130,246,0.35)';
    const progressColor = isCurrentUser ? 'rgba(255,255,255,0.95)' : 'rgba(59,130,246,0.9)';

    // Background
    ctx.clearRect(0, 0, width, height);

    // Draw full waveform (base)
    ctx.fillStyle = baseColor;
    for (let x = 0; x < width; x++) {
      const amp = peaks[x];
      const y = Math.max(1, Math.round(amp * (height / 2)));
      ctx.fillRect(x, centerY - y, 1, y * 2);
    }

    // Overlay progress
    const progress = duration > 0 ? Math.min(1, currentTime / duration) : 0;
    const progressX = Math.round(progress * width);
    ctx.fillStyle = progressColor;
    for (let x = 0; x < progressX; x++) {
      const amp = peaks[x];
      const y = Math.max(1, Math.round(amp * (height / 2)));
      ctx.fillRect(x, centerY - y, 1, y * 2);
    }
  };

  const handleDownload = async () => {
    try {
      console.log('[VoiceMessage] Starting download for:', filename, {
        hasOriginalBase64: !!originalBase64Data,
        audioUrl: audioUrl.substring(0, 50) + '...'
      });

      // Prefer original base64 data for reliable downloads
      if (originalBase64Data) {
        try {
          // Create blob from original base64 data
          const cleanBase64 = originalBase64Data.trim().replace(/[^A-Za-z0-9+/=]/g, '');
          const binaryString = atob(cleanBase64);
          const bytes = new Uint8Array(binaryString.length);
          for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
          }

          const blob = new Blob([bytes], { type: mimeType || 'audio/webm' });
          const downloadUrl = URL.createObjectURL(blob);

          // Perform the download
          const link = document.createElement('a');
          link.href = downloadUrl;
          link.download = filename || `voice-note-${format(timestamp, 'yyyy-MM-dd-HH-mm-ss')}.webm`;
          link.style.display = 'none';
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);

          // Clean up the temporary URL
          setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);

          console.log('[VoiceMessage] Download from base64 completed successfully');
          return;
        } catch (base64Error) {
          console.error('[VoiceMessage] Base64 download failed, falling back to blob URL:', base64Error);
        }
      }

      // Fallback to blob URL method
      if (!audioUrl || audioUrl === 'File' || audioUrl === 'voice-note') {
        console.error('[VoiceMessage] Invalid audio URL for download:', audioUrl);
        alert('Cannot download voice note: Invalid audio data');
        return;
      }

      // For blob URLs, we need to fetch the data and create a new download
      if (audioUrl.startsWith('blob:')) {
        try {
          // Fetch the blob data
          const response = await fetch(audioUrl);
          if (!response.ok) {
            throw new Error(`Failed to fetch blob data: ${response.status}`);
          }

          const blob = await response.blob();

          // Create a new blob URL for download
          const downloadUrl = URL.createObjectURL(blob);

          // Perform the download
          const link = document.createElement('a');
          link.href = downloadUrl;
          link.download = filename || `voice-note-${format(timestamp, 'yyyy-MM-dd-HH-mm-ss')}.webm`;
          link.style.display = 'none';
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);

          // Clean up the temporary URL
          setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);

          console.log('[VoiceMessage] Download from blob URL completed successfully');
        } catch (blobError) {
          console.error('[VoiceMessage] Blob download failed:', blobError);
          alert('Cannot download voice note: Audio data is no longer available');
        }
      } else {
        // Regular URL, proceed with direct download
        const link = document.createElement('a');
        link.href = audioUrl;
        link.download = filename || `voice-note-${format(timestamp, 'yyyy-MM-dd-HH-mm-ss')}.webm`;
        link.style.display = 'none';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        console.log('[VoiceMessage] Direct download completed');
      }
    } catch (error) {
      console.error('[VoiceMessage] Download failed:', error);
      alert('Failed to download voice note: ' + (error instanceof Error ? error.message : 'Unknown error'));
    }
  };

  const progress = duration > 0 ? (currentTime / duration) * 100 : 0;

  return (
    <div className={cn("flex items-start gap-2 mb-4 group", isCurrentUser ? "flex-row-reverse" : "")}>
      <div className="w-9 h-9">
        <div className={cn(
          "w-9 h-9 rounded-full flex items-center justify-center text-white text-sm font-medium",
          isCurrentUser ? "bg-blue-500" : "bg-gray-500"
        )}>
          {sender.charAt(0).toUpperCase()}
        </div>
      </div>

      <div className={cn("flex flex-col", isCurrentUser ? "items-end" : "items-start")}>
        <div className="flex items-center gap-2 mb-1">
          <span className="text-sm font-medium">{sender}</span>
          <span className="text-xs text-muted-foreground">{format(timestamp, "h:mm a")}</span>
        </div>

        <div className={cn(
          "rounded-lg px-4 py-3 max-w-xs",
          isCurrentUser ? "bg-primary text-primary-foreground" : "bg-muted"
        )}>
          {error ? (
            <div className="text-red-500 text-sm">
              {error}
            </div>
          ) : (
            <div className="flex items-center gap-3">
              <Button
                onClick={togglePlayback}
                disabled={isLoading}
                variant="ghost"
                size="sm"
                className={cn(
                  "h-8 w-8 p-0 rounded-full",
                  isCurrentUser 
                    ? "hover:bg-primary-foreground/20 text-primary-foreground" 
                    : "hover:bg-muted-foreground/20"
                )}
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
                  <span className="text-xs font-mono">
                    {formatTime(currentTime)}
                  </span>
                  <span className="text-xs opacity-70">
                    / {formatTime(duration)}
                  </span>
                </div>
                {/* Waveform */}
                <div className="mt-1">
                  <canvas ref={canvasRef} width={240} height={40} className="w-full h-10" />
                </div>
              </div>

              <Button
                onClick={handleDownload}
                variant="ghost"
                size="sm"
                className={cn(
                  "h-8 w-8 p-0 rounded-full",
                  isCurrentUser 
                    ? "hover:bg-primary-foreground/20 text-primary-foreground" 
                    : "hover:bg-muted-foreground/20"
                )}
                title="Download voice note"
              >
                <Download className="w-3 h-3" />
              </Button>
            </div>
          )}
        </div>

        {/* Action buttons */}
        <div
          className={cn(
            "flex items-center gap-1 mt-2 opacity-0 group-hover:opacity-100 transition-opacity duration-200",
            isCurrentUser ? "justify-end" : "justify-start"
          )}
        >
          <button
            onClick={() => navigator.clipboard.writeText(filename || 'Voice note')}
            aria-label="Copy filename"
            className="p-1 rounded hover:bg-opacity-80 transition-colors"
            style={{ color: 'var(--color-text-secondary)' }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = 'var(--color-accent-primary)';
              e.currentTarget.style.color = 'white';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = 'transparent';
              e.currentTarget.style.color = 'var(--color-text-secondary)';
            }}
          >
            <svg
              width="15"
              height="15"
              viewBox="0 0 15 15"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M1 9.50006C1 10.3285 1.67157 11.0001 2.5 11.0001H4L4 10.0001H2.5C2.22386 10.0001 2 9.7762 2 9.50006L2 2.50006C2 2.22392 2.22386 2.00006 2.5 2.00006L9.5 2.00006C9.77614 2.00006 10 2.22392 10 2.50006V4.00002H5.5C4.67158 4.00002 4 4.67159 4 5.50002V12.5C4 13.3284 4.67158 14 5.5 14H12.5C13.3284 14 14 13.3284 14 12.5V5.50002C14 4.67159 13.3284 4.00002 12.5 4.00002H11V2.50006C11 1.67163 10.3284 1.00006 9.5 1.00006H2.5C1.67157 1.00006 1 1.67163 1 2.50006V9.50006ZM5 5.50002C5 5.22388 5.22386 5.00002 5.5 5.00002H12.5C12.7761 5.00002 13 5.22388 13 5.50002V12.5C13 12.7762 12.7761 13 12.5 13H5.5C5.22386 13 5 12.7762 5 12.5V5.50002Z"
                fill="currentColor"
                fillRule="evenodd"
                clipRule="evenodd"
              />
            </svg>
          </button>

          <button
            onClick={() => onReply?.({
              id: '',
              content: filename || 'Voice note',
              sender,
              timestamp,
              type: 'voice',
              filename,
              mimeType,
              originalBase64Data
            })}
            aria-label="Reply to voice note"
            className="p-1 rounded hover:bg-opacity-80 transition-colors"
            style={{ color: 'var(--color-text-secondary)' }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = 'var(--color-accent-primary)';
              e.currentTarget.style.color = 'white';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = 'transparent';
              e.currentTarget.style.color = 'var(--color-text-secondary)';
            }}
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              fill="none"
              viewBox="0 0 24 24"
              strokeWidth={1.5}
              stroke="currentColor"
              className="w-4 h-4"
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 15 3 9m0 0 6-6M3 9h12a6 6 0 0 1 0 12h-3" />
            </svg>
          </button>

          {isCurrentUser && (
            <button
              onClick={() => onDelete?.({
                id: '',
                content: filename || 'Voice note',
                sender,
                timestamp,
                type: 'voice',
                filename,
                mimeType,
                originalBase64Data
              })}
              aria-label="Delete voice note"
              className="p-1 rounded hover:bg-opacity-80 transition-colors"
              style={{ color: 'var(--color-text-secondary)' }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = '#ef4444';
                e.currentTarget.style.color = 'white';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'transparent';
                e.currentTarget.style.color = 'var(--color-text-secondary)';
              }}
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                strokeWidth={1.5}
                stroke="currentColor"
                className="w-4 h-4"
              >
                <path strokeLinecap="round" strokeLinejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0" />
              </svg>
            </button>
          )}
        </div>
      </div>
    </div>
  );
}