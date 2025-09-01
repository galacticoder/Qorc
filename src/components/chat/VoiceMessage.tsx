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
}

export function VoiceMessage({
  audioUrl,
  sender,
  timestamp,
  isCurrentUser,
  filename,
  originalBase64Data,
  mimeType
}: VoiceMessageProps) {
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const audioRef = useRef<HTMLAudioElement | null>(null);

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
    if (audioRef.current) {
      setDuration(audioRef.current.duration);
      setIsLoading(false);
    }
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
    <div className={cn("flex items-start gap-2 mb-4", isCurrentUser ? "flex-row-reverse" : "")}>
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
                
                <div className={cn(
                  "h-1 rounded-full overflow-hidden",
                  isCurrentUser ? "bg-primary-foreground/30" : "bg-muted-foreground/30"
                )}>
                  <div 
                    className={cn(
                      "h-full transition-all duration-100",
                      isCurrentUser ? "bg-primary-foreground" : "bg-primary"
                    )}
                    style={{ width: `${progress}%` }}
                  />
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
      </div>
    </div>
  );
}
