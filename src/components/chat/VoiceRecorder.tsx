import React, { useState, useRef, useEffect } from 'react';
import { Button } from '../ui/button';
import { Mic, Square, Play, Pause, Trash2, Send } from 'lucide-react';
import { cn } from '../../lib/utils';

interface VoiceRecorderProps {
  onSendVoiceNote: (audioBlob: Blob) => void;
  onCancel: () => void;
  disabled?: boolean;
}

export function VoiceRecorder({ onSendVoiceNote, onCancel, disabled }: VoiceRecorderProps) {
  const [isRecording, setIsRecording] = useState(false);
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
    setIsPlaying(false);
    setAudioLevel(0);
  };

  useEffect(() => {
    return cleanup;
  }, []);

  const monitorAudioLevel = () => {
    if (!analyserRef.current) return;
    const dataArray = new Uint8Array(analyserRef.current.frequencyBinCount);
    analyserRef.current.getByteFrequencyData(dataArray);
    const average = dataArray.reduce((sum, value) => sum + value, 0) / dataArray.length;
    setAudioLevel(average / 255);
    if (isRecording) {
      animationRef.current = requestAnimationFrame(monitorAudioLevel);
    }
  };

  const startRecording = async () => {
    try {
      setError(null);
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        throw new Error('Media devices not supported in this environment');
      }
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true,
          sampleRate: 16000,
          channelCount: 1,
        }
      });
      streamRef.current = stream;

      const AudioCtx: typeof AudioContext = (window as any).AudioContext || (window as any).webkitAudioContext;
      const audioContext = new AudioCtx();
      const analyser = audioContext.createAnalyser();
      const source = audioContext.createMediaStreamSource(stream);
      source.connect(analyser);
      analyser.fftSize = 256;
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
      if (!mimeType) {
        throw new Error('No supported audio recording format found');
      }

      const mediaRecorderOptions: MediaRecorderOptions = {
        mimeType,
        audioBitsPerSecond: 32000
      };
      const mediaRecorder = new MediaRecorder(stream, mediaRecorderOptions);
      mediaRecorderRef.current = mediaRecorder;
      chunksRef.current = [];

      mediaRecorder.ondataavailable = (event) => {
        if (event.data.size > 0) {
          chunksRef.current.push(event.data);
        }
      };

      mediaRecorder.onstop = () => {
        const blob = new Blob(chunksRef.current, { type: mimeType });
        setRecordedBlob(blob);
        cleanup();
      };

      mediaRecorder.onerror = () => {
        setError('Recording failed');
        cleanup();
      };

      mediaRecorder.start();
      setIsRecording(true);
      setDuration(0);

      intervalRef.current = setInterval(() => {
        setDuration(prev => prev + 1);
      }, 1000);

      monitorAudioLevel();

    } catch (_err) {
      setError('Failed to access microphone. Please check permissions.');
      cleanup();
    }
  };

  const stopRecording = () => {
    if (mediaRecorderRef.current && isRecording) {
      mediaRecorderRef.current.stop();
      setIsRecording(false);
      setAudioLevel(0);
    }
  };

  const playRecording = () => {
    if (!recordedBlob) return;
    if (audioRef.current) {
      audioRef.current.pause();
      audioRef.current = null;
    }
    if (blobUrlRef.current) {
      URL.revokeObjectURL(blobUrlRef.current);
    }
    const blobUrl = URL.createObjectURL(recordedBlob);
    blobUrlRef.current = blobUrl;
    const audio = new Audio(blobUrl);
    audioRef.current = audio;
    audio.onloadedmetadata = () => { setDuration(Math.floor(audio.duration)); };
    audio.ontimeupdate = () => { setCurrentTime(Math.floor(audio.currentTime)); };
    audio.onended = () => {
      setIsPlaying(false);
      setCurrentTime(0);
      if (blobUrlRef.current) { URL.revokeObjectURL(blobUrlRef.current); blobUrlRef.current = null; }
    };
    audio.play();
    setIsPlaying(true);
  };

  const pausePlayback = () => {
    if (audioRef.current) {
      audioRef.current.pause();
      setIsPlaying(false);
    }
  };

  const deleteRecording = () => {
    if (blobUrlRef.current) {
      URL.revokeObjectURL(blobUrlRef.current);
      blobUrlRef.current = null;
    }
    if (audioRef.current) {
      audioRef.current.pause();
      if (audioRef.current.src && audioRef.current.src.startsWith('blob:')) {
        try { URL.revokeObjectURL(audioRef.current.src); } catch {}
      }
      audioRef.current.src = '';
      audioRef.current = null;
    }
    setRecordedBlob(null);
    setDuration(0);
    setCurrentTime(0);
    setIsPlaying(false);
  };

  const sendVoiceNote = () => {
    if (recordedBlob) {
      onSendVoiceNote(recordedBlob);
    }
  };

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  return (
    <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 shadow-lg">
      {error && (
        <div className="text-red-500 text-sm mb-3 p-2 bg-red-50 dark:bg-red-900/20 rounded">
          {error}
        </div>
      )}

      <div className="flex items-center gap-3">
        {!recordedBlob ? (
          <>
            <Button
              onClick={isRecording ? stopRecording : startRecording}
              disabled={disabled}
              variant={isRecording ? "destructive" : "default"}
              size="sm"
              className={cn(
                "flex items-center gap-2",
                isRecording && "animate-pulse"
              )}
            >
              {isRecording ? <Square className="w-4 h-4" /> : <Mic className="w-4 h-4" />}
              {isRecording ? 'Stop' : 'Record'}
            </Button>

            {isRecording && (
              <div className="flex items-center gap-2 flex-1">
                <div className="text-sm font-mono text-red-500">
                  {formatTime(duration)}
                </div>
                <div className="flex-1 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-red-500 transition-all duration-100"
                    style={{ width: `${audioLevel * 100}%` }}
                  />
                </div>
              </div>
            )}
          </>
        ) : (
          <>
            <Button
              onClick={isPlaying ? pausePlayback : playRecording}
              variant="outline"
              size="sm"
              className="flex items-center gap-2"
            >
              {isPlaying ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
              {isPlaying ? 'Pause' : 'Play'}
            </Button>

            <div className="flex items-center gap-2 flex-1">
              <div className="text-sm font-mono">
                {formatTime(currentTime)} / {formatTime(duration)}
              </div>
              <div className="flex-1 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-blue-500 transition-all duration-100"
                  style={{ width: `${duration > 0 ? (currentTime / duration) * 100 : 0}%` }}
                />
              </div>
            </div>

            <Button
              onClick={deleteRecording}
              variant="outline"
              size="sm"
              className="flex items-center gap-2 text-red-500 hover:text-red-700"
            >
              <Trash2 className="w-4 h-4" />
            </Button>

            <Button
              onClick={sendVoiceNote}
              disabled={disabled}
              size="sm"
              className="flex items-center gap-2"
            >
              <Send className="w-4 h-4" />
              Send
            </Button>
          </>
        )}

        <Button
          onClick={onCancel}
          variant="outline"
          size="sm"
        >
          Cancel
        </Button>
      </div>
    </div>
  );
}