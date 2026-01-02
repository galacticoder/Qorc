import React, { useState, useEffect, useRef, useCallback, memo } from 'react';
import { Phone, PhoneOff, Video, VideoOff, Mic, MicOff, Monitor, MonitorOff, Minimize2, Maximize2, ChevronDown } from 'lucide-react';
import type { CallState } from '../../../lib/webrtc-calling';
import { useUnifiedUsernameDisplay } from '../../../hooks/database/useUnifiedUsernameDisplay';
import { UserAvatar } from '../../ui/UserAvatar';
import { Popover, PopoverContent, PopoverTrigger } from '../../ui/popover';
import { cn } from '../../../lib/utils/shared-utils';

const ScreenSourceSelectorLazy = React.lazy(() => import('./ScreenSourceSelector').then(m => ({ default: m.ScreenSourceSelector })));

interface ScreenSource {
  readonly id: string;
  readonly name: string;
  readonly type: 'screen' | 'window';
}

interface CallModalProps {
  readonly call: CallState | null;
  readonly localStream: MediaStream | null;
  readonly remoteStream: MediaStream | null;
  readonly remoteScreenStream?: MediaStream | null;
  readonly onAnswer: () => void;
  readonly onDecline: () => void;
  readonly onEndCall: () => void;
  readonly onToggleMute: () => boolean | Promise<boolean>;
  readonly onToggleVideo: () => boolean | Promise<boolean>;
  readonly onSwitchCamera: (deviceId: string) => Promise<void>;
  readonly onSwitchMicrophone: (deviceId: string) => Promise<void>;
  readonly onStartScreenShare?: (selectedSource?: { id: string; name: string }) => Promise<void>;
  readonly onStopScreenShare?: () => Promise<void>;
  readonly onGetAvailableScreenSources?: () => Promise<readonly ScreenSource[]>;
  readonly isScreenSharing?: boolean;
  readonly getDisplayUsername?: (username: string) => Promise<string>;
}

const VideoStreamDisplay = memo(({
  stream,
  muted = false,
  className,
  objectFit = 'cover',
  mirror = false
}: {
  stream: MediaStream | null;
  muted?: boolean;
  className?: string;
  objectFit?: 'cover' | 'contain';
  mirror?: boolean;
}) => {
  const videoRef = useRef<HTMLVideoElement>(null);

  useEffect(() => {
    if (videoRef.current && stream) {
      videoRef.current.srcObject = stream;
    } else if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
  }, [stream]);

  if (!stream) return null;

  return (
    <video
      ref={videoRef}
      autoPlay
      playsInline
      muted={muted}
      className={cn("w-full h-full pointer-events-none", className, mirror && "scale-x-[-1]")}
      style={{ objectFit }}
    />
  );
});
VideoStreamDisplay.displayName = 'VideoStreamDisplay';

// PIP Component
const DraggablePip = ({
  id,
  children,
  initialPosition,
  onPositionChange,
  onClick
}: {
  id: string;
  children: React.ReactNode;
  initialPosition: { x: number; y: number };
  onPositionChange?: (id: string, pos: { x: number; y: number }) => void;
  onClick?: () => void;
}) => {
  const [position, setPosition] = useState(initialPosition);
  const [isDragging, setIsDragging] = useState(false);
  const dragStartRef = useRef<{ x: number, y: number } | null>(null);
  const initialPosRef = useRef<{ x: number, y: number } | null>(null);
  const hasMovedRef = useRef(false);

  useEffect(() => {
    setPosition(initialPosition);
  }, [initialPosition.x, initialPosition.y]);

  const handleMouseDown = (e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    setIsDragging(true);
    hasMovedRef.current = false;
    dragStartRef.current = { x: e.clientX, y: e.clientY };
    initialPosRef.current = { x: position.x, y: position.y };
  };

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isDragging || !dragStartRef.current || !initialPosRef.current) return;

      const dx = e.clientX - dragStartRef.current.x;
      const dy = e.clientY - dragStartRef.current.y;

      if (Math.abs(dx) > 3 || Math.abs(dy) > 3) hasMovedRef.current = true;

      const newPos = {
        x: initialPosRef.current.x + dx,
        y: initialPosRef.current.y + dy
      };

      setPosition(newPos);
      onPositionChange?.(id, newPos);
    };

    const handleMouseUp = () => {
      setIsDragging(false);
    };

    if (isDragging) {
      window.addEventListener('mousemove', handleMouseMove);
      window.addEventListener('mouseup', handleMouseUp);
    }
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };
  }, [isDragging, id, onPositionChange]);

  return (
    <div
      className={cn(
        "absolute w-40 aspect-video bg-card rounded-lg overflow-hidden border border-border shadow-lg transition-transform hover:scale-105 z-20 cursor-move",
        isDragging && "scale-105 shadow-xl ring-2 ring-primary/50"
      )}
      style={{ left: position.x, top: position.y }}
      onMouseDown={handleMouseDown}
      onClick={(e) => {
        e.stopPropagation();
        if (!hasMovedRef.current && onClick) onClick();
      }}
      title="Drag to move, click to maximize"
    >
      {children}
    </div>
  );
};

export const CallModal: React.FC<CallModalProps> = memo(({
  call,
  localStream,
  remoteStream,
  remoteScreenStream,
  onAnswer,
  onDecline,
  onEndCall,
  onToggleMute,
  onToggleVideo,
  onSwitchCamera,
  onSwitchMicrophone,
  onStartScreenShare,
  onStopScreenShare,
  onGetAvailableScreenSources,
  isScreenSharing = false,
  getDisplayUsername
}) => {
  const [isMinimized, setIsMinimized] = useState(true);
  const [isMuted, setIsMuted] = useState(false);
  const [isVideoEnabled, setIsVideoEnabled] = useState(true);
  const [micLevel, setMicLevel] = useState(0);
  const [callDuration, setCallDuration] = useState(0);
  const [isExpandedScreenShare, setIsExpandedScreenShare] = useState(false);
  const [focusedView, setFocusedView] = useState<'remote-screen' | 'remote-cam' | 'local' | null>(null);

  const [pipPositions, setPipPositions] = useState<{ [key: number]: { x: number, y: number, isInitialized?: boolean } }>({
    0: { x: 20, y: 20, isInitialized: false },
    1: { x: 20, y: 140, isInitialized: false }
  });

  const mainStageRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (mainStageRef.current && !pipPositions[0].isInitialized) {
      const { clientWidth, clientHeight } = mainStageRef.current;
      setPipPositions({
        0: { x: clientWidth - 180, y: clientHeight - 110, isInitialized: true },
        1: { x: clientWidth - 180, y: 20, isInitialized: true }
      });
    }
  }, [mainStageRef.current, pipPositions]);

  const updatePipPosition = useCallback((slotIndex: number | string, pos: { x: number, y: number }) => {
    setPipPositions(prev => ({
      ...prev,
      [slotIndex]: { ...pos, isInitialized: true }
    }));
  }, []);

  const [micDevices, setMicDevices] = useState<MediaDeviceInfo[]>([]);
  const [videoDevices, setVideoDevices] = useState<MediaDeviceInfo[]>([]);
  const [preferredCameraId, setPreferredCameraId] = useState<string | null>(null);
  const [showScreenSourceSelector, setShowScreenSourceSelector] = useState(false);
  const [hasOpenedScreenShare, setHasOpenedScreenShare] = useState(false);

  useEffect(() => {
    if (showScreenSourceSelector) {
      setHasOpenedScreenShare(true);
    }
  }, [showScreenSourceSelector]);

  const wrapperRef = useRef<HTMLDivElement>(null);

  const [position, setPosition] = useState<{ x: number, bottom: number }>({
    x: 20,
    bottom: 20
  });

  const [isDragging, setIsDragging] = useState(false);
  const dragStartRef = useRef<{ x: number, y: number } | null>(null);
  const initialPosRef = useRef<{ x: number, bottom: number } | null>(null);
  const hasDraggedRef = useRef(false);

  const { displayName: displayPeerName } = useUnifiedUsernameDisplay({
    username: call?.peer || '',
    getDisplayUsername,
    fallbackToOriginal: true
  });

  const isConnected = call?.status === 'connected';
  const isIncoming = call?.direction === 'incoming';
  const isRinging = call?.status === 'ringing';
  const isVideoCall = call?.type === 'video';

  useEffect(() => {
    if (isExpandedScreenShare && !remoteScreenStream && !isScreenSharing) {
      setIsExpandedScreenShare(false);
    }
  }, [isExpandedScreenShare, remoteScreenStream, isScreenSharing]);

  useEffect(() => {
    const loadDevices = async () => {
      try {
        const devices = await navigator.mediaDevices.enumerateDevices();
        setMicDevices(devices.filter(d => d.kind === 'audioinput'));
        setVideoDevices(devices.filter(d => d.kind === 'videoinput'));

        // Load preferred camera
        try {
          const { encryptedStorage } = await import('../../../lib/encrypted-storage');
          const saved = await encryptedStorage.getItem('preferred_camera_deviceId_v1_pq');
          if (saved && typeof saved === 'string') setPreferredCameraId(saved);
        } catch { }
      } catch (e) {
        console.error("Device enumeration failed", e);
      }
    };
    loadDevices();
    navigator.mediaDevices.addEventListener('devicechange', loadDevices);
    return () => navigator.mediaDevices.removeEventListener('devicechange', loadDevices);
  }, []);

  useEffect(() => {
    if (localStream) {
      const videoTrack = localStream.getVideoTracks()[0];
      const audioTrack = localStream.getAudioTracks()[0];

      if (videoTrack) {
        setIsVideoEnabled(videoTrack.enabled);
        videoTrack.onended = () => setIsVideoEnabled(false);
      } else {
        setIsVideoEnabled(false);
      }

      if (audioTrack) {
        setIsMuted(!audioTrack.enabled);
      }
    }
  }, [localStream]);

  useEffect(() => {
    if (!localStream) { setMicLevel(0); return; }
    let audioCtx: AudioContext | null = null;
    let rafId: number;

    const analyze = () => {
      try {
        const AudioCtx = (window as any).AudioContext || (window as any).webkitAudioContext;
        audioCtx = new AudioCtx();
        const analyser = audioCtx.createAnalyser();
        analyser.fftSize = 256;
        const source = audioCtx.createMediaStreamSource(localStream);
        source.connect(analyser);
        const data = new Uint8Array(analyser.frequencyBinCount);

        const loop = () => {
          analyser.getByteFrequencyData(data);
          const avg = data.reduce((a, b) => a + b, 0) / data.length;
          setMicLevel(avg / 128);
          rafId = requestAnimationFrame(loop);
        };
        loop();
      } catch { setMicLevel(0); }
    };
    analyze();

    return () => {
      if (rafId) cancelAnimationFrame(rafId);
      audioCtx?.close().catch(() => { });
    };
  }, [localStream]);

  useEffect(() => {
    if (isConnected && call?.startTime) {
      const interval = setInterval(() => {
        setCallDuration(Math.floor((Date.now() - call.startTime!) / 1000));
      }, 1000);
      return () => clearInterval(interval);
    }
    setCallDuration(0);
  }, [isConnected, call?.startTime]);

  const handleDragStart = (e: React.MouseEvent) => {
    setIsDragging(true);
    hasDraggedRef.current = false;
    dragStartRef.current = { x: e.clientX, y: e.clientY };
    initialPosRef.current = { x: position.x, bottom: position.bottom };
  };

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isDragging || !dragStartRef.current || !initialPosRef.current) return;
      const dx = e.clientX - dragStartRef.current.x;
      const dy = e.clientY - dragStartRef.current.y;

      if (Math.abs(dx) > 10 || Math.abs(dy) > 10) {
        hasDraggedRef.current = true;
      }

      setPosition({
        x: Math.max(0, Math.min(window.innerWidth - 320, initialPosRef.current.x + dx)),
        bottom: Math.max(0, Math.min(window.innerHeight - 80, initialPosRef.current.bottom - dy))
      });
    };
    const handleMouseUp = () => {
      setIsDragging(false);
    };

    if (isDragging) {
      window.addEventListener('mousemove', handleMouseMove);
      window.addEventListener('mouseup', handleMouseUp);
    }
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };
  }, [isDragging]);

  const handleCameraChange = async (deviceId: string) => {
    try {
      const { encryptedStorage } = await import('../../../lib/encrypted-storage');
      await encryptedStorage.setItem('preferred_camera_deviceId_v1_pq', deviceId);
      setPreferredCameraId(deviceId);
      await onSwitchCamera(deviceId);
    } catch (err) {
      console.error("Failed to switch camera", err);
    }
  };

  const handleMicrophoneChange = async (deviceId: string) => {
    try {
      await onSwitchMicrophone(deviceId);
    } catch (err) {
      console.error("Failed to switch microphone", err);
    }
  };

  const toggleScreenShare = async () => {
    try {
      if (isScreenSharing) {
        await onStopScreenShare?.();
      } else {
        if (onGetAvailableScreenSources) {
          setShowScreenSourceSelector(true);
        } else {
          await onStartScreenShare?.();
        }
      }
    } catch (error: any) {
      console.error('Screen share toggle failed:', error);
      alert(`Screen share error: ${error.message || 'Unknown error'}`);
    }
  };

  const formatTime = (secs: number) => {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}:${s.toString().padStart(2, '0')}`;
  };

  if (!call) return null;

  if (isMinimized) {
    return (
      <div
        className="fixed z-50 bg-background border border-border rounded-lg shadow-xl p-3 flex items-center gap-3 select-none cursor-move"
        style={{
          left: position.x,
          bottom: position.bottom,
          width: 320
        }}
        onMouseDown={handleDragStart}
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <UserAvatar username={call.peer || ''} size="xs" />
            <span className="font-medium truncate text-sm">{displayPeerName}</span>
          </div>
          <div className="text-xs text-muted-foreground mt-0.5">
            {isIncoming && isRinging ? `Incoming ${isVideoCall ? 'video' : 'audio'} call...` : isConnected ? formatTime(callDuration) : 'Calling...'}
          </div>
        </div>
        <div className="flex items-center gap-1" onMouseDown={(e) => e.stopPropagation() }>
          {isIncoming && isRinging ? (
            <>
              <button
                onClick={() => {
                  onAnswer();
                }}
                className="p-1.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-md transition-colors"
                title="Answer"
              >
                <Phone className="w-4 h-4" />
              </button>
              <button
                onClick={onDecline}
                className="p-1.5 bg-red-600 hover:bg-red-700 text-white rounded-md transition-colors"
                title="Decline"
              >
                <PhoneOff className="w-4 h-4" />
              </button>
            </>
          ) : !isConnected ? (
            <button onClick={onEndCall} className="p-1.5 bg-red-600 hover:bg-red-700 text-white rounded-md transition-colors" title="Cancel">
              <PhoneOff className="w-4 h-4" />
            </button>
          ) : (
            <>
              <button
                onClick={async () => {
                  const newState = await onToggleMute();
                  setIsMuted(newState);
                }}
                className={cn("p-1.5 hover:bg-secondary rounded-md transition-colors", isMuted && "text-destructive bg-destructive/10")}
                title={isMuted ? "Unmute" : "Mute"}
              >
                {isMuted ? <MicOff className="w-4 h-4" /> : <Mic className="w-4 h-4" />}
              </button>
              {isVideoCall && (
                <button
                  onClick={async () => {
                    const enabled = await onToggleVideo();
                    setIsVideoEnabled(enabled);
                  }}
                  className={cn("p-1.5 hover:bg-secondary rounded-md transition-colors", !isVideoEnabled && "text-destructive bg-destructive/10")}
                  title={isVideoEnabled ? "Turn Off Video" : "Turn On Video"}
                >
                  {!isVideoEnabled ? <VideoOff className="w-4 h-4" /> : <Video className="w-4 h-4" />}
                </button>

              )}
              {/* Separator */}
              {isVideoCall && (
                <div className="h-4 w-[1px] bg-gradient-to-b from-transparent via-black/60 to-transparent dark:via-white/80 mx-1 opacity-90" />
              )}

              <button onClick={() => setIsMinimized(false)} className="p-1.5 hover:bg-secondary rounded-md transition-colors" title="Maximize">
                <Maximize2 className="w-4 h-4" />
              </button>
              <button onClick={onEndCall} className="p-1.5 bg-red-600 hover:bg-red-700 text-white rounded-md transition-colors" title="End Call">
                <PhoneOff className="w-4 h-4" />
              </button>
            </>
          )}
        </div>
      </div >
    );
  }

  return (
    <>
      <div
        ref={wrapperRef}
        className={cn(
          "fixed z-50 flex flex-col bg-background/95 backdrop-blur-lg border border-border shadow-xl rounded-2xl overflow-hidden cubic-bezier(0.4, 0, 0.2, 1)",
          !isDragging && "transition-all duration-300",
          isExpandedScreenShare ? "w-[90vw] h-[90vh] left-[5vw] top-[5vh]" : "w-[350px] sm:w-[420px]"
        )}
        style={!isExpandedScreenShare ? { left: position.x, bottom: position.bottom } : undefined}
      >
        {/* Header */}
        <div className="h-14 bg-card/80 backdrop-blur-md border-b border-border flex items-center justify-between px-5 select-none relative" onMouseDown={!isExpandedScreenShare ? handleDragStart : undefined}>
          <div className={cn("flex items-center gap-2", !isExpandedScreenShare && "cursor-move")}>
            <UserAvatar username={call.peer || ''} size="xs" />
            <div className="flex flex-col">
              <span className="text-sm font-semibold text-foreground leading-none">{displayPeerName}</span>
              <span className="text-[10px] text-muted-foreground font-mono mt-0.5">
                {isIncoming && isRinging ? `Incoming ${isVideoCall ? 'video' : 'audio'} call...` : isConnected ? formatTime(callDuration) : 'Calling...'}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-1">
            {(remoteScreenStream || isScreenSharing) && (
              <button
                onClick={() => setIsExpandedScreenShare(prev => !prev)}
                className="p-1.5 text-muted-foreground hover:text-foreground hover:bg-muted rounded-md transition-colors"
                title={isExpandedScreenShare ? "Collapse" : "Expand"}
              >
                {isExpandedScreenShare ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
              </button>
            )}
            {!isExpandedScreenShare && (
              <button
                onClick={() => setIsMinimized(true)}
                className="p-1.5 text-muted-foreground hover:text-foreground hover:bg-muted rounded-md transition-colors"
              >
                <Minimize2 className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        {/* Main Stage */}
        <div className="flex-1 bg-black relative overflow-hidden group" ref={mainStageRef}>
          {(() => {
            const hasRemoteScreen = remoteScreenStream && remoteScreenStream.getVideoTracks().length > 0;
            const hasRemoteVideo = remoteStream && remoteStream.getVideoTracks().length > 0;
            const hasLocalVideo = localStream && (isVideoEnabled || isScreenSharing) && localStream.getVideoTracks().length > 0;

            type StreamType = 'remote-screen' | 'remote-cam' | 'local';
            const availableStreams: StreamType[] = [];
            if (hasRemoteScreen) availableStreams.push('remote-screen');
            if (hasRemoteVideo) availableStreams.push('remote-cam');
            if (hasLocalVideo) availableStreams.push('local');

            let mainView: StreamType = 'local'; 

            if (focusedView && availableStreams.includes(focusedView)) {
              mainView = focusedView;
            } else {
              if (hasRemoteScreen) mainView = 'remote-screen';
              
              else if (hasRemoteVideo) mainView = 'remote-cam';
              else if (hasLocalVideo) mainView = 'local';
              else mainView = 'local';
            }

            const pipViews = availableStreams.filter(s => s !== mainView);

            const renderStream = (type: StreamType, _isMain: boolean) => {
              if (type === 'remote-screen') {
                return <VideoStreamDisplay stream={remoteScreenStream} objectFit="contain" className="w-full h-full" />;
              }
              if (type === 'remote-cam') {
                return <VideoStreamDisplay stream={remoteStream} className="w-full h-full" />;
              }
              if (type === 'local') {
                return <VideoStreamDisplay stream={localStream} mirror={!isScreenSharing} muted className="w-full h-full" />;
              }
              return null;
            };

            let MainComponent = null;
            if (availableStreams.length === 0) {
              MainComponent = (
                <div className="absolute inset-0 flex flex-col items-center justify-center text-muted-foreground">
                  <UserAvatar username={call.peer || ''} size="xl" className="mb-4 opacity-50" />
                  <p className="text-sm font-medium">
                    {isRinging ? 'Waiting for answer...' : 'Waiting for video...'}
                  </p>
                </div>
              );
            } else {
              MainComponent = renderStream(mainView, true);
            }

            return (
              <>
                {/* Main Video */}
                {MainComponent}

                {/* Draggable Slots */}
                {pipViews.map((type, index) => {
                  const pos = pipPositions[index] || { x: 20, y: 20 + (index * 130) };

                  return (
                    <DraggablePip
                      key={`slot-${index}`}
                      id={`slot-${index}`}
                      initialPosition={pos}
                      onPositionChange={(id, newPos) => updatePipPosition(index, newPos)}
                      onClick={() => setFocusedView(type)}
                    >
                      {renderStream(type, false)}
                    </DraggablePip>
                  );
                })}
              </>
            );
          })()}
        </div>

        {/* Controls Bar */}
        <div className="bg-card/80 backdrop-blur-md border-t border-border p-5 flex items-center justify-center gap-6">

          {/* Accept/Decline Incoming */}
          {isIncoming && isRinging ? (
            <>
              <button
                onClick={onDecline}
                className="h-14 w-14 rounded-full bg-destructive hover:bg-destructive/90 flex items-center justify-center text-destructive-foreground transition-all hover:scale-110 shadow-lg shadow-red-900/20"
              >
                <PhoneOff className="w-6 h-6" />
              </button>
              <button
                onClick={() => {
                  onAnswer();
                  setIsMinimized(true);
                }}
                className="h-14 w-14 rounded-full bg-emerald-600 hover:bg-emerald-700 flex items-center justify-center text-white transition-all hover:scale-110 shadow-lg shadow-green-900/20"
              >
                <Phone className="w-6 h-6" />
              </button>
            </>
          ) : (
            /* Active Call Controls */
            <>
              {/* Mic Control */}
              <div className="flex flex-col items-center gap-1">
                <div className="flex items-center bg-secondary/50 rounded-full border border-border">
                  <button
                    onClick={async () => {
                      const newState = await onToggleMute();
                      setIsMuted(newState);
                    }}
                    className={cn(
                      "w-12 h-12 rounded-l-full flex items-center justify-center transition-colors",
                      isMuted ? "bg-destructive/10 text-destructive hover:bg-destructive/20" : "hover:bg-muted text-foreground"
                    )}
                  >
                    {isMuted ? <MicOff className="w-5 h-5" /> : <Mic className="w-5 h-5" />}
                  </button>
                  <div className="w-[1px] h-6 bg-border" />
                  <Popover>
                    <PopoverTrigger asChild>
                      <button className="w-8 h-12 rounded-r-full flex items-center justify-center hover:bg-muted text-muted-foreground hover:text-foreground transition-colors">
                        <ChevronDown className="w-3.5 h-3.5" />
                      </button>
                    </PopoverTrigger>
                    <PopoverContent side="top" align="center" className="bg-popover border-border text-popover-foreground w-64 p-1">
                      <div className="px-2 py-1.5 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Microphone</div>
                      {micDevices.map(d => <button
                        key={d.deviceId}
                        className="w-full text-left px-2 py-2 text-sm rounded hover:bg-muted truncate"
                        onClick={() => handleMicrophoneChange(d.deviceId)}
                      >
                        {d.label || `Mic ${d.deviceId.slice(0, 5)}`}
                      </button>
                      )}
                    </PopoverContent>
                  </Popover>
                </div>
                <div className="mt-1 h-1 w-20 bg-muted/40 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-primary"
                    style={{ width: `${Math.max(0, Math.min(1, micLevel / 2)) * 100}%` }}
                  />
                </div>
              </div>

              {/* Video Control */}
              {isVideoCall && (
                <div className={cn("flex items-center bg-secondary/50 rounded-full border border-border transition-opacity", videoDevices.length === 0 && "opacity-50 grayscale cursor-not-allowed")}>
                  <button
                    onClick={async () => {
                      const enabled = await onToggleVideo();
                      setIsVideoEnabled(enabled);
                    }}
                    className={cn(
                      "w-12 h-12 rounded-l-full flex items-center justify-center transition-colors",
                      !isVideoEnabled ? "bg-destructive/10 text-destructive hover:bg-destructive/20" : "hover:bg-muted text-foreground",
                      videoDevices.length === 0 && "pointer-events-none text-muted-foreground"
                    )}
                    disabled={videoDevices.length === 0}
                  >
                    {!isVideoEnabled ? <VideoOff className="w-5 h-5" /> : <Video className="w-5 h-5" />}
                  </button>
                  <div className="w-[1px] h-6 bg-border" />
                  <Popover>
                    <PopoverTrigger asChild disabled={videoDevices.length === 0}>
                      <button className="w-8 h-12 rounded-r-full flex items-center justify-center hover:bg-muted text-muted-foreground hover:text-foreground transition-colors">
                        <ChevronDown className="w-3.5 h-3.5" />
                      </button>
                    </PopoverTrigger>
                    <PopoverContent side="top" align="center" className="bg-popover border-border text-popover-foreground w-64 p-1">
                      <div className="px-2 py-1.5 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Camera</div>
                      {videoDevices.map(d => (
                        <button
                          key={d.deviceId}
                          className={cn(
                            "w-full text-left px-2 py-2 text-sm rounded hover:bg-muted truncate",
                            d.deviceId === preferredCameraId && "text-primary bg-primary/10"
                          )}
                          onClick={() => handleCameraChange(d.deviceId)}
                        >
                          {d.label || `Camera ${d.deviceId.slice(0, 5)}`}
                        </button>
                      ))}
                    </PopoverContent>
                  </Popover>
                </div>
              )}

              {/* Screen Share */}
              <button
                onClick={toggleScreenShare}
                className={cn(
                  "h-12 w-12 rounded-full border border-border flex items-center justify-center transition-colors",
                  isScreenSharing ? "bg-primary text-primary-foreground border-primary" : "bg-secondary/50 text-foreground hover:bg-muted"
                )}
                title="Share Screen"
              >
                {isScreenSharing ? <MonitorOff className="w-5 h-5" /> : <Monitor className="w-5 h-5" />}
              </button>

              {/* End Call */}
              <button
                onClick={onEndCall}
                className="h-14 w-14 rounded-full bg-red-600 hover:bg-red-700 flex items-center justify-center text-white transition-all hover:scale-105 shadow-lg shadow-red-900/20"
              >
                <PhoneOff className="w-6 h-6" />
              </button>
            </>
          )}
        </div>
      </div>

      {/* Screen Source Selector */}
      {(showScreenSourceSelector || hasOpenedScreenShare) && onGetAvailableScreenSources && (
        <React.Suspense fallback={null}>
          <ScreenSourceSelectorLazy
            isOpen={showScreenSourceSelector}
            onSelect={async (source: any) => {
              if (onStartScreenShare) {
                await onStartScreenShare(source);
                setShowScreenSourceSelector(false);
              }
            }}
            onClose={() => setShowScreenSourceSelector(false)}
            onCancel={() => setShowScreenSourceSelector(false)}
            onGetAvailableScreenSources={onGetAvailableScreenSources}
          />
        </React.Suspense>
      )}
    </>
  );
});

CallModal.displayName = 'CallModal';
export default CallModal;