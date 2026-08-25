import React, { useState, useEffect, useRef, useCallback, useLayoutEffect, memo } from 'react';
import { Phone, PhoneOff, Video, VideoOff, Mic, MicOff, Monitor, MonitorOff, Minimize2, Maximize2, ChevronDown, Volume2 } from 'lucide-react';
import type { CallState } from '../../../lib/transport/secure-calling-service';
import { useDisplayUsername } from '../../../hooks/database/useDisplayUsername';
import { UserAvatar } from '../../ui/UserAvatar';
import { Popover, PopoverContent, PopoverTrigger } from '../../ui/popover';
import { cn } from '../../../lib/utils/shared-utils';
import { STORAGE_KEYS } from '../../../lib/database/storage-keys';
import { encryptedStorage } from '../../../lib/database/encrypted-storage';
import { formatClockDurationSeconds } from '../../../lib/utils/date-utils';
import { nativeCamera, nativeMicrophone } from '../../../lib/tauri-bindings';
import { getDefaultAvatarColor } from '../../../lib/utils/avatar-utils';

interface CallModalProps {
  readonly call: CallState | null;
  readonly localStream: MediaStream | null;
  readonly localVideoCanvas: HTMLCanvasElement | null;
  readonly localScreenCanvas: HTMLCanvasElement | null;
  readonly remoteVideoCanvas: HTMLCanvasElement | null;
  readonly remoteScreenCanvas?: HTMLCanvasElement | null;
  readonly onAnswer: () => void | Promise<void>;
  readonly onDecline: () => void;
  readonly onEndCall: () => void;
  readonly onToggleMute: () => boolean | Promise<boolean>;
  readonly onToggleVideo: () => boolean | Promise<boolean>;
  readonly onSwitchCamera: (deviceId: string) => Promise<void>;
  readonly onSwitchMicrophone: (deviceId: string) => Promise<void>;
  readonly onSwitchSpeaker: (deviceId: string) => Promise<void>;
  readonly onStartScreenShare?: () => Promise<void>;
  readonly onStopScreenShare?: () => Promise<void>;
  readonly isScreenSharing?: boolean;
  readonly isAttached?: boolean;
}

const CanvasDisplay = memo(({
  canvas,
  className,
  objectFit = 'cover'
}: {
  canvas: HTMLCanvasElement | null;
  className?: string;
  objectFit?: 'cover' | 'contain';
}) => {
  const hostRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const host = hostRef.current;
    if (!host || !canvas) return;
    canvas.style.width = '100%';
    canvas.style.height = '100%';
    canvas.style.display = 'block';
    canvas.style.objectFit = objectFit;
    host.replaceChildren(canvas);
    return () => {
      if (canvas.parentElement === host) canvas.remove();
    };
  }, [canvas, objectFit]);

  if (!canvas) return null;
  return <div ref={hostRef} className={cn('overflow-hidden', className)} />;
});
CanvasDisplay.displayName = 'CanvasDisplay';

type PipCorner = 'top-left' | 'top-right' | 'bottom-left' | 'bottom-right';
type StageSource = 'screen' | 'remote-video' | 'local-video';
type PipSource = 'screen' | 'remote-cam' | 'local';

const PIP_CORNER_CLASSES: Record<PipCorner, string> = {
  'top-left': 'left-3 top-3',
  'top-right': 'right-3 top-3',
  'bottom-left': 'bottom-3 left-3',
  'bottom-right': 'bottom-3 right-3'
};

const DockedPip = ({
  children,
  corner,
  label,
  stageRef,
  onCornerChange,
  onActivate,
  large = false
}: {
  children: React.ReactNode;
  corner: PipCorner;
  label?: string;
  stageRef: React.RefObject<HTMLDivElement>;
  onCornerChange: (corner: PipCorner) => void;
  onActivate: () => void;
  large?: boolean;
}) => {
  const pointerStartRef = useRef<{ pointerId: number; x: number; y: number } | null>(null);

  const handlePointerDown = (event: React.PointerEvent<HTMLDivElement>) => {
    if (event.button !== 0) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    pointerStartRef.current = { pointerId: event.pointerId, x: event.clientX, y: event.clientY };
    event.stopPropagation();
  };

  const finishPointerInteraction = (event: React.PointerEvent<HTMLDivElement>) => {
    const start = pointerStartRef.current;
    pointerStartRef.current = null;
    if (!start || start.pointerId !== event.pointerId) return;
    const moved = Math.hypot(event.clientX - start.x, event.clientY - start.y) > 4;
    const stage = stageRef.current;
    if (!moved) {
      onActivate();
      return;
    }
    if (!stage) return;
    const bounds = stage.getBoundingClientRect();
    const vertical = event.clientY < bounds.top + bounds.height / 2 ? 'top' : 'bottom';
    const horizontal = event.clientX < bounds.left + bounds.width / 2 ? 'left' : 'right';
    onCornerChange(`${vertical}-${horizontal}` as PipCorner);
  };

  const cancelPointerInteraction = () => {
    pointerStartRef.current = null;
  };

  return (
    <div
      className={cn(
        'absolute z-20 aspect-video touch-none cursor-pointer overflow-hidden rounded-xl bg-card',
        large ? 'w-44 sm:w-52' : 'w-28 sm:w-32',
        PIP_CORNER_CLASSES[corner]
      )}
      onPointerDown={handlePointerDown}
      onPointerUp={finishPointerInteraction}
      onPointerCancel={cancelPointerInteraction}
      title="Click to make main or drag to another corner"
    >
      {children}
      {label && (
        <span className="pointer-events-none absolute bottom-1.5 left-1.5 rounded-md bg-black/45 px-1.5 py-0.5 text-[10px] font-medium text-white backdrop-blur-md">
          {label}
        </span>
      )}
    </div>
  );
};

type DeviceOption = { deviceId: string; label: string };

const MediaDeviceControl = ({
  kind,
  enabled,
  devices,
  selectedDeviceId,
  open,
  onOpenChange,
  onToggle,
  onSelect
}: {
  kind: 'microphone' | 'camera';
  enabled: boolean;
  devices: DeviceOption[];
  selectedDeviceId?: string | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onToggle: () => void | Promise<void>;
  onSelect: (deviceId: string) => void | Promise<void>;
}) => {
  const isMicrophone = kind === 'microphone';
  const toggleTitle = isMicrophone
    ? enabled ? 'Mute' : 'Unmute'
    : enabled ? 'Turn Off Video' : 'Turn On Video';
  const pickerTitle = isMicrophone ? 'Choose microphone' : 'Choose camera';

  return (
    <div className="relative h-10 w-11">
      <button
        type="button"
        onClick={() => void onToggle()}
        className={cn(
          'relative flex h-full w-full cursor-pointer items-center justify-center rounded-xl bg-black/40 text-white backdrop-blur-xl hover:bg-black/55',
          !enabled && 'bg-red-600/75 hover:bg-red-500/85'
        )}
        title={toggleTitle}
      >
        {isMicrophone
          ? enabled ? <Mic className="h-4 w-4" /> : <MicOff className="h-4 w-4" />
          : enabled ? <Video className="h-4 w-4" /> : <VideoOff className="h-4 w-4" />}
      </button>
      <Popover open={open} onOpenChange={onOpenChange}>
        <PopoverTrigger asChild disabled={devices.length === 0}>
          <button
            type="button"
            className={cn(
              'absolute bottom-0.5 right-0.5 flex cursor-pointer items-center justify-center rounded-md bg-transparent text-white/70 hover:text-white',
              'h-4 w-4',
              devices.length === 0 && 'opacity-40'
            )}
            title={pickerTitle}
          >
            <ChevronDown className="h-2.5 w-2.5" />
          </button>
        </PopoverTrigger>
        <PopoverContent side="top" align="center" className="w-64 select-none p-1 [&_button]:cursor-pointer">
          <div className="px-2 py-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            {isMicrophone ? 'Microphone' : 'Camera'}
          </div>
          {devices.map(device => (
            <button
              type="button"
              key={device.deviceId}
              className={cn(
                'w-full cursor-pointer truncate rounded px-2 py-2 text-left text-sm hover:bg-muted',
                device.deviceId === selectedDeviceId && 'bg-primary/10 text-primary'
              )}
              onClick={() => {
                void onSelect(device.deviceId);
                onOpenChange(false);
              }}
            >
              {device.label || `${isMicrophone ? 'Mic' : 'Camera'} ${device.deviceId.slice(0, 5)}`}
            </button>
          ))}
        </PopoverContent>
      </Popover>
    </div>
  );
};

const OutputDeviceControl = ({
  devices,
  selectedDeviceId,
  open,
  onOpenChange,
  onSelect
}: {
  devices: DeviceOption[];
  selectedDeviceId?: string | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSelect: (deviceId: string) => void | Promise<void>;
}) => (
  <div className="relative h-10 w-11">
    <button
      type="button"
      onClick={() => onOpenChange(true)}
      className="relative flex h-full w-full cursor-pointer items-center justify-center rounded-xl bg-black/40 text-white backdrop-blur-xl hover:bg-black/55"
      title="Choose speaker"
    >
      <Volume2 className="h-4 w-4" />
    </button>
    <Popover open={open} onOpenChange={onOpenChange}>
      <PopoverTrigger asChild disabled={devices.length === 0}>
        <button
          type="button"
          className={cn(
            'absolute bottom-0.5 right-0.5 flex h-4 w-4 cursor-pointer items-center justify-center rounded-md bg-transparent text-white/70 hover:text-white',
            devices.length === 0 && 'opacity-40'
          )}
          title="Choose speaker"
        >
          <ChevronDown className="h-2.5 w-2.5" />
        </button>
      </PopoverTrigger>
      <PopoverContent side="top" align="center" className="w-64 select-none p-1 [&_button]:cursor-pointer">
        <div className="px-2 py-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Speaker</div>
        {devices.map(device => (
          <button
            type="button"
            key={device.deviceId}
            className={cn(
              'w-full cursor-pointer truncate rounded px-2 py-2 text-left text-sm hover:bg-muted',
              device.deviceId === selectedDeviceId && 'bg-primary/10 text-primary'
            )}
            onClick={() => {
              void onSelect(device.deviceId);
              onOpenChange(false);
            }}
          >
            {device.label || `Speaker ${device.deviceId.slice(0, 5)}`}
          </button>
        ))}
      </PopoverContent>
    </Popover>
  </div>
);

export const CallModal: React.FC<CallModalProps> = memo(({
  call,
  localStream,
  localVideoCanvas,
  localScreenCanvas,
  remoteVideoCanvas,
  remoteScreenCanvas,
  onAnswer,
  onDecline,
  onEndCall,
  onToggleMute,
  onToggleVideo,
  onSwitchCamera,
  onSwitchMicrophone,
  onSwitchSpeaker,
  onStartScreenShare,
  onStopScreenShare,
  isScreenSharing = false,
  isAttached = false
}) => {
  const [isMuted, setIsMuted] = useState(false);
  const [isVideoEnabled, setIsVideoEnabled] = useState(true);
  const [callDuration, setCallDuration] = useState(0);
  const [isExpandedScreenShare, setIsExpandedScreenShare] = useState(false);
  const [mainStageSource, setMainStageSource] = useState<StageSource>('remote-video');
  const [pipCorners, setPipCorners] = useState<Record<PipSource, PipCorner>>({
    local: 'bottom-right',
    'remote-cam': 'top-right',
    screen: 'top-left'
  });
  const sharedScreenWasAvailableRef = useRef(false);
  const mainStageRef = useRef<HTMLDivElement>(null);
  const [controlsVisible, setControlsVisible] = useState(true);
  const [isScreenShareStarting, setIsScreenShareStarting] = useState(false);
  const [devicePicker, setDevicePicker] = useState<'microphone' | 'camera' | 'speaker' | null>(null);
  const controlsTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [micDevices, setMicDevices] = useState<Array<{ deviceId: string; label: string }>>([]);
  const [speakerDevices, setSpeakerDevices] = useState<Array<{ deviceId: string; label: string }>>([]);
  const [videoDevices, setVideoDevices] = useState<Array<{ deviceId: string; label: string }>>([]);
  const [preferredCameraId, setPreferredCameraId] = useState<string | null>(null);
  const [preferredSpeakerId, setPreferredSpeakerId] = useState<string | null>(null);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const [attachmentBounds, setAttachmentBounds] = useState<{
    left: number;
    top: number;
    width: number;
    height: number;
  } | null>(null);

  const [position, setPosition] = useState<{ x: number, bottom: number }>({
    x: 20,
    bottom: 20
  });

  const [isDragging, setIsDragging] = useState(false);
  const dragStartRef = useRef<{ x: number, y: number } | null>(null);
  const initialPosRef = useRef<{ x: number, bottom: number } | null>(null);

  const displayPeerName = useDisplayUsername({
    username: call?.peer || ''
  });

  const isConnected = call?.status === 'connected';
  const isIncoming = call?.direction === 'incoming';
  const isRinging = call?.status === 'ringing';
  const isVideoCall = call?.type === 'video';
  const callStatusText = isIncoming && isRinging
    ? `Incoming ${isVideoCall ? 'video' : 'audio'} call...`
    : isConnected
      ? formatClockDurationSeconds(callDuration)
      : 'Calling...';

  const revealControls = useCallback(() => {
    if (controlsTimerRef.current) clearTimeout(controlsTimerRef.current);
    setControlsVisible(true);
    if (devicePicker === null) {
      controlsTimerRef.current = setTimeout(() => setControlsVisible(false), 5000);
    }
  }, [devicePicker]);

  const holdControls = useCallback(() => {
    if (controlsTimerRef.current) clearTimeout(controlsTimerRef.current);
    setControlsVisible(true);
  }, []);

  const handleStageMouseMove = (event: React.MouseEvent<HTMLDivElement>) => {
    if (event.target instanceof Element && event.target.closest('[data-call-overlay]')) return;
    revealControls();
  };

  useEffect(() => {
    revealControls();
    return () => {
      if (controlsTimerRef.current) clearTimeout(controlsTimerRef.current);
    };
  }, [call?.id, revealControls]);

  useEffect(() => {
    setPipCorners({ local: 'bottom-right', 'remote-cam': 'top-right', screen: 'top-left' });
    setMainStageSource('remote-video');
    setIsScreenShareStarting(false);
    sharedScreenWasAvailableRef.current = false;
    if (call?.type !== 'video') setIsExpandedScreenShare(false);
  }, [call?.id, call?.type]);

  useLayoutEffect(() => {
    if (!isAttached) return;
    const pane = document.querySelector<HTMLElement>('.qor-chat-pane');
    if (!pane) return;
    const updateBounds = () => {
      const bounds = pane.getBoundingClientRect();
      setAttachmentBounds({
        left: bounds.left,
        top: bounds.top,
        width: bounds.width,
        height: Math.min(600, Math.max(320, bounds.height * 0.58))
      });
    };
    updateBounds();
    const observer = new ResizeObserver(updateBounds);
    observer.observe(pane);
    window.addEventListener('resize', updateBounds);
    return () => {
      observer.disconnect();
      window.removeEventListener('resize', updateBounds);
    };
  }, [isAttached]);

  const answerCall = useCallback(() => {
    void Promise.resolve(onAnswer()).catch(error => {
      console.error('Failed to answer call:', error);
    });
  }, [onAnswer]);

  useEffect(() => {
    if (isExpandedScreenShare && (!isVideoCall || (!remoteScreenCanvas && !isScreenSharing))) {
      setIsExpandedScreenShare(false);
    }
  }, [isExpandedScreenShare, isVideoCall, remoteScreenCanvas, isScreenSharing]);

  useEffect(() => {
    if (!localStream) {
      setMicDevices([]);
      setSpeakerDevices([]);
      setVideoDevices([]);
      return;
    }
    let cancelled = false;
    const loadDevices = async () => {
      try {
        const [microphones, speakers, cameras] = await Promise.all([
          nativeMicrophone.devices(),
          nativeMicrophone.outputDevices(),
          isVideoCall ? nativeCamera.devices() : Promise.resolve([]),
        ]);
        if (cancelled) return;
        setMicDevices(microphones.map(microphone => ({ deviceId: microphone.device_id, label: microphone.label })));
        setSpeakerDevices(speakers.map(speaker => ({ deviceId: speaker.device_id, label: speaker.label })));
        setVideoDevices(cameras.map(camera => ({ deviceId: camera.device_id, label: camera.label })));

        // Load preferred camera
        try {
          const saved = await encryptedStorage.getItem(STORAGE_KEYS.PREFERRED_CAMERA);
          if (saved && typeof saved === 'string') setPreferredCameraId(saved);
        } catch { }
        try {
          const storedSettings = await encryptedStorage.getItem(STORAGE_KEYS.APP_SETTINGS);
          const parsed = storedSettings ? JSON.parse(storedSettings) : null;
          if (parsed && typeof parsed.preferredSpeakerId === 'string') {
            setPreferredSpeakerId(parsed.preferredSpeakerId);
          }
        } catch { }
      } catch (e) {
        if (cancelled) return;
        console.error("Device enumeration failed", e);
      }
    };
    void loadDevices();
    return () => {
      cancelled = true;
    };
  }, [localStream, isVideoCall]);

  useEffect(() => {
    if (!localStream) {
      setIsVideoEnabled(isVideoCall);
      return;
    }
    const audioTrack = localStream.getAudioTracks()[0];
    setIsVideoEnabled(isVideoCall);
    setIsMuted(audioTrack ? !audioTrack.enabled : false);
  }, [localStream, isVideoCall, call?.id]);

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
    dragStartRef.current = { x: e.clientX, y: e.clientY };
    initialPosRef.current = { x: position.x, bottom: position.bottom };
  };

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isDragging || !dragStartRef.current || !initialPosRef.current) return;
      const dx = e.clientX - dragStartRef.current.x;
      const dy = e.clientY - dragStartRef.current.y;

      const bounds = wrapperRef.current?.getBoundingClientRect();
      const width = bounds?.width ?? 320;
      const height = bounds?.height ?? 80;
      setPosition({
        x: Math.max(0, Math.min(window.innerWidth - width, initialPosRef.current.x + dx)),
        bottom: Math.max(0, Math.min(window.innerHeight - height, initialPosRef.current.bottom - dy))
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
      await onSwitchCamera(deviceId);
      setPreferredCameraId(deviceId);
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

  const handleSpeakerChange = async (deviceId: string) => {
    try {
      await onSwitchSpeaker(deviceId);
      setPreferredSpeakerId(deviceId);
    } catch (err) {
      console.error('Failed to switch speaker', err);
    }
  };

  const toggleMute = async () => {
    try {
      setIsMuted(await onToggleMute());
    } catch (error) {
      console.error('Failed to toggle microphone', error);
    }
  };

  const toggleVideo = async () => {
    try {
      setIsVideoEnabled(await onToggleVideo());
    } catch (error) {
      console.error('Failed to toggle camera', error);
    }
  };

  const dockPip = (type: PipSource, corner: PipCorner) => {
    setPipCorners(previous => {
      const occupiedBy = (Object.keys(previous) as PipSource[])
        .find(source => source !== type && previous[source] === corner);
      if (!occupiedBy) return { ...previous, [type]: corner };
      return { ...previous, [type]: corner, [occupiedBy]: previous[type] };
    });
  };

  const toggleScreenShare = async () => {
    if (isScreenShareStarting) return;
    if (!isScreenSharing) setIsScreenShareStarting(true);
    try {
      if (isScreenSharing) {
        await onStopScreenShare?.();
      } else {
        await onStartScreenShare?.();
      }
    } catch (error: any) {
      console.error('Screen share toggle failed:', error);
    } finally {
      setIsScreenShareStarting(false);
    }
  };

  const sharedScreenCanvas = remoteScreenCanvas ?? (isScreenSharing ? localScreenCanvas : null);
  const hasSharedScreen = Boolean(sharedScreenCanvas);
  const hasRemoteVideo = Boolean(remoteVideoCanvas);
  const showLocalPreview = isVideoCall && Boolean(localVideoCanvas || localStream);
  useEffect(() => {
    const screenBecameAvailable = hasSharedScreen && !sharedScreenWasAvailableRef.current;
    sharedScreenWasAvailableRef.current = hasSharedScreen;
    if (screenBecameAvailable) {
      setMainStageSource('screen');
      return;
    }
    setMainStageSource(previous => {
      if (previous === 'screen' && !hasSharedScreen) {
        return hasRemoteVideo ? 'remote-video' : 'local-video';
      }
      if (previous === 'local-video' && !showLocalPreview) {
        return hasSharedScreen ? 'screen' : 'remote-video';
      }
      return previous;
    });
  }, [hasSharedScreen, hasRemoteVideo, showLocalPreview]);

  if (!call) return null;

  const glassControl = 'flex h-10 w-11 cursor-pointer items-center justify-center rounded-xl bg-black/40 text-white backdrop-blur-xl hover:bg-black/55';
  const peerAvatarColor = getDefaultAvatarColor(call.peer || '');
  const avatarStageStyle: React.CSSProperties = {
    backgroundColor: peerAvatarColor,
    backgroundImage: `radial-gradient(circle at center, color-mix(in srgb, ${peerAvatarColor} 78%, white) 0%, ${peerAvatarColor} 68%)`,
    backgroundPosition: 'center',
    backgroundRepeat: 'no-repeat',
    backgroundSize: '190% 190%'
  };

  const activeMainStageSource = mainStageSource === 'screen' && !hasSharedScreen
    ? hasRemoteVideo ? 'remote-video' : 'local-video'
    : mainStageSource === 'local-video' && !showLocalPreview
      ? hasSharedScreen ? 'screen' : 'remote-video'
      : mainStageSource;
  const overlayVisibility = controlsVisible
    ? 'pointer-events-auto opacity-100'
    : 'pointer-events-none opacity-0';
  const isDocked = isAttached && attachmentBounds !== null && !isExpandedScreenShare;
  const modalStyle = isExpandedScreenShare
    ? undefined
    : isDocked
      ? {
        left: attachmentBounds.left,
        top: attachmentBounds.top,
        width: attachmentBounds.width,
        height: attachmentBounds.height
      }
      : { left: position.x, bottom: position.bottom };

  return (
    <div
      ref={wrapperRef}
      className={cn(
        'fixed z-50 select-none overflow-hidden bg-background shadow-xl [&_button]:cursor-pointer',
        isExpandedScreenShare && 'left-[5vw] top-[5vh] h-[90vh] w-[90vw] rounded-2xl border border-border',
        !isExpandedScreenShare && !isDocked && 'aspect-video w-[min(92vw,520px)] rounded-2xl border border-border',
        isDocked && 'rounded-xl border border-border shadow-none',
        isAttached && !attachmentBounds && !isExpandedScreenShare && 'pointer-events-none opacity-0'
      )}
      style={modalStyle}
    >
      <div
        ref={mainStageRef}
        className="relative h-full w-full overflow-hidden bg-background"
        onMouseEnter={revealControls}
        onMouseMove={handleStageMouseMove}
        onMouseLeave={revealControls}
        onFocusCapture={revealControls}
      >
        {!isVideoCall ? (
          <div
            className="absolute inset-0 flex flex-col items-center justify-center overflow-hidden text-white/80"
            style={avatarStageStyle}
          >
            <UserAvatar username={call.peer || ''} size="xl" className="relative" />
            {!isConnected && <p className="mt-3 text-sm font-medium">{callStatusText}</p>}
          </div>
        ) : activeMainStageSource === 'screen' && hasSharedScreen ? (
          <CanvasDisplay canvas={sharedScreenCanvas} objectFit="contain" className="h-full w-full" />
        ) : activeMainStageSource === 'local-video' && showLocalPreview ? (
          <div className="relative h-full w-full bg-zinc-900">
            <CanvasDisplay
              canvas={localVideoCanvas}
              className={cn('h-full w-full', !isVideoEnabled && 'opacity-0')}
            />
            {!isVideoEnabled && (
              <div className="absolute inset-0 flex items-center justify-center">
                <VideoOff className="h-8 w-8 text-white/60" />
              </div>
            )}
            {isVideoEnabled && !localVideoCanvas && (
              <div className="absolute inset-0 flex items-center justify-center">
                <Video className="h-8 w-8 text-white/60" />
              </div>
            )}
            <span className="pointer-events-none absolute bottom-3 left-3 rounded-md bg-black/45 px-2 py-1 text-xs font-medium text-white backdrop-blur-md">
              You
            </span>
          </div>
        ) : activeMainStageSource === 'remote-video' && hasRemoteVideo ? (
          <CanvasDisplay canvas={remoteVideoCanvas} className="h-full w-full" />
        ) : (
          <div
            className="absolute inset-0 flex flex-col items-center justify-center text-white/75"
            style={avatarStageStyle}
          >
            <UserAvatar username={call.peer || ''} size="xl" className="mb-3 opacity-70" />
            {!isConnected && <p className="text-sm font-medium">{callStatusText}</p>}
          </div>
        )}

        {isVideoCall && hasRemoteVideo && activeMainStageSource !== 'remote-video' && (
          <DockedPip
            corner={pipCorners['remote-cam']}
            label={displayPeerName}
            stageRef={mainStageRef}
            onCornerChange={(corner) => dockPip('remote-cam', corner)}
            onActivate={() => setMainStageSource('remote-video')}
            large={isDocked}
          >
            <CanvasDisplay canvas={remoteVideoCanvas} className="h-full w-full" />
          </DockedPip>
        )}

        {showLocalPreview && activeMainStageSource !== 'local-video' && (
          <DockedPip
            corner={pipCorners.local}
            label="You"
            stageRef={mainStageRef}
            onCornerChange={(corner) => dockPip('local', corner)}
            onActivate={() => setMainStageSource('local-video')}
            large={isDocked}
          >
            <div className="relative h-full w-full bg-zinc-900">
              <CanvasDisplay
                canvas={localVideoCanvas}
                className={cn('h-full w-full', !isVideoEnabled && 'opacity-0')}
              />
              {!isVideoEnabled && (
                <div className="absolute inset-0 flex items-center justify-center">
                  <VideoOff className="h-5 w-5 text-white/60" />
                </div>
              )}
              {isVideoEnabled && !localVideoCanvas && (
                <div className="absolute inset-0 flex items-center justify-center">
                  <Video className="h-5 w-5 text-white/60" />
                </div>
              )}
            </div>
          </DockedPip>
        )}

        {isVideoCall && hasSharedScreen && activeMainStageSource !== 'screen' && (
          <DockedPip
            corner={pipCorners.screen}
            label={remoteScreenCanvas ? `${displayPeerName}'s screen` : 'Your screen'}
            stageRef={mainStageRef}
            onCornerChange={(corner) => dockPip('screen', corner)}
            onActivate={() => setMainStageSource('screen')}
            large={isDocked}
          >
            <CanvasDisplay canvas={sharedScreenCanvas} objectFit="contain" className="h-full w-full bg-zinc-950" />
          </DockedPip>
        )}

        <div
          className={cn(
            'absolute inset-x-0 top-0 z-30 flex items-start justify-between p-3 text-white transition-opacity duration-200',
            overlayVisibility
          )}
          data-call-overlay
          onMouseEnter={holdControls}
          onMouseMove={holdControls}
          onMouseLeave={revealControls}
        >
          <div
            className={cn(
              'flex select-none items-center gap-2',
              !isDocked && 'drop-shadow-lg',
              !isExpandedScreenShare && !isDocked && 'cursor-move'
            )}
            onMouseDown={!isExpandedScreenShare && !isDocked ? handleDragStart : undefined}
          >
            <UserAvatar
              username={call.peer || ''}
              size="xs"
              className={isDocked ? 'qor-docked-call-avatar' : undefined}
            />
            <div className={cn(
              'flex min-w-0 flex-col justify-center',
              isDocked ? 'qor-docked-call-copy' : 'text-shadow-sm'
            )}>
              <span className="max-w-48 truncate text-sm font-semibold leading-none">{displayPeerName}</span>
              {isConnected && (
                <span className="mt-1 text-[10px] font-medium text-white/80">
                  {formatClockDurationSeconds(callDuration)}
                </span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-1.5" onMouseDown={(event) => event.stopPropagation()}>
            {isVideoCall && (hasSharedScreen || isScreenSharing) && (
              <button
                type="button"
                onClick={() => setIsExpandedScreenShare(previous => !previous)}
                className={glassControl}
                title={isExpandedScreenShare ? 'Collapse' : 'Expand'}
              >
                {isExpandedScreenShare ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
              </button>
            )}
          </div>
        </div>

        <div
          className={cn(
            'absolute bottom-3 left-1/2 z-30 flex -translate-x-1/2 items-center gap-2 transition-opacity duration-200',
            overlayVisibility
          )}
          data-call-overlay
          onMouseEnter={holdControls}
          onMouseMove={holdControls}
          onMouseLeave={revealControls}
          onMouseDown={(event) => event.stopPropagation()}
        >
          {isIncoming && isRinging ? (
            <>
              <button
                type="button"
                onClick={onDecline}
                className="flex h-10 w-11 cursor-pointer items-center justify-center rounded-xl bg-red-600/90 text-white backdrop-blur-xl hover:bg-red-500"
                title="Decline"
              >
                <PhoneOff className="h-4 w-4" />
              </button>
              <button
                type="button"
                onClick={answerCall}
                className="flex h-10 w-11 cursor-pointer items-center justify-center rounded-xl bg-emerald-600/90 text-white backdrop-blur-xl hover:bg-emerald-500"
                title="Answer"
              >
                <Phone className="h-4 w-4" />
              </button>
            </>
          ) : (
            <>
              <MediaDeviceControl
                kind="microphone"
                enabled={!isMuted}
                devices={micDevices}
                open={devicePicker === 'microphone'}
                onOpenChange={(open) => setDevicePicker(open ? 'microphone' : null)}
                onToggle={toggleMute}
                onSelect={handleMicrophoneChange}
              />

              <OutputDeviceControl
                devices={speakerDevices}
                selectedDeviceId={preferredSpeakerId}
                open={devicePicker === 'speaker'}
                onOpenChange={(open) => setDevicePicker(open ? 'speaker' : null)}
                onSelect={handleSpeakerChange}
              />

              {isVideoCall && (
                <MediaDeviceControl
                  kind="camera"
                  enabled={isVideoEnabled}
                  devices={videoDevices}
                  selectedDeviceId={preferredCameraId}
                  open={devicePicker === 'camera'}
                  onOpenChange={(open) => setDevicePicker(open ? 'camera' : null)}
                  onToggle={toggleVideo}
                  onSelect={handleCameraChange}
                />
              )}

              {isVideoCall && (
                <button
                  type="button"
                  onClick={toggleScreenShare}
                  className={cn(glassControl, (isScreenSharing || isScreenShareStarting) && 'bg-primary/80 hover:bg-primary/90')}
                  title={isScreenSharing ? 'Stop Sharing' : isScreenShareStarting ? 'Starting Screen Share' : 'Share Screen'}
                >
                  {isScreenSharing ? <MonitorOff className="h-4 w-4" /> : <Monitor className="h-4 w-4" />}
                </button>
              )}
              <button
                type="button"
                onClick={onEndCall}
                className="flex h-10 w-11 cursor-pointer items-center justify-center rounded-xl bg-red-600/90 text-white backdrop-blur-xl hover:bg-red-500"
                title={isConnected ? 'End Call' : 'Cancel Call'}
              >
                <PhoneOff className="h-4 w-4" />
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
});

CallModal.displayName = 'CallModal';
export default CallModal;
