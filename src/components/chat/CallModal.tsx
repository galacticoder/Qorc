import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { Phone, PhoneOff, Video, VideoOff, Mic, MicOff, Monitor, MonitorOff, Settings } from 'lucide-react';
import type { CallState } from '../../lib/webrtc-calling';
// Lazy-load heavy subcomponents to avoid potential import cycles
const ScreenSourceSelectorLazy = React.lazy(() => import('./ScreenSourceSelector').then(m => ({ default: m.ScreenSourceSelector || m.default })));
const ScreenSharingSettingsLazy = React.lazy(() => import('../settings/ScreenSharingSettings').then(m => ({ default: m.ScreenSharingSettings || m.default })));
import { useUnifiedUsernameDisplay } from '../../hooks/useUnifiedUsernameDisplay';

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
  readonly peerConnection?: RTCPeerConnection | null;
  readonly onAnswer: () => void;
  readonly onDecline: () => void;
  readonly onEndCall: () => void;
  readonly onToggleMute: () => boolean;
  readonly onToggleVideo: () => boolean;
  readonly onSwitchCamera: () => void;
  readonly onStartScreenShare?: (selectedSource?: { id: string; name: string }) => Promise<void>;
  readonly onStopScreenShare?: () => Promise<void>;
  readonly onGetAvailableScreenSources?: () => Promise<readonly ScreenSource[]>;
  readonly isScreenSharing?: boolean;
  readonly getDisplayUsername?: (username: string) => Promise<string>;
}

export const CallModal: React.FC<CallModalProps> = ({
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
  onStartScreenShare,
  onStopScreenShare,
  onGetAvailableScreenSources,
  isScreenSharing = false,
  getDisplayUsername
}) => {
  // Use unified username display for the call peer
  const { displayName: displayPeerName } = useUnifiedUsernameDisplay({
    username: call?.peer || '',
    getDisplayUsername,
    fallbackToOriginal: true
  });

  const [isMuted, setIsMuted] = useState(false);
  const [isVideoEnabled, setIsVideoEnabled] = useState(true);
  const [callDuration, setCallDuration] = useState(0);
  const [isProcessing, setIsProcessing] = useState(false);



  // State declarations
  const [micLevel, setMicLevel] = useState(0);
  const [showScreenSourceSelector, setShowScreenSourceSelector] = useState(false);
  const [showScreenSharingSettings, setShowScreenSharingSettings] = useState(false);
  const [micMenuOpen, setMicMenuOpen] = useState(false);
  const [videoMenuOpen, setVideoMenuOpen] = useState(false);
  const [micDevices, setMicDevices] = useState<MediaDeviceInfo[]>([]);
  const [videoDevices, setVideoDevices] = useState<MediaDeviceInfo[]>([]);
  // Camera devices & dropdown state (declare early to avoid TDZ in effects)
  const [cameraDevices, setCameraDevices] = useState<MediaDeviceInfo[]>([]);
  const [cameraMenuOpen, setCameraMenuOpen] = useState(false);
  const [preferredCameraId, setPreferredCameraId] = useState<string | null>(null);

  // Load available devices
  useEffect(() => {
    const loadDevices = async () => {
      try {
        const devices = await navigator.mediaDevices.enumerateDevices();
        setMicDevices(devices.filter(device => device.kind === 'audioinput'));
        setVideoDevices(devices.filter(device => device.kind === 'videoinput'));
      } catch {
        // Device enumeration failure - graceful degradation
      }
    };

    loadDevices();

    // Listen for device changes
    navigator.mediaDevices.addEventListener('devicechange', loadDevices);
    return () => {
      navigator.mediaDevices.removeEventListener('devicechange', loadDevices);
    };
  }, []);

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Element;

      // Check if click is inside any dropdown menu or dropdown trigger
      const isInsideDropdown = target.closest('[data-dropdown-menu]') ||
                              target.closest('[data-dropdown-trigger]');

      if (!isInsideDropdown) {
        setMicMenuOpen(false);
        setVideoMenuOpen(false);
        setCameraMenuOpen(false);
      }
    };

    if (micMenuOpen || videoMenuOpen || cameraMenuOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [micMenuOpen, videoMenuOpen, cameraMenuOpen]);
  const audioCtxRef = useRef<AudioContext | null>(null);
  const analyserRef = useRef<AnalyserNode | null>(null);
  const rafRef = useRef<number | null>(null);
  const wrapperRef = useRef<HTMLDivElement | null>(null);
  const [dragging, setDragging] = useState(false);
  const dragStartRef = useRef<{ x: number; y: number; left: number; top: number; width: number; height: number } | null>(null);
  const [freePos, setFreePos] = useState<{ left: number; top: number } | null>(null);
  const [anchorCorner, setAnchorCorner] = useState<'tl' | 'tr' | 'bl' | 'br'>('br');
  const [anchorOffset, setAnchorOffset] = useState<{ x: number; y: number }>({ x: 16, y: 16 });


  useEffect(() => {
    let mounted = true;

    const loadCameraDevices = async () => {
      const all = await navigator.mediaDevices.enumerateDevices();
      const devs = all.filter(d => d.kind === 'videoinput');
      if (!mounted) return;

      setCameraDevices(devs);

      // Load preferred camera and validate it still exists
      try {
        const { encryptedStorage } = await import('../../lib/encrypted-storage');
        const enc = await encryptedStorage.getItem('preferred_camera_deviceId_v1_pq');
        const saved = typeof enc === 'string' ? enc : '';
        if (saved && saved.length < 512) {
          const exists = devs.some(dev => dev.deviceId === saved);
          if (exists) {
            setPreferredCameraId(saved);
          } else {
            setPreferredCameraId(null);
            await encryptedStorage.setItem('preferred_camera_deviceId_v1_pq', '');
          }
        }
      } catch {}
    };

    loadCameraDevices();

    // Listen for device changes (cameras plugged/unplugged)
    const handleDeviceChange = () => {
      if (mounted) {
        loadCameraDevices();
      }
    };

    navigator.mediaDevices.addEventListener('devicechange', handleDeviceChange);

    return () => {
      mounted = false;
      navigator.mediaDevices.removeEventListener('devicechange', handleDeviceChange);
    };
  }, []);

  // Camera selection handler
  const handleCameraSelect = useCallback(async (deviceId: string) => {
    try {
      // Save preferred camera
      const { encryptedStorage } = await import('../../lib/encrypted-storage');
      await encryptedStorage.setItem('preferred_camera_deviceId_v1_pq', deviceId);
      setPreferredCameraId(deviceId);
      
      // Switch to selected camera
      if (localStream) {
        const videoTrack = localStream.getVideoTracks()[0];
        if (videoTrack) {
          // Get new stream with selected camera
          const constraints = {
            video: { deviceId: { exact: deviceId } },
            audio: false
          };
          const newStream = await navigator.mediaDevices.getUserMedia(constraints);
          const newVideoTrack = newStream.getVideoTracks()[0];
          
          // Replace track in local stream
          localStream.removeTrack(videoTrack);
          localStream.addTrack(newVideoTrack);
          videoTrack.stop();
          
          // Update the video element
          if (localVideoRef.current) {
            localVideoRef.current.srcObject = localStream;
          }
        }
      }
      
      setCameraMenuOpen(false);
    } catch (_error) {
      console.error('Failed to switch camera:', _error);
    }
  }, [localStream]);

  // Drag handling
  useEffect(() => {
    const onMouseMove = (e: MouseEvent) => {
      if (!dragging || !dragStartRef.current) return;
      const dx = e.clientX - dragStartRef.current.x;
      const dy = e.clientY - dragStartRef.current.y;
      let left = dragStartRef.current.left + dx;
      let top = dragStartRef.current.top + dy;
      // Constrain to viewport with 8px margin
      const margin = 8;
      const vw = window.innerWidth;
      const vh = window.innerHeight;
      const w = dragStartRef.current.width;
      const h = dragStartRef.current.height;
      left = Math.max(margin, Math.min(left, vw - w - margin));
      top = Math.max(margin, Math.min(top, vh - h - margin));
      setFreePos({ left, top });
    };
    const onMouseUp = () => {
      if (!dragging || !dragStartRef.current || !wrapperRef.current || !freePos) {
        setDragging(false);
        document.body.style.userSelect = '';
        return;
      }
      // Snap to nearest corner
      const rect = { left: freePos.left, top: freePos.top, width: dragStartRef.current.width, height: dragStartRef.current.height };
      const vw = window.innerWidth;
      const vh = window.innerHeight;
      const distances = [
        { corner: 'tl' as const, d: rect.left + rect.top },
        { corner: 'tr' as const, d: (vw - (rect.left + rect.width)) + rect.top },
        { corner: 'bl' as const, d: rect.left + (vh - (rect.top + rect.height)) },
        { corner: 'br' as const, d: (vw - (rect.left + rect.width)) + (vh - (rect.top + rect.height)) }
      ];
      distances.sort((a, b) => a.d - b.d);
      const nearest = distances[0].corner;
      setAnchorCorner(nearest);
      // Compute offset from that corner (8px min)
      let offX = 16, offY = 16;
      if (nearest === 'tl') { offX = rect.left; offY = rect.top; }
      if (nearest === 'tr') { offX = vw - (rect.left + rect.width); offY = rect.top; }
      if (nearest === 'bl') { offX = rect.left; offY = vh - (rect.top + rect.height); }
      if (nearest === 'br') { offX = vw - (rect.left + rect.width); offY = vh - (rect.top + rect.height); }
      setAnchorOffset({ x: Math.max(8, Math.round(offX)), y: Math.max(8, Math.round(offY)) });
      setFreePos(null);
      setDragging(false);
      document.body.style.userSelect = '';
    };
    if (dragging) {
      window.addEventListener('mousemove', onMouseMove);
      window.addEventListener('mouseup', onMouseUp);
    }
    return () => {
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
    };
  }, [dragging, freePos]);

  const beginDrag = (e: React.MouseEvent) => {
    if (!wrapperRef.current) return;
    const rect = wrapperRef.current.getBoundingClientRect();
    dragStartRef.current = { x: e.clientX, y: e.clientY, left: rect.left, top: rect.top, width: rect.width, height: rect.height };
    setDragging(true);
    setFreePos({ left: rect.left, top: rect.top });
    document.body.style.userSelect = 'none';
  };

  // Mic level analyser from local stream
  useEffect(() => {
    // Cleanup if no stream
    if (!localStream) {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
      if (audioCtxRef.current) { try { audioCtxRef.current.close(); } catch {}
      }
      audioCtxRef.current = null;
      analyserRef.current = null;
      setMicLevel(0);
      return;
    }

    const audioTracks = localStream.getAudioTracks();
    if (audioTracks.length === 0) {
      setMicLevel(0);
      return;
    }

    try {
      const AudioCtx: typeof AudioContext = (window as any).AudioContext || (window as any).webkitAudioContext;
      const audioCtx = new AudioCtx();
      const analyser = audioCtx.createAnalyser();
      analyser.fftSize = 1024;
      const source = audioCtx.createMediaStreamSource(localStream);
      source.connect(analyser);
      audioCtxRef.current = audioCtx;
      analyserRef.current = analyser;
      const data = new Uint8Array(analyser.frequencyBinCount);

      const tick = () => {
        analyser.getByteTimeDomainData(data);
        let min = 128, max = 128;
        for (let i = 0; i < data.length; i++) {
          const v = data[i];
          if (v < min) min = v;
          if (v > max) max = v;
        }
        const amp = Math.min(1, (max - min) / 128);
        setMicLevel(prev => prev * 0.8 + amp * 0.2); // smooth
        rafRef.current = requestAnimationFrame(tick);
      };
      rafRef.current = requestAnimationFrame(tick);
    } catch {
      setMicLevel(0);
    }

    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
      if (audioCtxRef.current) { try { audioCtxRef.current.close(); } catch {}
      }
      audioCtxRef.current = null;
      analyserRef.current = null;
    };
  }, [localStream]);

  const handleAnswerClick = useCallback(async () => {
    if (isProcessing) return;
    setIsProcessing(true);
    try {
      await onAnswer();
    } finally {
      setTimeout(() => setIsProcessing(false), 300);
    }
  }, [isProcessing, onAnswer]);

  const handleDeclineClick = useCallback(async () => {
    if (isProcessing) return;
    setIsProcessing(true);
    try {
      await onDecline();
    } finally {
      setTimeout(() => setIsProcessing(false), 300);
    }
  }, [isProcessing, onDecline]);

  const handleEndClick = useCallback(async () => {
    if (isProcessing) return;
    setIsProcessing(true);
    try {
      await Promise.resolve(onEndCall());
    } finally {
      setTimeout(() => setIsProcessing(false), 300);
    }
  }, [isProcessing, onEndCall]);
  
  const localVideoRef = useRef<HTMLVideoElement>(null);
  const remoteVideoRef = useRef<HTMLVideoElement>(null);
  const remoteScreenVideoRef = useRef<HTMLVideoElement>(null);
  const durationIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Update video streams
  useEffect(() => {
    if (localVideoRef.current && localStream) {
      localVideoRef.current.srcObject = localStream;
    }
  }, [localStream]);

  useEffect(() => {
    if (remoteVideoRef.current) {
      if (remoteStream) {
        remoteVideoRef.current.srcObject = remoteStream;
      } else {
        try { remoteVideoRef.current.pause?.(); } catch {}
        remoteVideoRef.current.srcObject = null as any;
        try { 
          remoteVideoRef.current.removeAttribute('src');
          (remoteVideoRef.current as any).src = '';
          remoteVideoRef.current.load(); 
        } catch {}
      }
    }
  }, [remoteStream]);

  useEffect(() => {
    if (remoteScreenVideoRef.current) {
      if (remoteScreenStream) {
        remoteScreenVideoRef.current.srcObject = remoteScreenStream;
        const playPromise = remoteScreenVideoRef.current.play();
        if (playPromise) {
          playPromise.catch(() => {
            if (remoteScreenVideoRef.current) {
              remoteScreenVideoRef.current.muted = true;
              remoteScreenVideoRef.current.play().catch(() => {});
            }
          });
        }
      } else {
        try { remoteScreenVideoRef.current.pause?.(); } catch {}
        remoteScreenVideoRef.current.srcObject = null as any;
        try { 
          remoteScreenVideoRef.current.removeAttribute('src');
          (remoteScreenVideoRef.current as any).src = '';
          remoteScreenVideoRef.current.load(); 
        } catch {}
      }
    }
  }, [remoteScreenStream]);

  // Track call duration
  useEffect(() => {
    if (call?.status === 'connected') {
      durationIntervalRef.current = setInterval(() => {
        if (call.startTime) {
          setCallDuration(Math.floor((Date.now() - call.startTime) / 1000));
        }
      }, 1000);
    } else {
      if (durationIntervalRef.current) {
        clearInterval(durationIntervalRef.current);
        durationIntervalRef.current = null;
      }
      setCallDuration(0);
    }

    return () => {
      if (durationIntervalRef.current) {
        clearInterval(durationIntervalRef.current);
      }
    };
  }, [call?.status, call?.startTime]);

  const handleToggleMute = useCallback(() => {
    const muted = onToggleMute();
    setIsMuted(muted);
  }, [onToggleMute]);

  const handleToggleVideo = useCallback(async () => {
    const enabled = await onToggleVideo();
    setIsVideoEnabled(enabled);
  }, [onToggleVideo]);

  const handleScreenShare = useCallback(async () => {
    if (isProcessing) return;

    if (isScreenSharing) {
      setIsProcessing(true);
      try {
        await onStopScreenShare?.();
      } catch (_error) {
        alert('Failed to stop screen sharing: ' + (_error as Error).message);
      } finally {
        setIsProcessing(false);
      }
    } else {
      if (onGetAvailableScreenSources) {
        setShowScreenSourceSelector(true);
      } else {
        setIsProcessing(true);
        try {
          await onStartScreenShare?.();
        } catch (_error) {
          alert('Failed to start screen sharing: ' + (_error as Error).message);
        } finally {
          setIsProcessing(false);
        }
      }
    }
  }, [isProcessing, isScreenSharing, onStopScreenShare, onStartScreenShare, onGetAvailableScreenSources]);

  const handleScreenSourceSelect = useCallback(async (source: ScreenSource) => {
    setIsProcessing(true);
    try {
      await onStartScreenShare?.(source);
    } catch (_error) {
      alert('Failed to start screen sharing: ' + (_error as Error).message);
    } finally {
      setIsProcessing(false);
      setShowScreenSourceSelector(false);
    }
  }, [onStartScreenShare]);

  const handleScreenSourceCancel = useCallback(() => {
    setShowScreenSourceSelector(false);
  }, []);

  const formatDuration = useCallback((seconds: number): string => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  }, []);

  if (!call) return null;

  const isVideoCall = useMemo(() => call.type === 'video', [call.type]);
  const isIncoming = useMemo(() => call.direction === 'incoming', [call.direction]);
  const isConnected = useMemo(() => call.status === 'connected', [call.status]);
  const isRinging = useMemo(() => call.status === 'ringing', [call.status]);
  const isConnecting = useMemo(() => call.status === 'connecting', [call.status]);

  const wrapperStyle = useMemo((): React.CSSProperties => {
    if (freePos) {
      return { position: 'fixed', left: Math.round(freePos.left), top: Math.round(freePos.top), zIndex: 50, width: '380px' };
    }
    const base = { position: 'fixed' as const, zIndex: 50, width: '380px' };
    switch (anchorCorner) {
      case 'tl': return { ...base, left: anchorOffset.x, top: anchorOffset.y };
      case 'tr': return { ...base, right: anchorOffset.x, top: anchorOffset.y };
      case 'bl': return { ...base, left: anchorOffset.x, bottom: anchorOffset.y };
      default: return { ...base, right: anchorOffset.x, bottom: anchorOffset.y };
    }
  }, [freePos, anchorCorner, anchorOffset]);

  return (
    <div ref={wrapperRef} style={wrapperStyle} className="sm:w-[420px]">
      <div className="bg-gray-900/95 backdrop-blur rounded-xl shadow-[0_20px_60px_-15px_rgba(0,0,0,0.6)] border border-gray-700 overflow-hidden flex flex-col">
        
        {/* Header */}
        <div className="p-5 border-b border-gray-700 bg-gradient-to-r from-gray-900 to-gray-800 cursor-move select-none" onMouseDown={beginDrag}>
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-semibold text-white">
                {isConnected ? 'In Call' :
                 isConnecting ? 'Connecting' :
                 isIncoming ? 'Incoming Call' : 'Calling'}
              </h2>
              <p className="text-gray-300">{displayPeerName}</p>
              {isConnected && (
                <p className="text-sm text-green-400">{formatDuration(callDuration)}</p>
              )}
              {isConnecting && (
                <p className="text-sm text-blue-400">Connecting...</p>
              )}
              {isRinging && (
                <p className="text-sm text-yellow-400">
                  {isIncoming ? 'Ringing...' : 'Calling...'}
                </p>
              )}
              {/* Mic indicator */}
              <div className="mt-2">
                <div className="flex items-center gap-2 text-xs text-gray-300 mb-1">
                  <span className="inline-flex items-center gap-1">
                    {isMuted ? (
                      <MicOff className="w-3.5 h-3.5 text-red-400" />
                    ) : (
                      <Mic className="w-3.5 h-3.5 text-emerald-400" />
                    )}
                    <span>Mic</span>
                  </span>
                </div>
                <div className="h-2 w-40 bg-gray-700 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${isMuted ? 'bg-red-500' : 'bg-emerald-400'}`}
                    style={{ width: `${Math.min(100, Math.round(micLevel * 100))}%` }}
                  />
                </div>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <span className={`px-3 py-1 rounded-full text-sm ${
                isVideoCall ? 'bg-blue-600 text-white' : 'bg-green-600 text-white'
              }`}>
                {isVideoCall ? 'Video' : 'Audio'}
              </span>
              <span className={`w-3 h-3 rounded-full ${
                isConnected ? 'bg-green-500' : 
                isRinging ? 'bg-yellow-500 animate-pulse' : 
                isConnecting ? 'bg-blue-500 animate-pulse' :
                'bg-red-500'
              }`} />
            </div>
          </div>
        </div>

        {/* Video Area - Show for video calls OR if there's a remote screen/video stream */}
        {(isVideoCall || remoteStream || remoteScreenStream) && (
          <div className="space-y-3">
            {/* Main Video Display */}
            <div className="relative bg-black h-56">
              {/* Dedicated remote screen share video (shown only when available) */}
              <video
                ref={remoteScreenVideoRef}
                autoPlay
                playsInline
                className={`w-full h-full object-cover ${remoteScreenStream ? '' : 'hidden'}`}
              />

              {/* Dedicated remote camera video (hidden when screen share is active) */}
              <video
                ref={remoteVideoRef}
                autoPlay
                playsInline
                className={`w-full h-full object-cover ${remoteScreenStream ? 'hidden' : ''}`}
              />

              {/* Local Video (Picture-in-Picture) */}
              <div className="absolute top-3 right-3 w-28 h-20 bg-gray-800 rounded-md overflow-hidden border border-gray-600 shadow-md">
                <video
                  ref={localVideoRef}
                  autoPlay
                  playsInline
                  muted
                  className="w-full h-full object-cover"
                />
              </div>

              {/* Stream Type Indicator */}
              {remoteScreenStream && (
                <div className="absolute top-3 left-3 bg-blue-600 text-white px-2 py-1 rounded text-xs font-medium">
                  Screen Share
                </div>
              )}

              {!remoteStream && !remoteScreenStream && (
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="text-center text-gray-400">
                    <div className="w-24 h-24 bg-gray-700 rounded-full flex items-center justify-center mx-auto mb-4">
                      <span className="text-2xl font-bold">
                        {displayPeerName.charAt(0).toUpperCase()}
                      </span>
                    </div>
                    <p>Waiting for video...</p>
                  </div>
                </div>
              )}
            </div>

            {/* Secondary Video (Camera when screen sharing) */}
            {remoteScreenStream && remoteStream && (
              <div className="relative bg-black h-32 rounded-md overflow-hidden">
                <video
                  ref={remoteVideoRef}
                  autoPlay
                  playsInline
                  className="w-full h-full object-cover"
                />
                <div className="absolute top-2 left-2 bg-gray-800 text-white px-2 py-1 rounded text-xs">
                  Camera
                </div>
              </div>
            )}

          </div>
        )}

        {/* Audio Only View - Only show if no video/screen streams */}
        {!isVideoCall && !remoteStream && !remoteScreenStream && (
          <div className="py-6 flex items-center justify-center bg-gradient-to-br from-gray-800 to-gray-900">
            <div className="text-center text-white">
              <div className="w-32 h-32 bg-gray-700 rounded-full flex items-center justify-center mx-auto mb-6">
                <span className="text-4xl font-bold">
                  {displayPeerName.charAt(0).toUpperCase()}
                </span>
              </div>
              <h3 className="text-2xl font-semibold mb-2">{displayPeerName}</h3>
              {isConnected && (
                <p className="text-lg text-green-400">{formatDuration(callDuration)}</p>
              )}
              {isConnecting && (
                <p className="text-lg text-blue-400">Connecting...</p>
              )}
              {isRinging && (
                <p className="text-lg text-yellow-400">
                  {isIncoming ? 'Incoming call...' : 'Calling...'}
                </p>
              )}
            </div>
          </div>
        )}

        {/* Controls */}
        <div className="p-6 border-t border-gray-700">
          {/* Incoming Call Controls */}
          {isIncoming && isRinging && (
            <div className="flex justify-center space-x-8">
              <button
                onClick={handleDeclineClick}
                disabled={isProcessing}
                className="w-16 h-16 bg-red-600 hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-full flex items-center justify-center transition-colors"
              >
                <PhoneOff className="w-8 h-8 text-white" />
              </button>
              <button
                onClick={handleAnswerClick}
                disabled={isProcessing}
                className="w-16 h-16 bg-green-600 hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-full flex items-center justify-center transition-colors"
              >
                <Phone className="w-8 h-8 text-white" />
              </button>
            </div>
          )}

          {/* In-Call Controls */}
          {(isConnected || isConnecting || (!isIncoming && isRinging)) && (
            <div className="flex justify-center items-center space-x-6">
              {/* Mute Button with Integrated Dropdown */}
              <div className="relative">
                <button
                  onClick={handleToggleMute}
                  className={`w-16 h-16 rounded-full flex items-center justify-center transition-colors relative ${
                    isMuted ? 'bg-red-600 hover:bg-red-700' : 'bg-gray-600 hover:bg-gray-700'
                  }`}
                  title={isMuted ? 'Unmute' : 'Mute'}
                  data-dropdown-trigger
                >
                  {isMuted ? (
                    <MicOff className="w-7 h-7 text-white" />
                  ) : (
                    <Mic className="w-7 h-7 text-white" />
                  )}
                  {/* Integrated dropdown arrow */}
                  <div
                    className="absolute bottom-1 right-1 w-4 h-4 bg-black bg-opacity-30 rounded-full flex items-center justify-center cursor-pointer hover:bg-opacity-50 transition-colors"
                    onClick={(e) => {
                      e.stopPropagation();
                      setMicMenuOpen(v => !v);
                    }}
                    title="Select microphone"
                    data-dropdown-trigger
                  >
                    <span className="text-white text-xs">▾</span>
                  </div>
                </button>

                {/* Microphone dropdown menu */}
                {micMenuOpen && (
                  <div
                    className="fixed bg-gray-800 border border-gray-600 rounded-lg shadow-xl py-2 min-w-[200px]"
                    style={{
                      zIndex: 9999,
                      bottom: '100px',
                      left: '50%',
                      transform: 'translateX(-50%)',
                      maxHeight: '200px',
                      overflowY: 'auto'
                    }}
                    data-dropdown-menu
                  >
                    <div className="px-3 py-1 text-xs text-gray-400 border-b border-gray-600 mb-1">
                      Select Microphone
                    </div>
                    {micDevices.map((device) => (
                      <button
                        key={device.deviceId}
                        onClick={() => {
                          setMicMenuOpen(false);
                        }}
                        className="w-full text-left px-3 py-2 text-sm text-white hover:bg-gray-700 transition-colors"
                      >
                        {device.label || `Microphone ${device.deviceId.slice(0, 8)}...`}
                      </button>
                    ))}
                    {micDevices.length === 0 && (
                      <div className="px-3 py-2 text-sm text-gray-400">
                        No microphones detected
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Video Toggle with Integrated Dropdown (for video calls) */}
              {isVideoCall && (
                <div className="relative">
                  <button
                    onClick={handleToggleVideo}
                    disabled={videoDevices.length === 0}
                    title={videoDevices.length === 0 ? 'No camera detected' : (isVideoEnabled ? 'Turn off video' : 'Turn on video')}
                    className={`w-16 h-16 rounded-full flex items-center justify-center transition-colors relative ${
                      videoDevices.length === 0
                        ? 'bg-gray-500 opacity-60 cursor-not-allowed'
                        : (!isVideoEnabled ? 'bg-red-600 hover:bg-red-700' : 'bg-gray-600 hover:bg-gray-700')
                    }`}
                    data-dropdown-trigger
                  >
                    {isVideoEnabled ? (
                      <Video className="w-7 h-7 text-white" />
                    ) : (
                      <VideoOff className="w-7 h-7 text-white" />
                    )}
                    {/* Integrated dropdown arrow */}
                    <div
                      className="absolute bottom-1 right-1 w-4 h-4 bg-black bg-opacity-30 rounded-full flex items-center justify-center cursor-pointer hover:bg-opacity-50 transition-colors"
                      onClick={(e) => {
                        e.stopPropagation();
                        setVideoMenuOpen(v => !v);
                      }}
                      title="Select camera"
                      data-dropdown-trigger
                    >
                      <span className="text-white text-xs">▾</span>
                    </div>
                  </button>

                  {/* Video dropdown menu */}
                  {videoMenuOpen && (
                    <div
                      className="fixed bg-gray-800 border border-gray-600 rounded-lg shadow-xl py-2 min-w-[200px]"
                      style={{
                        zIndex: 9999,
                        bottom: '100px',
                        left: '50%',
                        transform: 'translateX(-50%)',
                        maxHeight: '250px',
                        overflowY: 'auto'
                      }}
                      data-dropdown-menu
                    >
                      <div className="px-3 py-1 text-xs text-gray-400 border-b border-gray-600 mb-1">
                        Select Camera
                      </div>
                      {cameraDevices.map((device) => (
                        <button
                          key={device.deviceId}
                          onClick={() => handleCameraSelect(device.deviceId)}
                          className={`w-full text-left px-3 py-2 text-sm transition-colors ${
                            device.deviceId === preferredCameraId
                              ? 'bg-blue-600 text-white'
                              : 'text-white hover:bg-gray-700'
                          }`}
                        >
                          {device.label || `Camera ${device.deviceId.slice(0, 8)}...`}
                          {device.deviceId === preferredCameraId && (
                            <span className="ml-2 text-xs">✓</span>
                          )}
                        </button>
                      ))}
                      {cameraDevices.length === 0 && (
                        <div className="px-3 py-2 text-sm text-gray-400">
                          No cameras detected
                        </div>
                      )}
                      <div className="border-t border-gray-600 mt-1 pt-1">
                        <button
                          onClick={() => {
                            onSwitchCamera();
                            setVideoMenuOpen(false);
                          }}
                          disabled={cameraDevices.length <= 1}
                          className="w-full text-left px-3 py-2 text-sm text-white hover:bg-gray-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          Switch Camera
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Screen Share Button (only for video calls) */}
              {isVideoCall && onStartScreenShare && onStopScreenShare && (
                <div className="flex items-center gap-1">
                  <button
                    onClick={handleScreenShare}
                    disabled={isProcessing}
                    className={`w-14 h-14 rounded-full flex items-center justify-center transition-colors ${
                      isScreenSharing ? 'bg-blue-600 hover:bg-blue-700' : 'bg-gray-600 hover:bg-gray-700'
                    }`}
                    title={isScreenSharing ? 'Stop screen sharing' : 'Start screen sharing'}
                  >
                    {isScreenSharing ? (
                      <MonitorOff className="w-6 h-6 text-white" />
                    ) : (
                      <Monitor className="w-6 h-6 text-white" />
                    )}
                  </button>
                  <button
                    onClick={() => setShowScreenSharingSettings(true)}
                    disabled={isProcessing}
                    className="ml-2 w-10 h-10 rounded-full bg-gray-700 hover:bg-gray-600 flex items-center justify-center transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    title="Screen sharing settings"
                  >
                    <Settings className="w-4 h-4 text-white" />
                  </button>
                </div>
              )}

              {/* End Call Button */}
              <button
                onClick={handleEndClick}
                disabled={isProcessing}
                className="w-18 h-18 min-w-[72px] min-h-[72px] bg-red-600 hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-full flex items-center justify-center transition-colors shrink-0"
                title="End call"
              >
                <PhoneOff className="w-9 h-9 text-white" />
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Screen Source Selector */}
<React.Suspense fallback={null}>
        <ScreenSourceSelectorLazy
          isOpen={showScreenSourceSelector}
          onClose={() => setShowScreenSourceSelector(false)}
          onSelect={handleScreenSourceSelect}
          onCancel={handleScreenSourceCancel}
          onGetAvailableScreenSources={onGetAvailableScreenSources}
        />
      </React.Suspense>

      {/* Screen Sharing Settings Modal */}
      {showScreenSharingSettings && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4 max-h-[80vh] overflow-y-auto">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-semibold">Screen Sharing Settings</h3>
              <button
                onClick={() => setShowScreenSharingSettings(false)}
                disabled={isProcessing}
                className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                ✕
              </button>
            </div>
            <React.Suspense fallback={null}>
              <ScreenSharingSettingsLazy />
            </React.Suspense>
            <div className="mt-4 flex justify-end">
              <button
                onClick={() => setShowScreenSharingSettings(false)}
                disabled={isProcessing}
                className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default CallModal;