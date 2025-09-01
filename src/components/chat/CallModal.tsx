/**
 * Call Modal Components for Incoming/Outgoing Calls
 */

import React, { useState, useEffect, useRef } from 'react';
import { Phone, PhoneOff, Video, VideoOff, Mic, MicOff, RotateCcw, Monitor, MonitorOff, Settings } from 'lucide-react';
import { CallState, WebRTCCallingService } from '../../lib/webrtc-calling';
import { ScreenSourceSelector } from './ScreenSourceSelector';
import { ScreenSharingSettings } from '../settings/ScreenSharingSettings';
import { VideoQualityMonitor } from '../debug/VideoQualityMonitor';

interface CallModalProps {
  call: CallState | null;
  localStream: MediaStream | null;
  remoteStream: MediaStream | null;
  remoteScreenStream?: MediaStream | null;
  peerConnection?: RTCPeerConnection | null;
  onAnswer: () => void;
  onDecline: () => void;
  onEndCall: () => void;
  onToggleMute: () => boolean;
  onToggleVideo: () => boolean;
  onSwitchCamera: () => void;
  onStartScreenShare?: (selectedSource?: { id: string; name: string }) => Promise<void>;
  onStopScreenShare?: () => Promise<void>;
  onGetAvailableScreenSources?: () => Promise<Array<{ id: string; name: string; type: 'screen' | 'window' }>>;
  isScreenSharing?: boolean;
}

export const CallModal: React.FC<CallModalProps> = ({
  call,
  localStream,
  remoteStream,
  remoteScreenStream,
  peerConnection,
  onAnswer,
  onDecline,
  onEndCall,
  onToggleMute,
  onToggleVideo,
  onSwitchCamera,
  onStartScreenShare,
  onStopScreenShare,
  onGetAvailableScreenSources,
  isScreenSharing = false
}) => {
  const [isMuted, setIsMuted] = useState(false);
  const [isVideoEnabled, setIsVideoEnabled] = useState(true);
  const [callDuration, setCallDuration] = useState(0);
  const [isProcessing, setIsProcessing] = useState(false);
  const [micLevel, setMicLevel] = useState(0);
  const [showScreenSourceSelector, setShowScreenSourceSelector] = useState(false);
  const [showScreenSharingSettings, setShowScreenSharingSettings] = useState(false);
  const audioCtxRef = useRef<AudioContext | null>(null);
  const analyserRef = useRef<AnalyserNode | null>(null);
  const rafRef = useRef<number | null>(null);
  const wrapperRef = useRef<HTMLDivElement | null>(null);
  const [dragging, setDragging] = useState(false);
  const dragStartRef = useRef<{ x: number; y: number; left: number; top: number; width: number; height: number } | null>(null);
  const [freePos, setFreePos] = useState<{ left: number; top: number } | null>(null);
  const [anchorCorner, setAnchorCorner] = useState<'tl' | 'tr' | 'bl' | 'br'>('br');
  const [anchorOffset, setAnchorOffset] = useState<{ x: number; y: number }>({ x: 16, y: 16 });

  // Camera devices & dropdown state
  const [cameraDevices, setCameraDevices] = useState<MediaDeviceInfo[]>([]);
  const [cameraMenuOpen, setCameraMenuOpen] = useState(false);
  const [preferredCameraId, setPreferredCameraId] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;

    const loadCameraDevices = async () => {
      const devs = await WebRTCCallingService.getVideoInputDevices();
      if (!mounted) return;

      setCameraDevices(devs);

      // Load preferred camera and validate it still exists
      try {
        const saved = localStorage.getItem('preferred_camera_deviceId_v1');
        if (saved && saved.length < 256) {
          // Check if the saved camera still exists
          const deviceExists = devs.some(dev => dev.deviceId === saved);
          if (deviceExists) {
            setPreferredCameraId(saved);
          } else {
            // Reset to null if saved device no longer exists
            setPreferredCameraId(null);
            localStorage.removeItem('preferred_camera_deviceId_v1');
          }
        }
      } catch {}
    };

    // Initial load
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

  const handleSelectCamera = async (deviceId: string) => {
    try { localStorage.setItem('preferred_camera_deviceId_v1', deviceId || ''); } catch {}
    setPreferredCameraId(deviceId || null);
    setCameraMenuOpen(false);
    // Note: live switching mid-call requires access to callingService.
    // This selection will be applied automatically on the next video call.
  };

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

    // Check if the stream has audio tracks before creating analyser
    const audioTracks = localStream.getAudioTracks();
    if (audioTracks.length === 0) {
      console.log('[CallModal] No audio tracks in stream, skipping mic analyser setup');
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
    } catch (e) {
      console.warn('[CallModal] Failed to initialize mic analyser', e);
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

  const handleAnswerClick = async () => {
    if (isProcessing) return;
    setIsProcessing(true);
    try {
      await onAnswer();
    } finally {
      setTimeout(() => setIsProcessing(false), 300);
    }
  };

  const handleDeclineClick = async () => {
    if (isProcessing) return;
    setIsProcessing(true);
    try {
      await onDecline();
    } finally {
      setTimeout(() => setIsProcessing(false), 300);
    }
  };

  const handleEndClick = async () => {
    if (isProcessing) return;
    setIsProcessing(true);
    try {
      await Promise.resolve(onEndCall());
    } finally {
      setTimeout(() => setIsProcessing(false), 300);
    }
  };
  
  const localVideoRef = useRef<HTMLVideoElement>(null);
  const remoteVideoRef = useRef<HTMLVideoElement>(null);
  const remoteScreenVideoRef = useRef<HTMLVideoElement>(null);
  const durationIntervalRef = useRef<NodeJS.Timeout | null>(null);

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
        // Clear the last frame when stream ends
        try { remoteVideoRef.current.pause?.(); } catch {}
        remoteVideoRef.current.srcObject = null as any;
        try { 
          remoteVideoRef.current.removeAttribute('src'); 
          // Force clear by setting to empty video
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
        console.log('[CallModal] Remote screen stream connected to video element');
      } else {
        // Clear the last frame when screen share ends
        try { remoteScreenVideoRef.current.pause?.(); } catch {}
        remoteScreenVideoRef.current.srcObject = null as any;
        try { 
          remoteScreenVideoRef.current.removeAttribute('src'); 
          // Force clear by setting to empty video
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

  const handleToggleMute = () => {
    const muted = onToggleMute();
    setIsMuted(muted);
  };

  const handleToggleVideo = () => {
    const enabled = onToggleVideo();
    setIsVideoEnabled(enabled);
  };

  const handleScreenShare = async () => {
    if (isProcessing) return;

    if (isScreenSharing) {
      // Stop screen sharing
      setIsProcessing(true);
      try {
        await onStopScreenShare?.();
      } catch (error) {
        console.error('Screen sharing error:', error);
        alert('Failed to stop screen sharing: ' + (error as Error).message);
      } finally {
        setIsProcessing(false);
      }
    } else {
      // Start screen sharing - show source selector if available
      if (onGetAvailableScreenSources) {
        setShowScreenSourceSelector(true);
      } else {
        // Fallback to direct screen sharing without selection
        setIsProcessing(true);
        try {
          await onStartScreenShare?.();
        } catch (error) {
          console.error('Screen sharing error:', error);
          alert('Failed to start screen sharing: ' + (error as Error).message);
        } finally {
          setIsProcessing(false);
        }
      }
    }
  };

  const handleScreenSourceSelect = async (source: { id: string; name: string; type: 'screen' | 'window' }) => {
    setIsProcessing(true);
    try {
      await onStartScreenShare?.(source);
    } catch (error) {
      console.error('Screen sharing error:', error);
      alert('Failed to start screen sharing: ' + (error as Error).message);
    } finally {
      setIsProcessing(false);
      setShowScreenSourceSelector(false);
    }
  };

  const handleScreenSourceCancel = () => {
    // Close the screen source selector
    setShowScreenSourceSelector(false);
  };

  const formatDuration = (seconds: number): string => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  if (!call) return null;

  const isVideoCall = call.type === 'video';
  const isIncoming = call.direction === 'incoming';
  const isConnected = call.status === 'connected';
  const isRinging = call.status === 'ringing';
  const isConnecting = call.status === 'connecting';

  // Compute wrapper style based on drag/free or anchored corner
  const wrapperStyle: React.CSSProperties = freePos
    ? { position: 'fixed', left: Math.round(freePos.left), top: Math.round(freePos.top), zIndex: 50, width: '380px' }
    : anchorCorner === 'tl'
      ? { position: 'fixed', left: anchorOffset.x, top: anchorOffset.y, zIndex: 50, width: '380px' }
      : anchorCorner === 'tr'
        ? { position: 'fixed', right: anchorOffset.x, top: anchorOffset.y, zIndex: 50, width: '380px' }
        : anchorCorner === 'bl'
          ? { position: 'fixed', left: anchorOffset.x, bottom: anchorOffset.y, zIndex: 50, width: '380px' }
          : { position: 'fixed', right: anchorOffset.x, bottom: anchorOffset.y, zIndex: 50, width: '380px' };

  return (
    <div ref={wrapperRef} style={wrapperStyle} className="sm:w-[420px]">
      <div className="bg-gray-900/95 backdrop-blur rounded-xl shadow-[0_20px_60px_-15px_rgba(0,0,0,0.6)] border border-gray-700 overflow-hidden flex flex-col">
        
        {/* Header */}
        <div className="p-5 border-b border-gray-700 bg-gradient-to-r from-gray-900 to-gray-800 cursor-move select-none" onMouseDown={beginDrag}>
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-semibold text-white">
                {isIncoming ? 'Incoming Call' : 'Calling'}
              </h2>
              <p className="text-gray-300">{call.peer}</p>
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

        {/* Video Area */}
        {isVideoCall && (
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

              {/* No video placeholder */}
              {!remoteStream && !remoteScreenStream && (
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="text-center text-gray-400">
                    <div className="w-24 h-24 bg-gray-700 rounded-full flex items-center justify-center mx-auto mb-4">
                      <span className="text-2xl font-bold">
                        {call.peer.charAt(0).toUpperCase()}
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

            {/* Quality Monitor */}
            {(remoteStream || remoteScreenStream) && (
              <VideoQualityMonitor
                peerConnection={peerConnection || null}
                remoteStream={remoteScreenStream || remoteStream}
                isVisible={true}
              />
            )}
          </div>
        )}

        {/* Audio Only View */}
        {!isVideoCall && (
          <div className="py-6 flex items-center justify-center bg-gradient-to-br from-gray-800 to-gray-900">
            <div className="text-center text-white">
              <div className="w-32 h-32 bg-gray-700 rounded-full flex items-center justify-center mx-auto mb-6">
                <span className="text-4xl font-bold">
                  {call.peer.charAt(0).toUpperCase()}
                </span>
              </div>
              <h3 className="text-2xl font-semibold mb-2">{call.peer}</h3>
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
              {/* Mute Button */}
              <button
                onClick={handleToggleMute}
                className={`w-12 h-12 rounded-full flex items-center justify-center transition-colors ${
                  isMuted ? 'bg-red-600 hover:bg-red-700' : 'bg-gray-600 hover:bg-gray-700'
                }`}
              >
                {isMuted ? (
                  <MicOff className="w-6 h-6 text-white" />
                ) : (
                  <Mic className="w-6 h-6 text-white" />
                )}
              </button>

              {/* Video Toggle (for video calls) */}
              {isVideoCall && (
                <>
                  {/* Video toggle */}
                  <div className="relative inline-flex items-center">
                    <button
                      onClick={handleToggleVideo}
                      disabled={cameraDevices.length === 0}
                      title={cameraDevices.length === 0 ? 'No camera detected' : ''}
                      className={`w-12 h-12 rounded-full flex items-center justify-center transition-colors ${
                        cameraDevices.length === 0
                          ? 'bg-gray-500 opacity-60 cursor-not-allowed'
                          : (!isVideoEnabled ? 'bg-red-600 hover:bg-red-700' : 'bg-gray-600 hover:bg-gray-700')
                      }`}
                    >
                      {isVideoEnabled ? (
                        <Video className="w-6 h-6 text-white" />
                      ) : (
                        <VideoOff className="w-6 h-6 text-white" />
                      )}
                    </button>
                    {/* Camera switch button */}
                    <button
                      type="button"
                      onClick={onSwitchCamera}
                      disabled={cameraDevices.length <= 1}
                      aria-label={cameraDevices.length <= 1 ? 'No other cameras available' : 'Switch camera'}
                      aria-disabled={cameraDevices.length <= 1}
                      title={cameraDevices.length <= 1 ? 'No other cameras available' : 'Switch camera'}
                      data-testid="switch-camera-button"
                      className={`ml-1 w-8 h-8 rounded-full flex items-center justify-center transition-colors ${
                        cameraDevices.length <= 1 ? 'bg-gray-500 opacity-60 cursor-not-allowed' : 'bg-gray-600 hover:bg-gray-700'
                      }`}
                    >
                      <RotateCcw className="w-4 h-4 text-white" />
                    </button>

                    {/* Dropdown trigger */}
                    <button
                      onClick={() => setCameraMenuOpen(v => !v)}
                      disabled={cameraDevices.length === 0}
                      title={cameraDevices.length === 0 ? 'No camera detected' : 'Select camera'}
                      className={`ml-1 w-8 h-8 rounded-full flex items-center justify-center transition-colors ${
                        cameraDevices.length === 0 ? 'bg-gray-500 opacity-60 cursor-not-allowed' : 'bg-gray-600 hover:bg-gray-700'
                      }`}
                    >
                      <span className="text-white text-xs">▾</span>
                    </button>

                    {/* Dropdown menu */}
                    {cameraMenuOpen && cameraDevices.length > 0 && (
                      <div className="absolute top-12 left-0 bg-gray-800 text-white text-sm rounded-md shadow-lg border border-gray-700 min-w-[220px] z-50">
                        <div className="px-3 py-2 border-b border-gray-700 text-gray-300">Select camera</div>
                        <ul className="max-h-60 overflow-auto">
                          {cameraDevices.map((d) => (
                            <li key={d.deviceId}>
                              <button
                                onClick={() => handleSelectCamera(d.deviceId)}
                                className={`w-full text-left px-3 py-2 hover:bg-gray-700 ${preferredCameraId === d.deviceId ? 'bg-gray-700' : ''}`}
                              >
                                {d.label || `Camera (${d.deviceId.slice(0,6)}…)`}
                              </button>
                            </li>
                          ))}
                          {cameraDevices.length === 0 && (
                            <li className="px-3 py-2 text-gray-400">No cameras found</li>
                          )}
                        </ul>
                        <div className="px-3 py-2 border-t border-gray-700 text-xs text-gray-400">
                          Selection applies to the next video call.
                        </div>
                      </div>
                    )}
                  </div>
                </>
              )}

              {/* Screen Share Button (only for video calls) */}
              {isVideoCall && onStartScreenShare && onStopScreenShare && (
                <div className="flex items-center gap-1">
                  <button
                    onClick={handleScreenShare}
                    disabled={isProcessing}
                    className={`w-12 h-12 rounded-full flex items-center justify-center transition-colors ${
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
                    className="w-8 h-8 rounded-full bg-gray-700 hover:bg-gray-600 flex items-center justify-center transition-colors"
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
                className="w-16 h-16 bg-red-600 hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-full flex items-center justify-center transition-colors"
              >
                <PhoneOff className="w-8 h-8 text-white" />
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Screen Source Selector */}
      <ScreenSourceSelector
        isOpen={showScreenSourceSelector}
        onClose={() => setShowScreenSourceSelector(false)}
        onSelect={handleScreenSourceSelect}
        onCancel={handleScreenSourceCancel}
        onGetAvailableScreenSources={onGetAvailableScreenSources}
      />

      {/* Screen Sharing Settings Modal */}
      {showScreenSharingSettings && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4 max-h-[80vh] overflow-y-auto">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-semibold">Screen Sharing Settings</h3>
              <button
                onClick={() => setShowScreenSharingSettings(false)}
                className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
              >
                ✕
              </button>
            </div>
            <ScreenSharingSettings />
            <div className="mt-4 flex justify-end">
              <button
                onClick={() => setShowScreenSharingSettings(false)}
                className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors"
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
