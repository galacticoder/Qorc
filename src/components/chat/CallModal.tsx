/**
 * Call Modal Components for Incoming/Outgoing Calls
 */

import React, { useState, useEffect, useRef } from 'react';
import { Phone, PhoneOff, Video, VideoOff, Mic, MicOff, RotateCcw, Monitor, MonitorOff } from 'lucide-react';
import { CallState, WebRTCCallingService } from '../../lib/webrtc-calling';

interface CallModalProps {
  call: CallState | null;
  localStream: MediaStream | null;
  remoteStream: MediaStream | null;
  onAnswer: () => void;
  onDecline: () => void;
  onEndCall: () => void;
  onToggleMute: () => boolean;
  onToggleVideo: () => boolean;
  onSwitchCamera: () => void;
  onStartScreenShare?: () => Promise<void>;
  onStopScreenShare?: () => Promise<void>;
  isScreenSharing?: boolean;
}

export const CallModal: React.FC<CallModalProps> = ({
  call,
  localStream,
  remoteStream,
  onAnswer,
  onDecline,
  onEndCall,
  onToggleMute,
  onToggleVideo,
  onSwitchCamera,
  onStartScreenShare,
  onStopScreenShare,
  isScreenSharing = false
}) => {
  const [isMuted, setIsMuted] = useState(false);
  const [isVideoEnabled, setIsVideoEnabled] = useState(true);
  const [callDuration, setCallDuration] = useState(0);
  const [isProcessing, setIsProcessing] = useState(false);
  const [micLevel, setMicLevel] = useState(0);
  const audioCtxRef = useRef<AudioContext | null>(null);
  const analyserRef = useRef<AnalyserNode | null>(null);
  const rafRef = useRef<number | null>(null);

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
  const durationIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Update video streams
  useEffect(() => {
    if (localVideoRef.current && localStream) {
      localVideoRef.current.srcObject = localStream;
    }
  }, [localStream]);

  useEffect(() => {
    if (remoteVideoRef.current && remoteStream) {
      remoteVideoRef.current.srcObject = remoteStream;
    }
  }, [remoteStream]);

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

    setIsProcessing(true);
    try {
      if (isScreenSharing) {
        await onStopScreenShare?.();
      } else {
        await onStartScreenShare?.();
      }
    } catch (error) {
      console.error('Screen sharing error:', error);
      alert('Failed to ' + (isScreenSharing ? 'stop' : 'start') + ' screen sharing: ' + (error as Error).message);
    } finally {
      setIsProcessing(false);
    }
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

  return (
    <div className="fixed bottom-4 right-4 z-50 w-[380px] sm:w-[420px]">
      <div className="bg-gray-900 rounded-xl shadow-2xl border border-gray-700 overflow-hidden flex flex-col">
        
        {/* Header */}
        <div className="p-5 border-b border-gray-700 bg-gradient-to-r from-gray-900 to-gray-800">
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
          <div className="relative bg-black h-56">
            {/* Remote Video */}
            <video
              ref={remoteVideoRef}
              autoPlay
              playsInline
              className="w-full h-full object-cover"
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

            {/* No video placeholder */}
            {!remoteStream && (
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
    </div>
  );
};

export default CallModal;
