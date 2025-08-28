/**
 * Call Modal Components for Incoming/Outgoing Calls
 */

import React, { useState, useEffect, useRef } from 'react';
import { Phone, PhoneOff, Video, VideoOff, Mic, MicOff, RotateCcw } from 'lucide-react';
import { CallState } from '../../lib/webrtc-calling';

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
  onSwitchCamera
}) => {
  const [isMuted, setIsMuted] = useState(false);
  const [isVideoEnabled, setIsVideoEnabled] = useState(true);
  const [callDuration, setCallDuration] = useState(0);
  
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

  return (
    <div className="fixed inset-0 bg-black bg-opacity-90 flex items-center justify-center z-50">
      <div className="bg-gray-900 rounded-lg shadow-2xl w-full max-w-4xl h-full max-h-[90vh] flex flex-col">
        
        {/* Header */}
        <div className="p-6 border-b border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-semibold text-white">
                {isIncoming ? 'Incoming Call' : 'Calling'}
              </h2>
              <p className="text-gray-300">{call.peer}</p>
              {isConnected && (
                <p className="text-sm text-green-400">{formatDuration(callDuration)}</p>
              )}
              {isRinging && (
                <p className="text-sm text-yellow-400">
                  {isIncoming ? 'Ringing...' : 'Calling...'}
                </p>
              )}
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
                'bg-red-500'
              }`} />
            </div>
          </div>
        </div>

        {/* Video Area */}
        {isVideoCall && (
          <div className="flex-1 relative bg-black">
            {/* Remote Video */}
            <video
              ref={remoteVideoRef}
              autoPlay
              playsInline
              className="w-full h-full object-cover"
            />
            
            {/* Local Video (Picture-in-Picture) */}
            <div className="absolute top-4 right-4 w-48 h-36 bg-gray-800 rounded-lg overflow-hidden border-2 border-gray-600">
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
          <div className="flex-1 flex items-center justify-center bg-gradient-to-br from-gray-800 to-gray-900">
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
                onClick={onDecline}
                className="w-16 h-16 bg-red-600 hover:bg-red-700 rounded-full flex items-center justify-center transition-colors"
              >
                <PhoneOff className="w-8 h-8 text-white" />
              </button>
              <button
                onClick={onAnswer}
                className="w-16 h-16 bg-green-600 hover:bg-green-700 rounded-full flex items-center justify-center transition-colors"
              >
                <Phone className="w-8 h-8 text-white" />
              </button>
            </div>
          )}

          {/* In-Call Controls */}
          {(isConnected || (!isIncoming && isRinging)) && (
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
                  <button
                    onClick={handleToggleVideo}
                    className={`w-12 h-12 rounded-full flex items-center justify-center transition-colors ${
                      !isVideoEnabled ? 'bg-red-600 hover:bg-red-700' : 'bg-gray-600 hover:bg-gray-700'
                    }`}
                  >
                    {isVideoEnabled ? (
                      <Video className="w-6 h-6 text-white" />
                    ) : (
                      <VideoOff className="w-6 h-6 text-white" />
                    )}
                  </button>

                  {/* Camera Switch */}
                  <button
                    onClick={onSwitchCamera}
                    className="w-12 h-12 bg-gray-600 hover:bg-gray-700 rounded-full flex items-center justify-center transition-colors"
                  >
                    <RotateCcw className="w-6 h-6 text-white" />
                  </button>
                </>
              )}

              {/* End Call Button */}
              <button
                onClick={onEndCall}
                className="w-16 h-16 bg-red-600 hover:bg-red-700 rounded-full flex items-center justify-center transition-colors"
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
