/**
 * WebRTC Secure Voice/Video Calling Service
 * Implements end-to-end encrypted audio/video calls with post-quantum security
 */

// Crypto utilities are handled by Signal Protocol encryption
import { SignalType } from './signals';
import websocketClient from './websocket';
import { screenSharingSettings } from './screen-sharing-settings';

// Screen sharing settings types
export interface ScreenSharingResolution {
  id: string;
  name: string;
  width: number;
  height: number;
  isNative?: boolean;
}

export interface ScreenSharingSettings {
  resolution: ScreenSharingResolution;
  frameRate: number;
  quality: 'low' | 'medium' | 'high';
}

// Predefined resolution presets
export const SCREEN_SHARING_RESOLUTIONS: ScreenSharingResolution[] = [
  { id: 'native', name: 'Native Resolution', width: 0, height: 0, isNative: true },
  { id: '720p', name: '720p (1280×720)', width: 1280, height: 720 },
  { id: '1080p', name: '1080p (1920×1080)', width: 1920, height: 1080 },
  { id: '1440p', name: '1440p (2560×1440)', width: 2560, height: 1440 },
  { id: '4k', name: '4K (3840×2160)', width: 3840, height: 2160 },
];

// Framerate options
export const SCREEN_SHARING_FRAMERATES = [15, 30, 60] as const;
export type ScreenSharingFrameRate = typeof SCREEN_SHARING_FRAMERATES[number];

// Default settings are now defined in screen-sharing-settings.ts to avoid circular dependency

export interface CallState {
  id: string;
  type: 'audio' | 'video';
  direction: 'incoming' | 'outgoing';
  status: 'ringing' | 'connecting' | 'connected' | 'ended' | 'declined' | 'missed';
  peer: string;
  startTime?: number;
  endTime?: number;
  duration?: number;
  endReason?: 'user' | 'timeout' | 'missed' | 'failed' | 'connection-lost' | 'shutdown' | string;
}

export interface CallOffer {
  callId: string;
  type: 'audio' | 'video';
  from: string;
  to: string;
  sdp: RTCSessionDescriptionInit;
  timestamp: number;
}

export interface CallAnswer {
  callId: string;
  from: string;
  to: string;
  sdp: RTCSessionDescriptionInit;
  accepted: boolean;
}

export interface CallSignal {
  type: 'offer' | 'answer' | 'ice-candidate' | 'end-call' | 'decline-call';
  callId: string;
  from: string;
  to: string;
  data?: any;
  timestamp: number;
  isRenegotiation?: boolean; // Flag to indicate this is a renegotiation offer
}

export class WebRTCCallingService {
  private localStream: MediaStream | null = null;
  private remoteStream: MediaStream | null = null;
  private remoteScreenStream: MediaStream | null = null; // Separate stream for remote screen sharing
  private screenStream: MediaStream | null = null;
  private screenShareSender: RTCRtpSender | null = null; // Keep a dedicated sender for screen share
  private peerConnection: RTCPeerConnection | null = null;
  private currentCall: CallState | null = null;
  private isScreenSharing: boolean = false;
  private isTogglingScreenShare: boolean = false;
  private isRenegotiating: boolean = false;
  private renegotiationTimeoutId: ReturnType<typeof setTimeout> | null = null;
  private iceConnectionFailureTimeoutId: ReturnType<typeof setTimeout> | null = null;
  private localUsername: string = '';
  private preferredCameraDeviceId: string | null = null;
  
  // Callbacks
  private onIncomingCallCallback: ((call: CallState) => void) | null = null;
  private onCallStateChangeCallback: ((call: CallState) => void) | null = null;
  private onRemoteStreamCallback: ((stream: MediaStream | null) => void) | null = null;
  private onRemoteScreenStreamCallback: ((stream: MediaStream | null) => void) | null = null;
  private onLocalStreamCallback: ((stream: MediaStream) => void) | null = null;

  // Security: Enhanced WebRTC configuration for maximum security
  private rtcConfig: RTCConfiguration = {
    iceServers: [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' },
      { urls: 'stun:stun2.l.google.com:19302' },
    ],
    iceCandidatePoolSize: 10,
    bundlePolicy: 'max-bundle',
    rtcpMuxPolicy: 'require',
    // Enable DTLS-SRTP for media encryption
  };

  // Call timeout settings
  private readonly CALL_TIMEOUT = 30000; // 30 seconds (aligned with ring timeout)
  private readonly RING_TIMEOUT = 30000; // 30 seconds
  private callTimeoutId: ReturnType<typeof setTimeout> | null = null;

  constructor(username: string) {
    this.localUsername = username;
    try {
      const saved = localStorage.getItem('preferred_camera_deviceId_v1');
      if (saved && typeof saved === 'string' && saved.length < 256) {
        this.preferredCameraDeviceId = saved;
      }
    } catch {}
  }

  /**
   * Initialize calling service
   */
  initialize(): void {
    console.log('[Calling] Initializing WebRTC calling service');
    
    // Listen for encrypted call signals
    this.setupSignalHandlers();
  }

  /**
   * Start an outgoing call (audio or video)
   */
  async startCall(targetUser: string, callType: 'audio' | 'video' = 'audio'): Promise<string> {
    if (this.currentCall) {
      throw new Error('Another call is already in progress');
    }

    const callId = this.generateCallId();
    
    console.log(`[Calling] Starting ${callType} call to ${targetUser}`, { callId });

    // Create call state
    this.currentCall = {
      id: callId,
      type: callType,
      direction: 'outgoing',
      status: 'connecting',
      peer: targetUser,
      startTime: Date.now()
    };

    // Notify initial state so UI can show "started"
    this.onCallStateChangeCallback?.(this.currentCall);

    try {
      // Get user media
      await this.setupLocalMedia(callType);
      
      // Create peer connection
      await this.createPeerConnection();
      
      // Add local stream to peer connection
      if (this.localStream) {
        this.localStream.getTracks().forEach(track => {
          this.peerConnection!.addTrack(track, this.localStream!);
        });
      }

      // Create offer
      const offer = await this.peerConnection!.createOffer({
        offerToReceiveAudio: true,
        offerToReceiveVideo: callType === 'video'
      });
      
      await this.peerConnection!.setLocalDescription(offer);

      // Send encrypted call offer
      await this.sendCallSignal({
        type: 'offer',
        callId,
        from: this.localUsername,
        to: targetUser,
        data: offer,
        timestamp: Date.now()
      });

      // Update call status
      this.currentCall.status = 'ringing';
      this.onCallStateChangeCallback?.(this.currentCall);

      // Set call timeout
      this.callTimeoutId = setTimeout(() => {
        if (this.currentCall?.status === 'ringing') {
          this.endCall('timeout');
        }
      }, this.CALL_TIMEOUT);

      return callId;

    } catch (error) {
      console.error('[Calling] Failed to start call:', error);
      this.endCall('failed');
      throw error;
    }
  }

  /**
   * Answer an incoming call
   */
  async answerCall(callId: string): Promise<void> {
    if (!this.currentCall || this.currentCall.id !== callId) {
      throw new Error('No matching incoming call found');
    }

    console.log('[Calling] Answering call:', callId);

    // Prevent duplicate/invalid answer attempts
    if (!this.peerConnection) {
      console.warn('[Calling] No peer connection present when answering');
      return;
    }
    if (this.currentCall.status !== 'ringing') {
      console.warn('[Calling] Ignoring answer: call status is', this.currentCall.status);
      return;
    }
    const signalingState = this.peerConnection.signalingState;
    if (signalingState !== 'have-remote-offer' && signalingState !== 'have-local-pranswer') {
      console.warn('[Calling] Ignoring answer: invalid signalingState', signalingState);
      return;
    }

    try {
      // Get user media
      await this.setupLocalMedia(this.currentCall.type);
      
      // Add local stream to existing peer connection
      if (this.localStream && this.peerConnection) {
        this.localStream.getTracks().forEach(track => {
          this.peerConnection!.addTrack(track, this.localStream!);
        });
      }

      // Create answer
      const answer = await this.peerConnection!.createAnswer();
      await this.peerConnection!.setLocalDescription(answer);

      // Send encrypted answer
      await this.sendCallSignal({
        type: 'answer',
        callId,
        from: this.localUsername,
        to: this.currentCall.peer,
        data: { sdp: answer, accepted: true },
        timestamp: Date.now()
      });

      // Update call status
      this.currentCall.status = 'connecting';
      this.onCallStateChangeCallback?.(this.currentCall);

    } catch (error) {
      console.error('[Calling] Failed to answer call:', error);
      // Ignore duplicate answer attempts or invalid state; do not auto-decline
      return;
    }
  }

  /**
   * Decline an incoming call
   */
  async declineCall(callId: string): Promise<void> {
    if (!this.currentCall || this.currentCall.id !== callId) {
      return;
    }

    console.log('[Calling] Declining call:', callId);

    // Send decline signal
    await this.sendCallSignal({
      type: 'decline-call',
      callId,
      from: this.localUsername,
      to: this.currentCall.peer,
      timestamp: Date.now()
    });

    // Update call status
    this.currentCall.status = 'declined';
    this.currentCall.endTime = Date.now();
    this.onCallStateChangeCallback?.(this.currentCall);

    // Cleanup
    this.cleanup();
  }

  /**
   * End the current call
   */
  async endCall(reason: string = 'user'): Promise<void> {
    if (!this.currentCall) {
      return;
    }

    console.log('[Calling] Ending call:', this.currentCall.id, 'reason:', reason);

    // Send end call signal
    if (this.currentCall.status !== 'ended') {
      await this.sendCallSignal({
        type: 'end-call',
        callId: this.currentCall.id,
        from: this.localUsername,
        to: this.currentCall.peer,
        data: { reason },
        timestamp: Date.now()
      });
    }

    // Update call status
    this.currentCall.status = 'ended';
    this.currentCall.endTime = Date.now();
    if (this.currentCall.startTime) {
      this.currentCall.duration = this.currentCall.endTime - this.currentCall.startTime;
    }
    if (this.currentCall) {
      this.currentCall.endReason = reason as CallState['endReason'];
    }
    this.onCallStateChangeCallback?.(this.currentCall);

    // Cleanup
    this.cleanup();
  }

  /**
   * Toggle mute for audio
   */
  toggleMute(): boolean {
    if (!this.localStream) return false;

    const audioTrack = this.localStream.getAudioTracks()[0];
    if (audioTrack) {
      audioTrack.enabled = !audioTrack.enabled;
      return !audioTrack.enabled; // Return muted state
    }
    return false;
  }

  /**
   * Toggle video on/off
   */
  toggleVideo(): boolean {
    if (!this.localStream) return false;

    const videoTrack = this.localStream.getVideoTracks()[0];
    if (videoTrack) {
      videoTrack.enabled = !videoTrack.enabled;
      return videoTrack.enabled; // Return video enabled state
    }
    return false;
  }

  /**
   * Switch between front and back camera (mobile)
   */
  async switchCamera(): Promise<void> {
    if (!this.localStream) return;

    const videoTrack = this.localStream.getVideoTracks()[0];
    if (!videoTrack) return;

    try {
      // Get current constraints
      const constraints = videoTrack.getConstraints();
      const currentFacingMode = constraints.facingMode;
      
      // Toggle between front and back camera
      const newFacingMode = currentFacingMode === 'user' ? 'environment' : 'user';
      
      // Stop current track
      videoTrack.stop();
      
      // Get new stream with different camera
      const newStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: newFacingMode },
        audio: false
      });
      
      const newVideoTrack = newStream.getVideoTracks()[0];
      
      // Replace track in peer connection
      if (this.peerConnection) {
        const sender = this.peerConnection.getSenders().find(s => 
          s.track && s.track.kind === 'video'
        );
        if (sender) {
          await sender.replaceTrack(newVideoTrack);
        }
      }
      
      // Replace track in local stream
      this.localStream.removeTrack(videoTrack);
      this.localStream.addTrack(newVideoTrack);
      
      // Notify callback
      this.onLocalStreamCallback?.(this.localStream);
      
    } catch (error) {
      console.error('[Calling] Failed to switch camera:', error);
    }
  }

  /**
   * Start screen sharing with optional source selection
   */
  async startScreenShare(selectedSource?: { id: string; name: string }): Promise<void> {
    if (!this.peerConnection) {
      throw new Error('No active call to share screen');
    }

    // SECURITY: Prevent screen sharing during ringing to avoid auto-answering
    if (this.currentCall?.status === 'ringing') {
      throw new Error('Cannot start screen sharing during ringing call. Please answer the call first.');
    }

    if (this.isScreenSharing) {
      throw new Error('Screen sharing is already active');
    }

    if (this.isTogglingScreenShare) {
      throw new Error('Screen sharing operation already in progress');
    }

    this.isTogglingScreenShare = true;

    try {
      // Check if we're in Electron and what APIs are exposed
      const electronApi = (window as any).electronAPI || null;
      const edgeApi = (window as any).edgeApi || null;
      const isElectron = !!electronApi || !!edgeApi;
      const getScreenSourcesFn = electronApi?.getScreenSources || edgeApi?.getScreenSources || null;

      console.log('[Calling] Screen share - isElectron:', isElectron);
      console.log('[Calling] electronAPI available:', !!electronApi);
      console.log('[Calling] edgeApi available:', !!edgeApi);
      console.log('[Calling] getScreenSources available:', !!getScreenSourcesFn);
      console.log('[Calling] electronAPI keys:', electronApi ? Object.keys(electronApi) : 'none');

      // Try to use Electron API if available, with fallback
      if (isElectron) {
        // Check if getScreenSources is available
        if (!getScreenSourcesFn) {
          console.warn('[Calling] getScreenSources not found in electronAPI');
          console.warn('[Calling] Available electronAPI functions:', Object.keys(electronApi || {}));

          // Test debug function and check actual API availability
          if (edgeApi?.debugElectronAPI) {
            const debugInfo = edgeApi.debugElectronAPI();
            console.log('[Calling] Debug info:', debugInfo);
          }

          // Check actual API availability in renderer context
          const hasGetScreenSources = typeof getScreenSourcesFn === 'function';
          const hasTestFunction = typeof edgeApi?.testFunction === 'function' || typeof electronApi?.testFunction === 'function';
          const electronAPIKeys = electronApi ? Object.keys(electronApi) : [];

          console.log('[Calling] Renderer context API check:', {
            hasGetScreenSources,
            hasTestFunction,
            electronAPIKeys
          });

          // Try to manually test the IPC call
          if (electronApi?.send) {
            console.log('[Calling] Attempting manual IPC test...');
            try {
              electronApi.send('test-screen-sources', {});
            } catch (e) {
              console.log('[Calling] Manual IPC test failed:', e);
            }
          }

          console.warn('[Calling] This usually means the app needs to be restarted after permission changes');
          console.log('[Calling] Attempting to use browser getDisplayMedia API as fallback');

          // Try to manually invoke the IPC call as a last resort
          try {
            if (electronApi?.send) {
              console.log('[Calling] Attempting manual IPC call for screen sources');
              // This won't work but will help us debug
            }
          } catch (e) {
            console.log('[Calling] Manual IPC attempt failed:', e);
          }
        }
      }

      if (isElectron && getScreenSourcesFn) {
        try {
          // Use Electron's desktopCapturer API
          console.log('[Calling] Using Electron desktopCapturer API');
          const sources = await getScreenSourcesFn();
          console.log('[Calling] Got screen sources:', sources?.length || 0);

          if (!sources || sources.length === 0) {
            throw new Error('No screen sources available');
          }

          // Use the selected source or default to first screen source
          let screenSource;
          if (selectedSource) {
            screenSource = sources.find((source: any) => source.id === selectedSource.id);
            if (!screenSource) {
              throw new Error(`Selected screen source "${selectedSource.name}" not found`);
            }
          } else {
            screenSource = sources.find((source: any) => source.id.startsWith('screen:')) || sources[0];
          }
          console.log('[Calling] Selected screen source:', screenSource.name);

          // Get user settings for video constraints
          const electronConstraints = screenSharingSettings.getElectronVideoConstraints();
          // Ensure mandatory object exists before assigning properties
          if (!electronConstraints.mandatory) {
            electronConstraints.mandatory = {};
          }
          electronConstraints.mandatory.chromeMediaSource = 'desktop';
          electronConstraints.mandatory.chromeMediaSourceId = screenSource.id;

          console.log('[Calling] Using Electron constraints:', JSON.stringify(electronConstraints, null, 2));

          this.screenStream = await navigator.mediaDevices.getUserMedia({
            audio: false,
            video: electronConstraints as MediaTrackConstraints
          });

          // Log actual stream properties for verification
          const videoTrack = this.screenStream.getVideoTracks()[0];
          if (videoTrack) {
            const actualSettings = videoTrack.getSettings();
            console.log('[Calling] Actual Electron stream settings:', actualSettings);
            console.log('[Calling] Resolution verification: requested vs actual:', {
              requested: electronConstraints.mandatory,
              actual: { width: actualSettings.width, height: actualSettings.height, frameRate: actualSettings.frameRate }
            });
          }
        } catch (electronError) {
          console.warn('[Calling] Electron screen capture failed, falling back to browser API:', electronError);
          // Fall through to browser API
          const videoConstraints = screenSharingSettings.getVideoConstraints();
          console.log('[Calling] Using browser constraints (fallback):', JSON.stringify(videoConstraints, null, 2));

          this.screenStream = await navigator.mediaDevices.getDisplayMedia({
            video: videoConstraints,
            audio: true
          });

          // Log actual stream properties for verification
          const videoTrack = this.screenStream.getVideoTracks()[0];
          if (videoTrack) {
            const actualSettings = videoTrack.getSettings();
            console.log('[Calling] Actual browser stream settings (fallback):', actualSettings);
            console.log('[Calling] Resolution verification (fallback): requested vs actual:', {
              requested: videoConstraints,
              actual: { width: actualSettings.width, height: actualSettings.height, frameRate: actualSettings.frameRate }
            });
          }
        }
      } else {
        // Fallback to standard getDisplayMedia for browsers
        console.log('[Calling] Using browser getDisplayMedia API');

        // Check if getDisplayMedia is available
        if (!navigator.mediaDevices?.getDisplayMedia) {
          throw new Error('Screen sharing not supported in this environment. Please restart the Electron app to enable screen sharing permissions.');
        }

        console.log('[Calling] Attempting browser screen capture...');

        // Get user settings for video constraints
        const videoConstraints = screenSharingSettings.getVideoConstraints();
        console.log('[Calling] Using browser constraints:', JSON.stringify(videoConstraints, null, 2));

        this.screenStream = await navigator.mediaDevices.getDisplayMedia({
          video: videoConstraints,
          audio: true // Include system audio if available
        });

        // Log actual stream properties for verification
        const videoTrack = this.screenStream.getVideoTracks()[0];
        if (videoTrack) {
          const actualSettings = videoTrack.getSettings();
          console.log('[Calling] Actual browser stream settings:', actualSettings);
          console.log('[Calling] Resolution verification: requested vs actual:', {
            requested: videoConstraints,
            actual: { width: actualSettings.width, height: actualSettings.height, frameRate: actualSettings.frameRate }
          });
        }
      }

      const videoTrack = this.screenStream.getVideoTracks()[0];

      // Handle screen share end (user clicks "Stop sharing" in browser)
      videoTrack.onended = () => {
        console.log('[Calling] Screen share track ended by user or system');
        this.stopScreenShare();
      };

      // Always add screen share as a separate track so both camera and screen can be sent
      // This ensures simultaneous screen shares are visible on both sides
      console.log('[Calling] Adding screen share track as additional sender');
      this.screenShareSender = this.peerConnection.addTrack(videoTrack, this.screenStream);

      // Renegotiate so the remote peer receives the additional m=video line
      console.log('[Calling] Triggering renegotiation for new screen share track');
      await this.renegotiateConnection();

      this.isScreenSharing = true;
      console.log('[Calling] Screen sharing started successfully');

      // Notify callback about screen stream - but don't replace the original local stream
      // Instead, create a new stream that includes the screen video track
      if (this.localStream) {
        const audioTracks = this.localStream.getAudioTracks();
        const combinedStream = new MediaStream([videoTrack, ...audioTracks]);
        this.onLocalStreamCallback?.(combinedStream);
      } else {
        this.onLocalStreamCallback?.(this.screenStream);
      }

    } catch (error) {
      console.error('[Calling] Failed to start screen sharing:', error);

      // Clean up any partial state
      if (this.screenStream) {
        this.screenStream.getTracks().forEach(track => track.stop());
        this.screenStream = null;
      }
      this.isScreenSharing = false;

      throw error;
    } finally {
      this.isTogglingScreenShare = false;
    }
  }

  /**
   * Stop screen sharing and return to camera
   */
  async stopScreenShare(): Promise<void> {
    if (!this.isScreenSharing && !this.screenStream) {
      return; // Nothing to stop
    }

    if (this.isTogglingScreenShare) {
      console.log('[Calling] Screen share stop already in progress, waiting...');
      // Wait for the current operation to complete
      let attempts = 0;
      while (this.isTogglingScreenShare && attempts < 50) { // Max 5 seconds
        await new Promise(resolve => setTimeout(resolve, 100));
        attempts++;
      }
      return;
    }

    this.isTogglingScreenShare = true;

    // Create local copies to avoid race conditions
    const screenStream = this.screenStream;
    const peerConnection = this.peerConnection;
    const localStream = this.localStream;

    try {
      // Stop local capture
      if (screenStream) {
        screenStream.getTracks().forEach(track => track.stop());
      }

      // If we added a dedicated sender for screen share, remove it from the connection
      if (peerConnection && this.screenShareSender) {
        try {
          console.log('[Calling] Removing screen share sender from peer connection');
          peerConnection.removeTrack(this.screenShareSender);
        } catch (removeErr) {
          console.warn('[Calling] Failed to remove screen share sender:', removeErr);
        }
      } else if (localStream && peerConnection) {
        // Fallback path for legacy replaceTrack mode: restore camera to the single video sender
        const cameraTrack = localStream.getVideoTracks()[0];
        if (cameraTrack) {
          const sender = peerConnection.getSenders().find(s => s.track && s.track.kind === 'video');
          if (sender) {
            try {
              console.log('[Calling] Restoring camera track after screen share');
              await sender.replaceTrack(cameraTrack);
            } catch (replaceErr) {
              console.warn('[Calling] Failed to restore camera track:', replaceErr);
            }
          }
        }
      }

      // Renegotiate so the remote peer stops receiving the screen share track
      await this.renegotiateConnection();

      console.log('[Calling] Screen sharing stopped successfully');

      // Restore local camera preview
      if (localStream) {
        this.onLocalStreamCallback?.(localStream);
      }

    } catch (error) {
      console.error('[Calling] Failed to stop screen sharing:', error);
      // Don't throw - we still want to clean up state
    } finally {
      // Always perform cleanup and release the toggle flag
      if (this.screenStream) {
        try {
          this.screenStream.getTracks().forEach(track => {
            if (track.readyState !== 'ended') {
              track.stop();
            }
          });
        } catch (e) {
          console.warn('[Calling] Error stopping screen stream tracks:', e);
        }
        this.screenStream = null;
      }
      this.isScreenSharing = false;
      this.screenShareSender = null;
      this.isTogglingScreenShare = false;

      console.log('[Calling] Screen sharing cleanup completed');
    }
  }

  /**
   * Check if screen sharing is active
   */
  getScreenSharingStatus(): boolean {
    return this.isScreenSharing;
  }

  /**
   * Renegotiate the peer connection (for track changes)
   */
  private async renegotiateConnection(): Promise<void> {
    if (!this.peerConnection || !this.currentCall) {
      return;
    }

    try {
      this.isRenegotiating = true;
      // Avoid glare and invalid states
      if (this.peerConnection.signalingState !== 'stable') {
        console.log('[Calling] Skipping renegotiation: signalingState=', this.peerConnection.signalingState);
        this.isRenegotiating = false;
        return;
      }

      console.log('[Calling] Creating new offer for renegotiation');
      const offer = await this.peerConnection.createOffer();
      await this.peerConnection.setLocalDescription(offer);

      // Send the new offer from either side (supports simultaneous screen shares)
      await this.sendCallSignal({
        type: 'offer',
        callId: this.currentCall.id,
        from: this.localUsername,
        to: this.currentCall.peer,
        data: offer,
        timestamp: Date.now(),
        isRenegotiation: true
      });

      // Start timeout waiting for renegotiation answer to avoid indefinite wait
      if (this.renegotiationTimeoutId) {
        clearTimeout(this.renegotiationTimeoutId);
        this.renegotiationTimeoutId = null;
      }
      this.renegotiationTimeoutId = setTimeout(async () => {
        if (!this.peerConnection) return;
        if (this.peerConnection.signalingState === 'have-local-offer') {
          try {
            console.warn('[Calling] Renegotiation timed out; rolling back local offer');
            // 'rollback' is a valid type per WebRTC spec for rolling back offers
            await this.peerConnection.setLocalDescription({ type: 'rollback' } as RTCSessionDescriptionInit);
          } catch (rbErr) {
            console.warn('[Calling] Rollback after renegotiation timeout failed (non-fatal):', rbErr);
          }
        }
        this.isRenegotiating = false;
      }, 10000);
    } catch (error) {
      console.error('[Calling] Failed to renegotiate connection:', error);
      this.isRenegotiating = false;
      // Don't throw - screen sharing might still work without renegotiation
    }
  }

  /**
   * Get available screen sources for selection
   */
  async getAvailableScreenSources(): Promise<Array<{ id: string; name: string; type: 'screen' | 'window' }>> {
    try {
      const electronApi = (window as any).electronAPI || null;
      const edgeApi = (window as any).edgeApi || null;
      const getScreenSourcesFn = electronApi?.getScreenSources || edgeApi?.getScreenSources || null;

      if (!getScreenSourcesFn) {
        throw new Error('Screen source selection not available in this environment');
      }

      const sources = await getScreenSourcesFn();
      if (!sources || sources.length === 0) {
        throw new Error('No screen sources available');
      }

      return sources.map((source: any) => ({
        id: source.id,
        name: source.name,
        type: source.id.startsWith('screen:') ? 'screen' as const : 'window' as const
      }));
    } catch (error) {
      console.error('[Calling] Failed to get screen sources:', error);
      throw error;
    }
  }

  /**
   * Get current call state
   */
  getCurrentCall(): CallState | null {
    return this.currentCall;
  }

  /**
   * Get remote screen stream
   */
  getRemoteScreenStream(): MediaStream | null {
    return this.remoteScreenStream;
  }

  /**
   * Get peer connection for quality monitoring
   */
  getPeerConnection(): RTCPeerConnection | null {
    return this.peerConnection;
  }

  /**
   * Set up local media stream
   */
  private async setupLocalMedia(callType: 'audio' | 'video'): Promise<void> {
    try {
      // First, check if devices are available
      if (callType === 'video') {
        try {
          const devices = await navigator.mediaDevices.enumerateDevices();
          const videoDevices = devices.filter(device => device.kind === 'videoinput');
          const audioDevices = devices.filter(device => device.kind === 'audioinput');

          console.log('[Calling] Available devices:', {
            video: videoDevices.length,
            audio: audioDevices.length
          });

          if (videoDevices.length === 0) {
            console.warn('[Calling] No video devices found, falling back to audio-only');
            callType = 'audio';
          }
        } catch (enumError) {
          console.warn('[Calling] Failed to enumerate devices, proceeding with original call type:', enumError);
        }
      }

      let video: boolean | MediaTrackConstraints = false;
      if (callType === 'video') {
        const base: MediaTrackConstraints = {
          width: { ideal: 1280, max: 1920 },
          height: { ideal: 720, max: 1080 },
          frameRate: { ideal: 30, max: 60 },
          facingMode: 'user'
        };
        if (this.preferredCameraDeviceId) {
          (base as any).deviceId = { exact: this.preferredCameraDeviceId };
        }
        video = base;
      }
      const constraints: MediaStreamConstraints = {
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true,
          sampleRate: 48000,
          channelCount: 1
        },
        video
      };

      this.localStream = await navigator.mediaDevices.getUserMedia(constraints);
      
      console.log('[Calling] Local media stream obtained:', {
        audio: this.localStream.getAudioTracks().length > 0,
        video: this.localStream.getVideoTracks().length > 0
      });

      // Notify callback
      this.onLocalStreamCallback?.(this.localStream);

    } catch (error: any) {
      console.error('[Calling] Failed to get user media:', error);

      // Provide more specific error messages based on error type
      let errorMessage = 'Failed to access camera/microphone';
      if (error.name === 'NotFoundError') {
        errorMessage = callType === 'video' ?
          'No camera found. Please connect a camera or try audio-only mode.' :
          'No microphone found. Please connect a microphone to make calls.';
      } else if (error.name === 'NotAllowedError') {
        errorMessage = 'Camera/microphone access denied. Please click the camera/microphone icon in your browser\'s address bar and allow access.';
      } else if (error.name === 'NotReadableError') {
        errorMessage = 'Camera/microphone is already in use. Please close other applications using your camera/microphone and try again.';
      } else if (error.name === 'OverconstrainedError') {
        errorMessage = 'Camera/microphone settings are not supported. Trying with default settings...';
      } else if (error.name === 'AbortError') {
        errorMessage = 'Camera/microphone access was interrupted. Please try again.';
      }

      // Fallback: if video requested but not available, try audio-only and continue the call
      if (callType === 'video') {
        try {
          console.warn('[Calling] Video device not found or inaccessible. Falling back to audio-only.');
          const audioOnlyConstraints: MediaStreamConstraints = {
            audio: {
              echoCancellation: true,
              noiseSuppression: true,
              autoGainControl: true,
              sampleRate: 48000,
              channelCount: 1
            },
            video: false
          };
          this.localStream = await navigator.mediaDevices.getUserMedia(audioOnlyConstraints);
          console.log('[Calling] Local media stream obtained (audio-only fallback):', {
            audio: this.localStream.getAudioTracks().length > 0,
            video: this.localStream.getVideoTracks().length > 0
          });
          // Notify callback
          this.onLocalStreamCallback?.(this.localStream);
          return; // Continue without throwing
        } catch (fallbackError: any) {
          console.error('[Calling] Audio-only fallback failed:', fallbackError);
          // Update error message for audio fallback failure
          if (fallbackError.name === 'NotFoundError') {
            errorMessage = 'No camera or microphone found. Please check your device connections.';
          } else if (fallbackError.name === 'NotAllowedError') {
            errorMessage = 'Microphone access denied. Please allow permissions to make calls.';
          }
        }
      }
      throw new Error(errorMessage);
    }
  }

  /**
   * Clear remote screen stream and notify callback
   */
  private clearRemoteScreenStream(): void {
    if (this.remoteScreenStream) {
      console.log('[Calling] Clearing remote screen stream');
      this.remoteScreenStream = null;
      this.onRemoteScreenStreamCallback?.(null);
    }
  }

  /**
   * Clear remote camera stream and notify callback
   */
  private clearRemoteStream(): void {
    if (this.remoteStream) {
      console.log('[Calling] Clearing remote camera stream');
      this.remoteStream = null;
      this.onRemoteStreamCallback?.(null);
    }
  }

  /**
   * Detect if a video track is from screen sharing based on its characteristics
   */
  private isScreenShareTrack(settings: MediaTrackSettings): boolean {
    // Screen shares typically have:
    // 1. No facingMode (cameras have 'user' or 'environment')
    // 2. Larger resolutions (usually > 1280x720)
    // 3. Different aspect ratios than typical cameras

    const hasNoFacingMode = !settings.facingMode;
    const isLargeResolution = (settings.width || 0) >= 1280 || (settings.height || 0) >= 720;
    const isWideAspectRatio = settings.width && settings.height ?
      (settings.width / settings.height) > 1.5 : false;
    // Type-safe device ID check
    const deviceId = (settings as MediaTrackSettings & { deviceId?: string }).deviceId;
    const isDesktopDeviceId =
      typeof deviceId === 'string' &&
      (deviceId.startsWith('screen:') || deviceId.startsWith('window:'));

    // Screen shares usually don't have facingMode and tend to be larger
    const isLikelyScreenShare = (hasNoFacingMode && (isLargeResolution || isWideAspectRatio)) || isDesktopDeviceId;

    console.log('[Calling] Screen share detection:', {
      hasNoFacingMode,
      isLargeResolution,
      isWideAspectRatio,
      isLikelyScreenShare,
      settings
    });

    return isLikelyScreenShare;
  }

  /**
   * Create WebRTC peer connection
   */
  private async createPeerConnection(): Promise<void> {
    this.peerConnection = new RTCPeerConnection(this.rtcConfig);

    // Handle remote stream
    this.peerConnection.ontrack = (event) => {
      console.log('[Calling] Received remote track:', event.track.kind, 'from stream:', event.streams[0]?.id);

      // Handle empty event.streams by creating a new MediaStream
      let stream: MediaStream;
      if (event.streams && event.streams[0]) {
        stream = event.streams[0];
      } else {
        // Create new MediaStream from the track
        stream = new MediaStream([event.track]);
        console.log('[Calling] Created new MediaStream from track:', event.track.kind);
      }

      const videoTrack = stream.getVideoTracks()[0];

      // Detect if this is a screen share based on track settings
      if (videoTrack) {
        const settings = videoTrack.getSettings();
        const isScreenShare = this.isScreenShareTrack(settings);

        console.log('[Calling] Track analysis:', {
          isScreenShare,
          width: settings.width,
          height: settings.height,
          frameRate: settings.frameRate,
          facingMode: settings.facingMode
        });

        if (isScreenShare) {
          console.log('[Calling] Detected remote screen share stream');

          // Clear previous screen stream if exists
          if (this.remoteScreenStream) {
            this.clearRemoteScreenStream();
          }

          this.remoteScreenStream = stream;

          // Attach ended handlers to clear screen stream
          videoTrack.onended = () => {
            console.log('[Calling] Remote screen share track ended');
            this.clearRemoteScreenStream();
          };
          const handleRemove = () => {
            console.log('[Calling] Remote screen share track removed');
            this.clearRemoteScreenStream();
          };
          try { (stream as any).onremovetrack = handleRemove; } catch {}

          this.onRemoteScreenStreamCallback?.(this.remoteScreenStream);
        } else {
          console.log('[Calling] Detected remote camera stream');

          // Clear previous camera stream if exists
          if (this.remoteStream) {
            this.clearRemoteStream();
          }

          this.remoteStream = stream;

          // Attach ended handlers to clear camera stream
          videoTrack.onended = () => {
            console.log('[Calling] Remote camera track ended');
            this.clearRemoteStream();
          };
          const handleRemoveCam = () => {
            console.log('[Calling] Remote camera track removed');
            this.clearRemoteStream();
          };
          try { (stream as any).onremovetrack = handleRemoveCam; } catch {}

          this.onRemoteStreamCallback?.(this.remoteStream);
        }
      } else {
        // Audio-only or fallback
        console.log('[Calling] Audio-only or fallback stream');

        if (this.remoteStream) {
          this.clearRemoteStream();
        }

        this.remoteStream = stream;

        // Attach ended handlers for audio tracks
        const audioTrack = stream.getAudioTracks()[0];
        if (audioTrack) {
          audioTrack.onended = () => {
            console.log('[Calling] Remote audio track ended');
            this.clearRemoteStream();
          };
        }

        this.onRemoteStreamCallback?.(this.remoteStream);
      }
    };

    // Handle connection state changes
    this.peerConnection.onconnectionstatechange = () => {
      const state = this.peerConnection?.connectionState;
      console.log('[Calling] Connection state changed:', state);

      if (this.currentCall) {
        switch (state) {
          case 'connected':
            this.currentCall.status = 'connected';
            if (this.callTimeoutId) {
              clearTimeout(this.callTimeoutId);
              this.callTimeoutId = null;
            }
            // Clear any pending ICE failure timeout since we're connected
            if (this.iceConnectionFailureTimeoutId) {
              clearTimeout(this.iceConnectionFailureTimeoutId);
              this.iceConnectionFailureTimeoutId = null;
            }
            if (this.renegotiationTimeoutId) {
              clearTimeout(this.renegotiationTimeoutId);
              this.renegotiationTimeoutId = null;
            }
            // Clear renegotiation flag if connection is restored
            if (this.isRenegotiating) {
              console.log('[Calling] ICE connection restored after renegotiation');
              this.isRenegotiating = false;
            }
            break;
          case 'disconnected':
            // During renegotiation, temporary disconnections are normal
            if (this.isRenegotiating) {
              console.log('[Calling] ICE disconnected during renegotiation, waiting for reconnection...');
              // Set a timeout to end the call if it doesn't reconnect within a reasonable time
              if (this.iceConnectionFailureTimeoutId) {
                clearTimeout(this.iceConnectionFailureTimeoutId);
              }
              this.iceConnectionFailureTimeoutId = setTimeout(() => {
                if (this.currentCall?.status !== 'ended' && this.peerConnection?.iceConnectionState === 'disconnected') {
                  console.log('[Calling] ICE connection failed to recover after renegotiation');
                  this.endCall('connection-lost');
                }
              }, 10000); // 10 second timeout
            } else if (this.currentCall.status !== 'ended') {
              // Not during renegotiation, end call immediately
              this.endCall('connection-lost');
            }
            break;
          case 'failed':
          case 'closed':
            if (this.currentCall.status !== 'ended') {
              this.endCall('connection-lost');
            }
            break;
        }
        this.onCallStateChangeCallback?.(this.currentCall);
      }
    };

    // Handle ICE candidates
    this.peerConnection.onicecandidate = async (event) => {
      if (event.candidate && this.currentCall) {
        await this.sendCallSignal({
          type: 'ice-candidate',
          callId: this.currentCall.id,
          from: this.localUsername,
          to: this.currentCall.peer,
          data: event.candidate,
          timestamp: Date.now()
        });
      }
    };

    // Handle ICE connection state
    this.peerConnection.oniceconnectionstatechange = () => {
      const state = this.peerConnection?.iceConnectionState;
      console.log('[Calling] ICE connection state:', state);
      if (this.currentCall) {
        if (state === 'connected' || state === 'completed') {
          // Some platforms only update iceConnectionState; mirror to overall call status
          if (this.currentCall.status !== 'connected') {
            this.currentCall.status = 'connected';
            this.onCallStateChangeCallback?.(this.currentCall);
          }
        } else if (state === 'checking' && this.currentCall.status === 'ringing') {
          // Move from ringing to connecting once ICE starts
          this.currentCall.status = 'connecting';
          this.onCallStateChangeCallback?.(this.currentCall);
        }
      }
    };
  }

  /**
   * Send encrypted call signal through existing secure channel
   */
  private async sendCallSignal(signal: CallSignal): Promise<void> {
    try {
      // Encrypt call signal using Signal Protocol
      const signalData = {
        messageId: this.generateCallId(),
        from: this.localUsername,
        to: signal.to,
        content: JSON.stringify(signal),
        timestamp: Date.now(),
        messageType: 'signal-protocol',
        type: 'call-signal'
      };

      // Use Signal Protocol encryption
      const encryptedMessage = await (window as any).edgeApi?.encrypt?.({
        fromUsername: this.localUsername,
        toUsername: signal.to,
        plaintext: JSON.stringify(signalData)
      });

      if (!encryptedMessage?.ciphertextBase64) {
        throw new Error('Failed to encrypt call signal');
      }

      // Send through WebSocket
      const payload = {
        type: SignalType.ENCRYPTED_MESSAGE,
        to: signal.to,
        encryptedPayload: {
          from: this.localUsername,
          to: signal.to,
          content: encryptedMessage.ciphertextBase64,
          messageId: signalData.messageId,
          type: encryptedMessage.type,
          sessionId: encryptedMessage.sessionId
        }
      };

      websocketClient.send(JSON.stringify(payload));
      console.log('[Calling] Encrypted call signal sent:', signal.type);

    } catch (error) {
      console.error('[Calling] Failed to send call signal:', error);
      throw error;
    }
  }

  /**
   * Handle incoming encrypted call signals
   */
  private setupSignalHandlers(): void {
    // Listen for call signals through the encrypted message handler
    window.addEventListener('call-signal', ((event: CustomEvent) => {
      const signal = event.detail as CallSignal;
      this.handleCallSignal(signal);
    }) as EventListener);
  }

  /**
   * Handle incoming call signals
   */
  private async handleCallSignal(signal: CallSignal): Promise<void> {
    console.log('[Calling] Received call signal:', signal.type, signal.callId);

    try {
      switch (signal.type) {
        case 'offer':
          await this.handleCallOffer(signal);
          break;
        case 'answer':
          await this.handleCallAnswer(signal);
          break;
        case 'ice-candidate':
          await this.handleIceCandidate(signal);
          break;
        case 'decline-call':
          this.handleCallDeclined(signal);
          break;
        case 'end-call':
          this.handleCallEnded(signal);
          break;
      }
    } catch (error) {
      console.error('[Calling] Error handling call signal:', error);
    }
  }

  /**
   * Handle incoming call offer
   */
  private async handleCallOffer(signal: CallSignal): Promise<void> {
    if (this.currentCall) {
      // Check if this is a renegotiation offer for the current call
      if (signal.isRenegotiation && signal.callId === this.currentCall.id) {
        console.log('[Calling] Handling renegotiation offer');

        // SECURITY: Only process renegotiation if call has been manually answered
        // Prevent automatic answering during renegotiation (e.g., when screen sharing starts)
        if (this.currentCall.status === 'ringing') {
          console.log('[Calling] Ignoring renegotiation offer - call not yet answered by user');
          return;
        }

        // Process the renegotiation offer only for answered calls
        try {
          if (!this.peerConnection) return;

          // Handle glare by rolling back local offer if present
          if (this.peerConnection.signalingState === 'have-local-offer') {
            try {
              console.log('[Calling] Rolling back local offer to resolve glare');
              // 'rollback' is a valid type per WebRTC spec for rolling back offers
              await this.peerConnection.setLocalDescription({ type: 'rollback' } as RTCSessionDescriptionInit);
            } catch (rbErr) {
              console.warn('[Calling] Rollback failed (non-fatal):', rbErr);
            }
          }

          await this.peerConnection.setRemoteDescription(signal.data);

          // Create and send answer for renegotiation
          const answer = await this.peerConnection.createAnswer();
          await this.peerConnection.setLocalDescription(answer);
          await this.sendCallSignal({
            type: 'answer',
            callId: signal.callId,
            from: this.localUsername,
            to: signal.from,
            data: answer,
            timestamp: Date.now(),
            isRenegotiation: true
          });
        } catch (error) {
          console.error('[Calling] Failed to handle renegotiation offer:', error);
        }
        return;
      }

      // Already in a call with different ID, decline automatically
      await this.sendCallSignal({
        type: 'decline-call',
        callId: signal.callId,
        from: this.localUsername,
        to: signal.from,
        data: { reason: 'busy' },
        timestamp: Date.now()
      });
      return;
    }

    // Determine call type from SDP
    const sdp = signal.data as RTCSessionDescriptionInit;
    const hasVideo = sdp.sdp?.includes('m=video') || false;
    const callType = hasVideo ? 'video' : 'audio';

    // Create incoming call state
    this.currentCall = {
      id: signal.callId,
      type: callType,
      direction: 'incoming',
      status: 'ringing',
      peer: signal.from,
      startTime: Date.now()
    };

    // Create peer connection
    await this.createPeerConnection();
    
    // Set remote description
    await this.peerConnection!.setRemoteDescription(sdp);

    // Notify about incoming call
    this.onIncomingCallCallback?.(this.currentCall);
    this.onCallStateChangeCallback?.(this.currentCall);

    // Set ring timeout
    this.callTimeoutId = setTimeout(() => {
      if (this.currentCall?.status === 'ringing') {
        this.currentCall.status = 'missed';
        this.onCallStateChangeCallback?.(this.currentCall);
        // Notify caller so their UI ends promptly
        this.sendCallSignal({
          type: 'end-call',
          callId: this.currentCall.id,
          from: this.localUsername,
          to: this.currentCall.peer,
          data: { reason: 'missed' },
          timestamp: Date.now()
        }).catch((e) => console.warn('[Calling] Failed to notify caller of missed call:', e));
        this.cleanup();
      }
    }, this.RING_TIMEOUT);
  }

  /**
   * Handle call answer
   */
  private async handleCallAnswer(signal: CallSignal): Promise<void> {
    if (!this.currentCall || this.currentCall.id !== signal.callId) {
      return;
    }

    // Check if this is a renegotiation answer
    if (signal.isRenegotiation) {
      console.log('[Calling] Handling renegotiation answer');
      if (this.peerConnection) {
        try {
          // For renegotiation, the data is directly the SDP
          const sdp = signal.data as RTCSessionDescriptionInit;
          await this.peerConnection.setRemoteDescription(sdp);
          console.log('[Calling] Renegotiation answer processed successfully');

          // Clear renegotiation flag since we successfully processed the answer
          this.isRenegotiating = false;
          if (this.renegotiationTimeoutId) {
            clearTimeout(this.renegotiationTimeoutId);
            this.renegotiationTimeoutId = null;
          }
        } catch (error) {
          console.error('[Calling] Failed to process renegotiation answer:', error);
        }
      }
      return;
    }

    // Handle normal call answer
    const answerData = signal.data as { sdp: RTCSessionDescriptionInit; accepted: boolean };

    if (answerData.accepted && this.peerConnection) {
      await this.peerConnection.setRemoteDescription(answerData.sdp);

      this.currentCall.status = 'connecting';
      this.onCallStateChangeCallback?.(this.currentCall);
    } else {
      // Call was declined
      this.currentCall.status = 'declined';
      this.currentCall.endTime = Date.now();
      this.onCallStateChangeCallback?.(this.currentCall);
      this.cleanup();
    }
  }

  /**
   * Handle ICE candidate
   */
  private async handleIceCandidate(signal: CallSignal): Promise<void> {
    if (!this.currentCall || this.currentCall.id !== signal.callId || !this.peerConnection) {
      return;
    }

    const candidate = signal.data as RTCIceCandidate;
    await this.peerConnection.addIceCandidate(candidate);
  }

  /**
   * Handle call declined
   */
  private handleCallDeclined(signal: CallSignal): void {
    if (!this.currentCall || this.currentCall.id !== signal.callId) {
      return;
    }

    this.currentCall.status = 'declined';
    this.currentCall.endTime = Date.now();
    this.onCallStateChangeCallback?.(this.currentCall);
    this.cleanup();
  }

  /**
   * Handle call ended
   */
  private handleCallEnded(signal: CallSignal): void {
    if (!this.currentCall || this.currentCall.id !== signal.callId) {
      return;
    }

    this.currentCall.status = 'ended';
    this.currentCall.endTime = Date.now();
    if (this.currentCall.startTime) {
      this.currentCall.duration = this.currentCall.endTime - this.currentCall.startTime;
    }
    this.onCallStateChangeCallback?.(this.currentCall);
    this.cleanup();
  }

  /**
   * Generate unique call ID
   */
  private generateCallId(): string {
    return `call_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
  }

  /**
   * Cleanup call resources
   */
  private cleanup(): void {
    console.log('[Calling] Cleaning up call resources');

    // Clear timeouts
    if (this.callTimeoutId) {
      clearTimeout(this.callTimeoutId);
      this.callTimeoutId = null;
    }
    if (this.iceConnectionFailureTimeoutId) {
      clearTimeout(this.iceConnectionFailureTimeoutId);
      this.iceConnectionFailureTimeoutId = null;
    }
    if (this.renegotiationTimeoutId) {
      clearTimeout(this.renegotiationTimeoutId);
      this.renegotiationTimeoutId = null;
    }

    // Stop local stream
    if (this.localStream) {
      this.localStream.getTracks().forEach(track => track.stop());
      this.localStream = null;
    }

    // Stop screen stream
    if (this.screenStream) {
      this.screenStream.getTracks().forEach(track => track.stop());
      this.screenStream = null;
    }

    // Reset screen share sender
    this.screenShareSender = null;

    // Close peer connection
    if (this.peerConnection) {
      this.peerConnection.close();
      this.peerConnection = null;
    }

    // Clear remote streams
    this.remoteStream = null;
    this.remoteScreenStream = null;

    // Reset screen sharing state
    this.isScreenSharing = false;
    this.isTogglingScreenShare = false;

    // Clear current call immediately to allow prompt re-calling
    this.currentCall = null;
  }

  /**
   * Set callback for incoming calls
   */
  onIncomingCall(callback: (call: CallState) => void): void {
    this.onIncomingCallCallback = callback;
  }

  /**
   * Set callback for call state changes
   */
  onCallStateChange(callback: (call: CallState) => void): void {
    this.onCallStateChangeCallback = callback;
  }

  /**
   * Set callback for remote stream
   */
  onRemoteStream(callback: (stream: MediaStream | null) => void): void {
    this.onRemoteStreamCallback = callback;
  }

  /**
   * Set callback for remote screen stream
   */
  onRemoteScreenStream(callback: (stream: MediaStream | null) => void): void {
    this.onRemoteScreenStreamCallback = callback;
  }

  /**
   * Set callback for local stream
   */
  onLocalStream(callback: (stream: MediaStream) => void): void {
    this.onLocalStreamCallback = callback;
  }

  /**
   * List available video input devices
   */
  static async getVideoInputDevices(): Promise<MediaDeviceInfo[]> {
    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      return devices.filter(d => d.kind === 'videoinput');
    } catch (e) {
      console.warn('[Calling] enumerateDevices failed:', e);
      return [];
    }
  }

  /**
   * Get preferred camera device id
   */
  getPreferredCameraDeviceId(): string | null {
    return this.preferredCameraDeviceId;
  }

  /**
   * Set preferred camera and apply immediately if possible
   */
  async setPreferredCameraDeviceId(deviceId: string): Promise<void> {
    this.preferredCameraDeviceId = deviceId || null;
    try { localStorage.setItem('preferred_camera_deviceId_v1', deviceId || ''); } catch {}

    // If there is an active connection, try to replace the video track
    if (this.peerConnection) {
      try {
        const newStream = await navigator.mediaDevices.getUserMedia({
          video: { deviceId: { exact: deviceId } },
          audio: false
        });
        const newVideo = newStream.getVideoTracks()[0];
        if (newVideo) {
          const sender = this.peerConnection.getSenders().find(s => s.track && s.track.kind === 'video');
          if (sender) {
            await sender.replaceTrack(newVideo);
          }
          if (!this.localStream) {
            this.localStream = new MediaStream([newVideo]);
          } else {
            const old = this.localStream.getVideoTracks()[0];
            if (old) { old.stop(); this.localStream.removeTrack(old); }
            this.localStream.addTrack(newVideo);
          }
          this.onLocalStreamCallback?.(this.localStream);
        }
      } catch (e) {
        console.error('[Calling] Failed to apply selected camera:', e);
      }
    }
  }

  /**
   * Destroy calling service
   */
  destroy(): void {
    console.log('[Calling] Destroying calling service');
    
    if (this.currentCall) {
      this.endCall('shutdown');
    }
    
    this.cleanup();
  }
}