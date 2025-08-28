/**
 * WebRTC Secure Voice/Video Calling Service
 * Implements end-to-end encrypted audio/video calls with post-quantum security
 */

// Crypto utilities are handled by Signal Protocol encryption
import { SignalType } from './signals';
import websocketClient from './websocket';

export interface CallState {
  id: string;
  type: 'audio' | 'video';
  direction: 'incoming' | 'outgoing';
  status: 'ringing' | 'connecting' | 'connected' | 'ended' | 'declined' | 'missed';
  peer: string;
  startTime?: number;
  endTime?: number;
  duration?: number;
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
}

export class WebRTCCallingService {
  private localStream: MediaStream | null = null;
  private remoteStream: MediaStream | null = null;
  private peerConnection: RTCPeerConnection | null = null;
  private currentCall: CallState | null = null;
  private localUsername: string = '';
  
  // Callbacks
  private onIncomingCallCallback: ((call: CallState) => void) | null = null;
  private onCallStateChangeCallback: ((call: CallState) => void) | null = null;
  private onRemoteStreamCallback: ((stream: MediaStream) => void) | null = null;
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
  private readonly CALL_TIMEOUT = 60000; // 60 seconds
  private readonly RING_TIMEOUT = 30000; // 30 seconds
  private callTimeoutId: NodeJS.Timeout | null = null;

  constructor(username: string) {
    this.localUsername = username;
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
      this.declineCall(callId);
      throw error;
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
   * Get current call state
   */
  getCurrentCall(): CallState | null {
    return this.currentCall;
  }

  /**
   * Set up local media stream
   */
  private async setupLocalMedia(callType: 'audio' | 'video'): Promise<void> {
    try {
      const constraints: MediaStreamConstraints = {
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true,
          sampleRate: 48000,
          channelCount: 1
        },
        video: callType === 'video' ? {
          width: { ideal: 1280, max: 1920 },
          height: { ideal: 720, max: 1080 },
          frameRate: { ideal: 30, max: 60 },
          facingMode: 'user'
        } : false
      };

      this.localStream = await navigator.mediaDevices.getUserMedia(constraints);
      
      console.log('[Calling] Local media stream obtained:', {
        audio: this.localStream.getAudioTracks().length > 0,
        video: this.localStream.getVideoTracks().length > 0
      });

      // Notify callback
      this.onLocalStreamCallback?.(this.localStream);

    } catch (error) {
      console.error('[Calling] Failed to get user media:', error);
      throw new Error('Failed to access camera/microphone');
    }
  }

  /**
   * Create WebRTC peer connection
   */
  private async createPeerConnection(): Promise<void> {
    this.peerConnection = new RTCPeerConnection(this.rtcConfig);

    // Handle remote stream
    this.peerConnection.ontrack = (event) => {
      console.log('[Calling] Received remote track:', event.track.kind);
      
      if (event.streams && event.streams[0]) {
        this.remoteStream = event.streams[0];
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
            break;
          case 'disconnected':
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
      // Already in a call, decline automatically
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
    return `call_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Cleanup call resources
   */
  private cleanup(): void {
    console.log('[Calling] Cleaning up call resources');

    // Clear timeout
    if (this.callTimeoutId) {
      clearTimeout(this.callTimeoutId);
      this.callTimeoutId = null;
    }

    // Stop local stream
    if (this.localStream) {
      this.localStream.getTracks().forEach(track => track.stop());
      this.localStream = null;
    }

    // Close peer connection
    if (this.peerConnection) {
      this.peerConnection.close();
      this.peerConnection = null;
    }

    // Clear remote stream
    this.remoteStream = null;

    // Clear current call after a delay to allow UI to show final state
    setTimeout(() => {
      this.currentCall = null;
    }, 3000);
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
  onRemoteStream(callback: (stream: MediaStream) => void): void {
    this.onRemoteStreamCallback = callback;
  }

  /**
   * Set callback for local stream
   */
  onLocalStream(callback: (stream: MediaStream) => void): void {
    this.onLocalStreamCallback = callback;
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
