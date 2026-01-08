import { PQNoiseSession } from "../transport/pq-noise-session";

export interface CallState {
    id: string;
    type: 'audio' | 'video';
    direction: 'incoming' | 'outgoing';
    status: 'ringing' | 'connecting' | 'connected' | 'ended' | 'declined' | 'missed';
    peer: string;
    startTime?: number;
    endTime?: number;
    duration?: number;
    endReason?: 'user' | 'remote' | 'timeout' | 'failed' | 'declined' | 'shutdown';
}

export interface CallOffer {
    callId: string;
    callType: 'audio' | 'video';
    from: string;
    timestamp: number;
}

export interface CallAnswer {
    callId: string;
    accepted: boolean;
    from: string;
}

export interface CallSignal {
    type: 'offer' | 'answer' | 'decline-call' | 'end-call' | 'connected' | 'ice-candidate' |
    'renegotiate' | 'screen-share-start' | 'screen-share-stop';
    callId: string;
    from: string;
    to: string;
    data?: any;
    timestamp: number;
    pqSignature?: {
        signature: string;
        publicKey: string;
    };
}

export interface MediaEncryptionContext {
    session: PQNoiseSession;
    audioKey: Uint8Array;
    videoKey: Uint8Array;
    screenKey: Uint8Array;
    frameCounter: bigint;
}