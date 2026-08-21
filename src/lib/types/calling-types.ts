export interface CallState {
    id: string;
    type: 'audio' | 'video';
    direction: 'incoming' | 'outgoing';
    status: 'ringing' | 'connecting' | 'connected' | 'ended' | 'declined' | 'missed';
    peer: string;
    startTime?: number;
    endTime?: number;
    duration?: number;
    endReason?: 'user' | 'remote' | 'timeout' | 'failed' | 'declined' | 'shutdown' | 'blocked';
}

interface CallSignalBase {
    callId: string;
    from: string;
    to: string;
    timestamp: number;
}

export type LocalCallEndReason = 'user' | 'timeout' | 'failed' | 'shutdown' | 'blocked';

export type CallSignal =
    | (CallSignalBase & {
        type: 'offer';
        data: { callType: 'audio' | 'video' };
    })
    | (CallSignalBase & { type: 'answer' })
    | (CallSignalBase & { type: 'decline-call' })
    | (CallSignalBase & { type: 'end-call' })
    | (CallSignalBase & {
        type: 'screen-share-start';
        data: { streamId: string };
    })
    | (CallSignalBase & {
        type: 'screen-share-ready';
        data: { streamId: string };
    })
    | (CallSignalBase & {
        type: 'screen-share-stop';
        data: { streamId: string };
    });
