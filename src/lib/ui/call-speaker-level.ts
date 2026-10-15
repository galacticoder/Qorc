const listeners = new Set<() => void>();
let session: string | null = null;
let level = 0;
let pendingLevel = 0;
let publishTimer: ReturnType<typeof setTimeout> | null = null;
let silenceTimer: ReturnType<typeof setTimeout> | null = null;

function publish(): void {
    if (publishTimer) clearTimeout(publishTimer);
    publishTimer = null;
    if (level === pendingLevel) return;
    level = pendingLevel;
    for (const listener of listeners) listener();
}

export function startCallSpeakerLevel(callId: string): void {
    if (session === callId) return;
    clearCallSpeakerLevel();
    session = callId;
}

export function updateCallSpeakerLevel(callId: string, rms: number): void {
    if (session !== callId) return;
    pendingLevel = Number.isFinite(rms) && rms > 0
        ? Math.max(0, Math.min(1, (20 * Math.log10(rms) + 50) / 40))
        : 0;
    if (!publishTimer) publishTimer = setTimeout(publish, 60);
    if (silenceTimer) clearTimeout(silenceTimer);
    silenceTimer = setTimeout(() => { pendingLevel = 0; publish(); }, 200);
}

export function clearCallSpeakerLevel(callId?: string): void {
    if (callId && session !== callId) return;
    if (publishTimer) clearTimeout(publishTimer);
    if (silenceTimer) clearTimeout(silenceTimer);
    publishTimer = null;
    silenceTimer = null;
    session = null;
    pendingLevel = 0;
    publish();
}

export function subscribeCallSpeakerLevel(listener: () => void): () => void {
    listeners.add(listener);
    return () => { listeners.delete(listener); };
}

export function getCallSpeakerLevel(callId: string): number {
    return session === callId ? level : 0;
}
