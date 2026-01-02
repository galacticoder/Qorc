import { useCallback, useRef } from 'react';

// Rate limiting hook for events
export function useRateLimiter(windowMs: number, maxEvents: number) {
    const rateBucketsRef = useRef<Map<string, { windowStart: number; count: number }>>(new Map());

    const allowEvent = useCallback((key: string): boolean => {
        const now = Date.now();
        const bucket = rateBucketsRef.current.get(key) ?? { windowStart: now, count: 0 };

        if (now - bucket.windowStart > windowMs) {
            bucket.windowStart = now;
            bucket.count = 0;
        }

        bucket.count += 1;
        rateBucketsRef.current.set(key, bucket);

        return bucket.count <= maxEvents;
    }, [windowMs, maxEvents]);

    const resetLimit = useCallback((key: string) => {
        rateBucketsRef.current.delete(key);
    }, []);

    return { allowEvent, resetLimit };
}
