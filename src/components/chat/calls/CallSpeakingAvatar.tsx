import { memo, useCallback, useSyncExternalStore, type ComponentProps, type CSSProperties } from 'react';
import { UserAvatar } from '../../ui/UserAvatar';
import { getCallSpeakerLevel, subscribeCallSpeakerLevel } from '../../../lib/ui/call-speaker-level';
import { cn } from '../../../lib/utils/shared-utils';

export const CallSpeakingAvatar = memo(function CallSpeakingAvatar({
    callId,
    active,
    username,
    size = 'xl',
    className,
}: {
    callId: string;
    active: boolean;
    username: string;
    size?: ComponentProps<typeof UserAvatar>['size'];
    className?: string;
}) {
    const snapshot = useCallback(() => active ? getCallSpeakerLevel(callId) : 0, [active, callId]);
    const level = useSyncExternalStore(subscribeCallSpeakerLevel, snapshot, snapshot);
    return (
        <div
            className={cn('qorc-speaking-avatar', className)}
            data-speaking={level > 0.05 ? 'true' : 'false'}
            style={{ '--qorc-speaking-level': level } as CSSProperties}
        >
            <span className="qorc-speaking-ring" aria-hidden="true" />
            <UserAvatar username={username} size={size} className="relative z-[1]" />
        </div>
    );
});
