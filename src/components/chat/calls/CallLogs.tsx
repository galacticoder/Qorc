import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Phone, Video, Search, Clock, Trash2, MoreVertical, ShieldOff } from 'lucide-react';
import { Popover, PopoverContent, PopoverTrigger } from '../../ui/popover';
import { Input } from '../../ui/input';
import { Button } from '../../ui/button';
import { ScrollArea } from '../../ui/scroll-area';
import { UserAvatar } from '../../ui/UserAvatar';
import { useCallHistory, type CallLogEntry } from '../../../contexts/CallHistoryContext';
import { useDisplayUsername } from '../../../hooks/database/useDisplayUsername';
import { useBlockStatus } from '../../../hooks/useBlockStatus';
import { formatRelativeAge, formatCallDurationSeconds } from '../../../lib/utils/date-utils';
import { NEAR_BOTTOM_THRESHOLD, SCROLL_THRESHOLD } from '../../../lib/constants';

interface CallLogItemProps {
    readonly log: CallLogEntry;
    readonly index: number;
    readonly totalLogs: number;
    readonly getDisplayUsername?: (username: string) => Promise<string>;
    readonly onDelete: (id: string) => void;
}

const CallLogItem: React.FC<CallLogItemProps> = React.memo(({
    log,
    index,
    totalLogs,
    onDelete
}) => {
    const displayName = useDisplayUsername({
        username: log.peerUsername
    });

    const isBlocked = useBlockStatus(log.peerUsername, { load: false });

    return (
        <React.Fragment>
            <div className="p-3 flex items-center gap-3 hover:bg-accent/50 rounded-lg transition-colors select-none">
                <UserAvatar
                    username={log.peerUsername}
                    size="md"
                />

                <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-2 overflow-hidden">
                            <h3 className="font-semibold truncate text-foreground max-w-[180px]">{displayName}</h3>
                            {isBlocked && (
                                <div className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-red-900/20 shrink-0">
                                    <ShieldOff className="w-3 h-3 text-red-600 dark:text-red-400" />
                                    <span className="text-xs font-medium text-red-600 dark:text-red-400">
                                        Blocked
                                    </span>
                                </div>
                            )}
                        </div>
                        <span className="text-xs text-muted-foreground font-medium shrink-0 ml-2">
                            {formatRelativeAge(log.startTime)}
                        </span>
                    </div>

                    <div className="flex items-center gap-3 text-sm text-muted-foreground">
                        <div className="flex items-center gap-1.5">
                            {log.type === 'video' ? (
                                <Video className={`w-4 h-4 ${log.status === 'missed' ? 'text-red-500' : 'text-gray-500'}`} />
                            ) : (
                                <Phone className={`w-4 h-4 ${log.status === 'missed' ? 'text-red-500' : 'text-gray-500'}`} />
                            )}
                            <span className={log.status === 'missed' ? 'text-red-500 font-medium' : ''}>
                                {log.status === 'missed' ? 'Missed Call' : (log.direction === 'outgoing' ? 'Outgoing' : 'Incoming')}
                            </span>
                        </div>

                        {log.duration !== undefined && log.duration > 0 && (
                            <>
                                <span className="w-1 h-1 rounded-full bg-zinc-200" />
                                <span>
                                    {formatCallDurationSeconds(log.duration)}
                                </span>
                            </>
                        )}
                    </div>
                </div>

                <div className="flex items-center gap-1">
                    <Button
                        variant="ghost"
                        size="icon"
                        className="rounded-full text-destructive"
                        onClick={() => onDelete(log.id)}
                    >
                        <Trash2 className="w-4 h-4" />
                    </Button>
                </div>
            </div>

            {/* Separator */}
            {index < totalLogs - 1 && (
                <div className="h-px my-2 bg-gradient-to-r from-transparent via-border to-transparent opacity-50" />
            )}
        </React.Fragment>
    );
});

CallLogItem.displayName = 'CallLogItem';

interface CallLogsProps {
    readonly getDisplayUsername?: (username: string) => Promise<string>;
}

export const CallLogs = React.memo<CallLogsProps>(({ getDisplayUsername }) => {
    const {
        logs,
        hasMoreLogs,
        loadMoreLogs,
        scheduleLogRelease,
        cancelLogRelease,
        getAllLogs,
        clearLogs,
        deleteLog,
    } = useCallHistory();
    const [searchQuery, setSearchQuery] = useState('');
    const [usernameMap, setUsernameMap] = useState<Record<string, string>>({});
    const scrollAreaRef = useRef<HTMLDivElement>(null);
    const isSearching = searchQuery.length > 0;
    const hasMoreLogsRef = useRef(hasMoreLogs);
    hasMoreLogsRef.current = hasMoreLogs;
    const isSearchingRef = useRef(isSearching);
    isSearchingRef.current = isSearching;

    const searchScopeLogs = useMemo(
        () => (isSearching ? getAllLogs() : logs),
        [isSearching, logs, getAllLogs],
    );

    useEffect(() => {
        cancelLogRelease();
        return () => { scheduleLogRelease(); };
    }, [cancelLogRelease, scheduleLogRelease]);

    const handleScroll = useCallback((viewport: Element) => {
        const distanceToBottom = viewport.scrollHeight - viewport.scrollTop - viewport.clientHeight;
        if (!isSearchingRef.current && hasMoreLogsRef.current && distanceToBottom < SCROLL_THRESHOLD) {
            loadMoreLogs();
            return;
        }
        if (viewport.scrollTop < NEAR_BOTTOM_THRESHOLD) scheduleLogRelease();
        else cancelLogRelease();
    }, [loadMoreLogs, scheduleLogRelease, cancelLogRelease]);

    useEffect(() => {
        const viewport = scrollAreaRef.current?.querySelector('[data-radix-scroll-area-viewport]');
        if (!viewport) return;
        const onScroll = () => handleScroll(viewport);
        viewport.addEventListener('scroll', onScroll);
        return () => viewport.removeEventListener('scroll', onScroll);
    }, [handleScroll]);

    // Resolve display names for all usernames
    useEffect(() => {
        if (!getDisplayUsername) return;

        const resolveUsernames = async () => {
            const newMap: Record<string, string> = {};
            const uniqueUsernames = Array.from(new Set(searchScopeLogs.map(log => log.peerUsername)));

            await Promise.all(
                uniqueUsernames.map(async (username) => {
                    try {
                        const displayName = await getDisplayUsername(username);
                        newMap[username] = displayName || username;
                    } catch {
                        newMap[username] = username;
                    }
                })
            );

            setUsernameMap(newMap);
        };

        resolveUsernames();
    }, [searchScopeLogs, getDisplayUsername]);

    const filteredLogs = useMemo(() => {
        if (!searchQuery) return searchScopeLogs;

        const query = searchQuery.toLowerCase();
        return searchScopeLogs.filter(log => {
            const displayName = usernameMap[log.peerUsername] || log.peerUsername;
            return displayName.toLowerCase().includes(query);
        });
    }, [searchScopeLogs, searchQuery, usernameMap]);

    return (
        <div className="flex flex-col h-full relative" style={{ backgroundColor: 'var(--qor-chat-bg)' }}>
            <div className="absolute top-0 left-0 right-0 z-10 p-6 space-y-4 bg-gradient-to-b from-background via-background/80 to-transparent">
                <div className="flex items-center gap-2">
                    <div className="relative flex-1">
                        <Input
                            placeholder="Search call history..."
                            className="pl-9 bg-background/50 border-border dark:border-gray-600 focus:border-primary backdrop-blur-sm"
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                        />
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
                    </div>

                    {/* Options Menu */}
                    <Popover>
                        <PopoverTrigger asChild>
                            <Button
                                size="sm"
                                variant="outline"
                                className="flex items-center justify-center select-none dark:border-gray-600 [&:hover]:!bg-background [&:hover]:!text-foreground dark:[&:hover]:!border-gray-600 bg-background/50 backdrop-blur-sm"
                            >
                                <MoreVertical className="w-4 h-4" />
                            </Button>
                        </PopoverTrigger>
                        <PopoverContent className="w-48 p-2 select-none" align="end">
                            <div className="space-y-1">
                                <div className="px-2 py-1 text-sm font-medium text-muted-foreground">
                                    Call Options
                                </div>
                                <Button
                                    variant="ghost"
                                    size="sm"
                                    className="w-full justify-start text-destructive hover:text-destructive hover:bg-destructive/10 disabled:opacity-50 disabled:cursor-not-allowed"
                                    onClick={() => clearLogs()}
                                    disabled={logs.length === 0}
                                >
                                    <Trash2 className="w-4 h-4 mr-2" />
                                    Clear All Calls
                                </Button>
                            </div>
                        </PopoverContent>
                    </Popover>
                </div>
            </div>

            <ScrollArea ref={scrollAreaRef} className="absolute inset-0 z-0 h-full w-full">
                <div className="space-y-2 px-6 pb-4 pt-24">
                    {filteredLogs.length === 0 ? (
                        <div className="text-center py-12 text-muted-foreground select-none">
                            <Clock className="w-12 h-12 mx-auto mb-4 opacity-20" />
                            <p>No recent calls</p>
                        </div>
                    ) : (
                        filteredLogs.map((log, index) => (
                            <CallLogItem
                                key={log.id}
                                log={log}
                                index={index}
                                totalLogs={filteredLogs.length}
                                getDisplayUsername={getDisplayUsername}
                                onDelete={deleteLog}
                            />
                        ))
                    )}
                </div>
            </ScrollArea>
        </div>
    );
});

CallLogs.displayName = 'CallLogs';
