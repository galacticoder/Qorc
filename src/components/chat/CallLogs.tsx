import React, { useState, useMemo, useCallback, useEffect } from 'react';
import { Phone, Video, Search, Clock, Trash2, MoreVertical, ShieldOff } from 'lucide-react';
import { Popover, PopoverContent, PopoverTrigger } from '../ui/popover';
import { Input } from '../ui/input';
import { Button } from '../ui/button';
import { ScrollArea } from '../ui/scroll-area';
import { Avatar, AvatarFallback, AvatarImage } from '../ui/avatar';
import { useCallHistory, type CallLogEntry } from '../../contexts/CallHistoryContext';
import { useUnifiedUsernameDisplay } from '../../hooks/useUnifiedUsernameDisplay';
import { blockStatusCache } from '../../lib/block-status-cache';

interface CallLogItemProps {
    readonly log: CallLogEntry;
    readonly index: number;
    readonly totalLogs: number;
    readonly formatTime: (timestamp: number) => string;
    readonly formatDuration: (seconds?: number) => string;
    readonly getDisplayUsername?: (username: string) => Promise<string>;
    readonly onDelete: (id: string) => void;
}

const CallLogItem: React.FC<CallLogItemProps> = React.memo(({
    log,
    index,
    totalLogs,
    formatTime,
    formatDuration,
    getDisplayUsername,
    onDelete
}) => {
    const { displayName } = useUnifiedUsernameDisplay({
        username: log.peerUsername,
        getDisplayUsername,
        fallbackToOriginal: true
    });

    const [isBlocked, setIsBlocked] = useState<boolean>(false);

    // Check if user is blocked
    useEffect(() => {
        const checkBlockedStatus = () => {
            const blocked = blockStatusCache.get(log.peerUsername);
            setIsBlocked(blocked === true);
        };

        checkBlockedStatus();

        const handleBlockStatusChange = (event: Event) => {
            const { username, isBlocked: newBlockedState } = (event as CustomEvent).detail;
            if (username === log.peerUsername) {
                setIsBlocked(newBlockedState);
            }
        };

        window.addEventListener('block-status-changed', handleBlockStatusChange as EventListener);
        return () => window.removeEventListener('block-status-changed', handleBlockStatusChange as EventListener);
    }, [log.peerUsername]);

    return (
        <React.Fragment>
            <div className="p-3 flex items-center gap-3 hover:bg-accent/50 rounded-lg transition-colors select-none">
                <Avatar className="h-10 w-10 border-2 border-background shadow-sm">
                    <AvatarFallback className="bg-primary/10 text-primary font-bold">
                        {displayName.slice(0, 2).toUpperCase()}
                    </AvatarFallback>
                </Avatar>

                <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-1">
                        <h3 className="font-semibold truncate text-foreground max-w-[180px]">{displayName}</h3>
                        <span className="text-xs text-muted-foreground font-medium">
                            {formatTime(log.startTime)}
                        </span>
                    </div>

                    <div className="flex items-center gap-3 text-sm text-muted-foreground">
                        <div className="flex items-center gap-1.5">
                            {log.type === 'video' ? (
                                <Video className={`w-4 h-4 ${log.status === 'missed' ? 'text-destructive' : 'text-gray-500'}`} />
                            ) : (
                                <Phone className={`w-4 h-4 ${log.status === 'missed' ? 'text-destructive' : 'text-gray-500'}`} />
                            )}
                            <span className={log.status === 'missed' ? 'text-destructive font-medium' : ''}>
                                {log.status === 'missed' ? 'Missed Call' : (log.direction === 'outgoing' ? 'Outgoing' : 'Incoming')}
                            </span>
                        </div>

                        {log.duration && (
                            <>
                                <span className="w-1 h-1 rounded-full bg-border" />
                                <span>
                                    {formatDuration(log.duration)}
                                </span>
                            </>
                        )}

                        {/* Blocked Status Indicator */}
                        {isBlocked && (
                            <>
                                <span className="w-1 h-1 rounded-full bg-border" />
                                <div className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-red-100 dark:bg-red-900/20">
                                    <ShieldOff className="w-3 h-3 text-red-600 dark:text-red-400" />
                                    <span className="text-xs font-medium text-red-600 dark:text-red-400">
                                        Blocked
                                    </span>
                                </div>
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
    const { logs, clearLogs, deleteLog } = useCallHistory();
    const [searchQuery, setSearchQuery] = useState('');
    const [usernameMap, setUsernameMap] = useState<Record<string, string>>({});

    // Resolve display names for all usernames
    useEffect(() => {
        if (!getDisplayUsername) return;

        const resolveUsernames = async () => {
            const newMap: Record<string, string> = {};
            const uniqueUsernames = Array.from(new Set(logs.map(log => log.peerUsername)));

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
    }, [logs, getDisplayUsername]);

    const filteredLogs = useMemo(() => {
        if (!searchQuery) return logs;

        const query = searchQuery.toLowerCase();
        return logs.filter(log => {
            const displayName = usernameMap[log.peerUsername] || log.peerUsername;
            return displayName.toLowerCase().includes(query);
        });
    }, [logs, searchQuery, usernameMap]);

    const formatTime = useCallback((timestamp: number): string => {
        const date = new Date(timestamp);
        if (!date || !(date instanceof Date) || isNaN(date.getTime())) {
            return "";
        }

        const now = new Date();
        const diff = now.getTime() - date.getTime();

        if (diff < 0) return "";

        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(diff / 3600000);
        const days = Math.floor(diff / 86400000);

        if (minutes < 1) return "now";
        if (minutes < 60) return `${minutes}m`;
        if (hours < 24) return `${hours}h`;
        if (days < 7) return `${days}d`;

        const month = (date.getMonth() + 1).toString().padStart(2, '0');
        const day = date.getDate().toString().padStart(2, '0');
        const year = date.getFullYear().toString().slice(-2);
        return `${month}/${day}/${year}`;
    }, []);

    const formatDuration = useCallback((seconds?: number) => {
        if (!seconds) return '';

        const hours = Math.floor(seconds / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;

        if (hours > 0) {
            return `${hours}hr ${mins}m ${secs}s`;
        } else if (mins > 0) {
            return `${mins}m ${secs}s`;
        } else {
            return `${secs}s`;
        }
    }, []);

    return (
        <div className="h-full flex flex-col bg-background select-none">
            <div className="p-6 space-y-4">
                <div className="flex items-center gap-2">
                    <div className="relative flex-1">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                        <Input
                            placeholder="Search call history..."
                            className="pl-9 bg-background border-border dark:border-gray-600 focus:border-primary"
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                        />
                    </div>

                    {/* Options Menu */}
                    <Popover>
                        <PopoverTrigger asChild>
                            <Button
                                size="sm"
                                variant="outline"
                                className="flex items-center justify-center select-none dark:border-gray-600 [&:hover]:!bg-background [&:hover]:!text-foreground dark:[&:hover]:!border-gray-600"
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

            <ScrollArea className="flex-1 px-6 pb-4">
                <div className="space-y-2">
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
                                formatTime={formatTime}
                                formatDuration={formatDuration}
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
