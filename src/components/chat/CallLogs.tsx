import React, { useState, useMemo, useCallback } from 'react';
import { Phone, Video, Search, ArrowUpRight, ArrowDownLeft, Clock, Trash2 } from 'lucide-react';
import { Input } from '../ui/input';
import { Button } from '../ui/button';
import { ScrollArea } from '../ui/scroll-area';
import { Avatar, AvatarFallback, AvatarImage } from '../ui/avatar';
import { Card } from '../ui/card';
import { useCallHistory } from '../../contexts/CallHistoryContext';
import { format } from 'date-fns';

export const CallLogs = React.memo(() => {
    const { logs, clearLogs } = useCallHistory();
    const [searchQuery, setSearchQuery] = useState('');

    const filteredLogs = useMemo(() =>
        logs.filter(log =>
            log.peerUsername.toLowerCase().includes(searchQuery.toLowerCase())
        ),
        [logs, searchQuery]
    );

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
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${mins}m ${secs}s`;
    }, []);

    return (
        <div className="h-full flex flex-col bg-background">
            <div className="p-6 space-y-4">
                <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                        placeholder="Search call history..."
                        className="pl-9 bg-background border-border focus:border-primary"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                    />
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
                            <React.Fragment key={log.id}>
                                <div className="p-3 flex items-center gap-3 hover:bg-accent/50 rounded-lg transition-colors">
                                    <Avatar className="h-10 w-10 border-2 border-background shadow-sm">
                                        <AvatarFallback className="bg-primary/10 text-primary font-bold">
                                            {log.peerUsername.slice(0, 2).toUpperCase()}
                                        </AvatarFallback>
                                    </Avatar>

                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center justify-between mb-1">
                                            <h3 className="font-semibold truncate text-foreground max-w-[180px]">{log.peerUsername}</h3>
                                            <span className="text-xs text-muted-foreground font-medium">
                                                {formatTime(log.startTime)}
                                            </span>
                                        </div>

                                        <div className="flex items-center gap-3 text-sm text-muted-foreground">
                                            <div className="flex items-center gap-1.5">
                                                {log.direction === 'outgoing' ? (
                                                    <ArrowUpRight className="w-4 h-4 text-emerald-500 dark:text-emerald-400" />
                                                ) : (
                                                    <ArrowDownLeft className={`w-4 h-4 ${log.status === 'missed' ? 'text-destructive' : 'text-gray-500'}`} />
                                                )}
                                                <span className={log.status === 'missed' ? 'text-destructive font-medium' : ''}>
                                                    {log.status === 'missed' ? 'Missed Call' : (log.direction === 'outgoing' ? 'Outgoing' : 'Incoming')}
                                                </span>
                                            </div>

                                            {log.duration && (
                                                <>
                                                    <span className="w-1 h-1 rounded-full bg-border" />
                                                    <span className="flex items-center gap-1">
                                                        <Clock className="w-3 h-3" />
                                                        {formatDuration(log.duration)}
                                                    </span>
                                                </>
                                            )}
                                        </div>
                                    </div>

                                    <Button variant="ghost" size="icon" className="rounded-full hover:bg-primary/10 hover:text-primary">
                                        {log.type === 'video' ? (
                                            <Video className="w-5 h-5" />
                                        ) : (
                                            <Phone className="w-5 h-5" />
                                        )}
                                    </Button>
                                </div>

                                {/* Separator with fade effect - not after last item */}
                                {index < filteredLogs.length - 1 && (
                                    <div className="h-px my-2 bg-gradient-to-r from-transparent via-border to-transparent opacity-50" />
                                )}
                            </React.Fragment>
                        ))
                    )}
                </div>
            </ScrollArea>
        </div>
    );
});

CallLogs.displayName = 'CallLogs';
