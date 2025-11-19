import React, { useState } from 'react';
import { Phone, Video, Search, ArrowUpRight, ArrowDownLeft, Clock, Trash2 } from 'lucide-react';
import { Input } from '../ui/input';
import { Button } from '../ui/button';
import { ScrollArea } from '../ui/scroll-area';
import { Avatar, AvatarFallback, AvatarImage } from '../ui/avatar';
import { Card } from '../ui/card';
import { useCallHistory } from '../../contexts/CallHistoryContext';
import { format } from 'date-fns';

export function CallLogs() {
    const { logs, clearLogs } = useCallHistory();
    const [searchQuery, setSearchQuery] = useState('');

    const filteredLogs = logs.filter(log =>
        log.peerUsername.toLowerCase().includes(searchQuery.toLowerCase())
    );

    const formatDuration = (seconds?: number) => {
        if (!seconds) return '';
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${mins}m ${secs}s`;
    };

    return (
        <div className="h-full flex flex-col bg-background/50 backdrop-blur-xl">
            <div className="p-6 border-b border-border/50 space-y-4">
                <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                        placeholder="Search call history..."
                        className="pl-9 bg-background/50 border-border/50 focus:border-primary/50 transition-all duration-300"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                    />
                </div>
            </div>

            <ScrollArea className="flex-1 p-4">
                <div className="space-y-3 max-w-3xl mx-auto">
                    {filteredLogs.length === 0 ? (
                        <div className="text-center py-12 text-muted-foreground">
                            <Clock className="w-12 h-12 mx-auto mb-4 opacity-20" />
                            <p>No recent calls</p>
                        </div>
                    ) : (
                        filteredLogs.map((log) => (
                            <Card key={log.id} className="p-4 flex items-center gap-4 hover:bg-accent/50 transition-colors border-border/50 bg-card/50 backdrop-blur-sm">
                                <Avatar className="h-12 w-12 border-2 border-background shadow-sm">

                                    <AvatarFallback className="bg-primary/10 text-primary font-bold">
                                        {log.peerUsername.slice(0, 2).toUpperCase()}
                                    </AvatarFallback>
                                </Avatar>

                                <div className="flex-1 min-w-0">
                                    <div className="flex items-center justify-between mb-1">
                                        <h3 className="font-semibold truncate text-foreground">{log.peerUsername}</h3>
                                        <span className="text-xs text-muted-foreground font-medium">
                                            {format(log.startTime, 'MMM d, h:mm a')}
                                        </span>
                                    </div>

                                    <div className="flex items-center gap-3 text-sm text-muted-foreground">
                                        <div className="flex items-center gap-1.5">
                                            {log.direction === 'outgoing' ? (
                                                <ArrowUpRight className="w-4 h-4 text-emerald-500 dark:text-emerald-400" />
                                            ) : (
                                                <ArrowDownLeft className={`w-4 h-4 ${log.status === 'missed' ? 'text-destructive' : 'text-blue-500 dark:text-blue-400'}`} />
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

                                <Button variant="ghost" size="icon" className="rounded-full hover:bg-primary/10 hover:text-primary transition-colors">
                                    {log.type === 'video' ? (
                                        <Video className="w-5 h-5" />
                                    ) : (
                                        <Phone className="w-5 h-5" />
                                    )}
                                </Button>
                            </Card>
                        ))
                    )}
                </div>
            </ScrollArea>
        </div>
    );
}
