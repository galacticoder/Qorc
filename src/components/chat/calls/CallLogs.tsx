import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { format, isThisYear, isToday, isYesterday } from 'date-fns';
import {
    MoreVertical,
    Search,
    Trash2,
    Video,
    X,
} from 'lucide-react';
import { Popover, PopoverContent, PopoverTrigger } from '../../ui/popover';
import { Button } from '../../ui/button';
import { ScrollArea } from '../../ui/scroll-area';
import { UserAvatar } from '../../ui/UserAvatar';
import { CallIcon } from '../assets/icons';
import { useCallHistory, type CallLogEntry } from '../../../contexts/CallHistoryContext';
import { useDisplayUsername } from '../../../hooks/database/useDisplayUsername';
import { formatCallDurationSeconds } from '../../../lib/utils/date-utils';
import { NEAR_BOTTOM_THRESHOLD, SCROLL_THRESHOLD } from '../../../lib/constants';
import { CallLogRowsSkeleton } from '../../ui/ViewSkeletons';
import { useMobileLayout } from '../../../hooks/useMobileLayout';
import { ConversationSwipeRow } from '../messaging/ConversationSwipeRow';
import { useAppBack } from '../../../hooks/useAppBack';

interface CallLogsProps {
    readonly getDisplayUsername: (username: string) => Promise<string>;
    readonly onOpenConversation: (username: string) => void;
}

interface CallLogGroup {
    readonly key: string;
    readonly label: string;
    readonly logs: CallLogEntry[];
}

const callDayKey = (timestamp: number): string => format(new Date(timestamp), 'yyyy-MM-dd');

const callDayLabel = (timestamp: number): string => {
    const date = new Date(timestamp);
    if (isToday(date)) return 'Today';
    if (isYesterday(date)) return 'Yesterday';
    return format(date, isThisYear(date) ? 'EEEE, MMMM d' : 'MMMM d, yyyy');
};

const callStatusLabel = (log: CallLogEntry): string => {
    const kind = log.type === 'video' ? 'video' : 'audio';
    if (log.status !== 'completed') {
        return log.direction === 'incoming'
            ? `Missed ${kind} call`
            : `Unanswered ${kind} call`;
    }
    return `${log.direction === 'incoming' ? 'Incoming' : 'Outgoing'} ${kind} call`;
};

interface CallLogDeleteButtonProps {
    readonly id: string;
    readonly displayName: string;
    readonly onDelete: (id: string) => void;
    readonly onAction?: () => void;
    readonly swipe?: boolean;
}

const CallLogDeleteButton = React.memo(function CallLogDeleteButton({
    id,
    displayName,
    onDelete,
    onAction,
    swipe = false,
}: CallLogDeleteButtonProps) {
    const handleDelete = useCallback(() => {
        onAction?.();
        onDelete(id);
    }, [id, onDelete, onAction]);

    return (
        <Button
            size="sm"
            variant="ghost"
            className={swipe
                ? 'qorc-conversation-tiny-btn danger qorc-call-log-delete'
                : 'qorc-call-pill-btn qorc-call-log-delete'}
            title="Delete"
            aria-label={`Delete call with ${displayName}`}
            onClick={handleDelete}
        >
            <Trash2 className="w-4 h-4" aria-hidden="true" />
        </Button>
    );
});

interface CallLogItemProps {
    readonly mobile: boolean;
    readonly log: CallLogEntry;
    readonly onDelete: (id: string) => void;
    readonly onOpenConversation: (username: string) => void;
}

const CallLogItem = React.memo(function CallLogItem({
    mobile,
    log,
    onDelete,
    onOpenConversation,
}: CallLogItemProps) {
    const displayName = useDisplayUsername({ username: log.peerUsername });
    const [swipeOpen, setSwipeOpen] = useState(false);
    useEffect(() => { setSwipeOpen(false); }, [mobile]);
    const isUnanswered = log.status !== 'completed';
    const hasDistinctDisplayName = displayName.toLowerCase() !== log.peerUsername.toLowerCase();

    return (
        <ConversationSwipeRow
            enabled={mobile}
            open={swipeOpen}
            onOpenChange={setSwipeOpen}
            actionWidth={56}
            allowButtonSwipes
            className="qorc-call-log-swipe"
            actions={<CallLogDeleteButton swipe id={log.id} displayName={displayName} onDelete={onDelete} onAction={() => setSwipeOpen(false)} />}
        >
        <article className="qorc-call-log-row">
            <button
                type="button"
                className="qorc-call-log-person"
                onClick={() => onOpenConversation(log.peerUsername)}
                aria-label={`Open conversation with ${displayName}`}
            >
                <UserAvatar username={log.peerUsername} size={mobile ? 'lg' : 'md'} className="qorc-call-log-avatar" />

                <span className="qorc-call-log-copy">
                    <span className="qorc-call-log-name-line">
                        <span className="qorc-call-log-name" title={displayName}>{displayName}</span>
                        {hasDistinctDisplayName && (
                            <span className="qorc-call-log-handle" title={log.peerUsername}>@{log.peerUsername}</span>
                        )}
                    </span>

                    <span className="qorc-call-log-detail-line">
                        <span className={`qorc-call-log-result${isUnanswered ? ' is-unanswered' : ''}`}>
                            {log.type === 'video' ? (
                                <Video aria-hidden="true" />
                            ) : (
                                <CallIcon aria-hidden="true" />
                            )}
                            <span>{callStatusLabel(log)}</span>
                        </span>

                    </span>
                    <time className="qorc-call-log-time" dateTime={new Date(log.startTime).toISOString()} title={format(new Date(log.startTime), 'PPpp')}>
                        {format(new Date(log.startTime), 'h:mm a')}
                    </time>
                    {log.status === 'completed' && log.duration !== undefined && log.duration > 0 && (
                        <span className="qorc-call-log-duration">
                            <span>{formatCallDurationSeconds(log.duration)}</span>
                        </span>
                    )}
                </span>
            </button>

            {!mobile && <CallLogDeleteButton id={log.id} displayName={displayName} onDelete={onDelete} />}
        </article>
        </ConversationSwipeRow>
    );
});

export const CallLogs = React.memo<CallLogsProps>(function CallLogs({
    getDisplayUsername,
    onOpenConversation,
}) {
    const mobile = useMobileLayout();
    const {
        logs,
        hasMoreLogs,
        loadMoreLogs,
        scheduleLogRelease,
        cancelLogRelease,
        getAllLogs,
        clearLogs,
        deleteLog,
        isLoading,
    } = useCallHistory();
    const [searchQuery, setSearchQuery] = useState('');
    const [searchOpen, setSearchOpen] = useState(false);
    const searchInput = useRef<HTMLInputElement>(null);
    const searchButton = useRef<HTMLButtonElement>(null);
    const wasSearching = useRef(false);
    const [usernameMap, setUsernameMap] = useState<Record<string, string>>({});
    const [optionsOpen, setOptionsOpen] = useState(false);
    const historyControlsDisabled = isLoading || logs.length === 0;
    const scrollAreaRef = useRef<HTMLDivElement>(null);
    const normalizedQuery = searchQuery.trim().toLowerCase();
    const isSearching = normalizedQuery.length > 0;
    const hasMoreLogsRef = useRef(hasMoreLogs);
    hasMoreLogsRef.current = hasMoreLogs;
    const isSearchingRef = useRef(isSearching);
    isSearchingRef.current = isSearching;
    const closeSearch = useCallback(() => {
        searchInput.current?.blur();
        setSearchQuery('');
        setSearchOpen(false);
    }, []);
    useAppBack(searchOpen, closeSearch, 30);
    useEffect(() => {
        if (searchOpen) searchInput.current?.focus();
        else if (wasSearching.current) searchButton.current?.focus();
        wasSearching.current = searchOpen;
    }, [searchOpen]);

    useEffect(() => {
        if (!isLoading && logs.length === 0) setSearchQuery('');
    }, [isLoading, logs.length]);

    useEffect(() => {
        if (historyControlsDisabled) { setOptionsOpen(false); closeSearch(); }
    }, [historyControlsDisabled, closeSearch]);

    const searchScopeLogs = useMemo(
        () => (isSearching ? getAllLogs() : logs),
        [getAllLogs, isSearching, logs],
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
    }, [cancelLogRelease, loadMoreLogs, scheduleLogRelease]);

    useEffect(() => {
        const viewport = scrollAreaRef.current?.querySelector('[data-radix-scroll-area-viewport]');
        if (!viewport) return;
        const onScroll = () => handleScroll(viewport);
        viewport.addEventListener('scroll', onScroll);
        return () => viewport.removeEventListener('scroll', onScroll);
    }, [handleScroll]);

    useEffect(() => {
        let cancelled = false;
        const uniqueUsernames = Array.from(new Set(searchScopeLogs.map((log) => log.peerUsername)));

        void Promise.all(uniqueUsernames.map(async (username) => {
            try {
                const displayName = await getDisplayUsername(username);
                return [username, displayName || username] as const;
            } catch {
                return [username, username] as const;
            }
        })).then((resolvedNames) => {
            if (!cancelled) setUsernameMap(Object.fromEntries(resolvedNames));
        });

        return () => { cancelled = true; };
    }, [getDisplayUsername, searchScopeLogs]);

    const filteredLogs = useMemo(() => {
        if (!normalizedQuery) return searchScopeLogs;
        return searchScopeLogs.filter((log) => {
            const displayName = usernameMap[log.peerUsername] || log.peerUsername;
            return displayName.toLowerCase().includes(normalizedQuery)
                || log.peerUsername.toLowerCase().includes(normalizedQuery)
                || callStatusLabel(log).toLowerCase().includes(normalizedQuery);
        });
    }, [normalizedQuery, searchScopeLogs, usernameMap]);

    const groupedLogs = useMemo<CallLogGroup[]>(() => {
        const groups: CallLogGroup[] = [];
        for (const log of filteredLogs) {
            const key = callDayKey(log.startTime);
            const existing = groups[groups.length - 1];
            if (existing?.key === key) {
                existing.logs.push(log);
            } else {
                groups.push({ key, label: callDayLabel(log.startTime), logs: [log] });
            }
        }
        return groups;
    }, [filteredLogs]);

    const handleClearLogs = useCallback(() => {
        if (historyControlsDisabled) return;
        clearLogs();
        setSearchQuery('');
        setOptionsOpen(false);
    }, [clearLogs, historyControlsDisabled]);

    return (
        <section className="qorc-call-log-page">
            <header className={`qorc-call-log-header${searchOpen ? ' is-searching' : ''}`}>
                <div className="qorc-call-log-heading" hidden={mobile && searchOpen}>
                    <CallIcon className="qorc-call-log-heading-icon" aria-hidden="true" />
                    <h1>Calls</h1>
                </div>

                <div className="qorc-call-log-header-actions">
                    {searchOpen ? <div className="qorc-call-log-search qorc-search-field">
                        <span className="qorc-search-icon" aria-hidden="true"><Search /></span>
                        <input
                            ref={searchInput}
                            autoFocus
                            type="text"
                            className="qorc-search-input"
                            value={searchQuery}
                            onChange={(event) => setSearchQuery(event.target.value)}
                            placeholder="Search calls"
                            aria-label="Search call history"
                            disabled={historyControlsDisabled}
                            onKeyDown={event => { if (event.key === 'Escape') { event.preventDefault(); closeSearch(); } }}
                        />
                            <button
                                type="button"
                                className="qorc-search-action"
                                onClick={searchQuery ? () => { setSearchQuery(''); searchInput.current?.focus(); } : closeSearch}
                                onPointerDown={event => event.preventDefault()}
                                title={searchQuery ? 'Clear search' : 'Close search'}
                                aria-label={searchQuery ? 'Clear call search' : 'Close call search'}
                                disabled={historyControlsDisabled}
                            >
                                <X aria-hidden="true" />
                            </button>
                    </div> : <button type="button" ref={searchButton}
                        className="qorc-call-pill-btn qorc-call-log-search-btn"
                        aria-label="Search call history" title="Search calls" aria-expanded={false}
                        disabled={historyControlsDisabled}
                        onClick={() => { setOptionsOpen(false); setSearchOpen(true); }}>
                        <Search aria-hidden="true" />
                    </button>}

                    <Popover
                        open={optionsOpen && !historyControlsDisabled}
                        onOpenChange={(open) => setOptionsOpen(open && !historyControlsDisabled)}
                    >
                        <PopoverTrigger asChild>
                            <Button
                                size="sm"
                                variant="ghost"
                                className="qorc-call-pill-btn qorc-call-log-options-btn"
                                title="Call history options"
                                aria-label="Call history options"
                                disabled={historyControlsDisabled}
                            >
                                <MoreVertical className="w-4 h-4" aria-hidden="true" />
                            </Button>
                        </PopoverTrigger>
                        <PopoverContent className="qorc-call-log-popover select-none" align="end">
                            <div className="qorc-call-log-options-menu">
                                <button
                                    type="button"
                                    className="qorc-call-log-popover-action is-danger"
                                    onClick={handleClearLogs}
                                    disabled={historyControlsDisabled}
                                >
                                    <Trash2 aria-hidden="true" />
                                    <span>Clear history</span>
                                </button>
                            </div>
                        </PopoverContent>
                    </Popover>
                </div>
            </header>

            <ScrollArea ref={scrollAreaRef} className="qorc-call-log-scroll">
                <div className="qorc-call-log-content">
                    {isLoading ? (
                        <CallLogRowsSkeleton />
                    ) : groupedLogs.length === 0 ? (
                        <div className="qorc-call-log-empty">
                            <strong>{isSearching ? 'No matching calls' : 'No calls yet'}</strong>
                            <span>{isSearching ? 'Try another name or call type.' : 'Your recent calls will appear here.'}</span>
                        </div>
                    ) : (
                        groupedLogs.map((group) => (
                            <section className="qorc-call-log-group" key={group.key} aria-labelledby={`call-group-${group.key}`}>
                                <h2 id={`call-group-${group.key}`}>{group.label}</h2>
                                <div className="qorc-call-log-list">
                                    {group.logs.map((log) => (
                                        <CallLogItem
                                            key={log.id}
                                            mobile={mobile}
                                            log={log}
                                            onDelete={deleteLog}
                                            onOpenConversation={onOpenConversation}
                                        />
                                    ))}
                                </div>
                            </section>
                        ))
                    )}
                </div>
            </ScrollArea>
        </section>
    );
});

CallLogs.displayName = 'CallLogs';
