import React, { memo, useMemo, useEffect, useState, useCallback } from "react";
import { cn } from "../../../lib/utils";
import { ScrollArea } from "../../ui/scroll-area";
import { Button } from "../../ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "../../ui/dialog";
import { Trash2, Search, Phone, Video, Loader2 } from "lucide-react";
import { Input } from "../../ui/input";
import { toast } from "sonner";
import { UserAvatar } from "../../ui/UserAvatar";
import { isPlainObject, hasPrototypePollutionKeys, sanitizeUiText } from "../../../lib/sanitizers";
import { EventType } from "../../../lib/event-types";
import { UI_CALL_STATUS_RATE_WINDOW_MS, UI_CALL_STATUS_RATE_MAX, MAX_UI_CALL_STATUS_PEER_LENGTH, MAX_UI_CALL_STATUS_VALUE_LENGTH } from "../../../lib/constants";
import { formatRelativeAge } from "../../../lib/date-utils";

export interface Conversation {
  readonly id: string;
  readonly username: string;
  readonly isOnline: boolean;
  readonly lastMessage?: string;
  readonly lastMessageTime?: Date;
  readonly unreadCount?: number;
  readonly displayName?: string;
}

interface ConversationListProps {
  readonly conversations: ReadonlyArray<Conversation>;
  readonly selectedConversation?: string;
  readonly onSelectConversation: (username: string) => void;
  readonly onRemoveConversation?: (username: string) => void;
  readonly onAddConversation?: (username: string) => Promise<void>;
  readonly getDisplayUsername?: (username: string) => Promise<string>;
  readonly showNewChatInput?: boolean;
}

// Call status type
type CallStatus = { status: 'ringing' | 'connecting' | 'connected'; isVideo: boolean } | null;

// Anonymize username for display
const anonymize = (value: string): string => {
  if (typeof value !== 'string' || value.length === 0) {
    return 'anon:user';
  }
  try {
    const bytes = new TextEncoder().encode(value);
    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    return `anon:${hex.slice(0, 12)}`;
  } catch {
    return 'anon:user';
  }
};

interface ConversationItemProps {
  readonly conversation: Conversation;
  readonly isSelected: boolean;
  readonly onSelect: (username: string) => void;
  readonly onRemove?: (username: string) => void;
  readonly callStatus?: CallStatus;
  readonly getDisplayUsername?: (username: string) => Promise<string>;
}

const ConversationItem = memo<ConversationItemProps>(({
  conversation,
  isSelected,
  onSelect,
  onRemove,
  callStatus,
  getDisplayUsername
}) => {
  const [resolvedName, setResolvedName] = useState<string | null>(null);

  const resolverRef = React.useRef(getDisplayUsername);
  useEffect(() => { resolverRef.current = getDisplayUsername; }, [getDisplayUsername]);

  useEffect(() => {
    let ignore = false;

    const resolveName = async () => {
      try {
        if (resolverRef.current && typeof conversation.username === 'string') {
          const dn = await resolverRef.current(conversation.username);
          if (!ignore && typeof dn === 'string' && dn.trim().length > 0) {
            setResolvedName(dn);
          }
        }
      } catch { }
    };

    resolveName();
    return () => { ignore = true; };
  }, [conversation.username]);

  const displayName = useMemo(() => {
    if (conversation.displayName && conversation.displayName.trim().length > 0) {
      return conversation.displayName;
    }
    if (resolvedName && resolvedName.trim().length > 0) {
      return resolvedName;
    }
    return anonymize(conversation.username);
  }, [conversation.displayName, conversation.username, resolvedName]);

  // Handle conversation selection
  const handleClick = useCallback(() => {
    onSelect(conversation.username);
  }, [onSelect, conversation.username]);

  // Handle conversation removal
  const handleRemove = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    if (onRemove) {
      onRemove(conversation.username);
    }
  }, [onRemove, conversation.username]);

  return (
    <div
      className={cn(
        "flex items-center gap-3 p-3 cursor-pointer transition-all duration-200 group relative",
        "hover:bg-opacity-80 min-w-0 w-full max-w-full overflow-hidden"
      )}
      style={{
        backgroundColor: isSelected ? 'var(--color-accent-primary)' : 'transparent',
        borderRadius: 'var(--radius-medium)'
      }}
      onMouseEnter={(e) => {
        if (!isSelected) {
          e.currentTarget.style.backgroundColor = 'rgba(59, 130, 246, 0.05)';
        }
      }}
      onMouseLeave={(e) => {
        if (!isSelected) {
          e.currentTarget.style.backgroundColor = 'transparent';
        }
      }}
      onClick={handleClick}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          handleClick();
        }
      }}
      aria-label={`Conversation with ${displayName}`}
      aria-selected={isSelected}
    >
      <UserAvatar
        username={conversation.username}
        size="md"
        className={isSelected ? 'opacity-80' : ''}
      />

      <div className="flex-1 min-w-0 w-0">
        <div className="flex items-center gap-2 mb-1 min-w-0 w-full">
          <span
            className="font-medium text-sm truncate flex-1 min-w-0 block select-none"
            style={{ color: isSelected ? 'white' : 'var(--color-text-primary)' }}
            title={displayName}
          >
            {displayName}
          </span>
          {conversation.lastMessageTime && (
            <span
              className="text-xs flex-shrink-0 select-none"
              style={{ color: isSelected ? 'rgba(255, 255, 255, 0.7)' : 'var(--color-text-secondary)' }}
            >
              {formatRelativeAge(conversation.lastMessageTime)}
            </span>
          )}
        </div>

        {conversation.lastMessage && (
          <div
            className="text-xs truncate pr-2 select-none"
            style={{ color: isSelected ? 'rgba(255, 255, 255, 0.8)' : 'var(--color-text-secondary)' }}
            title={conversation.lastMessage}
          >
            {conversation.lastMessage.replace(conversation.username, displayName)}
          </div>
        )}
      </div>

      {(callStatus || onRemove) && (
        <div className="absolute bottom-1 right-1 flex items-center gap-1">
          {callStatus && (
            <div
              className={cn(
                "text-xs px-2 py-1 rounded-full font-medium flex-shrink-0 flex items-center justify-center",
                callStatus.status === 'ringing' && "bg-yellow-100 text-yellow-800",
                callStatus.status === 'connecting' && "bg-blue-100 text-blue-800",
                callStatus.status === 'connected' && "bg-green-100 text-green-800"
              )}
              role="status"
              aria-label={`Call status: ${callStatus.status}${callStatus.isVideo ? ' video' : ' audio'}`}
            >
              {callStatus.status === 'connecting' ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : callStatus.isVideo ? (
                <Video className="w-3.5 h-3.5" />
              ) : (
                <Phone className="w-3.5 h-3.5" />
              )}
            </div>
          )}

          {onRemove && (
            <Button
              variant="ghost"
              size="sm"
              onClick={handleRemove}
              className="opacity-0 group-hover:opacity-100 transition-opacity p-1 h-6 w-6"
              style={{
                backgroundColor: 'transparent',
                color: 'var(--color-error)'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = 'rgba(239, 68, 68, 0.1)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'transparent';
              }}
              aria-label={`Remove conversation with ${displayName}`}
            >
              <Trash2 className="h-3 w-3" />
            </Button>
          )}
        </div>
      )}
    </div>
  );
});

// Main conversation list component
export const ConversationList = memo<ConversationListProps>(function ConversationList({
  conversations,
  selectedConversation,
  onSelectConversation,
  onRemoveConversation,
  onAddConversation,
  getDisplayUsername,
  showNewChatInput = false
}: ConversationListProps) {
  const [activePeer, setActivePeer] = useState<string | null>(null);
  const [activeStatus, setActiveStatus] = useState<CallStatus>(null);
  const [showConfirmDialog, setShowConfirmDialog] = useState<boolean>(false);
  const [conversationToDelete, setConversationToDelete] = useState<string | null>(null);
  const [newChatUsername, setNewChatUsername] = useState("");
  const [isAdding, setIsAdding] = useState(false);

  // Handle remove conversation click
  const handleRemoveClick = useCallback((username: string) => {
    setConversationToDelete(username);
    setShowConfirmDialog(true);
  }, []);

  // Handle confirm removal
  const handleConfirmRemove = useCallback(() => {
    if (conversationToDelete && onRemoveConversation) {
      onRemoveConversation(conversationToDelete);
    }
    setShowConfirmDialog(false);
    setConversationToDelete(null);
  }, [conversationToDelete, onRemoveConversation]);

  // Handle cancel removal
  const handleCancelRemove = useCallback(() => {
    setShowConfirmDialog(false);
    setConversationToDelete(null);
  }, []);

  // Handle add new chat
  const handleAddChat = useCallback(async () => {
    if (!newChatUsername.trim() || !onAddConversation) return;

    setIsAdding(true);
    try {
      await onAddConversation(newChatUsername.trim());
      setNewChatUsername("");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to add conversation");
    } finally {
      setIsAdding(false);
    }
  }, [newChatUsername, onAddConversation]);

  const callStatusRateRef = React.useRef<{ windowStart: number; count: number }>({ windowStart: Date.now(), count: 0 });

  // Handle call status events
  const handleCallStatus = useCallback((e: Event) => {
    try {
      const now = Date.now();
      const bucket = callStatusRateRef.current;
      if (now - bucket.windowStart > UI_CALL_STATUS_RATE_WINDOW_MS) {
        bucket.windowStart = now;
        bucket.count = 0;
      }
      bucket.count += 1;
      if (bucket.count > UI_CALL_STATUS_RATE_MAX) {
        return;
      }

      if (!(e instanceof CustomEvent)) return;
      const detail = e.detail;
      if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

      const peer = sanitizeUiText((detail as any).peer, MAX_UI_CALL_STATUS_PEER_LENGTH);
      if (!peer) return;

      const status = sanitizeUiText((detail as any).status, MAX_UI_CALL_STATUS_VALUE_LENGTH);
      if (!status) return;

      const type = sanitizeUiText((detail as any).type, MAX_UI_CALL_STATUS_VALUE_LENGTH);
      const isVideo = type === 'video';

      if (status === 'ringing' || status === 'connecting' || status === 'connected') {
        setActivePeer(peer);
        setActiveStatus({ status: status as CallStatus['status'], isVideo });
      } else {
        setActivePeer(prev => (prev === peer ? null : prev));
        setActiveStatus(null);
      }
    } catch { }
  }, []);

  useEffect(() => {
    window.addEventListener(EventType.UI_CALL_STATUS, handleCallStatus as EventListener);
    return () => window.removeEventListener(EventType.UI_CALL_STATUS, handleCallStatus as EventListener);
  }, [handleCallStatus]);

  const [refreshTick, setRefreshTick] = useState(0);

  useEffect(() => {
    const getRefreshInterval = (): number => {
      const now = Date.now();
      let minAgeMs = Infinity;

      for (const conv of conversations) {
        if (conv.lastMessageTime) {
          const age = now - conv.lastMessageTime.getTime();
          if (age < minAgeMs) minAgeMs = age;
        }
      }

      // If all messages are older than a week, no need to refresh
      if (minAgeMs >= 7 * 24 * 60 * 60 * 1000) return 0;

      // If newest message is days old, refresh every hour
      if (minAgeMs >= 24 * 60 * 60 * 1000) return 60 * 60 * 1000;

      // If newest message is hours old, refresh every 5 minutes
      if (minAgeMs >= 60 * 60 * 1000) return 5 * 60 * 1000;

      // For recent messages < 1 hour, refresh every minute
      return 60 * 1000;
    };

    const interval = getRefreshInterval();
    if (interval === 0) return;

    const timer = setInterval(() => {
      setRefreshTick(t => t + 1);
    }, interval);

    return () => clearInterval(timer);
  }, [conversations]);

  const displayUsername = useMemo(() => {
    if (!conversationToDelete) return 'User';
    return /^[a-f0-9]{32,}$/i.test(conversationToDelete) ? 'User' : conversationToDelete;
  }, [conversationToDelete]);

  return (
    <div className="flex flex-col h-full">
      {showNewChatInput && (
        <div className="p-4 space-y-4">
          <div className="relative">
            {isAdding ? (
              <Loader2 className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground animate-spin" />
            ) : (
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            )}
            <Input
              placeholder="Username..."
              value={newChatUsername}
              onChange={(e) => setNewChatUsername(e.target.value)}
              className="pl-8 select-none"
              disabled={isAdding}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !isAdding) {
                  handleAddChat();
                }
              }}
            />
          </div>
        </div>
      )}

      <ScrollArea className="flex-1">
        <div className="p-2">
          {conversations.length === 0 ? (
            <div
              className="text-center text-xs py-8 select-none"
              style={{ color: 'var(--color-text-secondary)' }}
            >
              No conversations yet
            </div>
          ) : (
            <div className="space-y-1">
              {conversations.map((conversation) => (
                <ConversationItem
                  key={conversation.id}
                  conversation={conversation}
                  isSelected={selectedConversation === conversation.username}
                  onSelect={onSelectConversation}
                  onRemove={handleRemoveClick}
                  callStatus={conversation.username === activePeer ? activeStatus : null}
                  getDisplayUsername={getDisplayUsername}
                />
              ))}
            </div>
          )}
        </div>
      </ScrollArea>

      <Dialog open={showConfirmDialog} onOpenChange={setShowConfirmDialog}>
        <DialogContent
          style={{ backgroundColor: 'var(--color-surface)', borderColor: 'var(--color-border)' }}
          aria-describedby="dialog-description"
        >
          <DialogHeader>
            <DialogTitle className="text-foreground">Remove Conversation</DialogTitle>
            <DialogDescription id="dialog-description" className="text-muted-foreground">
              Are you sure you want to remove the conversation with {displayUsername}?
              This action cannot be undone and will delete all message history.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={handleCancelRemove} aria-label="Cancel removal">
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleConfirmRemove} aria-label="Confirm removal">
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
});