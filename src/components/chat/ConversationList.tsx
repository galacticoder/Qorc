import React, { memo, useMemo, useEffect, useState, useCallback } from "react";
import { cn } from "../../lib/utils";
import { ScrollArea } from "../ui/scroll-area";
import { Button } from "../ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "../ui/dialog";
import { Trash2, Search } from "lucide-react";
import { Input } from "../ui/input";
import { toast } from "sonner";

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

type CallStatus = 'ringing' | 'connecting' | 'connected' | null;

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

const getAvatarColor = (username: string): string => {
  if (typeof username !== 'string' || username.length === 0) {
    return 'hsl(0, 65%, 55%)';
  }
  const hash = username.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
  const hue = Math.abs(hash) % 360;
  return `hsl(${hue}, 65%, 55%)`;
};

interface ConversationItemProps {
  readonly conversation: Conversation;
  readonly isSelected: boolean;
  readonly onSelect: (username: string) => void;
  readonly onRemove?: (username: string) => void;
  readonly formatTime: (date?: Date) => string;
  readonly callStatus?: CallStatus;
  readonly getDisplayUsername?: (username: string) => Promise<string>;
}

const ConversationItem = memo<ConversationItemProps>(({
  conversation,
  isSelected,
  onSelect,
  onRemove,
  formatTime,
  callStatus,
  getDisplayUsername
}) => {
  const [resolvedName, setResolvedName] = useState<string | null>(null);

  // Stabilize the resolver function to avoid effect churn when parent re-renders
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

  const avatarColor = useMemo(() =>
    isSelected ? 'rgba(255, 255, 255, 0.2)' : getAvatarColor(conversation.username),
    [isSelected, conversation.username]
  );

  const handleClick = useCallback(() => {
    onSelect(conversation.username);
  }, [onSelect, conversation.username]);

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
      <div
        className="w-10 h-10 rounded-full flex items-center justify-center font-medium text-sm flex-shrink-0 select-none"
        style={{
          backgroundColor: avatarColor,
          color: 'white'
        }}
        aria-hidden="true"
      >
        {displayName.trim().charAt(0).toUpperCase()}
      </div>

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
              {formatTime(conversation.lastMessageTime)}
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

      {callStatus && (
        <div
          className={cn(
            "text-xs px-2 py-1 rounded-full font-medium flex-shrink-0",
            callStatus === 'ringing' && "bg-yellow-100 text-yellow-800",
            callStatus === 'connecting' && "bg-blue-100 text-blue-800",
            callStatus === 'connected' && "bg-green-100 text-green-800"
          )}
          role="status"
          aria-label={`Call status: ${callStatus}`}
        >
          {callStatus === 'ringing' && "📞"}
          {callStatus === 'connecting' && "🔄"}
          {callStatus === 'connected' && "📞"}
        </div>
      )}

      {onRemove && (
        <Button
          variant="ghost"
          size="sm"
          onClick={handleRemove}
          className="absolute bottom-1 right-1 opacity-0 group-hover:opacity-100 transition-opacity p-1 h-6 w-6"
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
  );
});

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

  const handleRemoveClick = useCallback((username: string) => {
    setConversationToDelete(username);
    setShowConfirmDialog(true);
  }, []);

  const handleConfirmRemove = useCallback(() => {
    if (conversationToDelete && onRemoveConversation) {
      onRemoveConversation(conversationToDelete);
    }
    setShowConfirmDialog(false);
    setConversationToDelete(null);
  }, [conversationToDelete, onRemoveConversation]);

  const handleCancelRemove = useCallback(() => {
    setShowConfirmDialog(false);
    setConversationToDelete(null);
  }, []);

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

  useEffect(() => {
    const handler = (e: Event) => {
      try {
        const ce = e as CustomEvent;
        const detail = ce.detail;
        if (!detail || typeof detail !== 'object') return;

        const { peer, status } = detail as { peer?: unknown; status?: unknown };
        if (typeof peer !== 'string' || typeof status !== 'string') return;

        if (status === 'ringing' || status === 'connecting' || status === 'connected') {
          setActivePeer(peer);
          setActiveStatus(status as CallStatus);
        } else {
          setActivePeer(prev => (prev === peer ? null : prev));
          setActiveStatus(null);
        }
      } catch { }
    };

    window.addEventListener('ui-call-status', handler as EventListener);
    return () => window.removeEventListener('ui-call-status', handler as EventListener);
  }, []);

  const formatTime = useCallback((date?: Date): string => {
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
    return `${days}d`;
  }, []);

  const displayUsername = useMemo(() => {
    if (!conversationToDelete) return 'User';
    return /^[a-f0-9]{32,}$/i.test(conversationToDelete) ? 'User' : conversationToDelete;
  }, [conversationToDelete]);

  return (
    <div className="flex flex-col h-full">
      {showNewChatInput && (
        <div className="p-4 space-y-4">
          <div className="relative">
            <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Username"
              value={newChatUsername}
              onChange={(e) => setNewChatUsername(e.target.value)}
              className="pl-8 select-none"
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
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
              className="text-center text-xs py-8"
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
                  formatTime={formatTime}
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