import React, { memo, useMemo, useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "../../../lib/utils/shared-utils";
import { ScrollArea } from "../../ui/scroll-area";
import { Button } from "../../ui/button";
import { Dialog, DialogContent, DialogTitle, DialogDescription } from "../../ui/dialog";
import { Trash2, Search, Phone, Video, Loader2, Pin, PinOff } from "lucide-react";
import { Input } from "../../ui/input";
import { toast } from "sonner";
import { UserAvatar } from "../../ui/UserAvatar";
import { isPlainObject, hasPrototypePollutionKeys, sanitizeUiText } from "../../../lib/sanitizers";
import { EventType } from "../../../lib/types/event-types";
import { UI_CALL_STATUS_RATE_WINDOW_MS, UI_CALL_STATUS_RATE_MAX, MAX_UI_CALL_STATUS_PEER_LENGTH, MAX_UI_CALL_STATUS_VALUE_LENGTH } from "../../../lib/constants";
import { formatRelativeAge } from "../../../lib/utils/date-utils";
import { SecureCanvasText } from "./SecureCanvasText";
import { UnreadIndicator } from "./UnreadIndicator";
import { useDisplayUsername } from "../../../hooks/database/useDisplayUsername";

export interface Conversation {
  readonly id: string;
  readonly username: string;
  readonly inboxId?: string;
  readonly isOnline: boolean;
  readonly lastMessage?: string;
  readonly lastMessageTime?: Date;
  readonly unreadCount?: number;
  readonly displayName?: string;
  readonly secureContentId?: string;
  readonly isPinned?: boolean;
  readonly pinnedAt?: number;
}

interface ConversationListProps {
  readonly conversations: ReadonlyArray<Conversation>;
  readonly selectedConversation?: string;
  readonly onSelectConversation: (username: string) => void;
  readonly onRemoveConversation?: (username: string) => void;
  readonly onAddConversation?: (username: string) => Promise<void>;
  readonly getDisplayUsername?: (username: string) => Promise<string>;
  readonly showNewChatInput?: boolean;
  readonly onNewChatOpenChange?: (open: boolean) => void;
  readonly onTogglePin?: (username: string) => void;
}

// Call status type
type CallStatus = { status: 'ringing' | 'connecting' | 'connected'; isVideo: boolean } | null;

interface ConversationItemProps {
  readonly conversation: Conversation;
  readonly isSelected: boolean;
  readonly onSelect: (username: string) => void;
  readonly onRemove?: (username: string) => void;
  readonly callStatus?: CallStatus;
  readonly getDisplayUsername?: (username: string) => Promise<string>;
  readonly onTogglePin?: (username: string) => void;
}

const ConversationItem = memo<ConversationItemProps>(({
  conversation,
  isSelected,
  onSelect,
  onRemove,
  callStatus,
  onTogglePin,
}) => {
  const displayName = useDisplayUsername({ username: conversation.username });

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

  const handleTogglePin = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    if (onTogglePin) {
      onTogglePin(conversation.username);
    }
  }, [onTogglePin, conversation.username]);

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.95 }}
      transition={{ 
        layout: { type: "spring", stiffness: 600, damping: 45, mass: 1 },
        opacity: { duration: 0.2 }
      }}
      className={cn(
        "qor-conversation-item group",
        isSelected && "is-selected"
      )}
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
        className={cn("qor-conversation-avatar", isSelected && 'opacity-80')}
      />

      <div className="qor-conversation-main">
        <div className="qor-conversation-title-row">
          <span
            className={cn(
              "qor-conversation-name",
              !isSelected && (conversation.unreadCount ?? 0) > 0 ? "font-bold" : "font-medium"
            )}
            title={displayName}
          >
            {displayName}
          </span>
          {conversation.lastMessageTime && (
            <span
              className={cn(
                "qor-conversation-time",
                !isSelected && (conversation.unreadCount ?? 0) > 0 && "font-bold"
              )}
            >
              {formatRelativeAge(conversation.lastMessageTime)}
            </span>
          )}
        </div>

        {/* Show unread indicator if there are unread messages and conversation is not selected */}
        {!isSelected && (conversation.unreadCount ?? 0) > 0 ? (
          <div className="qor-conversation-preview">
            <UnreadIndicator count={conversation.unreadCount ?? 0} isSelected={isSelected} />
          </div>
        ) : (conversation.lastMessage || conversation.secureContentId) ? (
          <div
            className="qor-conversation-preview"
            title={conversation.lastMessage}
          >
            <SecureCanvasText
              messageId={conversation.secureContentId || conversation.id}
              maxWidth={200}
              fontSize={12}
              color="inherit"
            />
          </div>
        ) : null}
      </div>

      {(callStatus || onRemove || onTogglePin) && (
        <div className="qor-conversation-controls">
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

          {onTogglePin && (
            <Button
              variant="ghost"
              size="sm"
              onClick={handleTogglePin}
              className={cn(
                "qor-conversation-tiny-btn",
                conversation.isPinned ? "opacity-100" : "opacity-0 group-hover:opacity-100"
              )}
              aria-label={`${conversation.isPinned ? 'Unpin' : 'Pin'} conversation with ${displayName}`}
            >
              {conversation.isPinned ? <PinOff className="h-3 w-3" /> : <Pin className="h-3 w-3" />}
            </Button>
          )}

          {onRemove && (
            <Button
              variant="ghost"
              size="sm"
              onClick={handleRemove}
              className="qor-conversation-tiny-btn danger opacity-0 group-hover:opacity-100"
              aria-label={`Remove conversation with ${displayName}`}
            >
              <Trash2 className="h-3 w-3" />
            </Button>
          )}
        </div>
      )}
    </motion.div>
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
  showNewChatInput = false,
  onNewChatOpenChange,
  onTogglePin
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
      onNewChatOpenChange?.(false);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to add conversation");
    } finally {
      setIsAdding(false);
    }
  }, [newChatUsername, onAddConversation, onNewChatOpenChange]);

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

  const [_refreshTick, setRefreshTick] = useState(0);

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

  const deleteConversationDisplayName = useDisplayUsername({ username: conversationToDelete || '' });
  const displayUsername = deleteConversationDisplayName || conversationToDelete || 'User';

  const { pinnedChats, unpinnedChats } = useMemo(() => {
    const pinned: Conversation[] = [];
    const unpinned: Conversation[] = [];

    for (const c of conversations) {
      if (c.isPinned) {
        pinned.push(c);
      } else {
        unpinned.push(c);
      }
    }

    pinned.sort((a, b) => (b.pinnedAt || 0) - (a.pinnedAt || 0));

    return { pinnedChats: pinned, unpinnedChats: unpinned };
  }, [conversations]);

  const itemsToRender = useMemo(() => {
    const result: ({ type: 'header'; label: string; id: string } | { type: 'conversation'; data: Conversation })[] = [];
    
    if (pinnedChats.length > 0) {
      result.push({ type: 'header', label: 'PINNED CHATS', id: 'header-pinned' });
      pinnedChats.forEach(c => result.push({ type: 'conversation', data: c }));
    }
    
    if (unpinnedChats.length > 0) {
      if (pinnedChats.length > 0) {
        result.push({ type: 'header', label: 'CHATS', id: 'header-unpinned' });
      }
      unpinnedChats.forEach(c => result.push({ type: 'conversation', data: c }));
    }
    
    return result;
  }, [pinnedChats, unpinnedChats]);

  const handleNewChatOpenChange = useCallback((open: boolean) => {
    onNewChatOpenChange?.(open);
    if (!open) {
      setNewChatUsername("");
    }
  }, [onNewChatOpenChange]);

  return (
    <div className="qor-conversation-list">
      <Dialog open={showNewChatInput} onOpenChange={handleNewChatOpenChange}>
        <DialogContent
          className="qor-conversation-dialog"
          role="dialog"
          aria-modal="true"
          aria-labelledby="conversation-modal-title"
          aria-describedby="conversation-modal-description"
        >
          <div className="qor-conversation-modal-head">
            <div className="qor-conversation-modal-title">
              <DialogTitle id="conversation-modal-title">Add conversation</DialogTitle>
              <DialogDescription id="conversation-modal-description">Find a user, start a chat, or manage blocked users.</DialogDescription>
            </div>
            <button
              type="button"
              className="qor-conversation-close"
              onClick={() => handleNewChatOpenChange(false)}
              aria-label="Back to empty screen"
            />
          </div>

          <div className="qor-conversation-modal-body">
            <div className="qor-conversation-modal-controls">
              <label className="qor-conversation-modal-search" aria-label="Search users">
                {isAdding ? (
                  <Loader2 className="animate-spin" aria-hidden="true" />
                ) : (
                  <Search aria-hidden="true" />
                )}
                <Input
                  type="search"
                  placeholder="Search username"
                  value={newChatUsername}
                  onChange={(e) => setNewChatUsername(e.target.value)}
                  className="qor-conversation-search-input"
                  disabled={isAdding}
                  autoFocus
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !isAdding) {
                      handleAddChat();
                    }
                  }}
                />
              </label>
            </div>

            <div className="conversation-empty qor-add-conversation-empty">
              <div className="conversation-empty-copy">
                <h2>No users found</h2>
                <p>When a username is available, it will show here with the same chat, block, and call controls.</p>
              </div>
              <div className="conversation-empty-lines" aria-hidden="true">
                {Array.from({ length: 9 }).map((_, index) => (
                  <span key={index} />
                ))}
              </div>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {conversations.length === 0 ? (
        <div className="qor-conversation-static">
          <div className="qor-conversation-scroll-inner">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="qor-conversation-empty"
            >
              <div>
                <h3>No conversations yet</h3>
              </div>
              <div className="conversation-empty-lines qor-conversation-empty-lines" aria-hidden="true">
                {Array.from({ length: 9 }).map((_, index) => (
                  <span key={index} />
                ))}
              </div>
            </motion.div>
          </div>
        </div>
      ) : (
        <ScrollArea className="qor-conversation-scroll">
          <div className="qor-conversation-scroll-inner">
            <div className="qor-conversation-items">
              <AnimatePresence initial={false} mode="popLayout">
                {itemsToRender.map((item) => {
                  if (item.type === 'header') {
                    return (
                      <motion.div
                        key={item.id}
                        layout
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="qor-conversation-section-label"
                      >
                        {item.label}
                      </motion.div>
                    );
                  }
                  
                  const conversation = item.data;
                  return (
                    <ConversationItem
                      key={conversation.id}
                      conversation={conversation}
                      isSelected={selectedConversation === conversation.username}
                      onSelect={onSelectConversation}
                      onRemove={handleRemoveClick}
                      onTogglePin={onTogglePin}
                      callStatus={conversation.username === activePeer ? activeStatus : null}
                      getDisplayUsername={getDisplayUsername}
                    />
                  );
                })}
              </AnimatePresence>
            </div>
          </div>
        </ScrollArea>
      )}

      <Dialog open={showConfirmDialog} onOpenChange={setShowConfirmDialog}>
        <DialogContent
          className="remove-dialog"
          role="dialog"
          aria-modal="true"
          aria-labelledby="remove-title"
          aria-describedby="remove-description"
        >
          <div className="dialog-head">
            <div className="danger-mark" aria-hidden="true">
              <svg viewBox="0 0 24 24">
                <path d="M12 9v4m0 4h.01M10.3 3.9 2.6 17.2A2.4 2.4 0 0 0 4.7 21h14.6a2.4 2.4 0 0 0 2.1-3.8L13.7 3.9a2 2 0 0 0-3.4 0Z" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </div>
            <DialogTitle className="dialog-title" id="remove-title">Remove conversation?</DialogTitle>
            <DialogDescription className="dialog-copy" id="remove-description">
              This removes the conversation from this device. Messages with this user will no longer appear in your chat list.
            </DialogDescription>
          </div>
          <div className="target-user">
            <div className="avatar" aria-hidden="true" />
            <div><strong>{displayUsername}</strong></div>
          </div>
          <div className="dialog-actions">
            <button className="dialog-button" type="button" onClick={handleCancelRemove} aria-label="Cancel removal">
              Cancel
            </button>
            <button className="dialog-button remove" type="button" onClick={handleConfirmRemove} aria-label="Confirm removal">
              Remove
            </button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
});
