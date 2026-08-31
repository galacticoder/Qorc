import React, { memo, useMemo, useEffect, useState, useCallback } from "react";
import { motion } from "framer-motion";
import { cn } from "../../../lib/utils/shared-utils";
import { ScrollArea } from "../../ui/scroll-area";
import { Button } from "../../ui/button";
import { Dialog, DialogContent, DialogTitle, DialogDescription } from "../../ui/dialog";
import { Trash2, Search, Phone, Video, Loader2, Pin, X, Plus } from "lucide-react";
import { Input } from "../../ui/input";
import { toast } from "sonner";
import { UserAvatar } from "../../ui/UserAvatar";
import { isPlainObject, hasPrototypePollutionKeys, sanitizeUiText } from "../../../lib/sanitizers";
import { EventType } from "../../../lib/types/event-types";
import { blockingSystem } from "../../../lib/blocking/blocking-system";
import { UI_CALL_STATUS_RATE_WINDOW_MS, UI_CALL_STATUS_RATE_MAX, MAX_UI_CALL_STATUS_PEER_LENGTH, MAX_UI_CALL_STATUS_VALUE_LENGTH } from "../../../lib/constants";
import { formatRelativeAge } from "../../../lib/utils/date-utils";
import { BannerMessagePreview } from "../ChatInput/BannerMessagePreview";
import { UnreadIndicator } from "./UnreadIndicator";
import { useDisplayUsername } from "../../../hooks/database/useDisplayUsername";
import { useTypingIndicatorContext } from "../../../contexts/TypingIndicatorContext";
import { CallIcon } from "../assets/icons";
import { ConversationOptionsPopover } from "./ConversationOptionsPopover";

export interface Conversation {
  readonly id: string;
  readonly username: string;
  readonly lastMessage?: string;
  readonly lastMessageTime?: Date;
  readonly unreadCount?: number;
  readonly displayName?: string;
  readonly secureContentId?: string;
  readonly contentVersion?: string;
  readonly isPinned?: boolean;
  readonly pinnedAt?: number;
}

interface ConversationListProps {
  readonly currentUsername: string;
  readonly conversations: ReadonlyArray<Conversation>;
  readonly selectedConversation?: string;
  readonly onSelectConversation: (username: string) => void;
  readonly onRemoveConversation?: (username: string) => void;
  readonly onAddConversation?: (username: string, signal?: AbortSignal) => Promise<void>;
  readonly getDisplayUsername?: (username: string) => Promise<string>;
  readonly showNewChatInput?: boolean;
  readonly onNewChatOpenChange?: (open: boolean) => void;
  readonly onTogglePin?: (username: string) => void;
  readonly onStartCall?: (username: string, type: 'audio' | 'video') => void;
  readonly onToggleBlock?: (username: string, nextBlocked: boolean) => void | Promise<void>;
}

// Call status type
type CallStatus = { status: 'ringing' | 'connecting' | 'connected'; isVideo: boolean } | null;

interface ConversationItemProps {
  readonly conversation: Conversation;
  readonly isSelected: boolean;
  readonly onSelect: (username: string) => void;
  readonly onRemove?: (username: string) => void;
  readonly callStatus?: CallStatus;
  readonly isTyping: boolean;
  readonly getDisplayUsername?: (username: string) => Promise<string>;
  readonly onTogglePin?: (username: string) => void;
}

const ConversationItem = memo<ConversationItemProps>(({
  conversation,
  isSelected,
  onSelect,
  onRemove,
  callStatus,
  isTyping,
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
    <div
      className={cn(
        "qorc-conversation-item group",
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
        className={cn("qorc-conversation-avatar", isSelected && 'opacity-80')}
      />

      <div className="qorc-conversation-main">
        <div className="qorc-conversation-title-row">
          <span
            className={cn(
              "qorc-conversation-name",
              !isSelected && (conversation.unreadCount ?? 0) > 0 ? "font-bold" : "font-medium"
            )}
            title={displayName}
          >
            {displayName}
          </span>
          {(onTogglePin || onRemove) && (
            <div
              className={cn(
                "qorc-conversation-action-pill",
                conversation.isPinned && "is-pinned"
              )}
            >
              {onTogglePin && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleTogglePin}
                  className="qorc-conversation-tiny-btn"
                  aria-label={`${conversation.isPinned ? 'Unpin' : 'Pin'} conversation with ${displayName}`}
                  aria-pressed={conversation.isPinned}
                >
                  <Pin
                    className="h-3 w-3"
                    fill={conversation.isPinned ? "currentColor" : "none"}
                  />
                </Button>
              )}

              {onRemove && !conversation.isPinned && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleRemove}
                  className="qorc-conversation-tiny-btn danger"
                  aria-label={`Remove conversation with ${displayName}`}
                >
                  <Trash2 className="h-3 w-3" />
                </Button>
              )}
            </div>
          )}
          {conversation.lastMessageTime && (
            <span
              className={cn(
                "qorc-conversation-time",
                !isSelected && (conversation.unreadCount ?? 0) > 0 && "font-bold"
              )}
            >
              {formatRelativeAge(conversation.lastMessageTime)}
            </span>
          )}
        </div>

        {/* Show unread indicator if there are unread messages and conversation is not selected */}
        {isTyping && conversation.lastMessageTime ? (
          <div
            className="qorc-conversation-preview qorc-conversation-preview-typing"
            role="status"
            aria-label={`${displayName} is typing`}
          >
            <span>Typing</span>
            <span className="qorc-conversation-typing-dots" aria-hidden="true">
              <span />
              <span />
              <span />
            </span>
          </div>
        ) : !isSelected && (conversation.unreadCount ?? 0) > 0 ? (
          <div className="qorc-conversation-preview">
            <UnreadIndicator count={conversation.unreadCount ?? 0} isSelected={isSelected} />
          </div>
        ) : conversation.secureContentId ? (
          <div className="qorc-conversation-preview">
            <BannerMessagePreview
              messageId={conversation.secureContentId}
              contentVersion={`${conversation.contentVersion ?? ''}:${isSelected ? 'selected' : 'default'}`}
              maxWidth={800}
              fontSize={12}
              color="var(--qorc-conversation-preview-text)"
              className="qorc-conversation-secure-message-preview"
            />
          </div>
        ) : conversation.lastMessage ? (
          <div
            className="qorc-conversation-preview"
            title={conversation.lastMessage}
          >
            {conversation.lastMessage}
          </div>
        ) : null}
      </div>

      {callStatus && (
        <div className="qorc-conversation-controls">
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
        </div>
      )}
    </div>
  );
});

// manageable row inside add conversation modal
interface ConversationManageRowProps {
  readonly username: string;
  readonly blocked: boolean;
  readonly onChat: (username: string) => void;
  readonly onCall?: (username: string, type: 'audio' | 'video') => void;
  readonly onToggleBlock?: (username: string, nextBlocked: boolean) => void | Promise<void>;
}

const ConversationManageRow = memo<ConversationManageRowProps>(({
  username,
  blocked,
  onChat,
  onCall,
  onToggleBlock,
}) => {
  const displayName = useDisplayUsername({ username });

  return (
    <div
      className="qorc-cm-row"
      role="button"
      tabIndex={0}
      onClick={() => onChat(username)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onChat(username);
        }
      }}
      aria-label={`Open chat with ${displayName}`}
    >
      <UserAvatar username={username} size="md" className="qorc-cm-row-avatar" />

      <div className="qorc-cm-row-main">
        <span className="qorc-cm-row-name" title={displayName}>{displayName}</span>
        {displayName.toLowerCase() !== username.toLowerCase() && (
          <span className="qorc-cm-row-username" title={username}>@{username}</span>
        )}
      </div>

      <div className="qorc-call-pill qorc-cm-row-actions" onClick={(e) => e.stopPropagation()}>
        <Button
          size="sm"
          variant="outline"
          className="qorc-call-pill-btn"
          title="Audio call"
          aria-label={`Call ${displayName}`}
          disabled={blocked || !onCall}
          onClick={() => onCall?.(username, 'audio')}
        >
          <CallIcon className="w-4 h-4" aria-hidden="true" />
        </Button>
        <Button
          size="sm"
          variant="outline"
          className="qorc-call-pill-btn"
          title="Video call"
          aria-label={`Video call ${displayName}`}
          disabled={blocked || !onCall}
          onClick={() => onCall?.(username, 'video')}
        >
          <Video className="w-4 h-4" aria-hidden="true" />
        </Button>
        <ConversationOptionsPopover
          username={username}
          blocked={blocked}
          onToggleBlock={onToggleBlock}
          ariaLabel={`Conversation options for ${displayName}`}
        />
      </div>
    </div>
  );
});

// Main conversation list component
export const ConversationList = memo<ConversationListProps>(function ConversationList({
  currentUsername,
  conversations,
  selectedConversation,
  onSelectConversation,
  onRemoveConversation,
  onAddConversation,
  getDisplayUsername,
  showNewChatInput = false,
  onNewChatOpenChange,
  onTogglePin,
  onStartCall,
  onToggleBlock
}: ConversationListProps) {
  const { typingUsers } = useTypingIndicatorContext();
  const [activePeer, setActivePeer] = useState<string | null>(null);
  const [activeStatus, setActiveStatus] = useState<CallStatus>(null);
  const [showConfirmDialog, setShowConfirmDialog] = useState<boolean>(false);
  const [conversationToDelete, setConversationToDelete] = useState<string | null>(null);
  const [newChatUsername, setNewChatUsername] = useState("");
  const [isAdding, setIsAdding] = useState(false);
  const activeDiscoveryRef = React.useRef<AbortController | null>(null);
  const [blockVersion, setBlockVersion] = useState(0);
  const typingUserSet = useMemo(() => new Set(typingUsers), [typingUsers]);

  useEffect(() => {
    const bump = () => setBlockVersion((v) => v + 1);
    window.addEventListener(EventType.BLOCK_STATUS_CHANGED, bump as EventListener);
    window.addEventListener(EventType.USER_BLOCKED, bump as EventListener);
    window.addEventListener(EventType.USER_UNBLOCKED, bump as EventListener);
    return () => {
      window.removeEventListener(EventType.BLOCK_STATUS_CHANGED, bump as EventListener);
      window.removeEventListener(EventType.USER_BLOCKED, bump as EventListener);
      window.removeEventListener(EventType.USER_UNBLOCKED, bump as EventListener);
    };
  }, []);

  // Conversations shown in modal
  const trimmedQuery = newChatUsername.trim().toLowerCase();
  const filteredConversations = useMemo(() => {
    if (!trimmedQuery) return conversations;
    return conversations.filter((c) =>
      c.username.toLowerCase().includes(trimmedQuery) ||
      (c.displayName ?? "").toLowerCase().includes(trimmedQuery)
    );
  }, [conversations, trimmedQuery]);

  const hasExactMatch = useMemo(
    () => conversations.some((c) => c.username.toLowerCase() === trimmedQuery),
    [conversations, trimmedQuery]
  );
  const canAddTyped = !!newChatUsername.trim() && !hasExactMatch && !!onAddConversation;

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
  }, [conversationToDelete, onRemoveConversation]);

  // Handle cancel removal
  const handleCancelRemove = useCallback(() => {
    setShowConfirmDialog(false);
  }, []);

  const handleRemoveDialogOpenChange = useCallback((open: boolean) => {
    setShowConfirmDialog(open);
  }, []);

  const cancelActiveDiscovery = useCallback(() => {
    const controller = activeDiscoveryRef.current;
    if (!controller) return;
    activeDiscoveryRef.current = null;
    controller.abort();
    setIsAdding(false);
  }, []);

  useEffect(() => () => {
    activeDiscoveryRef.current?.abort();
    activeDiscoveryRef.current = null;
  }, []);

  // Handle add new chat
  const handleAddChat = useCallback(async () => {
    const username = newChatUsername.trim();
    if (!username || !onAddConversation || activeDiscoveryRef.current) return;

    const controller = new AbortController();
    activeDiscoveryRef.current = controller;
    setIsAdding(true);
    try {
      await onAddConversation(username, controller.signal);
      if (controller.signal.aborted) return;
      setNewChatUsername("");
      onNewChatOpenChange?.(false);
    } catch (error) {
      if (controller.signal.aborted || (error instanceof Error && error.name === 'AbortError')) return;
      toast.error(error instanceof Error ? error.message : "Failed to add conversation");
    } finally {
      if (activeDiscoveryRef.current === controller) {
        activeDiscoveryRef.current = null;
        setIsAdding(false);
      }
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
      if ((detail as any).account !== currentUsername || !currentUsername) return;

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
  }, [currentUsername]);

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
    if (!open) {
      cancelActiveDiscovery();
      setNewChatUsername("");
    }
    onNewChatOpenChange?.(open);
  }, [cancelActiveDiscovery, onNewChatOpenChange]);

  const handleChatFromModal = useCallback((username: string) => {
    onSelectConversation(username);
    handleNewChatOpenChange(false);
  }, [onSelectConversation, handleNewChatOpenChange]);

  return (
    <div className="qorc-conversation-list">
      <Dialog open={showNewChatInput} onOpenChange={handleNewChatOpenChange}>
        <DialogContent
          className="qorc-cm-dialog"
          role="dialog"
          aria-modal="true"
          aria-labelledby="conversation-modal-title"
        >
          <div className="qorc-cm-head">
            <div className="qorc-cm-head-text">
              <DialogTitle id="conversation-modal-title">Add and manage your conversations</DialogTitle>
            </div>
            <button
              type="button"
              className="qorc-cm-close"
              onClick={() => handleNewChatOpenChange(false)}
              aria-label="Close"
            >
              <X aria-hidden="true" />
            </button>
          </div>

          <div className={cn("qorc-cm-search", isAdding && "is-searching")}>
            <span className="qorc-cm-search-icon" aria-hidden="true">
              {isAdding ? <Loader2 className="animate-spin" /> : <Search />}
            </span>
            <Input
              type="text"
              placeholder="Search or enter a username"
              value={newChatUsername}
              onChange={(e) => setNewChatUsername(e.target.value)}
              className="qorc-cm-search-input"
              disabled={isAdding}
              autoFocus
              spellCheck={false}
              autoComplete="off"
              aria-label="Search conversations or enter a username"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !isAdding && canAddTyped) {
                  handleAddChat();
                }
              }}
            />
            {isAdding && (
              <button
                type="button"
                className="qorc-cm-search-cancel"
                onClick={cancelActiveDiscovery}
                aria-label="Cancel user search"
                title="Cancel search"
              >
                <X aria-hidden="true" />
              </button>
            )}
          </div>

          {(filteredConversations.length > 0 || canAddTyped) ? (
            <ScrollArea className="qorc-cm-body">
              <div className="qorc-cm-scroll-inner">
                {canAddTyped && (
                  <button
                    type="button"
                    className="qorc-cm-add-row"
                    onClick={handleAddChat}
                    disabled={isAdding}
                  >
                    <span className="qorc-cm-add-icon" aria-hidden="true">
                      {isAdding ? <Loader2 className="animate-spin" /> : <Plus />}
                    </span>
                    <span className="qorc-cm-add-copy">
                      <strong className="qorc-cm-add-name">{newChatUsername.trim()}</strong>
                      <span className="qorc-cm-add-text">Start a new conversation</span>
                    </span>
                  </button>
                )}

                {filteredConversations.length > 0 && (
                  <div className="qorc-cm-list" data-block-version={blockVersion}>
                    {filteredConversations.map((c) => (
                      <ConversationManageRow
                        key={c.id}
                        username={c.username}
                        blocked={blockingSystem.isBlockedSync(c.username)}
                        onChat={handleChatFromModal}
                        onCall={onStartCall}
                        onToggleBlock={onToggleBlock}
                      />
                    ))}
                  </div>
                )}
              </div>
            </ScrollArea>
          ) : (
            <div className="qorc-cm-body qorc-cm-body-static">
              <div className="qorc-cm-scroll-inner">
                <div className="qorc-cm-empty">
                  <span className="qorc-cm-empty-icon" aria-hidden="true">
                    <Search />
                  </span>
                  <div className="qorc-cm-empty-copy">
                    <h3>{trimmedQuery ? "No matches" : "No conversations yet"}</h3>
                    <p>
                      {trimmedQuery
                        ? "Type a full username above to start a new chat."
                        : "Search a username above to start your first conversation."}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {conversations.length === 0 ? (
        <div className="qorc-conversation-static">
          <div className="qorc-conversation-scroll-inner">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="qorc-conversation-empty"
            >
              <div>
                <h3>No conversations yet</h3>
              </div>
              <div className="conversation-empty-lines qorc-conversation-empty-lines" aria-hidden="true">
                {Array.from({ length: 14 }).map((_, index) => (
                  <span key={index} />
                ))}
              </div>
            </motion.div>
          </div>
        </div>
      ) : (
        <ScrollArea className="qorc-conversation-scroll">
          <div className="qorc-conversation-scroll-inner">
            <div className="qorc-conversation-items">
              {itemsToRender.map((item) => {
                if (item.type === 'header') {
                  return (
                    <div key={item.id} className="qorc-conversation-section-label">
                      {item.label}
                    </div>
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
                    isTyping={typingUserSet.has(conversation.username) && Boolean(conversation.lastMessageTime)}
                    getDisplayUsername={getDisplayUsername}
                  />
                );
              })}
            </div>
          </div>
        </ScrollArea>
      )}

      <Dialog open={showConfirmDialog} onOpenChange={handleRemoveDialogOpenChange}>
        <DialogContent
          className="qorc-delete-conversation-dialog"
          role="dialog"
          aria-modal="true"
          aria-labelledby="delete-conversation-title"
          aria-describedby="delete-conversation-description"
        >
          <div className="qorc-delete-conversation-head">
            <div className="qorc-delete-conversation-head-copy">
              <DialogTitle id="delete-conversation-title">Delete conversation</DialogTitle>
              <DialogDescription id="delete-conversation-description">
                This permanently deletes this conversation and its messages from this device. This cannot be undone.
              </DialogDescription>
            </div>
            <button
              type="button"
              className="qorc-delete-conversation-close"
              onClick={handleCancelRemove}
              aria-label="Close delete conversation dialog"
              title="Close"
            >
              <X aria-hidden="true" />
            </button>
          </div>

          <div className="qorc-delete-conversation-target">
            <UserAvatar
              username={conversationToDelete || ''}
              size="md"
              className="qorc-delete-conversation-avatar"
            />
            <div className="qorc-delete-conversation-user-copy">
              <span className="qorc-delete-conversation-name" title={displayUsername}>{displayUsername}</span>
              {conversationToDelete && displayUsername.toLowerCase() !== conversationToDelete.toLowerCase() && (
                <span className="qorc-delete-conversation-username" title={conversationToDelete}>@{conversationToDelete}</span>
              )}
            </div>
            <button
              className="qorc-delete-conversation-delete"
              type="button"
              onClick={handleConfirmRemove}
              aria-label="Delete conversation"
            >
              <Trash2 aria-hidden="true" />
              Delete
            </button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
});
