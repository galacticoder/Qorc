import React, { memo, useMemo, useEffect, useLayoutEffect, useState, useCallback } from "react";
import { createPortal } from "react-dom";
import { motion } from "framer-motion";
import { cn } from "../../../lib/utils/shared-utils";
import { ScrollArea } from "../../ui/scroll-area";
import { Dialog, DialogContent, DialogTitle, DialogDescription } from "../../ui/dialog";
import { ArrowLeft, BellOff, Trash2, Search, Video, Loader2, Pin, X, Plus } from "lucide-react";
import { Input } from "../../ui/input";
import { toast } from "sonner";
import { UserAvatar } from "../../ui/UserAvatar";
import { isPlainObject, hasPrototypePollutionKeys, sanitizeUiText } from "../../../lib/sanitizers";
import { EventType } from "../../../lib/types/event-types";
import { blockingSystem } from "../../../lib/blocking/blocking-system";
import {
  UI_CALL_STATUS_RATE_WINDOW_MS,
  UI_CALL_STATUS_RATE_MAX,
  MAX_UI_CALL_STATUS_PEER_LENGTH,
  MAX_UI_CALL_STATUS_VALUE_LENGTH,
} from '../../../lib/constants';
import { RelativeMessageTime } from './RelativeMessageTime';
import { BannerMessagePreview } from "../ChatInput/BannerMessagePreview";
import { UnreadIndicator } from "./UnreadIndicator";
import { TypingBubble } from "./TypingIndicator";
import { useDisplayUsername } from "../../../hooks/database/useDisplayUsername";
import { useTypingIndicatorContext } from "../../../contexts/TypingIndicatorContext";
import { CallIcon } from "../assets/icons";
import { ConversationOptionsPopover } from "./ConversationOptionsPopover";
import { useNotificationPreferences } from '../../../hooks/useNotificationPreferences';
import { getNotificationMutes } from '../../../lib/ui/notification-preferences';
import type { DiscoveryProgress, DiscoveryProgressObserver } from "../../../lib/discovery/progress";
import { useMobileLayout } from '../../../hooks/useMobileLayout';
import { ConversationSwipeRow } from './ConversationSwipeRow';
import { useAppBack } from '../../../hooks/useAppBack';
import { groupConversationsByLetter } from '../../../lib/ui/conversation-order';
import { animateView } from '../../../lib/ui/motion';

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

export type ConversationDialogMode = 'manage' | 'block';

interface ConversationListProps {
  readonly currentUsername: string;
  readonly conversations: ReadonlyArray<Conversation>;
  readonly selectedConversation?: string;
  readonly onSelectConversation: (username: string) => void;
  readonly onRemoveConversation: (username: string) => void;
  readonly onAddConversation: (username: string, signal?: AbortSignal, onProgress?: DiscoveryProgressObserver) => Promise<void>;
  readonly showNewChatInput?: boolean;
  readonly onNewChatOpenChange: (open: boolean) => void;
  readonly onTogglePin: (username: string) => void;
  readonly onStartCall: (username: string, type: 'audio' | 'video') => void;
  readonly onToggleBlock: (username: string, nextBlocked: boolean) => void | Promise<void>;
  readonly conversationDialogMode?: ConversationDialogMode;
  readonly onBlockConversation: (username: string) => void | Promise<void>;
}

// Call status type
type CallStatus = { status: 'ringing' | 'connecting' | 'connected'; isVideo: boolean; incoming: boolean } | null;

interface ConversationItemProps {
  readonly mobile: boolean;
  readonly actionsOpen: boolean;
  readonly onActionsOpenChange: (username: string, open: boolean) => void;
  readonly blocked: boolean;
  readonly onToggleBlock: (username: string, nextBlocked: boolean) => void | Promise<void>;
  readonly conversation: Conversation;
  readonly isSelected: boolean;
  readonly onSelect: (username: string) => void;
  readonly onRemove: (username: string) => void;
  readonly callStatus?: CallStatus;
  readonly isTyping: boolean;
  readonly onTogglePin: (username: string) => void;
}

const ConversationItem = memo<ConversationItemProps>(({
  mobile,
  actionsOpen,
  onActionsOpenChange,
  blocked,
  onToggleBlock,
  conversation,
  isSelected,
  onSelect,
  onRemove,
  callStatus: receivedCallStatus,
  isTyping,
  onTogglePin,
}) => {
  const displayName = useDisplayUsername({ username: conversation.username });
  const preferences = useNotificationPreferences();
  const muted = getNotificationMutes(conversation.username, preferences);
  const muteLabel = muted.messages && muted.calls ? 'Message and call alerts muted' : muted.messages ? 'Message alerts muted' : 'Call alerts muted';
  const callStatus = muted.calls && receivedCallStatus?.incoming && receivedCallStatus.status === 'ringing' ? null : receivedCallStatus;
  const callStatusLabel = callStatus?.status === 'connected' ? 'Active call'
    : callStatus?.status === 'connecting' ? 'Connecting call'
      : callStatus?.incoming ? 'Incoming call' : 'Calling';

  // Handle conversation selection
  const handleClick = useCallback(() => {
    onSelect(conversation.username);
  }, [onSelect, conversation.username]);

  const setActionsOpen = useCallback((open: boolean) => onActionsOpenChange(conversation.username, open), [conversation.username, onActionsOpenChange]);
  const closeActions = useCallback(() => setActionsOpen(false), [setActionsOpen]);

  const actions = <ConversationOptionsPopover
      username={conversation.username}
      blocked={blocked}
      onToggleBlock={onToggleBlock}
      compact
      isPinned={conversation.isPinned}
      onTogglePin={onTogglePin}
      onDeleteConversation={onRemove}
      onAction={mobile ? closeActions : undefined}
      ariaLabel={`Conversation options for ${displayName}`}
    />;

  return (
    <ConversationSwipeRow enabled={mobile} open={actionsOpen} onOpenChange={setActionsOpen} actions={actions} actionWidth={64}>
    <div
      className={cn(
        "qorc-conversation-item group",
        !mobile && isSelected && "is-selected"
      )}
      onClick={handleClick}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.target !== e.currentTarget) return;
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          handleClick();
        }
      }}
      aria-label={`Conversation with ${displayName}`}
      aria-selected={isSelected}
      aria-description={mobile ? 'Swipe right for conversation options, or press the right arrow key.' : undefined}
    >
      <UserAvatar
        username={conversation.username}
        size={mobile ? 'lg' : 'md'}
        className={cn("qorc-conversation-avatar", !mobile && isSelected && 'opacity-80')}
      />

      <div className="qorc-conversation-main">
        <div className="qorc-conversation-title-row">
          {callStatus && (
            <span className="qorc-conversation-call-status" role="status" title={callStatusLabel} aria-label={callStatusLabel}>
              {callStatus.isVideo ? (
                <Video size={16} fill="currentColor" aria-hidden="true" />
              ) : (
                <CallIcon className="fill-current" width={16} height={16} aria-hidden="true" />
              )}
            </span>
          )}
          <span
            className={cn(
              "qorc-conversation-name",
              !isSelected && (conversation.unreadCount ?? 0) > 0 ? "font-bold" : "font-medium"
            )}
            title={displayName}
          >
            {displayName}
          </span>
          {(conversation.isPinned || muted.messages || muted.calls) && (
            <div className="qorc-conversation-status-icons">
              {conversation.isPinned && <span title="Pinned" aria-label="Pinned"><Pin className="h-3 w-3" fill="currentColor" aria-hidden="true" /></span>}
              {(muted.messages || muted.calls) && <span title={muteLabel} aria-label={muteLabel}><BellOff className="h-3 w-3" aria-hidden="true" /></span>}
            </div>
          )}
          {!mobile && <div className="qorc-conversation-action-pill">{actions}</div>}
          {conversation.lastMessageTime && (
            <RelativeMessageTime
              date={conversation.lastMessageTime}
              className={cn(
                "qorc-conversation-time",
                !isSelected && (conversation.unreadCount ?? 0) > 0 && "font-bold"
              )}
            />
          )}
        </div>

        <div className="qorc-conversation-preview-row">
          {isTyping ? (
            <div
              className="qorc-conversation-preview qorc-conversation-preview-typing"
              role="status"
              aria-label={`${displayName} is typing`}
            >
              <TypingBubble compact />
            </div>
          ) : conversation.secureContentId ? (
            <div className="qorc-conversation-preview">
              <BannerMessagePreview
                messageId={conversation.secureContentId}
                contentVersion={`${conversation.contentVersion ?? ''}:${isSelected ? 'selected' : 'default'}`}
                maxWidth={800}
                fontSize={mobile ? 14 : 12}
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
          {!isSelected && (conversation.unreadCount ?? 0) > 0 && (
            <div className="qorc-conversation-controls">
              <UnreadIndicator count={conversation.unreadCount ?? 0} />
            </div>
          )}
        </div>
      </div>
    </div>
    </ConversationSwipeRow>
  );
});

// manageable row inside add conversation modal
interface ConversationManageRowProps {
  readonly mobile: boolean;
  readonly actionsOpen: boolean;
  readonly onActionsOpenChange: (username: string, open: boolean) => void;
  readonly isPinned: boolean;
  readonly onTogglePin: (username: string) => void;
  readonly username: string;
  readonly blocked: boolean;
  readonly mode: ConversationDialogMode;
  readonly onChat: (username: string) => void;
  readonly onCall: (username: string, type: 'audio' | 'video') => void;
  readonly onToggleBlock: (username: string, nextBlocked: boolean) => void | Promise<void>;
  readonly onBlock: (username: string) => void;
  readonly onRemove: (username: string) => void;
  readonly blocking?: boolean;
}

const ConversationManageRow = memo<ConversationManageRowProps>(({
  mobile,
  actionsOpen,
  onActionsOpenChange,
  isPinned,
  onTogglePin,
  username,
  blocked,
  mode,
  onChat,
  onCall,
  onToggleBlock,
  onBlock,
  onRemove,
  blocking = false,
}) => {
  const displayName = useDisplayUsername({ username });
  const swipeEnabled = mobile && mode === 'manage';
  const setActionsOpen = useCallback((open: boolean) => onActionsOpenChange(username, open), [username, onActionsOpenChange]);
  const closeActions = useCallback(() => setActionsOpen(false), [setActionsOpen]);
  const handlePrimaryAction = useCallback(() => {
    if (mode === 'block') {
      onBlock(username);
      return;
    }
    onChat(username);
  }, [mode, onBlock, onChat, username]);

  const actions = <>
    <button
      type="button"
      className="qorc-chat-call-button"
      title="Audio call"
      aria-label={`Call ${displayName}`}
      disabled={blocked}
      onClick={() => { closeActions(); onCall(username, 'audio'); }}
    >
      <CallIcon className="w-4 h-4" aria-hidden="true" />
    </button>
    <button
      type="button"
      className="qorc-chat-call-button"
      title="Video call"
      aria-label={`Video call ${displayName}`}
      disabled={blocked}
      onClick={() => { closeActions(); onCall(username, 'video'); }}
    >
      <Video className="w-4 h-4" aria-hidden="true" />
    </button>
    <ConversationOptionsPopover
      username={username}
      isPinned={isPinned}
      onTogglePin={onTogglePin}
      onDeleteConversation={onRemove}
      blocked={blocked}
      onToggleBlock={onToggleBlock}
      compact={swipeEnabled}
      onAction={swipeEnabled ? closeActions : undefined}
      ariaLabel={`Conversation options for ${displayName}`}
    />
  </>;

  return (
    <ConversationSwipeRow enabled={swipeEnabled} open={actionsOpen} onOpenChange={setActionsOpen} actions={actions} actionWidth={168} className="qorc-cm-swipe">
      <div
        className="qorc-cm-row"
        role={mode === 'block' ? 'group' : 'button'}
        tabIndex={mode === 'block' ? undefined : 0}
        onClick={mode === 'block' ? undefined : handlePrimaryAction}
        onKeyDown={(e) => {
          if (mode === 'block' || e.target !== e.currentTarget) return;
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            handlePrimaryAction();
          }
        }}
        aria-label={mode === 'block' ? `Conversation with ${displayName}` : `Open chat with ${displayName}`}
        aria-description={swipeEnabled ? 'Swipe right for calls and conversation options, or press the right arrow key.' : undefined}
      >
        <UserAvatar username={username} size="md" className="qorc-cm-row-avatar" />

        <div className="qorc-cm-row-main">
          <span className="qorc-cm-row-name" title={displayName}>{displayName}</span>
          {displayName.toLowerCase() !== username.toLowerCase() && (
            <span className="qorc-cm-row-username" title={username}>@{username}</span>
          )}
        </div>

        {mode === 'block' ? (
          <button
            type="button"
            className="qorc-cm-block-btn qorc-danger-button"
            disabled={blocking}
            aria-label={`Block ${displayName}`}
            onClick={(event) => {
              event.stopPropagation();
              onBlock(username);
            }}
          >
            <span>{blocking ? 'Blocking…' : 'Block'}</span>
          </button>
        ) : !swipeEnabled && (
          <div className="qorc-chat-call-actions qorc-cm-row-actions" onClick={(e) => e.stopPropagation()}>
            {actions}
          </div>
        )}
      </div>
    </ConversationSwipeRow>
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
  showNewChatInput = false,
  onNewChatOpenChange,
  onTogglePin,
  onStartCall,
  onToggleBlock,
  conversationDialogMode = 'manage',
  onBlockConversation,
}: ConversationListProps) {
  const mobile = useMobileLayout();
  const [actionsPeer, setActionsPeer] = useState<string | null>(null);
  const setActionsOpen = useCallback((username: string, open: boolean) => {
    setActionsPeer(current => open ? username : current === username ? null : current);
  }, []);
  useEffect(() => setActionsPeer(null), [currentUsername, mobile, selectedConversation]);
  const { typingUsers } = useTypingIndicatorContext();
  const [activePeer, setActivePeer] = useState<string | null>(null);
  const [activeStatus, setActiveStatus] = useState<CallStatus>(null);
  const [showConfirmDialog, setShowConfirmDialog] = useState<boolean>(false);
  const [conversationToDelete, setConversationToDelete] = useState<string | null>(null);
  const [newChatUsername, setNewChatUsername] = useState("");
  const [manageActionsPeer, setManageActionsPeer] = useState<string | null>(null);
  const manageActionsPeerRef = React.useRef<string | null>(null);
  React.useLayoutEffect(() => { manageActionsPeerRef.current = manageActionsPeer; }, [manageActionsPeer]);
  const setManageActionsOpen = useCallback((username: string, open: boolean) => {
    setManageActionsPeer(current => open ? username : current === username ? null : current);
  }, []);
  useEffect(() => setManageActionsPeer(null), [currentUsername, mobile, showNewChatInput, conversationDialogMode, newChatUsername]);
  const [isAdding, setIsAdding] = useState(false);
  const [discoveryProgress, setDiscoveryProgress] = useState<DiscoveryProgress | null>(null);
  const [blockingPeer, setBlockingPeer] = useState<string | null>(null);
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
  const availableConversations = useMemo(
    () => conversationDialogMode === 'block'
      ? conversations.filter((conversation) => !blockingSystem.isBlockedSync(conversation.username))
      : conversations,
    [blockVersion, conversationDialogMode, conversations],
  );
  const filteredConversations = useMemo(() => {
    if (!trimmedQuery) return availableConversations;
    return availableConversations.filter((c) =>
      c.username.toLowerCase().includes(trimmedQuery) ||
      (c.displayName ?? "").toLowerCase().includes(trimmedQuery)
    );
  }, [availableConversations, trimmedQuery]);
  const conversationLetterGroups = useMemo(() => groupConversationsByLetter(filteredConversations), [filteredConversations]);

  const hasExactMatch = useMemo(
    () => conversations.some((c) => c.username.toLowerCase() === trimmedQuery),
    [conversations, trimmedQuery]
  );
  const canAddTyped = conversationDialogMode === 'manage' && !!newChatUsername.trim() && !hasExactMatch;

  // Handle remove conversation click
  const handleRemoveClick = useCallback((username: string) => {
    setConversationToDelete(username);
    setShowConfirmDialog(true);
  }, []);

  // Handle confirm removal
  const handleConfirmRemove = useCallback(() => {
    if (conversationToDelete) {
      onRemoveConversation(conversationToDelete);
    }
    setShowConfirmDialog(false);
  }, [conversationToDelete, onRemoveConversation]);

  // Handle cancel removal
  const handleCancelRemove = useCallback(() => {
    setShowConfirmDialog(false);
  }, []);
  useAppBack(showConfirmDialog, handleCancelRemove, 100);

  const handleRemoveDialogOpenChange = useCallback((open: boolean) => {
    setShowConfirmDialog(open);
  }, []);

  const cancelActiveDiscovery = useCallback(() => {
    const controller = activeDiscoveryRef.current;
    if (!controller) return;
    activeDiscoveryRef.current = null;
    controller.abort();
    setIsAdding(false);
    setDiscoveryProgress(null);
  }, []);

  useEffect(() => () => {
    activeDiscoveryRef.current?.abort();
    activeDiscoveryRef.current = null;
  }, []);

  // Handle add new chat
  const handleAddChat = useCallback(async () => {
    const username = newChatUsername.trim();
    if (!username || activeDiscoveryRef.current) return;

    const controller = new AbortController();
    activeDiscoveryRef.current = controller;
    setIsAdding(true);
    setDiscoveryProgress({ phase: 'preparing', receivedBytes: 0, totalBytes: 0 });
    try {
      await onAddConversation(username, controller.signal, (progress) => {
        if (activeDiscoveryRef.current === controller && !controller.signal.aborted) setDiscoveryProgress(progress);
      });
      if (controller.signal.aborted) return;
      setNewChatUsername("");
      onNewChatOpenChange(false);
    } catch (error) {
      if (controller.signal.aborted || (error instanceof Error && error.name === 'AbortError')) return;
      toast.error(error instanceof Error ? error.message : "Failed to add conversation");
    } finally {
      if (activeDiscoveryRef.current === controller) {
        activeDiscoveryRef.current = null;
        setIsAdding(false);
        setDiscoveryProgress(null);
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
        setActiveStatus({ status: status as CallStatus['status'], isVideo, incoming: detail.direction === 'incoming' });
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
      setManageActionsPeer(null);
      cancelActiveDiscovery();
      setBlockingPeer(null);
      setNewChatUsername("");
    }
    onNewChatOpenChange(open);
  }, [cancelActiveDiscovery, onNewChatOpenChange]);

  const dialogContentRef = React.useRef<HTMLDivElement | null>(null);
  const pickerScreenRef = React.useRef<HTMLElement | null>(null);
  const pickerExitRef = React.useRef<Animation | null>(null);
  useLayoutEffect(() => {
    if (!showNewChatInput || !mobile) return;
    const entrance = animateView(pickerScreenRef.current, 'forward', false, 'slide');
    return () => {
      entrance?.cancel();
      pickerExitRef.current?.cancel();
      pickerExitRef.current = null;
    };
  }, [showNewChatInput, mobile]);
  const closePicker = useCallback(() => {
    if (pickerExitRef.current) return;
    const exit = mobile ? animateView(pickerScreenRef.current, 'back', true, 'slide') : null;
    if (!exit) { handleNewChatOpenChange(false); return; }
    pickerExitRef.current = exit;
    void exit.finished.then(() => {
      if (pickerExitRef.current !== exit) return;
      pickerExitRef.current = null;
      handleNewChatOpenChange(false);
    }, () => {});
  }, [mobile, handleNewChatOpenChange]);
  const mountDialogContent = useCallback((element: HTMLDivElement | null) => {
    dialogContentRef.current = element;
    element?.querySelector<HTMLElement>(mobile ? '.qorc-cm-close' : 'input')?.focus({ preventScroll: true });
  }, [mobile]);

  useAppBack(showNewChatInput, () => {
    if (document.querySelector('.qorc-conversation-options-popover')) return false;
    if (manageActionsPeer) { setManageActionsPeer(null); return; }
    closePicker();
  }, 80);

  useEffect(() => {
    if (!showNewChatInput) return;
    const previousFocus = document.activeElement;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const focusable = () => Array.from(dialogContentRef.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), [tabindex="0"]') ?? [])
      .filter(element => element.getClientRects().length > 0 && !element.closest('[inert]'));
    const keydown = (event: KeyboardEvent) => {
      if (event.defaultPrevented || document.querySelector('.qorc-delete-conversation-dialog') || (event.target instanceof Element && event.target.closest('.qorc-conversation-options-popover'))) return;
      if (event.key === 'Escape' && document.querySelector('.qorc-conversation-options-popover[data-state="open"]')) return;
      if (event.key === 'Escape') {
        event.preventDefault();
        if (manageActionsPeerRef.current) setManageActionsPeer(null);
        else closePicker();
        return;
      }
      if (event.key !== 'Tab' || !mobile) return;
      const items = focusable();
      if (!items.length) return;
      const index = items.indexOf(document.activeElement as HTMLElement);
      if (index < 0 || (event.shiftKey ? index === 0 : index === items.length - 1)) {
        event.preventDefault();
        items[event.shiftKey ? items.length - 1 : 0].focus();
      }
    };
    const focusin = (event: FocusEvent) => {
      if (mobile && event.target instanceof Element && !dialogContentRef.current?.contains(event.target) && !event.target.closest('.qorc-conversation-options-popover, .qorc-delete-conversation-dialog')) {
        focusable()[0]?.focus({ preventScroll: true });
      }
    };
    document.addEventListener('keydown', keydown);
    document.addEventListener('focusin', focusin);
    return () => {
      document.body.style.overflow = overflow;
      document.removeEventListener('keydown', keydown);
      document.removeEventListener('focusin', focusin);
      if (previousFocus instanceof HTMLElement && previousFocus.isConnected) previousFocus.focus({ preventScroll: true });
    };
  }, [showNewChatInput, closePicker, mobile]);

  const handleChatFromModal = useCallback((username: string) => {
    onSelectConversation(username);
    handleNewChatOpenChange(false);
  }, [onSelectConversation, handleNewChatOpenChange]);

  const handleCallFromPicker = useCallback((username: string, type: 'audio' | 'video') => {
    handleNewChatOpenChange(false);
    onStartCall(username, type);
  }, [handleNewChatOpenChange, onStartCall]);

  const handleBlockFromModal = useCallback(async (username: string) => {
    if (blockingPeer) return;
    setBlockingPeer(username);
    try {
      await onBlockConversation(username);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to block user');
    } finally {
      setBlockingPeer(null);
    }
  }, [blockingPeer, onBlockConversation]);

  const discoveryPercent = discoveryProgress && discoveryProgress.totalBytes > 0
    ? Math.min(100, Math.max(0, discoveryProgress.receivedBytes / discoveryProgress.totalBytes * 100))
    : 0;
  const displayedDiscoveryPercent = discoveryPercent > 0 && discoveryPercent < 1
    ? Number(discoveryPercent.toFixed(2)) : Math.floor(discoveryPercent);
  const discoveryLabel = discoveryProgress?.phase === 'checking-keys' ? 'Checking keys'
    : discoveryProgress?.phase === 'retrying-keys' ? 'Retrying key check'
    : discoveryProgress?.phase === 'retrying' ? `Retrying (${displayedDiscoveryPercent}%)`
    : discoveryProgress?.phase === 'verifying' ? 'Verifying'
    : discoveryProgress?.phase === 'downloading' ? `${displayedDiscoveryPercent}%`
    : 'Preparing';

  const pickerContent = (
    <div className="qorc-cm-content" ref={mountDialogContent}>
      <header className="qorc-cm-head">
        <button
          type="button"
          className="qorc-cm-close qorc-cm-back"
          onClick={closePicker}
          aria-label={conversationDialogMode === 'block' ? 'Back to settings' : 'Back to conversations'}
        >
          <ArrowLeft aria-hidden="true" />
        </button>
        <div className="qorc-cm-head-text">
          <DialogTitle id="conversation-modal-title">
            {conversationDialogMode === 'block' ? 'Block a conversation' : 'New conversation'}
          </DialogTitle>
        </div>
      </header>

      <div
        className={cn("qorc-cm-search", (isAdding || blockingPeer) && "is-searching", isAdding && "has-progress")}
        style={{ '--qorc-discovery-progress': `${discoveryPercent}%` } as React.CSSProperties}
      >
        <div className="qorc-cm-search-field qorc-search-field">
          {isAdding && (
            <span className="qorc-cm-search-progress" aria-hidden="true">
              <span className="qorc-cm-search-progress-fill" />
            </span>
          )}
          <span className="qorc-cm-search-icon qorc-search-icon" aria-hidden="true">
            {isAdding || blockingPeer ? <Loader2 className="animate-spin" /> : <Search />}
          </span>
          <Input
            type="text"
            placeholder={conversationDialogMode === 'block' ? 'Search conversations' : 'Search or enter username'}
            value={newChatUsername}
            onChange={(e) => setNewChatUsername(e.target.value)}
            className="qorc-cm-search-input qorc-search-input"
            disabled={isAdding || Boolean(blockingPeer)}
            spellCheck={false}
            autoComplete="off"
            aria-label={conversationDialogMode === 'block' ? 'Search conversations to block' : 'Search conversations or enter a username'}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !isAdding && canAddTyped) {
                handleAddChat();
              }
            }}
          />
          {conversationDialogMode === 'manage' && isAdding && (
            <button
              type="button"
              className="qorc-cm-search-cancel qorc-search-action"
              onClick={cancelActiveDiscovery}
              aria-label="Cancel user search"
              title="Cancel search"
            >
              <X aria-hidden="true" />
            </button>
          )}
        </div>
        {conversationDialogMode === 'manage' && isAdding && (
          <span
            className="qorc-cm-search-progress-label"
            role="progressbar"
            aria-label={discoveryProgress?.phase === 'downloading' ? 'Downloading discovery data' : `${discoveryLabel} discovery`}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={discoveryProgress?.phase === 'downloading' ? displayedDiscoveryPercent : undefined}
            aria-valuetext={discoveryLabel}
          >
            {discoveryLabel}
          </span>
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
                {conversationLetterGroups.map(group => <section className="qorc-cm-letter-group" key={group.letter} aria-label={`Conversations starting with ${group.letter}`}>
                  <h4 className="qorc-cm-letter-heading">{group.letter}</h4>
                  {group.conversations.map((c) => (
                  <ConversationManageRow
                    mobile={mobile}
                    actionsOpen={manageActionsPeer === c.username}
                    onActionsOpenChange={setManageActionsOpen}
                    isPinned={c.isPinned === true}
                    onTogglePin={onTogglePin}
                    key={c.id}
                    username={c.username}
                    blocked={blockingSystem.isBlockedSync(c.username)}
                    mode={conversationDialogMode}
                    onChat={handleChatFromModal}
                    onCall={handleCallFromPicker}
                    onToggleBlock={onToggleBlock}
                    onBlock={(username) => { void handleBlockFromModal(username); }}
                    onRemove={handleRemoveClick}
                    blocking={blockingPeer === c.username}
                  />
                  ))}
                </section>)}
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
                <h3>{trimmedQuery ? "No matches" : conversationDialogMode === 'block' ? "No conversations to block" : "No conversations yet"}</h3>
                <p>
                  {conversationDialogMode === 'block'
                    ? trimmedQuery
                      ? "Try another conversation name."
                      : "Only existing, unblocked conversations appear here."
                    : trimmedQuery
                      ? "Type a full username above to start a new chat."
                      : "Search a username above to start your first conversation."}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  return (
    <div className={cn('qorc-conversation-list', mobile && 'is-mobile')}>
      {showNewChatInput && createPortal(
        <section ref={pickerScreenRef} className="qorc-cm-dialog qorc-cm-screen" aria-labelledby="conversation-modal-title">
          {pickerContent}
        </section>,
        document.querySelector('.qorc-main-pane') ?? document.body,
      )}

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
                      {item.id === 'header-pinned' && <Pin className="h-3 w-3" aria-hidden="true" />}
                      {item.label}
                    </div>
                  );
                }

                const conversation = item.data;
                return (
                  <ConversationItem
                    mobile={mobile}
                    actionsOpen={actionsPeer === conversation.username}
                    onActionsOpenChange={setActionsOpen}
                    blocked={blockingSystem.isBlockedSync(conversation.username)}
                    onToggleBlock={onToggleBlock}
                    key={conversation.id}
                    conversation={conversation}
                    isSelected={selectedConversation === conversation.username}
                    onSelect={onSelectConversation}
                    onRemove={handleRemoveClick}
                    onTogglePin={onTogglePin}
                    callStatus={conversation.username === activePeer ? activeStatus : null}
                    isTyping={typingUserSet.has(conversation.username)}
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
