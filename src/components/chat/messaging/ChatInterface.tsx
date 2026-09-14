import React, { useEffect, useLayoutEffect, useRef, useState, useCallback } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { ChatMessage } from "./ChatMessage";
import { Message, MessageReply } from './types';
import { User } from "./UserList";
import { SignalType } from "@/lib/types/signal-types.ts";
import { useTypingIndicator } from "@/hooks/message-handling/useTypingIndicator";
import { useHasPendingIdentityChange } from "@/lib/security/identity-change-store";
import {
  keyTransparencyWarningStore,
  useKeyTransparencyRecoveryWarning,
} from "@/lib/key-transparency/warning-store";
import { keyTransparencyClient } from "@/lib/key-transparency/client";
import { keyTransparencyEpochStartMs } from "@/lib/key-transparency/crypto";
import { TypingIndicatorList } from "./TypingIndicatorList";
import { Video, TriangleAlert } from 'lucide-react';
import { CallIcon } from '../assets/icons';
import { ConversationOptionsPopover } from './ConversationOptionsPopover';
import { useReplyUpdates } from "@/hooks/message-handling/useReplyUpdates.ts";
import { useBlockStatus } from '@/hooks/useBlockStatus';
import {
  DEFAULT_UI_EVENT_RATE_MAX,
  SCROLL_THRESHOLD,
  NEAR_BOTTOM_THRESHOLD,
  CONVERSATION_SEGMENT_SIZE,
  SEGMENT_UNLOAD_IDLE_MS,
  INITIAL_LOAD_DELAY_MS
} from "../../../lib/constants";
import { releaseUnretainedVaultEntries } from "../../../lib/utils/message-state-limits";
import type { HybridKeys } from "../../../lib/types/auth-types";
import type { SecureDB } from '../../../lib/database/secureDB';
import { toast } from 'sonner';
import { ConversationSkeleton } from '../../ui/ViewSkeletons';
import { ChatInput } from '../ChatInput';
import type { CallState } from '../../../lib/types/calling-types';

interface ChatInterfaceProps {
  readonly onSendMessage: (
    messageId: string,
    content: string,
    messageSignalType: string,
    replyTo?: MessageReply | null
  ) => Promise<void>;
  readonly messages: ReadonlyArray<Message>;
  readonly setMessages: React.Dispatch<React.SetStateAction<Message[]>>;
  readonly currentUsername: string;
  readonly users: ReadonlyArray<User>;
  readonly selectedConversation: string;
  readonly saveMessageToLocalDB: (msg: Message) => Promise<void>;
  readonly getDisplayUsername: (username: string) => Promise<string>;
  readonly getKeysOnDemand: () => Promise<HybridKeys | null>;
  readonly findUser: (handle: string) => Promise<any>;
  readonly checkPeerSession: (peerUsername: string) => Promise<void>;
  readonly loadMoreMessages: (peerUsername: string, currentOffset: number, limit?: number) => Promise<Message[]>;
  readonly sendServerReadReceipt: (messageId: string, sender: string) => Promise<void>;
  readonly markMessageAsRead: (messageId: string) => Promise<void>;
  readonly getSmartReceiptStatus: (message: Message) => Message['receipt'] | undefined;
  readonly secureDB: SecureDB;
  readonly currentCall: CallState | null;
  readonly startCall: (targetUser: string, callType?: 'audio' | 'video') => Promise<string>;
  readonly onToggleBlock: (username: string, nextBlocked: boolean) => void | Promise<void>;
}

const distanceFromChatBottom = (container: Element): number => (
  Math.max(0, -container.scrollTop)
);

const distanceFromChatTop = (container: Element): number => (
  Math.max(0, container.scrollHeight - container.clientHeight + container.scrollTop)
);

const READ_RECEIPTABLE_MESSAGE_TYPES: ReadonlySet<string> = new Set([
  SignalType.MESSAGE,
  SignalType.TEXT,
  SignalType.FILE,
  SignalType.FILE_MESSAGE,
]);

const shouldCreateReadReceipt = (message: Message, currentUsername: string): boolean => (
  message.sender !== currentUsername &&
  !message.isSystemMessage &&
  READ_RECEIPTABLE_MESSAGE_TYPES.has(message.type || '') &&
  message.receipt?.read !== true
);

export const ChatInterface = React.memo<ChatInterfaceProps>(({ 
  onSendMessage,
  messages,
  setMessages,
  currentUsername,
  users,
  selectedConversation,
  saveMessageToLocalDB,
  getDisplayUsername,
  getKeysOnDemand,
  findUser,
  checkPeerSession: checkPeerSession,
  loadMoreMessages,
  sendServerReadReceipt,
  markMessageAsRead,
  getSmartReceiptStatus,
  secureDB,
  currentCall,
  startCall,
  onToggleBlock,
}) => {
  const scrollAreaRef = useRef<HTMLDivElement>(null);

  const displayResolverRef = useRef(getDisplayUsername);
  useEffect(() => { displayResolverRef.current = getDisplayUsername; }, [getDisplayUsername]);
  // Read by callbacks handed to every rendered row. Depending on `messages`
  // directly would give those callbacks a new identity on each append, receipt
  // and reaction, which defeats the memo on every ChatMessage at once.
  const messagesRef = useRef(messages);
  useEffect(() => { messagesRef.current = messages; }, [messages]);
  const getDisplayUsernameStable = useCallback((username: string) => {
    return displayResolverRef.current(username);
  }, []);
  const [replyTo, setReplyTo] = useState<Message | null>(null);
  const [editingMessage, setEditingMessage] = useState<Message | null>(null);
  const isUserBlocked = useBlockStatus(selectedConversation, { eventRateMax: DEFAULT_UI_EVENT_RATE_MAX });
  const hasAttachedCall = Boolean(currentCall && selectedConversation === currentCall.peer);
  const [isBlockedByUser, setIsBlockedByUser] = useState<boolean>(false);
  const messageActionsDisabled = isUserBlocked || isBlockedByUser;
  const [isLoadingMore, setIsLoadingMore] = useState<boolean>(false);
  const [openingConversation, setOpeningConversation] = useState<string | null>(null);
  const [hasMoreMessages, setHasMoreMessages] = useState<boolean>(true);
  const loadedMessagesCountRef = useRef<Map<string, number>>(new Map());
  const backgroundLoadConversationRef = useRef<string | null>(null);
  const prevMessagesLengthRef = useRef(messages.length);
  const lastMessageIdRef = useRef<string | null>(messages[messages.length - 1]?.id || null);

  const processedInScrollRef = useRef<Set<string>>(new Set());
  const lastScrollTimeRef = useRef<number>(0);
  const { handleLocalTyping, handleConversationChange, resetTypingAfterSend } = useTypingIndicator(currentUsername, selectedConversation);
  const keyChangePending = useHasPendingIdentityChange(selectedConversation);
  const recoveryWarning = useKeyTransparencyRecoveryWarning(selectedConversation);
  useEffect(() => {
    if (!currentUsername) {
      keyTransparencyWarningStore.clear();
      return;
    }
    void keyTransparencyClient.activateWarningStore(currentUsername).catch((error) => {
      console.error('Failed to activate the key transparency warning store:', error);
      toast.error('Unable to load security warnings');
    });
  }, [currentUsername]);

  useEffect(() => {
    handleConversationChange();
    setReplyTo(null);
    setEditingMessage(null);
    processedInScrollRef.current.clear();
    lastScrollTimeRef.current = 0;
  }, [selectedConversation, handleConversationChange]);

  useEffect(() => {
    loadedMessagesCountRef.current.clear();
    processedInScrollRef.current.clear();
    backgroundLoadConversationRef.current = null;
    setReplyTo(null);
    setEditingMessage(null);
  }, [currentUsername]);

  const scrollToBottom = useCallback((container: Element) => {
    try {
      container.scrollTo({ top: 0, behavior: 'auto' });
    } catch { }
  }, []);

  useLayoutEffect(() => {
    prevMessagesLengthRef.current = messages.length;
    lastMessageIdRef.current = messages[messages.length - 1]?.id || null;
    const scrollContainer = scrollAreaRef.current?.querySelector('[data-radix-scroll-area-viewport]');
    if (!scrollContainer) return;

    scrollToBottom(scrollContainer);
    const frame = requestAnimationFrame(() => scrollToBottom(scrollContainer));
    return () => cancelAnimationFrame(frame);
  }, [openingConversation, selectedConversation, scrollToBottom]);

  useLayoutEffect(() => {
    if (
      loadedMessagesCountRef.current.has(selectedConversation)
    ) {
      setOpeningConversation(null);
      return;
    }
    setOpeningConversation(selectedConversation);
  }, [loadMoreMessages, selectedConversation]);

  useEffect(() => {
    if (selectedConversation) {
      setHasMoreMessages(true);
      setIsLoadingMore(false);
      if (!loadedMessagesCountRef.current.has(selectedConversation)) {
        loadedMessagesCountRef.current.set(selectedConversation, 0);
      }
    }
  }, [selectedConversation]);

  useEffect(() => {
    const conversationToLoad = selectedConversation;
    backgroundLoadConversationRef.current = conversationToLoad;
    let cancelled = false;
    const isCurrentLoad = () => (
      !cancelled && backgroundLoadConversationRef.current === conversationToLoad
    );

    const loadBackgroundMessages = async () => {
      try {
        await new Promise(resolve => setTimeout(resolve, INITIAL_LOAD_DELAY_MS));
        if (!isCurrentLoad()) return;

        const currentCount = loadedMessagesCountRef.current.get(conversationToLoad) ?? 0;

        const batch = await loadMoreMessages(
          conversationToLoad,
          currentCount,
          CONVERSATION_SEGMENT_SIZE,
        );
        if (!isCurrentLoad()) return;
        if (batch.length > 0) {
          loadedMessagesCountRef.current.set(conversationToLoad, currentCount + batch.length);
        }
        if (batch.length < CONVERSATION_SEGMENT_SIZE) setHasMoreMessages(false);
      } catch (error) {
        console.error('[ChatInterface] Background message load failed', error);
      } finally {
        if (isCurrentLoad()) {
          backgroundLoadConversationRef.current = null;
          setOpeningConversation((current) => current === conversationToLoad ? null : current);
        }
      }
    };

    void loadBackgroundMessages();
    return () => {
      cancelled = true;
      if (backgroundLoadConversationRef.current === conversationToLoad) {
        backgroundLoadConversationRef.current = null;
      }
    };
  }, [selectedConversation, loadMoreMessages]);

  // Handle lazy loading of older messages on scroll
  const handleLazyLoadScroll = useCallback(async (scrollContainer: Element) => {
    if (
      isLoadingMore ||
      !hasMoreMessages ||
      backgroundLoadConversationRef.current === selectedConversation
    ) return;

    if (distanceFromChatTop(scrollContainer) < SCROLL_THRESHOLD) {
      setIsLoadingMore(true);

      try {
        const currentCount = loadedMessagesCountRef.current.get(selectedConversation) ?? 0;
        const moreMessages = await loadMoreMessages(
          selectedConversation,
          currentCount,
          CONVERSATION_SEGMENT_SIZE,
        );

        if (moreMessages.length < CONVERSATION_SEGMENT_SIZE) {
          setHasMoreMessages(false);
        }

        if (moreMessages.length > 0) {
          loadedMessagesCountRef.current.set(selectedConversation, currentCount + moreMessages.length);
        }
      } catch (error) {
        console.error('[ChatInterface] Older message load failed', error);
      } finally {
        setIsLoadingMore(false);
      }
    }
  }, [selectedConversation, loadMoreMessages, isLoadingMore, hasMoreMessages]);

  // Release segments that were paged in by scrolling up once the view has sat at the bottom long enough that they are clearly not being read
  const releaseScrolledBackSegments = useCallback(() => {
    const peer = selectedConversation;
    if (!peer) return;
    const loaded = loadedMessagesCountRef.current.get(peer) ?? 0;
    if (loaded <= CONVERSATION_SEGMENT_SIZE) return;

    setMessages(previous => {
      const belongsToPeer = (message: Message) => (
        message.sender === peer || message.recipient === peer
      );
      const conversation = previous.filter(belongsToPeer);
      if (conversation.length <= CONVERSATION_SEGMENT_SIZE) return previous;

      const retainedIds = new Set(
        conversation.slice(conversation.length - CONVERSATION_SEGMENT_SIZE).map(m => m.id)
      );
      const next = previous.filter(message => !belongsToPeer(message) || retainedIds.has(message.id));
      if (next.length === previous.length) return previous;
      releaseUnretainedVaultEntries(previous, previous, next);
      return next;
    });

    loadedMessagesCountRef.current.set(peer, CONVERSATION_SEGMENT_SIZE);

    // More history still exists on disk scrolling up must be able to page it
    setHasMoreMessages(true);
  }, [selectedConversation, setMessages]);

  useEffect(() => {
    const scrollContainer = scrollAreaRef.current?.querySelector('[data-radix-scroll-area-viewport]');
    if (!scrollContainer) return;

    let unloadTimer: ReturnType<typeof setTimeout> | null = null;
    const clearUnloadTimer = () => {
      if (unloadTimer !== null) {
        clearTimeout(unloadTimer);
        unloadTimer = null;
      }
    };

    const handleScroll = () => {
      void handleLazyLoadScroll(scrollContainer);

      const distanceToBottom = distanceFromChatBottom(scrollContainer);
      const atBottom = distanceToBottom <= NEAR_BOTTOM_THRESHOLD;
      if (!atBottom) {
        clearUnloadTimer();
        return;
      }
      if (unloadTimer !== null) return;
      unloadTimer = setTimeout(() => {
        unloadTimer = null;
        releaseScrolledBackSegments();
      }, SEGMENT_UNLOAD_IDLE_MS);
    };

    scrollContainer.addEventListener('scroll', handleScroll);
    return () => {
      clearUnloadTimer();
      scrollContainer.removeEventListener('scroll', handleScroll);
    };
  }, [handleLazyLoadScroll, releaseScrolledBackSegments]);

  useEffect(() => {
    setIsBlockedByUser(false);
  }, [selectedConversation]);

  useEffect(() => {
    if (!messageActionsDisabled) return;
    setReplyTo(null);
    setEditingMessage(null);
  }, [messageActionsDisabled]);

  // Send read receipt for message
  const sendReadReceipt = useCallback(async (messageId: string, sender: string) => {
    const message = messages.find(m => m.id === messageId);
    if (!message || message.sender !== sender || !shouldCreateReadReceipt(message, currentUsername)) return;
    const wireMessageId = message.wireMessageId || message.id;

    await sendServerReadReceipt(wireMessageId, sender);
  }, [currentUsername, messages, sendServerReadReceipt]);

  useReplyUpdates(messages, setMessages, saveMessageToLocalDB, currentUsername);

  useEffect(() => {
    if (!scrollAreaRef.current) return;

    const scrollContainer = scrollAreaRef.current.querySelector('[data-radix-scroll-area-viewport]');
    if (!scrollContainer) return;

    const currentMessagesLength = messages.length;
    const prevMessagesLength = prevMessagesLengthRef.current;

    const isNewMessage = currentMessagesLength > prevMessagesLength;

    const latestMessage = messages[messages.length - 1];
    const isNewMessageId = latestMessage && latestMessage.id !== lastMessageIdRef.current;

    if (isNewMessage && isNewMessageId && latestMessage) {
      const isNearBottom = distanceFromChatBottom(scrollContainer) <= NEAR_BOTTOM_THRESHOLD;
      const isCurrentUserMessage = latestMessage.sender === currentUsername;

      if (isNearBottom || isCurrentUserMessage) {
        scrollContainer.scrollTo({
          top: 0,
          behavior: 'smooth'
        });
      }

      lastMessageIdRef.current = latestMessage.id;
    }

    prevMessagesLengthRef.current = currentMessagesLength;
  }, [messages, currentUsername]);

  // Message lookup map
  const messageMapRef = useRef<Map<string, Message>>(new Map());
  useEffect(() => {
    const map = new Map<string, Message>();
    for (const msg of messages) {
      map.set(msg.id, msg);
    }
    messageMapRef.current = map;
  }, [messages]);

  const observedMessagesRef = useRef<Set<string>>(new Set());
  const readReceiptObserverRef = useRef<IntersectionObserver | null>(null);

  useEffect(() => {
    const scrollContainer = scrollAreaRef.current?.querySelector('[data-radix-scroll-area-viewport]');
    if (!scrollContainer || !window.IntersectionObserver) return;

    observedMessagesRef.current.clear();

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const messageId = entry.target.getAttribute('data-message-id');
            if (messageId) {
              if (document.hasFocus()) {
                markMessageAsRead(messageId);
                const msg = messageMapRef.current.get(messageId);
                if (msg) {
                  sendReadReceipt(messageId, msg.sender);
                }
                observer.unobserve(entry.target);
                observedMessagesRef.current.delete(messageId);
              }
            }
          }
        });
      },
      {
        root: scrollContainer,
        threshold: 0.5,
      }
    );

    readReceiptObserverRef.current = observer;

    const handleFocus = () => {
      const currentMessages = messageMapRef.current;
      for (const [msgId, msg] of currentMessages) {
        if (shouldCreateReadReceipt(msg, currentUsername)) {
          const el = document.getElementById(`message-${msgId}`);
          if (el) {
            const rect = el.getBoundingClientRect();
            const containerRect = scrollContainer.getBoundingClientRect();

            if (
              rect.top < containerRect.bottom &&
              rect.bottom > containerRect.top
            ) {
              markMessageAsRead(msgId);
              sendReadReceipt(msgId, msg.sender);
              observer.unobserve(el);
              observedMessagesRef.current.delete(msgId);
            }
          }
        }
      }
    };

    window.addEventListener('focus', handleFocus);

    return () => {
      observer.disconnect();
      readReceiptObserverRef.current = null;
      window.removeEventListener('focus', handleFocus);
      observedMessagesRef.current.clear();
    };
  }, [selectedConversation, currentUsername, markMessageAsRead, sendReadReceipt]);

  useEffect(() => {
    const observer = readReceiptObserverRef.current;
    if (!observer) return;

    for (const msg of messages) {
      if (shouldCreateReadReceipt(msg, currentUsername) && !observedMessagesRef.current.has(msg.id)) {
        const el = document.getElementById(`message-${msg.id}`);
        if (el) {
          el.setAttribute('data-message-id', msg.id);
          observer.observe(el);
          observedMessagesRef.current.add(msg.id);
        }
      }
    }
  }, [messages, currentUsername]);

  useEffect(() => {
    const scrollContainer = scrollAreaRef.current?.querySelector('[data-radix-scroll-area-viewport]');
    if (!scrollContainer || isLoadingMore) return;

    const isNearBottom = distanceFromChatBottom(scrollContainer) < 100;

    if (isNearBottom) {
      scrollToBottom(scrollContainer);
    }
  }, [messages, isLoadingMore, scrollToBottom]);

  const handleTypingUpdate = useCallback(() => {
    const scrollContainer = scrollAreaRef.current?.querySelector('[data-radix-scroll-area-viewport]');
    if (!scrollContainer) return;
    const isNearBottom = distanceFromChatBottom(scrollContainer) < 100;
    if (isNearBottom) {
      scrollToBottom(scrollContainer);
    }
  }, [scrollToBottom]);

  // Handle audio call initiation
  const handleAudioCall = useCallback(async () => {
    if (!selectedConversation) return;
    console.info('[CALL-DIAG]', { phase: 'ui.audio-click' });
    try {
      await startCall(selectedConversation, 'audio');
      console.info('[CALL-DIAG]', { phase: 'ui.audio-start-resolved' });
    } catch (_error) {
      console.error('[CALL-DIAG]', {
        phase: 'ui.audio-start-failed',
        errorName: _error instanceof Error ? _error.name : 'UnknownError',
        errorMessage: _error instanceof Error ? _error.message : String(_error),
      });
      toast.error('Failed to start call', {
        description: (_error as Error).message,
      });
    }
  }, [selectedConversation, startCall]);

  // Handle video call initiation
  const handleVideoCall = useCallback(async () => {
    if (!selectedConversation) return;
    console.info('[CALL-DIAG]', { phase: 'ui.video-click' });
    try {
      await startCall(selectedConversation, 'video');
      console.info('[CALL-DIAG]', { phase: 'ui.video-start-resolved' });
    } catch (_error) {
      console.error('[CALL-DIAG]', {
        phase: 'ui.video-start-failed',
        errorName: _error instanceof Error ? _error.name : 'UnknownError',
        errorMessage: _error instanceof Error ? _error.message : String(_error),
      });
      toast.error('Failed to start video call', {
        description: (_error as Error).message,
      });
    }
  }, [selectedConversation, startCall]);

  // Handle sending messages
  const handleMessageSend = useCallback(async (
    messageId: string | undefined,
    content: string,
    messageSignalType: string,
    replyToMsg?: MessageReply | null
  ) => {
    if (messageActionsDisabled) return;
    await onSendMessage(messageId ?? "", content, messageSignalType, replyToMsg);

    if (messageSignalType !== SignalType.TYPING_START && messageSignalType !== SignalType.TYPING_STOP) {
      resetTypingAfterSend();
      setReplyTo(null);
    }
  }, [messageActionsDisabled, onSendMessage, resetTypingAfterSend]);

  // Handle message deletion
  const handleDeleteMessage = useCallback((message: Message) => {
    onSendMessage(message.wireMessageId || message.id, "", SignalType.DELETE_MESSAGE, null);
  }, [onSendMessage]);

  // Handle message reactions
  const handleReactToMessage = useCallback((targetMessage: Message, emoji: string) => {
    if (messageActionsDisabled) return;
    const isRemove = !!(targetMessage.reactions && targetMessage.reactions[emoji] && targetMessage.reactions[emoji].includes(currentUsername));
    const action = isRemove ? SignalType.REACTION_REMOVE : SignalType.REACTION_ADD;
    onSendMessage(targetMessage.wireMessageId || targetMessage.id, emoji, action, null);
  }, [currentUsername, messageActionsDisabled, onSendMessage]);

  // Handle reply, edit, cancellation
  const handleCancelReply = useCallback(() => setReplyTo(null), []);
  const handleCancelEdit = useCallback(() => setEditingMessage(null), []);

  // Handle reply to message
  const handleReply = useCallback((message: Message) => {
    if (messageActionsDisabled) return;
    setEditingMessage(null);
    setReplyTo(message);
  }, [messageActionsDisabled]);

  // Handle message edit
  const handleEdit = useCallback((message: Message) => {
    if (messageActionsDisabled) return;
    setReplyTo(null);
    setEditingMessage(message);
  }, [messageActionsDisabled]);

  // Handle reply click navigation
  const handleReplyClick = useCallback((replyId: string) => {
    const localId = messagesRef.current.find((message) => message.wireMessageId === replyId)?.id || replyId;
    const el = document.getElementById(`message-${localId}`);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      el.classList.add('bg-secondary/20');
      setTimeout(() => el.classList.remove('bg-secondary/20'), 1500);
    }
  }, []);

  if (openingConversation === selectedConversation) {
    return <ConversationSkeleton hasAttachedCall={hasAttachedCall} />;
  }

  return (
    <div className={`qorc-interface${hasAttachedCall ? ' has-attached-call' : ''}`}>
      <div
        className="qorc-toolbar"
      >
        <div className="min-w-0 flex-1 pr-3" />
        <div className="flex items-center gap-2">
          {selectedConversation && (
            <div className="qorc-call-pill" role="group" aria-label="Conversation actions">
              {!keyChangePending && !hasAttachedCall && (
                <>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={handleAudioCall}
                    disabled={!!currentCall || isUserBlocked || isBlockedByUser}
                    className="qorc-call-pill-btn"
                    title="Audio call"
                  >
                    <CallIcon className="w-4 h-4" />
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={handleVideoCall}
                    disabled={!!currentCall || isUserBlocked || isBlockedByUser}
                    className="qorc-call-pill-btn"
                    title="Video call"
                  >
                    <Video className="w-4 h-4" />
                  </Button>
                </>
              )}
              <ConversationOptionsPopover
                username={selectedConversation}
                blocked={isUserBlocked}
                onToggleBlock={onToggleBlock}
              />
            </div>
          )}

        </div>
      </div>
      {selectedConversation && recoveryWarning && (
        <div
          className="flex items-start gap-2 border-y border-amber-500/30 bg-amber-950/55 px-4 py-2.5 text-sm text-amber-100"
          role="alert"
          aria-live="assertive"
        >
          <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" aria-hidden="true" />
          <div className="min-w-0">
            <div className="font-semibold">Account-key recovery pending for {selectedConversation}</div>
            <p className="mt-0.5 text-xs leading-relaxed text-amber-100/85">
              Qorc verified a recovery-key-authorized replacement request. The existing key remains active until{' '}
              {new Date(keyTransparencyEpochStartMs(recoveryWarning.activatesAtEpoch)).toLocaleString()}. Treat unexpected recovery as a security warning.
            </p>
          </div>
        </div>
      )}
      <ScrollArea
        className="qorc-message-scroll"
        ref={scrollAreaRef}
      >
        <div
          className={`qorc-message-stack${messages.length === 0 && !isLoadingMore ? ' is-empty' : ''}`}
        >
          {}
          {isLoadingMore ? (
            <div className="qorc-thread-loading" role="status" aria-label="Loading earlier messages">
              <span className="qorc-thread-loading-spinner" aria-hidden="true" />
            </div>
          ) : null}
          {messages.length === 0 && !isLoadingMore ? (
            <div className="qorc-thread-empty">
              <strong>No messages yet. Start the conversation!</strong>
            </div>
          ) : (
            messages.map((message, index) => {
              const smartReceipt = getSmartReceiptStatus(message);
              const isMine = message.isCurrentUser || message.sender === currentUsername;
              const receiptToShow = isMine && smartReceipt ? smartReceipt : undefined;
              const uniqueKey = message.id || `message-${index}`;
              return (
                <div key={uniqueKey} id={`message-${message.id}`}>
                  <ChatMessage
                    key={message.id}
                    message={message}
                    smartReceipt={receiptToShow}
                    previousMessage={index > 0 ? messages[index - 1] : undefined}
                    onReply={messageActionsDisabled ? undefined : handleReply}
                    onDelete={handleDeleteMessage}
                    onEdit={messageActionsDisabled ? undefined : handleEdit}
                    onReact={messageActionsDisabled ? undefined : handleReactToMessage}
                    onReplyClick={handleReplyClick}
                    currentUsername={currentUsername}
                    secureDB={secureDB}
                  />
                </div>
              );
            })
          )}

          {/* Typing Indicators */}
          <TypingIndicatorList
            selectedConversation={selectedConversation}
            onUpdate={handleTypingUpdate}
          />
        </div>
      </ScrollArea>

      <div
        className="qorc-composer-wrap"
      >
        {keyChangePending ? (
          <div className="qorc-composer-blocked px-4 py-3 text-center text-sm text-amber-200/90" role="status">
            {selectedConversation}'s new security keys are awaiting automatic
            key-transparency verification. Messaging and calls remain locked.
          </div>
        ) : (
          <ChatInput
            onSendMessage={handleMessageSend}
            currentUsername={currentUsername}
            users={users}
            replyTo={replyTo}
            onCancelReply={handleCancelReply}
            editingMessage={editingMessage}
            onCancelEdit={handleCancelEdit}
            onTyping={handleLocalTyping}
            selectedConversation={selectedConversation}
            getDisplayUsername={getDisplayUsernameStable}
            disabled={isUserBlocked || isBlockedByUser}
            disabledPlaceholder={isUserBlocked ? 'You blocked this user' : undefined}
            getKeysOnDemand={getKeysOnDemand}
            findUser={findUser}
            secureDB={secureDB}
            checkPeerSession={checkPeerSession}
          />
        )}
      </div>
    </div>
  );
});

ChatInterface.displayName = 'ChatInterface';
