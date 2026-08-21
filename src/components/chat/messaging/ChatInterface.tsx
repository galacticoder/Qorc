import React, { useEffect, useRef, useState, useCallback } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { ChatMessage } from "./ChatMessage";
import { Message } from "./types";
import { ChatInput } from "../ChatInput.tsx";
import { User } from "./UserList";
import { SignalType } from "@/lib/types/signal-types.ts";
import { MessageReply } from "./types";
import { useTypingIndicator } from "@/hooks/message-handling/useTypingIndicator";
import { useHasPendingIdentityChange } from "@/lib/security/identity-change-store";
import {
  keyTransparencyWarningStore,
  useKeyTransparencyRecoveryWarning,
} from "@/lib/key-transparency/warning-store";
import { keyTransparencyClient } from "@/lib/key-transparency/client";
import { keyTransparencyEpochStartMs } from "@/lib/key-transparency/crypto";
import { TypingIndicatorList } from "./TypingIndicatorList";
import { Video, MoreVertical, ShieldOff, TriangleAlert } from 'lucide-react';
import { CallIcon } from '../assets/icons';
import type { CallState } from "../../../lib/transport/secure-calling-service";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { BlockUserButton } from "../calls/BlockUserButton";
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
import type { HybridPublicKeys } from '../../../lib/types/message-sending-types';

interface ChatInterfaceProps {
  readonly onSendMessage: (
    messageId: string,
    content: string,
    messageSignalType: string,
    replyTo?: MessageReply | null
  ) => Promise<void>;
  readonly messages: ReadonlyArray<Message>;
  readonly setMessages: React.Dispatch<React.SetStateAction<Message[]>>;
  readonly isEncrypted?: boolean;
  readonly currentUsername: string;
  readonly users: ReadonlyArray<User>;
  readonly selectedConversation?: string;
  readonly saveMessageToLocalDB: (msg: Message) => Promise<void>;
  readonly getDisplayUsername?: (username: string) => Promise<string>;
  readonly getKeysOnDemand?: () => Promise<HybridKeys | null>;
  readonly getPeerHybridKeys?: (peerUsername: string) => Promise<HybridPublicKeys | null>;
  readonly findUser?: (handle: string) => Promise<any>;
  readonly ensurePeerSession?: (peerUsername: string) => Promise<void>;
  readonly p2pConnected?: boolean;
  readonly loadMoreMessages?: (peerUsername: string, currentOffset: number, limit?: number) => Promise<Message[]>;
  readonly sendServerReadReceipt: (messageId: string, sender: string) => Promise<void>;
  readonly markMessageAsRead: (messageId: string) => Promise<void>;
  readonly getSmartReceiptStatus: (message: Message) => Message['receipt'] | undefined;
  readonly secureDB?: any;
  readonly currentCall?: CallState | null;
  readonly startCall: (targetUser: string, callType?: 'audio' | 'video') => Promise<string>;
}

export const ChatInterface = React.memo<ChatInterfaceProps>(({
  onSendMessage,
  messages,
  setMessages,
  isEncrypted = true,
  currentUsername,
  users,
  selectedConversation,
  saveMessageToLocalDB,
  getDisplayUsername,
  getKeysOnDemand,
  getPeerHybridKeys,
  findUser,
  ensurePeerSession,
  p2pConnected: _p2pConnected = false,
  loadMoreMessages,
  sendServerReadReceipt,
  markMessageAsRead,
  getSmartReceiptStatus,
  secureDB,
  currentCall,
  startCall,
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
    const fn = displayResolverRef.current;
    return fn ? fn(username) : Promise.resolve(username);
  }, []);
  const [replyTo, setReplyTo] = useState<Message | null>(null);
  const [editingMessage, setEditingMessage] = useState<Message | null>(null);
  const isUserBlocked = useBlockStatus(selectedConversation, { eventRateMax: DEFAULT_UI_EVENT_RATE_MAX });
  const [isBlockedByUser, setIsBlockedByUser] = useState<boolean>(false);
  const [isLoadingMore, setIsLoadingMore] = useState<boolean>(false);
  const [hasMoreMessages, setHasMoreMessages] = useState<boolean>(true);
  const loadedMessagesCountRef = useRef<Map<string, number>>(new Map());
  const backgroundLoadConversationRef = useRef<string | null>(null);

  const processedInScrollRef = useRef<Set<string>>(new Set());
  const lastScrollTimeRef = useRef<number>(0);
  const { handleLocalTyping, handleConversationChange, resetTypingAfterSend } = useTypingIndicator(currentUsername, selectedConversation);
  const keyChangePending = useHasPendingIdentityChange(selectedConversation);
  const recoveryWarning = useKeyTransparencyRecoveryWarning(selectedConversation);
  const initialScrollDoneRef = useRef<Map<string, boolean>>(new Map());

  useEffect(() => {
    if (!currentUsername) {
      keyTransparencyWarningStore.clear();
      return;
    }
    void keyTransparencyClient.activateWarningStore(currentUsername).catch(() => undefined);
  }, [currentUsername]);

  useEffect(() => {
    handleConversationChange();
    setReplyTo(null);
    setEditingMessage(null);
    processedInScrollRef.current.clear();
    lastScrollTimeRef.current = 0;
    if (selectedConversation) {
      initialScrollDoneRef.current.delete(selectedConversation);
    }
  }, [selectedConversation, handleConversationChange]);

  useEffect(() => {
    loadedMessagesCountRef.current.clear();
    initialScrollDoneRef.current.clear();
    processedInScrollRef.current.clear();
    backgroundLoadConversationRef.current = null;
    setReplyTo(null);
    setEditingMessage(null);
  }, [currentUsername]);

  // Scroll container to bottom
  const scrollToBottom = useCallback((container: Element) => {
    try {
      container.scrollTo({ top: container.scrollHeight, behavior: 'auto' });
    } catch { }
  }, []);

  useEffect(() => {
    const scrollContainer = scrollAreaRef.current?.querySelector('[data-radix-scroll-area-viewport]');
    if (!scrollContainer) return;

    // Wait for messages to be loaded before scrolling
    const t1 = setTimeout(() => {
      if (messages.length > 0) scrollToBottom(scrollContainer);
    }, 150);
    const t2 = setTimeout(() => {
      scrollToBottom(scrollContainer);
    }, 500);
    const t3 = setTimeout(() => {
      scrollToBottom(scrollContainer);
    }, 1000);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
    };
  }, [selectedConversation, scrollToBottom]);

  useEffect(() => {
    if (!selectedConversation) return;
    const alreadyScrolled = initialScrollDoneRef.current.get(selectedConversation);
    if (alreadyScrolled) return;

    const scrollContainer = scrollAreaRef.current?.querySelector('[data-radix-scroll-area-viewport]');
    if (!scrollContainer) return;

    scrollToBottom(scrollContainer);
    if (messages.length > 0 || !hasMoreMessages) {
      initialScrollDoneRef.current.set(selectedConversation, true);
    }
  }, [messages, selectedConversation, scrollToBottom, hasMoreMessages]);

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
    if (!selectedConversation || !loadMoreMessages) return;

    const conversationToLoad = selectedConversation;
    backgroundLoadConversationRef.current = conversationToLoad;
    let cancelled = false;
    const isCurrentLoad = () => (
      !cancelled && backgroundLoadConversationRef.current === conversationToLoad
    );

    const loadBackgroundMessages = async () => {
      setIsLoadingMore(true);
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
      } catch {
      } finally {
        if (isCurrentLoad()) setIsLoadingMore(false);
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
    if (isLoadingMore || !hasMoreMessages || !selectedConversation || !loadMoreMessages) return;

    const scrollTop = scrollContainer.scrollTop;

    if (scrollTop < SCROLL_THRESHOLD) {
      setIsLoadingMore(true);

      try {
        const previousScrollHeight = scrollContainer.scrollHeight;
        const previousScrollTop = scrollContainer.scrollTop;
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
          requestAnimationFrame(() => {
            requestAnimationFrame(() => {
              const addedHeight = scrollContainer.scrollHeight - previousScrollHeight;
              scrollContainer.scrollTop = previousScrollTop + Math.max(0, addedHeight);
            });
          });
        }
      } catch {
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

      const atBottom = scrollContainer.scrollTop >=
        scrollContainer.scrollHeight - scrollContainer.clientHeight - NEAR_BOTTOM_THRESHOLD;
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

  // Send read receipt for message
  const sendReadReceipt = useCallback(async (messageId: string, sender: string) => {
    const message = messages.find(m => m.id === messageId);
    if (!message) return;
    const wireMessageId = message.wireMessageId || message.id;

    await sendServerReadReceipt(wireMessageId, sender);
  }, [messages, sendServerReadReceipt]);

  useReplyUpdates(messages, setMessages, saveMessageToLocalDB, currentUsername);

  const prevMessagesLengthRef = useRef(messages.length);
  const lastMessageIdRef = useRef<string | null>(null);

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
      const isNearBottom = scrollContainer.scrollTop >= scrollContainer.scrollHeight - scrollContainer.clientHeight - NEAR_BOTTOM_THRESHOLD;
      const isCurrentUserMessage = latestMessage.sender === currentUsername;

      if (isNearBottom || isCurrentUserMessage) {
        scrollContainer.scrollTo({
          top: scrollContainer.scrollHeight,
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
        if (msg.sender !== currentUsername && !msg.receipt?.read) {
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
      if (msg.sender !== currentUsername && !msg.receipt?.read && !observedMessagesRef.current.has(msg.id)) {
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

    const isNearBottom = scrollContainer.scrollHeight - scrollContainer.scrollTop - scrollContainer.clientHeight < 100;

    if (isNearBottom) {
      scrollToBottom(scrollContainer);
    }
  }, [messages, isLoadingMore, scrollToBottom]);

  const handleTypingUpdate = useCallback(() => {
    const scrollContainer = scrollAreaRef.current?.querySelector('[data-radix-scroll-area-viewport]');
    if (!scrollContainer) return;
    const isNearBottom = scrollContainer.scrollHeight - scrollContainer.scrollTop - scrollContainer.clientHeight < 100;
    if (isNearBottom) {
      scrollToBottom(scrollContainer);
    }
  }, [scrollToBottom]);

  // Handle audio call initiation
  const handleAudioCall = useCallback(async () => {
    if (!selectedConversation) return;
    try {
      await startCall(selectedConversation, 'audio');
    } catch (_error) {
      alert('Failed to start call: ' + (_error as Error).message);
    }
  }, [selectedConversation, startCall]);

  // Handle video call initiation
  const handleVideoCall = useCallback(async () => {
    if (!selectedConversation) return;
    try {
      await startCall(selectedConversation, 'video');
    } catch (_error) {
      alert('Failed to start video call: ' + (_error as Error).message);
    }
  }, [selectedConversation, startCall]);

  // Handle sending messages
  const handleMessageSend = useCallback(async (
    messageId: string | undefined,
    content: string,
    messageSignalType: string,
    replyToMsg?: MessageReply | null
  ) => {
    await onSendMessage(messageId ?? "", content, messageSignalType, replyToMsg);

    if (messageSignalType !== SignalType.TYPING_START && messageSignalType !== SignalType.TYPING_STOP) {
      resetTypingAfterSend();
      setReplyTo(null);
    }
  }, [onSendMessage, resetTypingAfterSend]);

  // Handle message deletion
  const handleDeleteMessage = useCallback((message: Message) => {
    onSendMessage(message.wireMessageId || message.id, "", SignalType.DELETE_MESSAGE, null);
  }, [onSendMessage]);

  // Handle message reactions
  const handleReactToMessage = useCallback((targetMessage: Message, emoji: string) => {
    const isRemove = !!(targetMessage.reactions && targetMessage.reactions[emoji] && targetMessage.reactions[emoji].includes(currentUsername));
    const action = isRemove ? SignalType.REACTION_REMOVE : SignalType.REACTION_ADD;
    onSendMessage(targetMessage.wireMessageId || targetMessage.id, emoji, action, null);
  }, [currentUsername, onSendMessage]);

  // Handle message editing
  const handleEditMessage = useCallback(async (newContent: string) => {
    if (editingMessage) {
      await onSendMessage(
        editingMessage.wireMessageId || editingMessage.id,
        newContent,
        SignalType.EDIT_MESSAGE,
        editingMessage.replyTo,
      );
      setEditingMessage(null);
    }
  }, [editingMessage, onSendMessage]);

  // Handle reply, edit, cancellation
  const handleCancelReply = useCallback(() => setReplyTo(null), []);
  const handleCancelEdit = useCallback(() => setEditingMessage(null), []);

  // Handle reply to message
  const handleReply = useCallback((message: Message) => {
    setEditingMessage(null);
    setReplyTo(message);
  }, []);

  // Handle message edit
  const handleEdit = useCallback((message: Message) => {
    setReplyTo(null);
    setEditingMessage(message);
  }, []);

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

  return (
    <div className="qor-chat-interface">
      <div
        className="qor-chat-toolbar"
      >
        <div className="min-w-0 flex-1 pr-3" />
        <div className="flex items-center gap-2">
          {/* Block Status Indicator */}
          {(isUserBlocked || isBlockedByUser) && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-red-900/20 select-none">
              <ShieldOff className="w-4 h-4 text-red-600 dark:text-red-400" />
              <span className="text-xs font-medium text-red-600 dark:text-red-400">
                {isUserBlocked ? 'Blocked' : 'Blocked You'}
              </span>
            </div>
          )}

          {selectedConversation && !keyChangePending && (
            <div className="qor-call-pill" role="group" aria-label="Call actions">
              <Button
                size="sm"
                variant="outline"
                onClick={handleAudioCall}
                disabled={!!currentCall || isUserBlocked || isBlockedByUser}
                className="qor-call-pill-btn"
                title="Audio call"
              >
                <CallIcon className="w-4 h-4" />
              </Button>
              <span className="qor-call-pill-divider" aria-hidden="true" />
              <Button
                size="sm"
                variant="outline"
                onClick={handleVideoCall}
                disabled={!!currentCall || isUserBlocked || isBlockedByUser}
                className="qor-call-pill-btn"
                title="Video call"
              >
                <Video className="w-4 h-4" />
              </Button>
            </div>
          )}

          {/* 3-dot menu */}
          {selectedConversation && (
            <Popover>
              <PopoverTrigger asChild>
                <Button
                  size="sm"
                  variant="ghost"
                  className="qor-chat-action-btn qor-chat-more-btn"
                >
                  <MoreVertical className="w-4 h-4" />
                </Button>
              </PopoverTrigger>
              <PopoverContent className="w-48 p-2 select-none" align="end">
                <div className="space-y-1">
                  <div className="px-2 py-1 text-sm font-medium text-muted-foreground">
                    Conversation Options
                  </div>
                  <div className="w-full">
                    <BlockUserButton
                      username={selectedConversation}
                      getDisplayUsername={getDisplayUsername}
                      initialBlocked={isUserBlocked}
                      variant="ghost"
                      size="sm"
                      className="w-full justify-start"
                      showText={true}
                    />
                  </div>
                </div>
              </PopoverContent>
            </Popover>
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
              Qor verified a recovery-key-authorized replacement request. The existing key remains active until{' '}
              {new Date(keyTransparencyEpochStartMs(recoveryWarning.activatesAtEpoch)).toLocaleString()}. Treat unexpected recovery as a security warning.
            </p>
          </div>
        </div>
      )}
      <ScrollArea
        className="qor-message-scroll"
        ref={scrollAreaRef}
      >
        <div className="qor-message-stack">
          {}
          {isLoadingMore && (
            <div className="qor-thread-loading" role="status" aria-live="polite">
              <span className="qor-thread-loading-spinner" aria-hidden="true" />
              <span>Loading earlier messages…</span>
            </div>
          )}
          {messages.length === 0 && !isLoadingMore ? (
            <div className="qor-thread-empty">
              No messages yet. Start the conversation!
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
                    onReply={handleReply}
                    onDelete={handleDeleteMessage}
                    onEdit={handleEdit}
                    onReact={handleReactToMessage}
                    onReplyClick={handleReplyClick}
                    currentUsername={currentUsername}
                    getDisplayUsername={getDisplayUsernameStable}
                    secureDB={secureDB}
                  />
                </div>
              );
            })
          )}

          {/* Typing Indicators */}
          <TypingIndicatorList
            selectedConversation={selectedConversation}
            getDisplayUsername={getDisplayUsernameStable}
            onUpdate={handleTypingUpdate}
          />
        </div>
      </ScrollArea>

      <div
        className="qor-chat-composer-wrap"
      >
        {keyChangePending ? (
          <div className="qor-chat-composer-blocked px-4 py-3 text-center text-sm text-amber-200/90" role="status">
            {selectedConversation}'s new security keys are awaiting automatic
            key-transparency verification. Messaging and calls remain locked.
          </div>
        ) : (
          <ChatInput
            onSendMessage={handleMessageSend}
            isEncrypted={isEncrypted}
            currentUsername={currentUsername}
            users={users}
            replyTo={replyTo}
            onCancelReply={handleCancelReply}
            editingMessage={editingMessage}
            onCancelEdit={handleCancelEdit}
            onEditMessage={handleEditMessage}
            onTyping={handleLocalTyping}
            selectedConversation={selectedConversation}
            getDisplayUsername={getDisplayUsernameStable}
            disabled={isUserBlocked || isBlockedByUser}
            getKeysOnDemand={getKeysOnDemand}
            getPeerHybridKeys={getPeerHybridKeys}
            findUser={findUser}
            secureDB={secureDB}
            ensurePeerSession={ensurePeerSession}
          />
        )}
      </div>
    </div>
  );
});

ChatInterface.displayName = 'ChatInterface';
