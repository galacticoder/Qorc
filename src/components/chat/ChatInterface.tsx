import React, { useEffect, useRef, useState, useCallback, useMemo } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { ChatMessage } from "./ChatMessage";
import { Message } from "./types";
import { ChatInput } from "./ChatInput.tsx";
import { User } from "./UserList";
import { SignalType } from "@/lib/signal-types";
import { MessageReply } from "./types";
import { useTypingIndicator } from "@/hooks/useTypingIndicator";
import { TypingIndicatorList } from "./TypingIndicatorList";
import { Video, MoreVertical, ShieldOff } from 'lucide-react';
import { CallIcon } from './icons';
import type { CallState } from "../../lib/webrtc-calling";
import type { useAuth } from "@/hooks/useAuth";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { BlockUserButton } from "./BlockUserButton";
import { blockingSystem } from "@/lib/blocking-system";
import { blockStatusCache } from "@/lib/block-status-cache";
import { useReplyUpdates } from "@/hooks/useReplyUpdates";


interface HybridKeys {
  readonly x25519: { readonly private: Uint8Array; readonly publicKeyBase64: string };
  readonly kyber: { readonly publicKeyBase64: string; readonly secretKey: Uint8Array };
  readonly dilithium: { readonly publicKeyBase64: string; readonly secretKey: Uint8Array };
}

interface ChatInterfaceProps {
  readonly onSendMessage: (
    messageId: string,
    content: string,
    messageSignalType: string,
    replyTo?: MessageReply | null
  ) => Promise<void>;
  readonly onSendFile: (fileData: unknown) => void;
  readonly messages: ReadonlyArray<Message>;
  readonly setMessages: React.Dispatch<React.SetStateAction<Message[]>>;
  readonly isEncrypted?: boolean;
  readonly currentUsername: string;
  readonly users: ReadonlyArray<User>;
  readonly selectedConversation?: string;
  readonly saveMessageToLocalDB: (msg: Message) => Promise<void>;
  readonly callingAuthContext?: ReturnType<typeof useAuth>;
  readonly getDisplayUsername?: (username: string) => Promise<string>;
  readonly getKeysOnDemand?: () => Promise<HybridKeys | null>;
  readonly getPeerHybridKeys?: (peerUsername: string) => Promise<{ kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64?: string } | null>;
  readonly p2pConnected?: boolean;
  readonly loadMoreMessages?: (peerUsername: string, currentOffset: number, limit?: number) => Promise<Message[]>;
  readonly sendP2PReadReceipt?: (messageId: string, recipient: string) => Promise<void>;
  readonly sendServerReadReceipt: (messageId: string, sender: string) => Promise<void>;
  readonly markMessageAsRead: (messageId: string) => Promise<void>;
  readonly getSmartReceiptStatus: (message: Message) => Message['receipt'] | undefined;
  readonly secureDB?: any;
  readonly currentCall?: CallState | null;
  readonly startCall: (targetUser: string, callType?: 'audio' | 'video') => Promise<string>;
}

const SCROLL_THRESHOLD = 200;
const NEAR_BOTTOM_THRESHOLD = 100;
const MAX_BACKGROUND_MESSAGES = 1000;
const BACKGROUND_BATCH_SIZE = 100;

const UI_EVENT_RATE_WINDOW_MS = 10_000;
const UI_EVENT_RATE_MAX = 500;
const MAX_UI_USERNAME_LENGTH = 256;

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

const hasPrototypePollutionKeys = (obj: unknown): boolean => {
  if (obj == null || typeof obj !== 'object') return false;
  const keys = Object.keys(obj as Record<string, unknown>);
  return keys.some((key) => key === '__proto__' || key === 'constructor' || key === 'prototype');
};

const sanitizeUiText = (value: unknown, maxLen: number): string | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  const cleaned = trimmed.replace(/[\x00-\x1F\x7F]/g, '');
  if (!cleaned) return null;
  return cleaned.slice(0, maxLen);
};

export const ChatInterface = React.memo<ChatInterfaceProps>(({
  onSendMessage,
  onSendFile,
  messages,
  setMessages,
  isEncrypted = true,
  currentUsername,
  users,
  selectedConversation,
  saveMessageToLocalDB,
  callingAuthContext,
  getDisplayUsername,
  getKeysOnDemand,
  getPeerHybridKeys,
  p2pConnected: _p2pConnected = false,
  loadMoreMessages,
  sendP2PReadReceipt,
  sendServerReadReceipt,
  markMessageAsRead,
  getSmartReceiptStatus,
  secureDB,
  currentCall,
  startCall,
}) => {
  const scrollAreaRef = useRef<HTMLDivElement>(null);

  const uiEventRateRef = useRef<{ windowStart: number; count: number }>({ windowStart: Date.now(), count: 0 });

  const displayResolverRef = useRef(getDisplayUsername);
  useEffect(() => { displayResolverRef.current = getDisplayUsername; }, [getDisplayUsername]);
  const getDisplayUsernameStable = useCallback((username: string) => {
    const fn = displayResolverRef.current;
    return fn ? fn(username) : Promise.resolve(username);
  }, []);
  const [replyTo, setReplyTo] = useState<Message | null>(null);
  const [editingMessage, setEditingMessage] = useState<Message | null>(null);
  const [isUserBlocked, setIsUserBlocked] = useState<boolean>(false);
  const [isBlockedByUser, setIsBlockedByUser] = useState<boolean>(false);
  const [isLoadingMore, setIsLoadingMore] = useState<boolean>(false);
  const [hasMoreMessages, setHasMoreMessages] = useState<boolean>(true);
  const loadedMessagesCountRef = useRef<Map<string, number>>(new Map());
  const backgroundLoadConversationRef = useRef<string | null>(null);

  const processedInScrollRef = useRef<Set<string>>(new Set());
  const lastScrollTimeRef = useRef<number>(0);
  const { handleLocalTyping, handleConversationChange, resetTypingAfterSend } = useTypingIndicator(currentUsername, selectedConversation, onSendMessage);
  const initialScrollDoneRef = useRef<Map<string, boolean>>(new Map());

  useEffect(() => {
    handleConversationChange();
    processedInScrollRef.current.clear();
    lastScrollTimeRef.current = 0;
    if (selectedConversation) {
      initialScrollDoneRef.current.delete(selectedConversation);
    }
  }, [selectedConversation, handleConversationChange]);

  const scrollToBottom = useCallback((container: Element) => {
    try {
      container.scrollTo({ top: container.scrollHeight, behavior: 'auto' });
    } catch { }
  }, []);

  useEffect(() => {
    const scrollContainer = scrollAreaRef.current?.querySelector('[data-radix-scroll-area-viewport]');
    if (!scrollContainer) return;

    const t1 = setTimeout(() => scrollToBottom(scrollContainer), 80);
    const t2 = setTimeout(() => scrollToBottom(scrollContainer), 400);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
    };
  }, [selectedConversation, scrollToBottom]);

  useEffect(() => {
    if (!selectedConversation) return;
    const alreadyScrolled = initialScrollDoneRef.current.get(selectedConversation);
    if (alreadyScrolled) return;

    const scrollContainer = scrollAreaRef.current?.querySelector('[data-radix-scroll-area-viewport]');
    if (!scrollContainer) return;

    scrollToBottom(scrollContainer);
    initialScrollDoneRef.current.set(selectedConversation, true);
  }, [messages, selectedConversation, scrollToBottom]);

  useEffect(() => {
    if (selectedConversation) {
      setHasMoreMessages(true);
      setIsLoadingMore(false);
      if (!loadedMessagesCountRef.current.has(selectedConversation)) {
        loadedMessagesCountRef.current.set(selectedConversation, 50);
      }
    }
  }, [selectedConversation]);

  useEffect(() => {
    if (!selectedConversation || !loadMoreMessages) return;

    const conversationToLoad = selectedConversation;
    backgroundLoadConversationRef.current = conversationToLoad;

    const loadBackgroundMessages = async () => {
      try {
        await new Promise(resolve => setTimeout(resolve, 500));

        const currentCount = loadedMessagesCountRef.current.get(conversationToLoad) || 50;
        const maxMessages = MAX_BACKGROUND_MESSAGES;
        const batchSize = BACKGROUND_BATCH_SIZE;

        // Load in batches up to 1000 messages
        let loadedCount = currentCount;
        while (loadedCount < maxMessages) {
          if (backgroundLoadConversationRef.current !== conversationToLoad) break;

          const batch = await loadMoreMessages(conversationToLoad, loadedCount, batchSize);
          if (batch.length === 0) break;

          loadedCount += batch.length;
          loadedMessagesCountRef.current.set(conversationToLoad, loadedCount);

          await new Promise(resolve => setTimeout(resolve, 100));

          if (batch.length < batchSize) break;
        }
      } catch {
      }
    };

    loadBackgroundMessages();
  }, [selectedConversation, loadMoreMessages]);

  const handleLazyLoadScroll = useCallback(async (scrollContainer: Element) => {
    if (isLoadingMore || !hasMoreMessages || !selectedConversation || !loadMoreMessages) return;

    const scrollTop = scrollContainer.scrollTop;

    if (scrollTop < SCROLL_THRESHOLD) {
      setIsLoadingMore(true);

      try {
        const currentCount = loadedMessagesCountRef.current.get(selectedConversation) || 50;
        const moreMessages = await loadMoreMessages(selectedConversation, currentCount, 50);

        if (moreMessages.length < 50) {
          setHasMoreMessages(false);
        }

        if (moreMessages.length > 0) {
          loadedMessagesCountRef.current.set(selectedConversation, currentCount + moreMessages.length);
        }
      } catch {
      } finally {
        setIsLoadingMore(false);
      }
    }
  }, [selectedConversation, loadMoreMessages, isLoadingMore, hasMoreMessages]);

  useEffect(() => {
    const scrollContainer = scrollAreaRef.current?.querySelector('[data-radix-scroll-area-viewport]');
    if (!scrollContainer) return;

    const handleScroll = () => handleLazyLoadScroll(scrollContainer);
    scrollContainer.addEventListener('scroll', handleScroll);
    return () => scrollContainer.removeEventListener('scroll', handleScroll);
  }, [handleLazyLoadScroll]);

  // Check blocking status when conversation changes or key material becomes available
  useEffect(() => {
    const checkBlockingStatus = async () => {
      if (!selectedConversation) {
        setIsUserBlocked(false);
        setIsBlockedByUser(false);
        return;
      }

      try {
        const passphrase = callingAuthContext?.passphrasePlaintextRef?.current;
        let keyArg: any = '';
        if (passphrase && typeof passphrase === 'string' && passphrase.length > 0) {
          keyArg = passphrase;
        } else {
          // Prefer Kyber secret when passphrase is not available
          let kyberSecret: Uint8Array | undefined = callingAuthContext?.hybridKeysRef?.current?.kyber?.secretKey;
          if (!kyberSecret && typeof callingAuthContext?.getKeysOnDemand === 'function') {
            try {
              const keys = await callingAuthContext.getKeysOnDemand();
              kyberSecret = keys?.kyber?.secretKey;
            } catch { }
          }
          if (kyberSecret instanceof Uint8Array && kyberSecret.length > 0) {
            keyArg = { kyberSecret };
          }
        }

        if (!keyArg) {
          const cached = blockStatusCache.get(selectedConversation);
          setIsUserBlocked(cached ?? false);
          setIsBlockedByUser(false);
          return;
        }

        const blocked = await blockingSystem.isUserBlocked(selectedConversation, keyArg);
        setIsUserBlocked(blocked);
        blockStatusCache.set(selectedConversation, blocked);

        setIsBlockedByUser(false);
      } catch {
        setIsUserBlocked(blockStatusCache.get(selectedConversation) ?? false);
        setIsBlockedByUser(false);
      }
    };

    checkBlockingStatus();
  }, [selectedConversation, callingAuthContext?.passphrasePlaintextRef?.current, callingAuthContext?.hybridKeysRef?.current]);

  const handleBlockStatusChange = useCallback((event: Event) => {
    try {
      const now = Date.now();
      const bucket = uiEventRateRef.current;
      if (now - bucket.windowStart > UI_EVENT_RATE_WINDOW_MS) {
        bucket.windowStart = now;
        bucket.count = 0;
      }
      bucket.count += 1;
      if (bucket.count > UI_EVENT_RATE_MAX) {
        return;
      }

      if (!(event instanceof CustomEvent)) return;
      const detail = event.detail;
      if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

      const username = sanitizeUiText((detail as any).username, MAX_UI_USERNAME_LENGTH);
      if (!username) return;
      const isBlocked = (detail as any).isBlocked === true;

      if (username === selectedConversation) {
        setIsUserBlocked(isBlocked);
      }
    } catch { }
  }, [selectedConversation]);

  useEffect(() => {
    window.addEventListener('block-status-changed', handleBlockStatusChange as EventListener);
    return () => window.removeEventListener('block-status-changed', handleBlockStatusChange as EventListener);
  }, [handleBlockStatusChange]);

  const sendReadReceipt = useCallback(async (messageId: string, sender: string) => {
    const message = messages.find(m => m.id === messageId);

    if (message?.p2p === true && sendP2PReadReceipt) {
      try {
        await sendP2PReadReceipt(messageId, sender);
      } catch { }
    } else {
      await sendServerReadReceipt(messageId, sender);
    }
  }, [messages, sendP2PReadReceipt, sendServerReadReceipt]);

  useReplyUpdates(messages, setMessages, saveMessageToLocalDB);

  const prevMessagesLengthRef = useRef(messages.length);
  const lastMessageIdRef = useRef<string | null>(null);

  useEffect(() => {
    if (!scrollAreaRef.current) return;

    const scrollContainer = scrollAreaRef.current.querySelector('[data-radix-scroll-area-viewport]');
    if (!scrollContainer) return;

    const currentMessagesLength = messages.length;
    const prevMessagesLength = prevMessagesLengthRef.current;

    // Check if this is a new message 
    const isNewMessage = currentMessagesLength > prevMessagesLength;

    // Get the latest message
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



  const handleAudioCall = useCallback(async () => {
    if (!selectedConversation) return;
    try {
      await startCall(selectedConversation, 'audio');
    } catch (_error) {
      alert('Failed to start call: ' + (_error as Error).message);
    }
  }, [selectedConversation, startCall]);

  const handleVideoCall = useCallback(async () => {
    if (!selectedConversation) return;
    try {
      await startCall(selectedConversation, 'video');
    } catch (_error) {
      alert('Failed to start video call: ' + (_error as Error).message);
    }
  }, [selectedConversation, startCall]);

  const handleMessageSend = useCallback(async (
    messageId: string | undefined,
    content: string,
    messageSignalType: string,
    replyToMsg?: MessageReply | null
  ) => {
    await onSendMessage(messageId ?? "", content, messageSignalType, replyToMsg);

    if (messageSignalType !== 'typing-start' && messageSignalType !== 'typing-stop') {
      resetTypingAfterSend();
      setReplyTo(null);
    }
  }, [onSendMessage, resetTypingAfterSend]);

  const handleDeleteMessage = useCallback((message: Message) => {
    onSendMessage(message.id, "", SignalType.DELETE_MESSAGE, null);
  }, [onSendMessage]);

  const handleReactToMessage = useCallback((targetMessage: Message, emoji: string) => {
    const isRemove = !!(targetMessage.reactions && targetMessage.reactions[emoji] && targetMessage.reactions[emoji].includes(currentUsername));
    const action = isRemove ? SignalType.REACTION_REMOVE : SignalType.REACTION_ADD;
    onSendMessage(targetMessage.id, emoji, action, null);
  }, [currentUsername, onSendMessage]);

  const handleEditMessage = useCallback(async (newContent: string) => {
    if (editingMessage) {
      await onSendMessage(editingMessage.id, newContent, SignalType.EDIT_MESSAGE, editingMessage.replyTo);
      setEditingMessage(null);
    }
  }, [editingMessage, onSendMessage]);

  const handleCancelReply = useCallback(() => setReplyTo(null), []);
  const handleCancelEdit = useCallback(() => setEditingMessage(null), []);
  const handleReply = useCallback((message: Message) => {
    setEditingMessage(null);
    setReplyTo(message);
  }, []);
  const handleEdit = useCallback((message: Message) => {
    setReplyTo(null);
    setEditingMessage(message);
  }, []);

  const handleBlockStatusChangeInline = useCallback((username: string, isBlocked: boolean) => {
    if (username === selectedConversation) {
      setIsUserBlocked(isBlocked);
    }
  }, [selectedConversation]);

  const emptyMessagesUI = useMemo(() => (
    <div
      className="flex items-center justify-center h-full min-h-[200px] text-sm select-none"
      style={{ color: 'var(--color-text-secondary)' }}
    >
      {selectedConversation ? "No messages yet. Start the conversation!" : "Select a conversation to view messages"}
    </div>
  ), [selectedConversation]);
  const handleReplyClick = useCallback((replyId: string) => {
    const el = document.getElementById(`message-${replyId}`);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      el.classList.add('bg-secondary/20');
      setTimeout(() => el.classList.remove('bg-secondary/20'), 1500);
    }
  }, []);


  return (
    <div className="flex flex-col h-full relative" style={{ backgroundColor: 'var(--chat-background)' }}>
      <div
        className="p-4 flex items-center justify-between absolute top-0 left-0 right-0 z-10"
        style={{
          border: 'none'
        }}
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

          {selectedConversation && (
            <>
              <Button
                size="sm"
                variant="outline"
                onClick={handleAudioCall}
                disabled={!!currentCall || isUserBlocked || isBlockedByUser}
                className="flex items-center justify-center select-none dark:border-gray-600 [&:hover]:!bg-background [&:hover]:!text-foreground dark:[&:hover]:!border-gray-600"
                title="Audio call"
              >
                <CallIcon className="w-4 h-4" />
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={handleVideoCall}
                disabled={!!currentCall || isUserBlocked || isBlockedByUser}
                className="flex items-center justify-center select-none dark:border-gray-600 [&:hover]:!bg-background [&:hover]:!text-foreground dark:[&:hover]:!border-gray-600"
                title="Video call"
              >
                <Video className="w-4 h-4" />
              </Button>
            </>
          )}

          {/* 3-dot menu */}
          {selectedConversation && (
            <Popover>
              <PopoverTrigger asChild>
                <Button
                  size="sm"
                  variant="ghost"
                  className="p-2"
                  style={{
                    color: 'var(--color-text-primary)'
                  }}
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
                      passphraseRef={callingAuthContext?.passphrasePlaintextRef}
                      kyberSecretRef={callingAuthContext?.hybridKeysRef?.current ? { current: callingAuthContext.hybridKeysRef.current.kyber?.secretKey || null } : undefined}
                      getDisplayUsername={getDisplayUsername}
                      initialBlocked={isUserBlocked}
                      variant="ghost"
                      size="sm"
                      className="w-full justify-start"
                      showText={true}
                      onBlockStatusChange={handleBlockStatusChangeInline}
                    />
                  </div>
                </div>
              </PopoverContent>
            </Popover>
          )}

        </div>
      </div>
      <ScrollArea
        className="absolute inset-0"
        style={{
          paddingTop: '0px',
          paddingLeft: '16px',
          paddingRight: '16px',
          backgroundColor: 'var(--chat-background)',
          zIndex: 0
        }}
        ref={scrollAreaRef}
      >
        <div className="space-y-4 pb-24 pt-20">
          {messages.length === 0 ? emptyMessagesUI : (
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
        className="absolute bottom-0 left-0 right-0 px-4 pb-4 z-20"
        style={{
          backgroundColor: 'transparent',
          backgroundImage: 'linear-gradient(to top, var(--chat-background), transparent)'
        }}
      >
        <ChatInput
          onSendMessage={handleMessageSend}
          onSendFile={onSendFile}
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
        />
      </div>
    </div>
  );
}, (prevProps, nextProps) => {
  return (
    prevProps.messages === nextProps.messages &&
    prevProps.selectedConversation === nextProps.selectedConversation &&
    prevProps.currentUsername === nextProps.currentUsername &&
    prevProps.p2pConnected === nextProps.p2pConnected &&
    prevProps.isEncrypted === nextProps.isEncrypted &&
    prevProps.users === nextProps.users &&
    prevProps.currentCall === nextProps.currentCall
  );
});

ChatInterface.displayName = 'ChatInterface';
