import React, { useEffect, useRef, useState, useCallback, useMemo } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { ChatMessage } from "./ChatMessage";
import { Message } from "./types";
import { ChatInput } from "./ChatInput.tsx";
import { User } from "./UserList";
import { SignalType } from "@/lib/signal-types.ts";
import { MessageReply } from "./types";
import { useTypingIndicator } from "@/hooks/useTypingIndicator";
import { TypingIndicator } from "./TypingIndicator";
import { useTypingIndicatorContext } from "@/contexts/TypingIndicatorContext";
import { resolveDisplayUsername } from "@/lib/unified-username-display";

import { Phone, Video, MoreVertical, X, Reply, Smile, Paperclip, Send, Trash2, Edit3, AlertTriangle, ShieldOff } from 'lucide-react';
import { useCalling } from "@/hooks/useCalling";
const CallModalLazy = React.lazy(() => import('./CallModal'));
import type { useAuth } from "@/hooks/useAuth";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { BlockUserButton } from "./BlockUserButton";
import { blockingSystem } from "@/lib/blocking-system";
import { blockStatusCache } from "@/lib/block-status-cache";
import { useReplyUpdates } from "@/hooks/useReplyUpdates";
import { useCallHistory } from "@/contexts/CallHistoryContext";


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
  readonly p2pConnected?: boolean;
  readonly selectedDisplayName?: string;
  readonly loadMoreMessages?: (peerUsername: string, currentOffset: number, limit?: number) => Promise<Message[]>;
  readonly sendP2PReadReceipt?: (messageId: string, recipient: string) => Promise<void>;
  readonly sendServerReadReceipt: (messageId: string, sender: string) => Promise<void>;
  readonly markMessageAsRead: (messageId: string) => Promise<void>;
  readonly getSmartReceiptStatus: (message: Message) => Message['receipt'] | undefined;
}

const HEX_PATTERN = /^[a-f0-9]{32,}$/i;
const SCROLL_THRESHOLD = 200;
const NEAR_BOTTOM_THRESHOLD = 100;
const SCROLL_DEBOUNCE_MS = 100;
const SCROLL_THROTTLE_MS = 300;
const READ_RECEIPT_CHECK_INTERVAL = 30000;
const MAX_BACKGROUND_MESSAGES = 1000;
const BACKGROUND_BATCH_SIZE = 100;

const truncateHash = (hash: string): string => {
  if (typeof hash !== 'string' || hash.length === 0) return '';
  return HEX_PATTERN.test(hash) ? `${hash.slice(0, 8)}...` : hash;
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
  p2pConnected = false,
  selectedDisplayName,
  loadMoreMessages,
  sendP2PReadReceipt,
  sendServerReadReceipt,
  markMessageAsRead,
  getSmartReceiptStatus,
}) => {
  const scrollAreaRef = useRef<HTMLDivElement>(null);
  const { addCallLog } = useCallHistory();

  const displayResolverRef = useRef(getDisplayUsername);
  useEffect(() => { displayResolverRef.current = getDisplayUsername; }, [getDisplayUsername]);
  const getDisplayUsernameStable = useCallback((username: string) => {
    const fn = displayResolverRef.current;
    return fn ? fn(username) : Promise.resolve(username);
  }, []);
  const [replyTo, setReplyTo] = useState<Message | null>(null);
  const [editingMessage, setEditingMessage] = useState<Message | null>(null);
  const [displayConversationName, setDisplayConversationName] = useState<string>("");
  const [isUserBlocked, setIsUserBlocked] = useState<boolean>(false);
  const [isBlockedByUser, setIsBlockedByUser] = useState<boolean>(false);
  const [isLoadingMore, setIsLoadingMore] = useState<boolean>(false);
  const [hasMoreMessages, setHasMoreMessages] = useState<boolean>(true);
  const loadedMessagesCountRef = useRef<Map<string, number>>(new Map());
  const backgroundLoadConversationRef = useRef<string | null>(null);

  const callingHook = useCalling(callingAuthContext);
  const {
    currentCall,
    localStream,
    remoteStream,
    remoteScreenStream,
    peerConnection,
    startCall,
    answerCall,
    declineCall,
    endCall,
    toggleMute,
    toggleVideo,
    switchCamera,
    startScreenShare,
    stopScreenShare,
    getAvailableScreenSources,
    isScreenSharing
  } = callingHook;

  // Track which messages have been processed in the current scroll event to prevent duplicates
  const processedInScrollRef = useRef<Set<string>>(new Set());
  const lastScrollTimeRef = useRef<number>(0);

  const { handleLocalTyping, handleConversationChange, resetTypingAfterSend } = useTypingIndicator(currentUsername, selectedConversation, onSendMessage);

  const { typingUsers: allTypingUsers } = useTypingIndicatorContext();

  const typingUsers = useMemo(() => {
    if (!selectedConversation) return [];
    return allTypingUsers.filter(username => username === selectedConversation);
  }, [allTypingUsers, selectedConversation]);

  const handleCallLog = useCallback(async (e: Event) => {
    try {
      const customEvent = e as CustomEvent;
      const detail = customEvent.detail;
      if (!detail || typeof detail !== 'object') return;
      if (!selectedConversation || detail.peer !== selectedConversation) return;

      const displayPeerName = await resolveDisplayUsername(detail.peer, getDisplayUsername);
      const durationSeconds = Math.round((detail.durationMs || 0) / 1000);

      // Save to persistent call history
      if (['ended', 'missed', 'declined'].includes(detail.type)) {
        const direction = detail.isOutgoing ? 'outgoing' : 'incoming';
        const status = detail.type === 'missed' ? 'missed' : detail.type === 'declined' ? 'declined' : 'completed';

        addCallLog({
          peerUsername: detail.peer,
          type: detail.isVideo ? 'video' : 'audio',
          direction,
          status,
          startTime: detail.at || Date.now(),
          duration: durationSeconds
        });
      }

      const label = detail.type === 'incoming' ? `Incoming call from ${displayPeerName}`
        : detail.type === 'connected' ? `Call connected with ${displayPeerName}`
          : detail.type === 'started' ? `Calling ${displayPeerName}...`
            : detail.type === 'ended' ? `Call with ${displayPeerName} ended (${durationSeconds}s)`
              : detail.type === 'declined' ? `${displayPeerName} declined the call`
                : detail.type === 'missed' ? `Missed call from ${displayPeerName}`
                  : detail.type === 'not-answered' ? `${displayPeerName} did not answer`
                    : `Call event: ${detail.type}`;

      const shouldHaveActions = ['missed', 'not-answered', 'ended', 'declined'].includes(detail.type);
      const actions = shouldHaveActions
        ? [{ label: 'Call back', onClick: () => startCall(detail.peer, 'audio').catch(() => { }) }]
        : undefined;

      setMessages((prev) => [...prev, {
        id: `call-log-${detail.callId || crypto.randomUUID()}-${detail.type}-${detail.at || Date.now()}`,
        content: JSON.stringify({ label, actionsType: actions ? 'callback' : undefined }),
        sender: 'System',
        timestamp: new Date(),
        isCurrentUser: false,
        isSystemMessage: true,
        type: 'system'
      } as Message]);
    } catch { }
  }, [setMessages, selectedConversation, getDisplayUsername, startCall, addCallLog]);

  useEffect(() => {
    window.addEventListener('ui-call-log', handleCallLog as EventListener);
    return () => window.removeEventListener('ui-call-log', handleCallLog as EventListener);
  }, [handleCallLog]);

  const handleCallRequest = useCallback((e: Event) => {
    try {
      const customEvent = e as CustomEvent;
      const detail = customEvent.detail;
      if (!detail || typeof detail !== 'object' || !detail.peer) return;
      const callType = detail.type === 'video' ? 'video' : 'audio';
      startCall(detail.peer, callType).catch(() => { });
    } catch { }
  }, [startCall]);

  useEffect(() => {
    window.addEventListener('ui-call-request', handleCallRequest as EventListener);
    return () => window.removeEventListener('ui-call-request', handleCallRequest as EventListener);
  }, [handleCallRequest]);

  // Handle conversation changes to stop typing indicators
  useEffect(() => {
    handleConversationChange();
    // Clear processed messages tracking when conversation changes
    processedInScrollRef.current.clear();
    lastScrollTimeRef.current = 0;
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
    if (selectedDisplayName && typeof selectedDisplayName === 'string') {
      setDisplayConversationName(selectedDisplayName);
    }
  }, [selectedDisplayName]);

  const resolveAndSetDisplayName = useCallback((username: string) => {
    if (!username) {
      setDisplayConversationName("");
      return;
    }

    if (getDisplayUsername) {
      getDisplayUsername(username)
        .then((resolved) => setDisplayConversationName(truncateHash(resolved)))
        .catch(() => setDisplayConversationName(truncateHash(username)));
    } else {
      setDisplayConversationName(truncateHash(username));
    }
  }, [getDisplayUsername]);

  useEffect(() => {
    if (selectedConversation) {
      resolveAndSetDisplayName(selectedConversation);
    } else {
      setDisplayConversationName("");
    }
  }, [selectedConversation, resolveAndSetDisplayName]);

  const handleUsernameMappingUpdate = useCallback(() => {
    if (selectedConversation) {
      resolveAndSetDisplayName(selectedConversation);
    }
  }, [selectedConversation, resolveAndSetDisplayName]);

  useEffect(() => {
    window.addEventListener('username-mapping-updated', handleUsernameMappingUpdate);
    window.addEventListener('username-mapping-received', handleUsernameMappingUpdate);
    return () => {
      window.removeEventListener('username-mapping-updated', handleUsernameMappingUpdate);
      window.removeEventListener('username-mapping-received', handleUsernameMappingUpdate);
    };
  }, [handleUsernameMappingUpdate]);

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
          // Prefer Kyber secret when passphrase is not available (token-login)
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
      } catch (_error) {
        setIsUserBlocked(blockStatusCache.get(selectedConversation) ?? false);
        setIsBlockedByUser(false);
      }
    };

    checkBlockingStatus();
  }, [selectedConversation, callingAuthContext?.passphrasePlaintextRef?.current, callingAuthContext?.hybridKeysRef?.current]);

  const handleBlockStatusChange = useCallback((event: CustomEvent) => {
    const { username, isBlocked } = event.detail;
    if (username === selectedConversation) {
      setIsUserBlocked(isBlocked);
    }
  }, [selectedConversation]);

  useEffect(() => {
    window.addEventListener('block-status-changed', handleBlockStatusChange as EventListener);
    return () => window.removeEventListener('block-status-changed', handleBlockStatusChange as EventListener);
  }, [handleBlockStatusChange]);

  // Unified read receipt function that handles both P2P and server messages
  const sendReadReceipt = useCallback(async (messageId: string, sender: string) => {
    const message = messages.find(m => m.id === messageId);

    if (message?.p2p === true && sendP2PReadReceipt) {
      try {
        await sendP2PReadReceipt(messageId, sender);
      } catch (_error) {
      }
    } else {
      await sendServerReadReceipt(messageId, sender);
    }
  }, [messages, sendP2PReadReceipt, sendServerReadReceipt]);

  useReplyUpdates(messages, setMessages, saveMessageToLocalDB);

  // Smart auto-scroll: only scroll to bottom when appropriate
  const prevMessagesLengthRef = useRef(messages.length);
  const lastMessageIdRef = useRef<string | null>(null);

  useEffect(() => {
    if (!scrollAreaRef.current) return;

    const scrollContainer = scrollAreaRef.current.querySelector('[data-radix-scroll-area-viewport]');
    if (!scrollContainer) return;

    const currentMessagesLength = messages.length;
    const prevMessagesLength = prevMessagesLengthRef.current;

    // Check if this is a new message (length increased)
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

    // Update the previous length
    prevMessagesLengthRef.current = currentMessagesLength;
  }, [messages, currentUsername]);

  // Mark messages as read when they come into view or when scrolled to bottom
  useEffect(() => {
    const scrollContainer = scrollAreaRef.current?.querySelector('[data-radix-scroll-area-viewport]');
    if (!scrollContainer) return;

    const isTabActive = () => document.visibilityState === 'visible' && document.hasFocus();

    const handleScroll = () => {
      if (!isTabActive()) return;

      const now = Date.now();
      if (now - lastScrollTimeRef.current < SCROLL_THROTTLE_MS) {
        return;
      }
      lastScrollTimeRef.current = now;
      processedInScrollRef.current.clear();

      const containerRect = scrollContainer.getBoundingClientRect();
      const containerBottom = containerRect.bottom;

      const isNearBottom = scrollContainer.scrollTop >= scrollContainer.scrollHeight - scrollContainer.clientHeight - NEAR_BOTTOM_THRESHOLD;

      let messagesToMarkAsRead: Message[] = [];

      if (isNearBottom) {
        messagesToMarkAsRead = messages.filter(message => {
          return message.sender !== currentUsername && !message.receipt?.read;
        });
      } else {
        messages.forEach(message => {
          if (message.sender === currentUsername || message.receipt?.read) return;
          if (processedInScrollRef.current.has(message.id)) return;

          const messageElement = document.getElementById(`message-${message.id}`);
          if (messageElement) {
            const messageRect = messageElement.getBoundingClientRect();
            const messageBottom = messageRect.bottom;

            if (messageBottom <= containerBottom && messageBottom >= containerRect.top) {
              messagesToMarkAsRead.push(message);
              processedInScrollRef.current.add(message.id);
            }
          }
        });
      }

      messagesToMarkAsRead.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
      messagesToMarkAsRead.forEach((msg) => {
        markMessageAsRead(msg.id);
        sendReadReceipt(msg.id, msg.sender);
      });
    };

    let scrollTimeout: ReturnType<typeof setTimeout>;
    const debouncedHandleScroll = () => {
      clearTimeout(scrollTimeout);
      scrollTimeout = setTimeout(handleScroll, SCROLL_DEBOUNCE_MS);
    };

    scrollContainer.addEventListener('scroll', debouncedHandleScroll);
    window.addEventListener('visibilitychange', handleScroll);
    window.addEventListener('focus', handleScroll);
    window.addEventListener('blur', handleScroll);

    setTimeout(handleScroll, 100);
    setTimeout(handleScroll, 500);

    return () => {
      clearTimeout(scrollTimeout);
      scrollContainer.removeEventListener('scroll', debouncedHandleScroll);
      window.removeEventListener('visibilitychange', handleScroll);
      window.removeEventListener('focus', handleScroll);
      window.removeEventListener('blur', handleScroll);
    };
  }, [messages, currentUsername, markMessageAsRead, sendReadReceipt]);

  // Auto-scroll to bottom when messages change or typing users change
  useEffect(() => {
    const scrollContainer = scrollAreaRef.current?.querySelector('[data-radix-scroll-area-viewport]');
    if (!scrollContainer || isLoadingMore) return;

    const isNearBottom = scrollContainer.scrollHeight - scrollContainer.scrollTop - scrollContainer.clientHeight < 100;

    if (isNearBottom) {
      scrollToBottom(scrollContainer);
    }
  }, [messages, typingUsers, isLoadingMore, scrollToBottom]);

  // Periodic check to ensure read receipts are sent for visible messages
  useEffect(() => {
    const checkForMissedReadReceipts = () => {
      if (document.visibilityState === 'visible' && document.hasFocus() && messages.length > 0) {

        const scrollContainer = scrollAreaRef.current?.querySelector('[data-radix-scroll-area-viewport]');
        if (scrollContainer) {
          const isNearBottom = scrollContainer.scrollTop >= scrollContainer.scrollHeight - scrollContainer.clientHeight - NEAR_BOTTOM_THRESHOLD;

          let messagesToProcess: Message[] = [];

          if (isNearBottom) {
            messagesToProcess = messages.filter(message => {
              return message.sender !== currentUsername && !message.receipt?.read;
            });
          } else {
            const containerRect = scrollContainer.getBoundingClientRect();
            const containerBottom = containerRect.bottom;

            messages.forEach(message => {
              if (message.sender === currentUsername || message.receipt?.read) return;

              const messageElement = document.getElementById(`message-${message.id}`);
              if (messageElement) {
                const messageRect = messageElement.getBoundingClientRect();
                const messageBottom = messageRect.bottom;

                // Only consider visible messages
                if (messageBottom <= containerBottom && messageBottom >= containerRect.top) {
                  messagesToProcess.push(message);
                }
              }
            });
          }

          // Send read receipts for messages that need them
          messagesToProcess
            .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
            .forEach((m) => {
              markMessageAsRead(m.id);
              sendReadReceipt(m.id, m.sender);
            });
        }
      }
    };

    // Check every 30 seconds for missed read receipts
    const interval = setInterval(checkForMissedReadReceipts, READ_RECEIPT_CHECK_INTERVAL);

    return () => clearInterval(interval);
  }, [messages, currentUsername, markMessageAsRead, sendReadReceipt]);



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
  const handleReply = useCallback((message: Message) => setReplyTo(message), []);
  const handleEdit = useCallback((message: Message) => setEditingMessage(message), []);

  const handleBlockStatusChangeInline = useCallback((username: string, isBlocked: boolean) => {
    if (username === selectedConversation) {
      setIsUserBlocked(isBlocked);
    }
  }, [selectedConversation]);

  const handleCallModalAnswer = useCallback(() => {
    if (currentCall) answerCall(currentCall.id);
  }, [currentCall, answerCall]);

  const handleCallModalDecline = useCallback(() => {
    if (currentCall) declineCall(currentCall.id);
  }, [currentCall, declineCall]);

  const emptyMessagesUI = useMemo(() => (
    <div
      className="flex items-center justify-center h-full min-h-[200px] text-sm"
      style={{ color: 'var(--color-text-secondary)' }}
    >
      {selectedConversation ? "No messages yet. Start the conversation!" : "Select a conversation to view messages"}
    </div>
  ), [selectedConversation]);
  return (
    <div
      className="flex flex-col h-full"
      style={{ backgroundColor: 'var(--color-background)' }}
    >
      <div
        className="p-4 border-b flex items-center justify-between"
        style={{
          backgroundColor: 'var(--color-surface)',
          borderColor: 'var(--color-border)'
        }}
      >
        <div className="min-w-0 flex-1 mr-4">
          <h2
            className="text-lg font-semibold truncate block"
            style={{ color: 'var(--color-text-primary)' }}
            title={displayConversationName || "Chat"}
          >
            {displayConversationName || "Chat"}
          </h2>
        </div>
        <div className="flex items-center gap-2">
          {selectedConversation && (
            <>
              <Button
                size="sm"
                variant="outline"
                onClick={handleAudioCall}
                disabled={!!currentCall || isUserBlocked || isBlockedByUser}
                className="flex items-center gap-2 select-none"
                style={{
                  backgroundColor: 'transparent',
                  borderColor: 'var(--color-border)',
                  color: 'var(--color-text-primary)'
                }}
              >
                <Phone className="w-4 h-4" />
                <span>Call</span>
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={handleVideoCall}
                disabled={!!currentCall || isUserBlocked || isBlockedByUser}
                className="flex items-center gap-2 select-none"
                style={{
                  backgroundColor: 'transparent',
                  borderColor: 'var(--color-border)',
                  color: 'var(--color-text-primary)'
                }}
              >
                <Video className="w-4 h-4" />
                <span>Video</span>
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


          {/* P2P Connection Indicator */}
          {p2pConnected && (
            <div
              className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium"
              style={{
                backgroundColor: 'var(--color-success-background, rgba(34, 197, 94, 0.1))',
                color: 'var(--color-success, #22c55e)',
                border: '1px solid var(--color-success, #22c55e)'
              }}
              title="Direct peer-to-peer connection active"
            >
              <svg
                className="w-3 h-3"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M13 10V3L4 14h7v7l9-11h-7z"
                />
              </svg>
              <span className="select-none">P2P</span>
            </div>
          )}

          {/* Block Status Indicator */}
          {(isUserBlocked || isBlockedByUser) && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-red-100 dark:bg-red-900/20 select-none">
              <ShieldOff className="w-4 h-4 text-red-600 dark:text-red-400" />
              <span className="text-xs font-medium text-red-600 dark:text-red-400">
                {isUserBlocked ? 'Blocked' : 'Blocked You'}
              </span>
            </div>
          )}
        </div>
      </div>
      <ScrollArea
        className="flex-1 p-4"
        ref={scrollAreaRef}
        style={{ backgroundColor: 'var(--color-background)' }}
      >
        <div className="space-y-4">
          {messages.length === 0 ? emptyMessagesUI : (
            messages.map((message, index) => {
              const smartReceipt = getSmartReceiptStatus(message);
              const isMine = message.isCurrentUser || message.sender === currentUsername;
              const receiptToShow = isMine && smartReceipt ? smartReceipt : undefined;
              const uniqueKey = message.id || `message-${index}`;
              return (
                <div key={uniqueKey} id={`message-${message.id}`}>
                  <ChatMessage
                    message={{
                      ...message,
                      receipt: receiptToShow,
                    }}
                    previousMessage={index > 0 ? messages[index - 1] : undefined}
                    onReply={() => handleReply(message)}
                    onDelete={() => handleDeleteMessage(message)}
                    onEdit={() => handleEdit(message)}
                    onReact={handleReactToMessage}
                    currentUsername={currentUsername}
                    getDisplayUsername={getDisplayUsernameStable}
                  />
                </div>
              );
            })
          )}

          {/* Typing Indicators */}
          {typingUsers.length > 0 && (
            <div className="flex flex-col gap-2 mt-2">
              {typingUsers.map((username) => (
                <TypingIndicator
                  key={username}
                  username={username}
                  getDisplayUsername={getDisplayUsernameStable}
                />
              ))}
            </div>
          )}
        </div>
      </ScrollArea>




      <div
        className="px-4 pb-4"
        style={{ backgroundColor: 'var(--color-background)' }}
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
        />
      </div>

      {/* Call Modal */}
      {currentCall && (
        <React.Suspense fallback={null}>
          <CallModalLazy
            call={currentCall}
            localStream={localStream}
            remoteStream={remoteStream}
            remoteScreenStream={remoteScreenStream}
            peerConnection={peerConnection}
            onAnswer={handleCallModalAnswer}
            onDecline={handleCallModalDecline}
            onEndCall={endCall}
            onToggleMute={toggleMute}
            onToggleVideo={toggleVideo}
            onSwitchCamera={switchCamera}
            onStartScreenShare={startScreenShare}
            onStopScreenShare={stopScreenShare}
            onGetAvailableScreenSources={getAvailableScreenSources}
            isScreenSharing={isScreenSharing}
            getDisplayUsername={getDisplayUsernameStable}
          />
        </React.Suspense>
      )}
    </div>
  );
}, (prevProps, nextProps) => {
  return (
    prevProps.messages === nextProps.messages &&
    prevProps.selectedConversation === nextProps.selectedConversation &&
    prevProps.currentUsername === nextProps.currentUsername &&
    prevProps.p2pConnected === nextProps.p2pConnected &&
    prevProps.selectedDisplayName === nextProps.selectedDisplayName &&
    prevProps.isEncrypted === nextProps.isEncrypted &&
    prevProps.users === nextProps.users
  );
});

ChatInterface.displayName = 'ChatInterface';
