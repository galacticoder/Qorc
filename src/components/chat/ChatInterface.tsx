import React, { useEffect, useRef, useState } from "react";
import { Card } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { ChatMessage } from "./ChatMessage";
import { Message } from "./types";
import { ChatInput } from "./ChatInput.tsx";
import { Separator } from "@/components/ui/separator";
import { User } from "./UserList";
import { SignalType } from "@/lib/signals.ts";
import { MessageReply } from "./types";
import { useTypingIndicator } from "@/hooks/useTypingIndicator";
import { TypingIndicator } from "./TypingIndicator";
import { useTypingIndicatorContext } from "@/contexts/TypingIndicatorContext";
import { resolveDisplayUsername } from "@/lib/unified-username-display";
import { useMessageReceipts } from "@/hooks/useMessageReceipts";
import { TorIndicator } from "@/components/ui/TorIndicator";
import { Phone, Video } from "lucide-react";
import { useCalling } from "@/hooks/useCalling";
import { CallModal } from "./CallModal";
import { useAuth } from "@/hooks/useAuth";


interface ChatInterfaceProps {
  onSendMessage: (
    messageId: string,
    content: string,
    messageSignalType: string,
    replyTo?: MessageReply | null
  ) => Promise<void>;
  onSendFile: (fileData: any) => void;
  messages: Message[];
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>;
  isEncrypted?: boolean;
  currentUsername: string;
  users: User[];
  selectedConversation?: string;
  saveMessageToLocalDB: (msg: Message) => Promise<void>;
  callingAuthContext?: ReturnType<typeof useAuth>;
  getDisplayUsername?: (username: string) => Promise<string>;
}

export function ChatInterface({
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
}: ChatInterfaceProps) {
  const scrollAreaRef = useRef<HTMLDivElement>(null);
  const [replyTo, setReplyTo] = useState<Message | null>(null);
  const [editingMessage, setEditingMessage] = useState<Message | null>(null);
  const [displayConversationName, setDisplayConversationName] = useState<string>("");

  // Calling functionality
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

  // Typing hook
  const { handleLocalTyping, handleConversationChange, resetTypingAfterSend } = useTypingIndicator(currentUsername, selectedConversation, onSendMessage);
  const { typingUsers } = useTypingIndicatorContext();

  // Log typing users changes
  useEffect(() => {
    console.log('[ChatInterface] typingUsers changed:', typingUsers);
  }, [typingUsers]);

  // Listen for call logs and inject system messages into conversation
  useEffect(() => {
    const handler = async (e: any) => {
      try {
        const d = e.detail || {};
        if (!selectedConversation || d.peer !== selectedConversation) return;

        // Resolve the peer name for display
        const displayPeerName = await resolveDisplayUsername(d.peer, getDisplayUsername);

        const label = d.type === 'incoming' ? `Incoming call from ${displayPeerName}`
          : d.type === 'connected' ? `Call connected with ${displayPeerName}`
          : d.type === 'started' ? `Calling ${displayPeerName}...`
          : d.type === 'ended' ? `Call with ${displayPeerName} ended (${Math.round((d.durationMs||0)/1000)}s)`
          : d.type === 'declined' ? `${displayPeerName} declined the call`
          : d.type === 'missed' ? `Missed call from ${displayPeerName}`
          : d.type === 'not-answered' ? `${displayPeerName} did not answer`
          : `Call event: ${d.type}`;
        const actions = (d.type === 'missed' || d.type === 'not-answered' || d.type === 'ended' || d.type === 'declined')
          ? [{ label: 'Call back', onClick: () => startCall(d.peer, 'audio').catch(() => {}) }]
          : undefined;
        setMessages((prev) => [...prev, {
          id: `call-log-${d.callId || crypto.randomUUID()}-${d.type}-${d.at || Date.now()}`,
          content: JSON.stringify({ label, actionsType: actions ? 'callback' : undefined }),
          sender: 'System',
          timestamp: new Date(),
          isCurrentUser: false,
          isSystemMessage: true,
          type: 'system'
        } as Message]);
      } catch {}
    };
    window.addEventListener('ui-call-log', handler as EventListener);
    return () => window.removeEventListener('ui-call-log', handler as EventListener);
  }, [setMessages, selectedConversation, getDisplayUsername]);

  // Handle global call-back requests from system messages
  useEffect(() => {
    const cb = (e: any) => {
      try {
        const d = e.detail || {};
        if (!d.peer) return;
        startCall(d.peer, d.type === 'video' ? 'video' : 'audio').catch(() => {});
      } catch {}
    };
    window.addEventListener('ui-call-request', cb as EventListener);
    return () => window.removeEventListener('ui-call-request', cb as EventListener);
  }, [startCall]);

  // Handle conversation changes to stop typing indicators
  useEffect(() => {
    handleConversationChange();
    // Clear processed messages tracking when conversation changes
    processedInScrollRef.current.clear();
    lastScrollTimeRef.current = 0;
  }, [selectedConversation, handleConversationChange]);

  // Resolve display name for selected conversation
  useEffect(() => {
    if (selectedConversation && getDisplayUsername) {
      getDisplayUsername(selectedConversation)
        .then((resolved) => {
          try {
            const hexPattern = /^[a-f0-9]{32,}$/i;
            setDisplayConversationName(hexPattern.test(resolved) ? `${resolved.slice(0, 8)}...` : resolved);
          } catch {
            setDisplayConversationName(resolved);
          }
        })
        .catch((error) => {
          console.error('Failed to resolve conversation display name:', error);
          try {
            const hexPattern = /^[a-f0-9]{32,}$/i;
            setDisplayConversationName(hexPattern.test(selectedConversation) ? `${selectedConversation.slice(0, 8)}...` : selectedConversation);
          } catch {
            setDisplayConversationName(selectedConversation);
          }
        });
    } else {
      if (!selectedConversation) {
        setDisplayConversationName("");
      } else {
        try {
          const hexPattern = /^[a-f0-9]{32,}$/i;
          setDisplayConversationName(hexPattern.test(selectedConversation) ? `${selectedConversation.slice(0, 8)}...` : selectedConversation);
        } catch {
          setDisplayConversationName(selectedConversation);
        }
      }
    }
  }, [selectedConversation, getDisplayUsername]);

  // Re-resolve header name when a mapping is updated/received
  useEffect(() => {
    const handler = () => {
      if (!selectedConversation || !getDisplayUsername) return;
      getDisplayUsername(selectedConversation)
        .then((resolved) => {
          try {
            const hexPattern = /^[a-f0-9]{32,}$/i;
            setDisplayConversationName(hexPattern.test(resolved) ? `${resolved.slice(0, 8)}...` : resolved);
          } catch {
            setDisplayConversationName(resolved);
          }
        })
        .catch(() => {});
    };
    window.addEventListener('username-mapping-updated', handler as EventListener);
    window.addEventListener('username-mapping-received', handler as EventListener);
    return () => {
      window.removeEventListener('username-mapping-updated', handler as EventListener);
      window.removeEventListener('username-mapping-received', handler as EventListener);
    };
  }, [selectedConversation, getDisplayUsername]);

  // Message receipts hook
  const { sendReadReceipt, markMessageAsRead, getSmartReceiptStatus } = useMessageReceipts(messages, setMessages, currentUsername, saveMessageToLocalDB);

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

    // Only auto-scroll if:
    // 1. It's a new message (not just an update to existing messages)
    // 2. User is near the bottom (within 100px) OR the new message is from current user
    if (isNewMessage && isNewMessageId && latestMessage) {
      const isNearBottom = scrollContainer.scrollTop >= scrollContainer.scrollHeight - scrollContainer.clientHeight - 100;
      const isCurrentUserMessage = latestMessage.sender === currentUsername;

      if (isNearBottom || isCurrentUserMessage) {
        // Smooth scroll to bottom
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

  // Mark messages as read when they come into view
  useEffect(() => {
    const scrollContainer = scrollAreaRef.current?.querySelector('[data-radix-scroll-area-viewport]');
    if (!scrollContainer) return;

    const isTabActive = () => document.visibilityState === 'visible' && document.hasFocus();

    const handleScroll = () => {
      if (!isTabActive()) return; // Do not mark as read if tab is not active

      const now = Date.now();
      // Prevent multiple scroll calls in quick succession (within 500ms)
      if (now - lastScrollTimeRef.current < 500) {
        return;
      }
      lastScrollTimeRef.current = now;

      // Clear the processed messages set for this scroll event
      processedInScrollRef.current.clear();

      const containerRect = scrollContainer.getBoundingClientRect();
      const containerBottom = containerRect.bottom;

      // Find all visible unread messages and send receipts for each
      const visibleUnread: Message[] = [];

      messages.forEach(message => {
        // Only process messages from OTHER users (not current user) and not already read
        if (message.sender === currentUsername || message.receipt?.read) return;

        // Skip if we've already processed this message in this scroll event
        if (processedInScrollRef.current.has(message.id)) return;

        const messageElement = document.getElementById(`message-${message.id}`);
        if (messageElement) {
          const messageRect = messageElement.getBoundingClientRect();
          const messageBottom = messageRect.bottom;

          // If message is visible in the scroll container
          if (messageBottom <= containerBottom && messageBottom >= containerRect.top) {
            visibleUnread.push(message);
            // Mark this message as processed in this scroll event
            processedInScrollRef.current.add(message.id);
          }
        }
      });

      // Sort by timestamp ascending to send older first
      visibleUnread.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

      // Mark and send read receipts for all visible unread messages
      visibleUnread.forEach((msg) => {
        markMessageAsRead(msg.id);
        sendReadReceipt(msg.id, msg.sender);
      });
    };

    // Debounce the scroll handler to prevent excessive calls
    let scrollTimeout: NodeJS.Timeout;
    const debouncedHandleScroll = () => {
      clearTimeout(scrollTimeout);
      scrollTimeout = setTimeout(handleScroll, 100);
    };

    scrollContainer.addEventListener('scroll', debouncedHandleScroll);
    window.addEventListener('visibilitychange', handleScroll);
    window.addEventListener('focus', handleScroll);
    window.addEventListener('blur', handleScroll);

    // Initial check with a small delay to ensure DOM is ready
    setTimeout(handleScroll, 100);

    return () => {
      clearTimeout(scrollTimeout);
      scrollContainer.removeEventListener('scroll', debouncedHandleScroll);
      window.removeEventListener('visibilitychange', handleScroll);
      window.removeEventListener('focus', handleScroll);
      window.removeEventListener('blur', handleScroll);
    };
  }, [messages, currentUsername, markMessageAsRead, sendReadReceipt, users]);

  // Periodic check to ensure read receipts are sent for visible messages
  useEffect(() => {
    const checkForMissedReadReceipts = () => {
      // Only check if tab is active and we have messages
      if (document.visibilityState === 'visible' && document.hasFocus() && messages.length > 0) {
        console.debug('[ChatInterface] Periodic check for missed read receipts');

        // Only check messages that are currently visible in the viewport
        const scrollContainer = scrollAreaRef.current?.querySelector('[data-radix-scroll-area-viewport]');
        if (scrollContainer) {
          const containerRect = scrollContainer.getBoundingClientRect();
          const containerBottom = containerRect.bottom;

          // Find all visible unread messages
          const visibleUnread: Message[] = [];

          messages.forEach(message => {
            // Only process messages from OTHER users (not current user) and not already read
            if (message.sender === currentUsername || message.receipt?.read) return;

            const messageElement = document.getElementById(`message-${message.id}`);
            if (messageElement) {
              const messageRect = messageElement.getBoundingClientRect();
              const messageBottom = messageRect.bottom;

              // Only consider visible messages
              if (messageBottom <= containerBottom && messageBottom >= containerRect.top) {
                visibleUnread.push(message);
              }
            }
          });

          // Send read receipts for all visible unread messages
          visibleUnread
            .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
            .forEach((m) => sendReadReceipt(m.id, m.sender));
        }
      }
    };

    // Check every 30 seconds for missed read receipts
    const interval = setInterval(checkForMissedReadReceipts, 30000);

    return () => clearInterval(interval);
  }, [messages, sendReadReceipt]);

  // Compute which messages should show status indicators: only latest read and latest delivered (unread)
  const lastReadId = [...messages]
    .reverse()
    .find((m) => m.isCurrentUser && (getSmartReceiptStatus(m) || m.receipt)?.read)?.id;

  const lastDeliveredId = [...messages]
    .reverse()
    .find((m) =>
      m.isCurrentUser &&
      (getSmartReceiptStatus(m) || m.receipt)?.delivered &&
      !(getSmartReceiptStatus(m) || m.receipt)?.read
    )?.id;
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
        <div>
          <h2 
            className="text-lg font-semibold"
            style={{ color: 'var(--color-text-primary)' }}
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
                onClick={async () => {
                  try {
                    await startCall(selectedConversation, 'audio');
                  } catch (error) {
                    console.error('[ChatInterface] Failed to start audio call:', error);
                    alert('Failed to start call: ' + (error as Error).message);
                  }
                }}
                disabled={!!currentCall}
                className="flex items-center gap-2"
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
                onClick={async () => {
                  try {
                    await startCall(selectedConversation, 'video');
                  } catch (error) {
                    console.error('[ChatInterface] Failed to start video call:', error);
                    alert('Failed to start video call: ' + (error as Error).message);
                  }
                }}
                disabled={!!currentCall}
                className="flex items-center gap-2"
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
          <TorIndicator />
        </div>
      </div>
      <ScrollArea 
        className="flex-1 p-4" 
        ref={scrollAreaRef}
        style={{ backgroundColor: 'var(--color-background)' }}
      >
        <div className="space-y-4">
          {messages.length === 0 ? (
            <div 
              className="flex items-center justify-center h-full min-h-[200px] text-sm"
              style={{ color: 'var(--color-text-secondary)' }}
            >
              {selectedConversation ? "No messages yet. Start the conversation!" : "Select a conversation to view messages"}
            </div>
          ) : (
            messages.map((message, index) => {
              const smartReceipt = getSmartReceiptStatus(message) || message.receipt;
              const shouldShowReceipt =
                message.isCurrentUser && smartReceipt && (message.id === lastReadId || message.id === lastDeliveredId);
              // Ensure unique key by combining message ID with index as fallback
              const uniqueKey = message.id ? `${message.id}-${index}` : `message-${index}-${Date.now()}`;
              return (
                <div key={uniqueKey} id={`message-${message.id}`}>
                  <ChatMessage
                    message={{
                      ...message,
                      receipt: shouldShowReceipt ? smartReceipt : undefined,
                    }}
                    previousMessage={index > 0 ? messages[index - 1] : undefined}
                    onReply={() => setReplyTo(message)}
                    onDelete={() =>
                      onSendMessage(message.id, "", SignalType.DELETE_MESSAGE, null) // add reply field later
                    }
                    onEdit={() => setEditingMessage(message)}
                    getDisplayUsername={getDisplayUsername}
                  />
                </div>
              );
            })
          )}
        </div>
      </ScrollArea>
      {typingUsers.length > 0 && (
        <div 
          className="px-4 py-3 border-t animate-in slide-in-from-bottom duration-200"
          style={{
            backgroundColor: 'var(--color-muted-panel)',
            borderColor: 'var(--color-border)'
          }}
        >
          <div className="flex flex-col gap-1">
            {typingUsers.map((username) => (
              <TypingIndicator 
                key={username} 
                username={username} 
                getDisplayUsername={getDisplayUsername}
              />
            ))}
          </div>
        </div>
      )}
      <div 
        className="px-4 pb-4"
        style={{ backgroundColor: 'var(--color-background)' }}
      >
        <ChatInput
          onSendMessage={async (
            messageId: string | undefined,
            content: string,
            messageSignalType: string,
            replyToMsg?: MessageReply | null
          ) => {
            // Send all message types to the parent handler
            await onSendMessage(messageId ?? "", content, messageSignalType, replyToMsg);
            
            // Reset typing indicator for ALL message types except typing indicators themselves
            console.log('[ChatInterface] Message sent, checking typing reset:', { messageSignalType });
            if (messageSignalType !== 'typing-start' && messageSignalType !== 'typing-stop') {
              console.log('[ChatInterface] Resetting typing indicator for message type:', messageSignalType);
              resetTypingAfterSend();
              setReplyTo(null);
            } else {
              console.log('[ChatInterface] Skipping typing reset for typing indicator:', messageSignalType);
            }
          }}
          onSendFile={onSendFile}
          isEncrypted={isEncrypted}
          currentUsername={currentUsername}
          users={users}
          replyTo={replyTo}
          onCancelReply={() => setReplyTo(null)}
          editingMessage={editingMessage}
          onCancelEdit={() => setEditingMessage(null)}
          onEditMessage={async (newContent) => {
            if (editingMessage) { //never is called since is handled from chatinpuit and that took me 2 hours to realize
              await onSendMessage(editingMessage.id, newContent, SignalType.EDIT_MESSAGE, editingMessage.replyTo);
              setEditingMessage(null);
            }
          }}
          onTyping={handleLocalTyping}
          selectedConversation={selectedConversation}
          getDisplayUsername={getDisplayUsername}
        />
      </div>

      {/* Call Modal */}
      {currentCall && (
        <CallModal
          call={currentCall}
          localStream={localStream}
          remoteStream={remoteStream}
          remoteScreenStream={remoteScreenStream}
          peerConnection={peerConnection}
          onAnswer={() => currentCall && answerCall(currentCall.id)}
          onDecline={() => currentCall && declineCall(currentCall.id)}
          onEndCall={endCall}
          onToggleMute={toggleMute}
          onToggleVideo={toggleVideo}
          onSwitchCamera={switchCamera}
          onStartScreenShare={startScreenShare}
          onStopScreenShare={stopScreenShare}
          onGetAvailableScreenSources={getAvailableScreenSources}
          isScreenSharing={isScreenSharing}
          getDisplayUsername={getDisplayUsername}
        />
      )}
    </div>
  );
}