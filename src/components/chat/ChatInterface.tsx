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
}: ChatInterfaceProps) {
  const scrollAreaRef = useRef<HTMLDivElement>(null);
  const [replyTo, setReplyTo] = useState<Message | null>(null);
  const [editingMessage, setEditingMessage] = useState<Message | null>(null);

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
    const handler = (e: any) => {
      try {
        const d = e.detail || {};
        if (!selectedConversation || d.peer !== selectedConversation) return;
        const label = d.type === 'incoming' ? `Incoming call from ${d.peer}`
          : d.type === 'connected' ? `Call connected with ${d.peer}`
          : d.type === 'started' ? `Calling ${d.peer}...`
          : d.type === 'ended' ? `Call with ${d.peer} ended (${Math.round((d.durationMs||0)/1000)}s)`
          : d.type === 'declined' ? `${d.peer} declined the call`
          : d.type === 'missed' ? `Missed call from ${d.peer}`
          : d.type === 'not-answered' ? `${d.peer} did not answer`
          : `Call event: ${d.type}`;
        setMessages((prev) => [...prev, {
          id: `call-log-${d.callId || crypto.randomUUID()}-${d.type}-${d.at || Date.now()}`,
          content: label,
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
  }, [setMessages, selectedConversation]);

  // Handle conversation changes to stop typing indicators
  useEffect(() => {
    handleConversationChange();
    // Clear processed messages tracking when conversation changes
    processedInScrollRef.current.clear();
    lastScrollTimeRef.current = 0;
  }, [selectedConversation, handleConversationChange]);

  // Message receipts hook
  const { sendReadReceipt, markMessageAsRead, getSmartReceiptStatus } = useMessageReceipts(messages, setMessages, currentUsername, saveMessageToLocalDB);

  useEffect(() => {
    if (scrollAreaRef.current) {
      const scrollContainer =
        scrollAreaRef.current.querySelector(
          '[data-radix-scroll-area-viewport]'
        );
      if (scrollContainer) {
        scrollContainer.scrollTop = scrollContainer.scrollHeight;
      }
    }
  }, [messages]);

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
    <Card className="flex flex-col h-full border border-gray-300 shadow-lg rounded-lg">
      <div className="p-4 border-b bg-gray-100 flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">
            {selectedConversation ? `Chat with ${selectedConversation}` : "Chat"}
          </h2>
          <p className="text-sm text-gray-500">
            {selectedConversation ? "Secure end-to-end encrypted messaging" : "Select a conversation to start chatting"}
          </p>
        </div>
        <div className="flex items-center space-x-2">
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
                className="flex items-center space-x-1"
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
                className="flex items-center space-x-1"
              >
                <Video className="w-4 h-4" />
                <span>Video</span>
              </Button>
            </>
          )}
          <TorIndicator />
        </div>
      </div>
      <ScrollArea className="flex-1 p-4 bg-white" ref={scrollAreaRef}>
        <div className="space-y-4">
          {messages.length === 0 ? (
            <div className="flex items-center justify-center h-full min-h-[200px] text-gray-400 text-sm">
              {selectedConversation ? "No messages yet. Start the conversation!" : "Select a conversation to view messages"}
            </div>
          ) : (
            messages.map((message, index) => {
              const smartReceipt = getSmartReceiptStatus(message) || message.receipt;
              const shouldShowReceipt =
                message.isCurrentUser && smartReceipt && (message.id === lastReadId || message.id === lastDeliveredId);
              return (
                <div key={message.id} id={`message-${message.id}`}>
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
                  />
                </div>
              );
            })
          )}
        </div>
      </ScrollArea>
      <Separator />
      {typingUsers.length > 0 && (
        <div className="px-4 py-3 bg-muted/30 border-t border-border/50 animate-in slide-in-from-bottom duration-200">
          <div className="flex flex-col gap-1">
            {typingUsers.map((username) => (
              <TypingIndicator key={username} username={username} />
            ))}
          </div>
        </div>
      )}
      <div className="p-4 bg-gray-50">
        <ChatInput
          onSendMessage={async (
            messageId: string | undefined,
            content: string,
            messageSignalType: string,
            replyToMsg?: MessageReply | null
          ) => {
            // For typing indicators, we need to send them to the server but they should not appear in chat
            if (messageSignalType === 'typing-start' || messageSignalType === 'typing-stop') {
              // Send typing indicator to server but don't add to local chat history
              await onSendMessage(messageId ?? "", content, messageSignalType, replyToMsg);
              return;
            }
            // For other message types, call the parent handler
            await onSendMessage(messageId ?? "", content, messageSignalType, replyToMsg);
            // Reset typing debounce/throttle so next keystroke can emit typing-start immediately
            resetTypingAfterSend();
            setReplyTo(null);
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
        />
      )}
    </Card>
  );
}