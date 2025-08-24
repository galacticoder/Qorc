import { useEffect, useRef, useState } from "react";
import { Card } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
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
}: ChatInterfaceProps) {
  const scrollAreaRef = useRef<HTMLDivElement>(null);
  const [replyTo, setReplyTo] = useState<Message | null>(null);
  const [editingMessage, setEditingMessage] = useState<Message | null>(null);
  
  // Track which messages have been processed in the current scroll event to prevent duplicates
  const processedInScrollRef = useRef<Set<string>>(new Set());
  const lastScrollTimeRef = useRef<number>(0);
  
  // Typing hook
  const { handleLocalTyping, handleConversationChange } = useTypingIndicator(currentUsername, selectedConversation, onSendMessage);
  const { typingUsers } = useTypingIndicatorContext();

  // Log typing users changes
  useEffect(() => {
    console.log('[ChatInterface] typingUsers changed:', typingUsers);
  }, [typingUsers]);

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

      // Check each message to see if it's visible
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
            // Mark as read locally and send read receipt to sender
            // Only send read receipt if the message isn't already marked as read
            if (!message.receipt?.read) {
              markMessageAsRead(message.id);
              sendReadReceipt(message.id, message.sender);
              // Mark this message as processed in this scroll event
              processedInScrollRef.current.add(message.id);
            }
          }
        }
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

  return (
    <Card className="flex flex-col h-full border border-gray-300 shadow-lg rounded-lg">
      <div className="p-4 border-b bg-gray-100">
        <h2 className="text-lg font-semibold">
          {selectedConversation ? `Chat with ${selectedConversation}` : "Chat"}
        </h2>
        <p className="text-sm text-gray-500">
          {selectedConversation ? "Secure end-to-end encrypted messaging" : "Select a conversation to start chatting"}
        </p>
      </div>
      <ScrollArea className="flex-1 p-4 bg-white" ref={scrollAreaRef}>
        <div className="space-y-4">
          {messages.length === 0 ? (
            <div className="flex items-center justify-center h-full min-h-[200px] text-gray-400 text-sm">
              {selectedConversation ? "No messages yet. Start the conversation!" : "Select a conversation to view messages"}
            </div>
          ) : (
            messages.map((message, index) => (
              <div key={message.id} id={`message-${message.id}`}>
                <ChatMessage
                  message={{
                    ...message,
                    receipt: getSmartReceiptStatus(message) // Remove redundant find operation
                  }}
                  previousMessage={index > 0 ? messages[index - 1] : undefined}
                  onReply={() => setReplyTo(message)}
                  onDelete={() =>
                    onSendMessage(message.id, "", SignalType.DELETE_MESSAGE, null) // add reply field later
                  }
                  onEdit={() => setEditingMessage(message)}
                />
              </div>
            ))
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
            replyToMsg?: Message | null
          ) => {
            // For typing indicators, we need to send them to the server but they should not appear in chat
            if (messageSignalType === 'typing-start' || messageSignalType === 'typing-stop') {
              // Send typing indicator to server but don't add to local chat history
              await onSendMessage(messageId ?? "", content, messageSignalType, replyToMsg);
              return;
            }
            // For other message types, call the parent handler
            await onSendMessage(messageId ?? "", content, messageSignalType, replyToMsg);
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
    </Card>
  );
}