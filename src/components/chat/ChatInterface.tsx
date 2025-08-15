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

interface ChatInterfaceProps {
  onSendMessage: (
    messageId: string,
    content: string,
    messageSignalType: string,
    replyTo?: MessageReply | null
  ) => Promise<void>;
  onSendFile: (fileData: any) => void;
  messages: Message[];
  isEncrypted?: boolean;
  currentUsername: string;
  users: User[];
}

export function ChatInterface({
  onSendMessage,
  onSendFile,
  messages,
  isEncrypted = true,
  currentUsername,
  users,
}: ChatInterfaceProps) {
  const scrollAreaRef = useRef<HTMLDivElement>(null);
  const [replyTo, setReplyTo] = useState<Message | null>(null);
  const [editingMessage, setEditingMessage] = useState<Message | null>(null);

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

  return (
    <Card className="flex flex-col h-full border border-gray-300 shadow-lg rounded-lg">
      <div className="p-4 border-b bg-gray-100">
        <h2 className="text-lg font-semibold">Chat Room</h2>
        <p className="text-sm text-gray-500">Secure and encrypted messaging</p>
      </div>
      <ScrollArea className="flex-1 p-4 bg-white" ref={scrollAreaRef}>
        <div className="space-y-4">
          {messages.length === 0 ? (
            <div className="flex items-center justify-center h-full min-h-[200px] text-gray-400 text-sm">
              No messages yet
            </div>
          ) : (
            messages.map((message, index) => (
              <ChatMessage
                key={message.id}
                message={message}
                previousMessage={index > 0 ? messages[index - 1] : undefined}
                onReply={() => setReplyTo(message)}
                onDelete={() =>
                  onSendMessage(message.id, "", SignalType.DELETE_MESSAGE, null) // add reply field later
                }
                onEdit={() => setEditingMessage(message)}
              />
            ))
          )}
        </div>
      </ScrollArea>
      <Separator />
      <div className="p-4 bg-gray-50">
        <ChatInput
          onSendMessage={async (
            messageId: string | undefined,
            content: string,
            messageSignalType: string,
            replyToMsg?: Message | null
          ) => {
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
        />
      </div>
    </Card>
  );
}
