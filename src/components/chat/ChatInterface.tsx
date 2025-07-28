import { useEffect, useRef } from "react";
import { Card } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { ChatMessage, Message } from "./ChatMessage";
import { ChatInput } from "./ChatInput";
import { Separator } from "@/components/ui/separator";
import { User } from "./UserList";
import { SignalType } from "@/lib/signals";

interface ChatInterfaceProps {
  onSendMessage: (message: string) => Promise<void>;
  onSendFile: (fileData: any) => void;
  onTyping: () => void;
  messages: Message[];
  isEncrypted?: boolean;
  currentUsername: string;
  users: User[];
}

export function ChatInterface({
  onSendMessage,
  onSendFile,
  onTyping,
  messages,
  isEncrypted = true,
  currentUsername,
  users
}: ChatInterfaceProps) {
  const scrollAreaRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollAreaRef.current) {
      const scrollContainer = scrollAreaRef.current.querySelector('[data-radix-scroll-area-viewport]');
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
            messages.map((message) => (
              <ChatMessage key={message.id} message={message} />
            ))
          )}
        </div>
      </ScrollArea>
      <Separator />
      <div className="p-4 bg-gray-50">
        <ChatInput
          onSendMessage={onSendMessage}
          onSendFile={onSendFile}
          onTyping={onTyping}
          isEncrypted={isEncrypted}
          currentUsername={currentUsername}
          users={users}
        />
      </div>
    </Card>
  );
}
