import React from "react";
import { cn } from "@/lib/utils";
import { ScrollArea } from "@/components/ui/scroll-area";

export interface Conversation {
  id: string;
  username: string;
  isOnline: boolean;
  lastMessage?: string;
  lastMessageTime?: Date;
  unreadCount?: number;
}

interface ConversationListProps {
  conversations: Conversation[];
  selectedConversation?: string;
  onSelectConversation: (username: string) => void;
  currentUsername?: string;
}

export function ConversationList({ 
  conversations, 
  selectedConversation, 
  onSelectConversation,
  currentUsername 
}: ConversationListProps) {
  const formatTime = (date?: Date) => {
    if (!date) return "";
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);

    if (minutes < 1) return "now";
    if (minutes < 60) return `${minutes}m`;
    if (hours < 24) return `${hours}h`;
    return `${days}d`;
  };

  return (
    <ScrollArea className="h-full">
      <div className="p-1">
        {conversations.length === 0 ? (
          <div className="text-center text-gray-500 text-xs py-4">
            No conversations yet
          </div>
        ) : (
          conversations.map((conversation) => (
            <div
              key={conversation.id}
              onClick={() => onSelectConversation(conversation.username)}
              className={cn(
                "flex items-center gap-2 p-2 rounded cursor-pointer transition-colors",
                selectedConversation === conversation.username
                  ? "bg-blue-100 border border-blue-200"
                  : "hover:bg-gray-100"
              )}
            >
              {/* Avatar */}
              <div className="relative">
                <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center">
                  <span className="text-white text-xs font-medium">
                    {conversation.username.charAt(0).toUpperCase()}
                  </span>
                </div>
                {/* Online indicator */}
                <div
                  className={cn(
                    "absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 border-white",
                    conversation.isOnline ? "bg-green-500" : "bg-gray-300"
                  )}
                />
              </div>

              {/* Conversation info */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-gray-900 truncate">
                    {conversation.username}
                  </span>
                  {conversation.lastMessageTime && (
                    <span className="text-xs text-gray-500">
                      {formatTime(conversation.lastMessageTime)}
                    </span>
                  )}
                </div>
                {conversation.lastMessage && (
                  <p className="text-xs text-gray-600 truncate">
                    {conversation.lastMessage}
                  </p>
                )}
              </div>

              {/* Unread count */}
              {conversation.unreadCount && conversation.unreadCount > 0 && (
                <div className="bg-red-500 text-white text-xs rounded-full w-5 h-5 flex items-center justify-center">
                  {conversation.unreadCount > 99 ? "99+" : conversation.unreadCount}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </ScrollArea>
  );
}
