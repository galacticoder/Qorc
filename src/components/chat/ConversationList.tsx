import React, { memo, useMemo } from "react";
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

// Memoized conversation item to prevent unnecessary re-renders
const ConversationItem = memo(({
  conversation,
  isSelected,
  onSelect,
  formatTime
}: {
  conversation: Conversation;
  isSelected: boolean;
  onSelect: (username: string) => void;
  formatTime: (date?: Date) => string;
}) => (
  <div
    onClick={() => onSelect(conversation.username)}
    className={cn(
      "flex items-center gap-2 p-2 rounded cursor-pointer transition-colors",
      isSelected
        ? "bg-blue-100 border border-blue-200"
        : "hover:bg-gray-100"
    )}
  >
    {/* Avatar */}
    <div className="relative">
      <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center text-white text-xs font-medium">
        {conversation.username.charAt(0).toUpperCase()}
      </div>
      {conversation.isOnline && (
        <div className="absolute -bottom-0.5 -right-0.5 w-3 h-3 bg-green-500 border-2 border-white rounded-full"></div>
      )}
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
));

export const ConversationList = memo(function ConversationList({
  conversations,
  selectedConversation,
  onSelectConversation,
  currentUsername
}: ConversationListProps) {
  // Memoize the formatTime function to prevent recreation on every render
  const formatTime = useMemo(() => (date?: Date) => {
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
  }, []);

  return (
    <ScrollArea className="h-full">
      <div className="p-1">
        {conversations.length === 0 ? (
          <div className="text-center text-gray-500 text-xs py-4">
            No conversations yet
          </div>
        ) : (
          conversations.map((conversation) => (
            <ConversationItem
              key={conversation.id}
              conversation={conversation}
              isSelected={selectedConversation === conversation.username}
              onSelect={onSelectConversation}
              formatTime={formatTime}
            />
          ))
        )}
      </div>
    </ScrollArea>
  );
});
