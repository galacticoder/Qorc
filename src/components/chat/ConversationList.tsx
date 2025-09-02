import React, { memo, useMemo, useEffect, useState } from "react";
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
  formatTime,
  callStatus
}: {
  conversation: Conversation;
  isSelected: boolean;
  onSelect: (username: string) => void;
  formatTime: (date?: Date) => string;
  callStatus?: 'ringing' | 'connecting' | 'connected' | null;
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
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm font-medium text-gray-900 truncate">
          {conversation.username}
        </span>
        <div className="flex items-center gap-2 shrink-0">
          {/* In-call badges using daisyUI */}
          {callStatus === 'connected' && (
            <div className="badge badge-success">
              <svg className="size-[1em]" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><g fill="currentColor" strokeLinejoin="miter" strokeLinecap="butt"><circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" strokeLinecap="square" strokeMiterlimit="10" strokeWidth="2"></circle><polyline points="7 13 10 16 17 8" fill="none" stroke="currentColor" strokeLinecap="square" strokeMiterlimit="10" strokeWidth="2"></polyline></g></svg>
              <span className="ml-1">In Call</span>
            </div>
          )}
          {(callStatus === 'ringing' || callStatus === 'connecting') && (
            <div className="badge badge-info">
              <svg className="size-[1em]" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><g fill="currentColor" strokeLinejoin="miter" strokeLinecap="butt"><circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" strokeLinecap="square" strokeMiterlimit="10" strokeWidth="2"></circle><path d="m12,17v-5.5c0-.276-.224-.5-.5-.5h-1.5" fill="none" stroke="currentColor" strokeLinecap="square" strokeMiterlimit="10" strokeWidth="2"></path><circle cx="12" cy="7.25" r="1.25" fill="currentColor" strokeWidth="2"></circle></g></svg>
              <span className="ml-1">Calling…</span>
            </div>
          )}
          {conversation.lastMessageTime && (
            <span className="text-xs text-gray-500">
              {formatTime(conversation.lastMessageTime)}
            </span>
          )}
        </div>
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
  // Track active call peer/status via global call-status events
  const [activePeer, setActivePeer] = useState<string | null>(null);
  const [activeStatus, setActiveStatus] = useState<'ringing' | 'connecting' | 'connected' | null>(null);

  useEffect(() => {
    const handler = (e: Event) => {
      const ce = e as CustomEvent;
      const { peer, status } = ce.detail || {};
      if (typeof peer === 'string' && typeof status === 'string') {
        if (status === 'ringing' || status === 'connecting' || status === 'connected') {
          setActivePeer(peer);
          setActiveStatus(status);
        } else {
          // Non-active status clears badge if it matches current peer
          setActivePeer(prev => (prev === peer ? null : prev));
          setActiveStatus(prev => (prev && prev && prev ? null : prev));
        }
      }
    };
    window.addEventListener('ui-call-status', handler as EventListener);
    return () => window.removeEventListener('ui-call-status', handler as EventListener);
  }, []);

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
              callStatus={conversation.username === activePeer ? activeStatus : null}
            />
          ))
        )}
      </div>
    </ScrollArea>
  );
});