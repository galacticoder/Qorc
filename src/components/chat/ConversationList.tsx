import React, { memo, useMemo, useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { X } from "lucide-react";

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
  onRemoveConversation?: (username: string) => void;
  currentUsername?: string;
}

// Memoized conversation item to prevent unnecessary re-renders
const ConversationItem = memo(({
  conversation,
  isSelected,
  onSelect,
  onRemove,
  formatTime,
  callStatus
}: {
  conversation: Conversation;
  isSelected: boolean;
  onSelect: (username: string) => void;
  onRemove?: (username: string) => void;
  formatTime: (date?: Date) => string;
  callStatus?: 'ringing' | 'connecting' | 'connected' | null;
}) => (
  <div
    className={cn(
      "flex items-center gap-2 p-2 rounded cursor-pointer transition-colors group",
      isSelected
        ? "bg-blue-100 border border-blue-200"
        : "hover:bg-gray-100"
    )}
  >
    <div 
      onClick={() => onSelect(conversation.username)}
      className="flex items-center gap-2 flex-1 min-w-0"
    >
      {/* Status indicator */}
      <div
        className={cn(
          "w-2 h-2 rounded-full",
          conversation.isOnline ? "bg-green-500" : "bg-gray-400"
        )}
      />
      
      {/* User info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between">
          <span className="font-medium text-sm truncate">
            {conversation.username}
          </span>
        </div>
        
        {conversation.lastMessage && (
          <div className="text-xs text-gray-500 truncate mt-0.5">
            {conversation.lastMessage}
          </div>
        )}
        
        {conversation.lastMessageTime && (
          <div className="text-xs text-gray-400 mt-0.5">
            {formatTime(conversation.lastMessageTime)}
          </div>
        )}
      </div>

      {/* Call status badge */}
      {callStatus && (
        <div className={cn(
          "text-xs px-2 py-1 rounded-full font-medium",
          callStatus === 'ringing' && "bg-yellow-100 text-yellow-800",
          callStatus === 'connecting' && "bg-blue-100 text-blue-800",
          callStatus === 'connected' && "bg-green-100 text-green-800"
        )}>
          {callStatus === 'ringing' && "📞 Ringing"}
          {callStatus === 'connecting' && "🔄 Connecting"}
          {callStatus === 'connected' && "📞 Connected"}
        </div>
      )}
    </div>

    {/* Remove button - only show on hover */}
    {onRemove && (
      <Button
        variant="ghost"
        size="sm"
        onClick={(e) => {
          e.stopPropagation();
          onRemove(conversation.username);
        }}
        className="opacity-0 group-hover:opacity-100 transition-opacity p-1 h-6 w-6 hover:bg-red-100 hover:text-red-600"
      >
        <X className="h-3 w-3" />
      </Button>
    )}
  </div>
));

export const ConversationList = memo(function ConversationList({
  conversations,
  selectedConversation,
  onSelectConversation,
  onRemoveConversation,
  currentUsername
}: ConversationListProps) {
  // Track active call peer/status via global call-status events
  const [activePeer, setActivePeer] = useState<string | null>(null);
  const [activeStatus, setActiveStatus] = useState<'ringing' | 'connecting' | 'connected' | null>(null);
  
  // Confirmation dialog state
  const [showConfirmDialog, setShowConfirmDialog] = useState(false);
  const [conversationToRemove, setConversationToRemove] = useState<string | null>(null);

  const handleRemoveClick = (username: string) => {
    setConversationToRemove(username);
    setShowConfirmDialog(true);
  };

  const handleConfirmRemove = () => {
    if (conversationToRemove && onRemoveConversation) {
      onRemoveConversation(conversationToRemove);
    }
    setShowConfirmDialog(false);
    setConversationToRemove(null);
  };

  const handleCancelRemove = () => {
    setShowConfirmDialog(false);
    setConversationToRemove(null);
  };

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
    <>
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
                onRemove={handleRemoveClick}
                formatTime={formatTime}
                callStatus={conversation.username === activePeer ? activeStatus : null}
              />
            ))
          )}
        </div>
      </ScrollArea>

      {/* Confirmation Dialog */}
      <Dialog open={showConfirmDialog} onOpenChange={setShowConfirmDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Remove Conversation</DialogTitle>
            <DialogDescription>
              Are you sure you want to remove the conversation with {conversationToRemove}? 
              This action cannot be undone and will delete all message history.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={handleCancelRemove}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleConfirmRemove}>
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
});