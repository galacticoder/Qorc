import React, { memo, useMemo, useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Trash2 } from "lucide-react";

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
      "flex items-center gap-3 p-3 cursor-pointer transition-all duration-200 group relative",
      "hover:bg-opacity-80"
    )}
    style={{
      backgroundColor: isSelected ? 'var(--color-accent-primary)' : 'transparent',
      borderRadius: 'var(--radius-medium)'
    }}
    onMouseEnter={(e) => {
      if (!isSelected) {
        e.currentTarget.style.backgroundColor = 'rgba(59, 130, 246, 0.05)';
      }
    }}
    onMouseLeave={(e) => {
      if (!isSelected) {
        e.currentTarget.style.backgroundColor = 'transparent';
      }
    }}
    onClick={() => onSelect(conversation.username)}
  >
    {/* Avatar */}
    <div 
      className="w-10 h-10 rounded-full flex items-center justify-center font-medium text-sm flex-shrink-0"
      style={{
        backgroundColor: isSelected ? 'rgba(255, 255, 255, 0.2)' : 'var(--color-accent-secondary)',
        color: isSelected ? 'white' : 'white'
      }}
    >
      {conversation.username.charAt(0).toUpperCase()}
    </div>
    
    {/* Content */}
    <div className="flex-1 min-w-0">
      {/* Primary line (name) */}
      <div className="flex items-center justify-between mb-1">
        <span 
          className="font-medium text-sm truncate"
          style={{ color: isSelected ? 'white' : 'var(--color-text-primary)' }}
        >
          {conversation.username}
        </span>
        {conversation.lastMessageTime && (
          <span 
            className="text-xs flex-shrink-0 ml-2"
            style={{ color: isSelected ? 'rgba(255, 255, 255, 0.7)' : 'var(--color-text-secondary)' }}
          >
            {formatTime(conversation.lastMessageTime)}
          </span>
        )}
      </div>
      
      {/* Secondary line (preview) */}
      {conversation.lastMessage && (
        <div 
          className="text-xs truncate"
          style={{ color: isSelected ? 'rgba(255, 255, 255, 0.8)' : 'var(--color-text-secondary)' }}
        >
          {conversation.lastMessage}
        </div>
      )}
    </div>

    {/* Call status badge only */}
    {callStatus && (
      <div className={cn(
        "text-xs px-2 py-1 rounded-full font-medium flex-shrink-0",
        callStatus === 'ringing' && "bg-yellow-100 text-yellow-800",
        callStatus === 'connecting' && "bg-blue-100 text-blue-800",
        callStatus === 'connected' && "bg-green-100 text-green-800"
      )}>
        {callStatus === 'ringing' && "📞"}
        {callStatus === 'connecting' && "🔄"}
        {callStatus === 'connected' && "📞"}
      </div>
    )}

    {/* Remove button - only show on hover */}
    {onRemove && (
      <Button
        variant="ghost"
        size="sm"
        onClick={(e) => {
          e.stopPropagation();
          onRemove(conversation.username);
        }}
        className="absolute bottom-1 right-1 opacity-0 group-hover:opacity-100 transition-opacity p-1 h-6 w-6"
        style={{
          backgroundColor: 'transparent',
          color: 'var(--color-error)'
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.backgroundColor = 'rgba(239, 68, 68, 0.1)';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.backgroundColor = 'transparent';
        }}
      >
        <Trash2 className="h-3 w-3" />
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
        <div className="p-2">
          {conversations.length === 0 ? (
            <div 
              className="text-center text-xs py-8"
              style={{ color: 'var(--color-text-secondary)' }}
            >
              No conversations yet
            </div>
          ) : (
            <div className="space-y-1">
              {conversations.map((conversation) => (
                <ConversationItem
                  key={conversation.id}
                  conversation={conversation}
                  isSelected={selectedConversation === conversation.username}
                  onSelect={onSelectConversation}
                  onRemove={handleRemoveClick}
                  formatTime={formatTime}
                  callStatus={conversation.username === activePeer ? activeStatus : null}
                />
              ))}
            </div>
          )}
        </div>
      </ScrollArea>

      {/* Confirmation Dialog */}
      <Dialog open={showConfirmDialog} onOpenChange={setShowConfirmDialog}>
        <DialogContent style={{ backgroundColor: 'var(--color-surface)', borderColor: 'var(--color-border)' }}>
          <DialogHeader>
            <DialogTitle style={{ color: 'var(--color-text-primary)' }}>Remove Conversation</DialogTitle>
            <DialogDescription style={{ color: 'var(--color-text-secondary)' }}>
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