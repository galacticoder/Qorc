import { useCallback, useEffect, useRef, useState } from 'react';
import { Ban, MoreVertical, Pin, PinOff, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '../../ui/button';
import { Popover, PopoverContent, PopoverTrigger } from '../../ui/popover';
import { ChatBubbleIcon, CallIcon } from '../assets/icons';
import { useNotificationPreferences } from '../../../hooks/useNotificationPreferences';
import { setConversationNotificationMutes, type NotificationMutes } from '../../../lib/ui/notification-preferences';

interface ConversationOptionsPopoverProps {
  readonly username: string;
  readonly blocked: boolean;
  readonly onToggleBlock: (username: string, nextBlocked: boolean) => void | Promise<void>;
  readonly ariaLabel?: string;
  readonly compact?: boolean;
  readonly isPinned?: boolean;
  readonly onTogglePin?: (username: string) => void;
  readonly onAction?: () => void;
  readonly onDeleteConversation?: (username: string) => void;
}

export function ConversationOptionsPopover({
  username,
  blocked,
  onToggleBlock,
  ariaLabel = 'Conversation options',
  compact = false,
  isPinned = false,
  onTogglePin,
  onAction,
  onDeleteConversation,
}: ConversationOptionsPopoverProps) {
  const [open, setOpen] = useState(false);
  const [updating, setUpdating] = useState(false);
  const operationRef = useRef<object | null>(null);
  const preferences = useNotificationPreferences();
  const mutes = preferences.conversations.find(entry => entry.username === username);

  const dismiss = useCallback(() => {
    setOpen(false);
    onAction?.();
  }, [onAction]);

  const toggleMute = (type: keyof NotificationMutes) => {
    dismiss();
    try {
      setConversationNotificationMutes(username, {
        messages: mutes?.messages === true,
        calls: mutes?.calls === true,
        [type]: !mutes?.[type],
      });
    } catch {
      toast.error('Failed to update conversation notifications');
    }
  };

  useEffect(() => {
    operationRef.current = null;
    setOpen(false);
    setUpdating(false);
    return () => {
      operationRef.current = null;
    };
  }, [username]);

  const handleToggleBlock = useCallback(async () => {
    if (!username || operationRef.current) return;
    const operation = {};
    operationRef.current = operation;
    setUpdating(true);
    dismiss();
    try {
      await onToggleBlock(username, !blocked);
      if (operationRef.current === operation) setOpen(false);
    } finally {
      if (operationRef.current === operation) {
        operationRef.current = null;
        setUpdating(false);
      }
    }
  }, [blocked, dismiss, onToggleBlock, username]);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          size="sm"
          variant="ghost"
          className={compact ? 'qorc-conversation-tiny-btn qorc-more-btn' : 'qorc-call-pill-btn qorc-more-btn'}
          title="Options"
          aria-label={ariaLabel}
          onClick={event => event.stopPropagation()}
        >
          <MoreVertical className="w-4 h-4" aria-hidden="true" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="qorc-conversation-options-popover select-none" align="end" onCloseAutoFocus={event => { if (onAction) event.preventDefault(); }} onClick={event => event.stopPropagation()} onKeyDown={event => event.stopPropagation()}>
        <div className="qorc-conversation-options-menu">
          {onTogglePin && (
            <button type="button" className="qorc-conversation-options-action" onClick={() => { dismiss(); onTogglePin(username); }}>
              {isPinned ? <PinOff aria-hidden="true" /> : <Pin aria-hidden="true" />}
              <span>{isPinned ? 'Unpin chat' : 'Pin chat'}</span>
            </button>
          )}
          {(['messages', 'calls'] as const).map(type => (
            <button key={type} type="button" className="qorc-conversation-options-action" onClick={() => toggleMute(type)}>
              <span className={`qorc-menu-alert-icon${mutes?.[type] ? '' : ' is-muted'}`} aria-hidden="true">
                {type === 'messages' ? <ChatBubbleIcon /> : <CallIcon />}
              </span>
              <span>{mutes?.[type] ? 'Unmute' : 'Mute'} {type}</span>
            </button>
          ))}
          <button
            type="button"
            className="qorc-conversation-options-destructive qorc-danger-button"
            disabled={updating}
            onClick={() => void handleToggleBlock()}
          >
            <Ban aria-hidden="true" />
            <span>{updating ? 'Updating...' : blocked ? 'Unblock user' : 'Block user'}</span>
          </button>
          {onDeleteConversation && <button type="button" className="qorc-conversation-options-destructive qorc-danger-button"
            onClick={() => { dismiss(); onDeleteConversation(username); }}><Trash2 aria-hidden="true" />Delete chat</button>}
        </div>
      </PopoverContent>
    </Popover>
  );
}
