import { useEffect, useState } from 'react';
import { Bell, BellOff, MessageSquare, Phone } from 'lucide-react';
import { toast } from 'sonner';
import { useNotificationPreferences } from '../../../hooks/useNotificationPreferences';
import { useDisplayUsername } from '../../../hooks/database/useDisplayUsername';
import { getNotificationMutes, setConversationNotificationMutes, type NotificationMutes } from '../../../lib/ui/notification-preferences';
import { Button } from '../../ui/button';
import { Popover, PopoverContent, PopoverTrigger } from '../../ui/popover';

export function ConversationNotificationControls({ username }: { username: string }) {
  const preferences = useNotificationPreferences();
  const mutes = preferences.conversations.find(entry => entry.username === username);
  const update = (type: keyof NotificationMutes, muted: boolean) => {
    try {
      setConversationNotificationMutes(username, {
        messages: mutes?.messages === true,
        calls: mutes?.calls === true,
        [type]: muted,
      });
    } catch {
      toast.error('Failed to update conversation notifications');
    }
  };

  return (
    <div className="qorc-notification-controls">
      <div className="qorc-conversation-options-title">Notifications</div>
      {(['messages', 'calls'] as const).map(type => (
        <button
          key={type}
          type="button"
          role="switch"
          aria-checked={mutes?.[type] === true}
          className="qorc-notification-option"
          onClick={() => update(type, !mutes?.[type])}
        >
          {type === 'messages' ? <MessageSquare aria-hidden="true" /> : <Phone aria-hidden="true" />}
          <span>{type === 'messages' ? 'Mute messages' : 'Mute calls'}</span>
          <span className="qorc-notification-switch" aria-hidden="true" />
        </button>
      ))}
      <p className="qorc-notification-hint">
        {preferences.doNotDisturb.messages || preferences.doNotDisturb.calls
          ? `Global do not disturb is also on for ${preferences.doNotDisturb.messages && preferences.doNotDisturb.calls ? 'messages and calls' : preferences.doNotDisturb.messages ? 'messages' : 'calls'}.`
          : 'Messages and call history are still saved.'}
      </p>
    </div>
  );
}

export function ConversationNotifications({ username, compact = false }: { username: string; compact?: boolean }) {
  const [open, setOpen] = useState(false);
  const preferences = useNotificationPreferences();
  const muted = getNotificationMutes(username, preferences);
  const displayName = useDisplayUsername({ username });
  const silenced = muted.messages || muted.calls;

  useEffect(() => { setOpen(false); }, [username]);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          size="sm"
          variant="ghost"
          className={compact ? 'qorc-conversation-tiny-btn' : 'qorc-call-pill-btn'}
          title={silenced ? 'Notifications muted' : 'Notifications'}
          aria-label={`Notification settings for ${displayName}${silenced ? ', muted' : ''}`}
          onClick={event => event.stopPropagation()}
        >
          {silenced ? <BellOff className={compact ? 'h-3 w-3' : 'h-4 w-4'} aria-hidden="true" /> : <Bell className={compact ? 'h-3 w-3' : 'h-4 w-4'} aria-hidden="true" />}
        </Button>
      </PopoverTrigger>
      <PopoverContent
        className="qorc-conversation-options-popover select-none"
        align="end"
        aria-label={`Notifications for ${displayName}`}
        onClick={event => event.stopPropagation()}
        onKeyDown={event => event.stopPropagation()}
      >
        <ConversationNotificationControls username={username} />
      </PopoverContent>
    </Popover>
  );
}
