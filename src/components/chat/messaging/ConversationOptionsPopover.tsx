import { useCallback, useEffect, useRef, useState } from 'react';
import { Ban, Loader2, MoreVertical } from 'lucide-react';
import { Button } from '../../ui/button';
import { Popover, PopoverContent, PopoverTrigger } from '../../ui/popover';

interface ConversationOptionsPopoverProps {
  readonly username: string;
  readonly blocked: boolean;
  readonly onToggleBlock: (username: string, nextBlocked: boolean) => void | Promise<void>;
  readonly ariaLabel?: string;
}

export function ConversationOptionsPopover({
  username,
  blocked,
  onToggleBlock,
  ariaLabel = 'Conversation options',
}: ConversationOptionsPopoverProps) {
  const [open, setOpen] = useState(false);
  const [updating, setUpdating] = useState(false);
  const operationRef = useRef<object | null>(null);

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
    try {
      await onToggleBlock(username, !blocked);
      if (operationRef.current === operation) setOpen(false);
    } finally {
      if (operationRef.current === operation) {
        operationRef.current = null;
        setUpdating(false);
      }
    }
  }, [blocked, onToggleBlock, username]);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          size="sm"
          variant="ghost"
          className="qorc-call-pill-btn qorc-more-btn"
          title="Options"
          aria-label={ariaLabel}
        >
          <MoreVertical className="w-4 h-4" aria-hidden="true" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="qorc-conversation-options-popover select-none" align="end">
        <div className="qorc-conversation-options-menu">
          <div className="qorc-conversation-options-title">Options</div>
          <button
            type="button"
            className="qorc-conversation-options-action"
            disabled={updating}
            onClick={() => void handleToggleBlock()}
          >
            {updating ? <Loader2 className="animate-spin" aria-hidden="true" /> : <Ban aria-hidden="true" />}
            <span>{updating ? 'Updating...' : blocked ? 'Unblock' : 'Block'}</span>
          </button>
        </div>
      </PopoverContent>
    </Popover>
  );
}
