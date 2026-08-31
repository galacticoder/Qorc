import { Cross2Icon } from "../assets/icons";
import type { Message } from '../messaging/types';
import { UserAvatar } from '../../ui/UserAvatar';
import { BannerMessagePreview } from './BannerMessagePreview';

interface EditingBannerProps {
  readonly onCancelEdit?: () => void;
  readonly editingMessage: Message;
}

export function EditingBanner({ onCancelEdit, editingMessage }: EditingBannerProps) {
  return (
    <div className="qorc-reply-banner select-none">
      <UserAvatar username={editingMessage.sender} size="xs" className="qorc-reply-banner-avatar" />
      <div className="qorc-reply-banner-copy">
        <span className="qorc-reply-banner-name">Editing message</span>
        <div className="qorc-reply-banner-preview">
          <BannerMessagePreview
            messageId={editingMessage.secureContentId || editingMessage.id}
            contentVersion={editingMessage.controlState?.editOperationId}
          />
        </div>
      </div>
      <button
        type="button"
        className="qorc-reply-banner-close"
        onClick={onCancelEdit}
        aria-label="Cancel edit"
        title="Cancel edit"
      >
        <Cross2Icon aria-hidden="true" />
      </button>
    </div>
  );
}
