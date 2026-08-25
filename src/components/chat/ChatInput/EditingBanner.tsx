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
    <div className="qor-reply-banner select-none">
      <UserAvatar username={editingMessage.sender} size="xs" className="qor-reply-banner-avatar" />
      <div className="qor-reply-banner-copy">
        <span className="qor-reply-banner-name">Editing message</span>
        <div className="qor-reply-banner-preview">
          <BannerMessagePreview
            messageId={editingMessage.secureContentId || editingMessage.id}
            contentVersion={editingMessage.controlState?.editOperationId}
          />
        </div>
      </div>
      <button
        type="button"
        className="qor-reply-banner-close"
        onClick={onCancelEdit}
        aria-label="Cancel edit"
        title="Cancel edit"
      >
        <Cross2Icon aria-hidden="true" />
      </button>
    </div>
  );
}
