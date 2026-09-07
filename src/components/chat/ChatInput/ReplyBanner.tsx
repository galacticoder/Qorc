import { useMemo } from "react";
import { Cross2Icon } from "../assets/icons";
import { Message } from "../messaging/types";
import { SignalType } from '@/lib/types/signal-types';
import { parseCurrentVoiceNoteFilename } from '@/lib/utils/file-utils';
import { UserAvatar } from '../../ui/UserAvatar';
import { MaterialFileIcon } from '../../ui/MaterialFileIcon';
import { BannerMessagePreview } from './BannerMessagePreview';

interface ReplyBannerProps {
  readonly replyTo: Message;
  readonly onCancelReply: () => void;
  readonly displaySender: string;
}

const isVoiceNote = (message: Message): boolean => {
  const metadata = parseCurrentVoiceNoteFilename(message.filename);
  return metadata !== null && metadata.mimeType === message.mimeType;
};

export function ReplyBanner({ replyTo, onCancelReply, displaySender }: ReplyBannerProps) {
  const isVoiceMsg = useMemo(() => isVoiceNote(replyTo), [replyTo]);
  const isFileMsg = useMemo(() =>
    replyTo.type === SignalType.FILE || replyTo.type === SignalType.FILE_MESSAGE || replyTo.filename,
    [replyTo]
  );
  return (
    <div className="qorc-reply-banner select-none">
      <UserAvatar username={replyTo.sender} size="xs" className="qorc-reply-banner-avatar" />
      <div className="qorc-reply-banner-copy">
        <span className="qorc-reply-banner-name">{displaySender}</span>
        <div className="qorc-reply-banner-preview">
          {isFileMsg ? (
            <>
              <MaterialFileIcon
                fileName={replyTo.filename}
                className="qorc-reply-banner-preview-icon"
              />
              <span className="qorc-reply-banner-preview-text">
                {isVoiceMsg ? 'Voice message' : replyTo.filename || 'File'}
              </span>
            </>
          ) : replyTo.secureContentId ? (
            <BannerMessagePreview
              messageId={replyTo.secureContentId}
              contentVersion={replyTo.controlState?.editOperationId}
            />
          ) : (
            <span className="qorc-reply-banner-preview-text">Message</span>
          )}
        </div>
      </div>
      <button
        type="button"
        className="qorc-reply-banner-close"
        onClick={onCancelReply}
        aria-label="Cancel reply"
        title="Cancel reply"
      >
        <Cross2Icon aria-hidden="true" />
      </button>
    </div>
  );
}
