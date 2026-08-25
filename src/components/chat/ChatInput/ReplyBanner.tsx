import { useMemo } from "react";
import { Cross2Icon } from "../assets/icons";
import { Message } from "../messaging/types";
import { Image, Video, Mic, Paperclip } from "lucide-react";
import { SignalType } from '@/lib/types/signal-types';
import { IMAGE_EXTENSIONS, VIDEO_EXTENSIONS, AUDIO_EXTENSIONS } from '@/lib/constants';
import { hasExtension } from '@/lib/utils/file-utils';
import { UserAvatar } from '../../ui/UserAvatar';
import { BannerMessagePreview } from './BannerMessagePreview';

interface ReplyBannerProps {
  readonly replyTo: Message;
  readonly onCancelReply: () => void;
  readonly displaySender: string;
}

const isVoiceNote = (message: Message): boolean => {
  return Boolean(
    (message.filename && message.filename.toLowerCase().includes('voice-note')) ||
    (message.mimeType && message.mimeType.startsWith('audio/')) ||
    (message.filename && hasExtension(message.filename, AUDIO_EXTENSIONS))
  );
};

const isImage = (message: Message): boolean => {
  return Boolean(message.filename && hasExtension(message.filename, IMAGE_EXTENSIONS));
};

const isVideo = (message: Message): boolean => {
  return Boolean(message.filename && hasExtension(message.filename, VIDEO_EXTENSIONS));
};

export function ReplyBanner({ replyTo, onCancelReply, displaySender }: ReplyBannerProps) {
  const isImageMsg = useMemo(() => isImage(replyTo), [replyTo]);
  const isVideoMsg = useMemo(() => isVideo(replyTo), [replyTo]);
  const isVoiceMsg = useMemo(() => isVoiceNote(replyTo), [replyTo]);
  const isFileMsg = useMemo(() =>
    replyTo.type === SignalType.FILE || replyTo.type === SignalType.FILE_MESSAGE || replyTo.filename,
    [replyTo]
  );
  return (
    <div className="qor-reply-banner select-none">
      <UserAvatar username={replyTo.sender} size="xs" className="qor-reply-banner-avatar" />
      <div className="qor-reply-banner-copy">
        <span className="qor-reply-banner-name">{displaySender}</span>
        <div className="qor-reply-banner-preview">
          {isImageMsg ? (
            <>
              <Image className="qor-reply-banner-preview-icon" />
              <span className="qor-reply-banner-preview-text">{replyTo.filename || 'Image'}</span>
            </>
          ) : isVideoMsg ? (
            <>
              <Video className="qor-reply-banner-preview-icon" />
              <span className="qor-reply-banner-preview-text">{replyTo.filename || 'Video'}</span>
            </>
          ) : isVoiceMsg ? (
            <>
              <Mic className="qor-reply-banner-preview-icon" />
              <span className="qor-reply-banner-preview-text">Voice message</span>
            </>
          ) : isFileMsg ? (
            <>
              <Paperclip className="qor-reply-banner-preview-icon" />
              <span className="qor-reply-banner-preview-text">{replyTo.filename || 'File'}</span>
            </>
          ) : replyTo.secureContentId ? (
            <BannerMessagePreview
              messageId={replyTo.secureContentId}
              contentVersion={replyTo.controlState?.editOperationId}
            />
          ) : (
            <span className="qor-reply-banner-preview-text">Message</span>
          )}
        </div>
      </div>
      <button
        type="button"
        className="qor-reply-banner-close"
        onClick={onCancelReply}
        aria-label="Cancel reply"
        title="Cancel reply"
      >
        <Cross2Icon aria-hidden="true" />
      </button>
    </div>
  );
}
