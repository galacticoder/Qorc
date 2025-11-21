import React, { useState, useEffect, useMemo } from "react";
import { Cross2Icon } from "../icons";
import { Message } from "../types";
import { Image, Video, Mic, Paperclip } from "lucide-react";

interface ReplyBannerProps {
  readonly replyTo: Message;
  readonly onCancelReply: () => void;
  readonly getDisplayUsername?: (username: string) => Promise<string>;
}

const IMAGE_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg', 'ico', 'tiff'] as const;
const VIDEO_EXTENSIONS = ['mp4', 'webm', 'ogg', 'avi', 'mov', 'wmv', 'flv', 'mkv'] as const;
const AUDIO_EXTENSIONS = ['mp3', 'wav', 'ogg', 'webm', 'm4a', 'aac', 'flac'] as const;
const HEX_PATTERN = /^[a-f0-9]{32,}$/i;

const hasExtension = (filename: string, extensions: readonly string[]): boolean => {
  if (!filename) return false;
  const ext = filename.toLowerCase().split('.').pop();
  return ext ? extensions.includes(ext) : false;
};

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

const sanitizeDisplayName = (name: string): string => {
  return HEX_PATTERN.test(name) ? 'User' : name;
};

export function ReplyBanner({ replyTo, onCancelReply, getDisplayUsername }: ReplyBannerProps) {
  const [displaySender, setDisplaySender] = useState(sanitizeDisplayName(replyTo.sender));

  useEffect(() => {
    if (getDisplayUsername) {
      getDisplayUsername(replyTo.sender)
        .then((resolved) => setDisplaySender(sanitizeDisplayName(resolved)))
        .catch(() => setDisplaySender(sanitizeDisplayName(replyTo.sender)));
    }
  }, [replyTo.sender, getDisplayUsername]);


  const isImageMsg = useMemo(() => isImage(replyTo), [replyTo]);
  const isVideoMsg = useMemo(() => isVideo(replyTo), [replyTo]);
  const isVoiceMsg = useMemo(() => isVoiceNote(replyTo), [replyTo]);
  const isFileMsg = useMemo(() =>
    replyTo.type === 'file' || replyTo.type === 'file-message' || replyTo.filename,
    [replyTo]
  );

  const contentPreview = useMemo(() => {
    if (!replyTo.content) return "";
    return replyTo.content.length > 100
      ? `${replyTo.content.slice(0, 100)}...`
      : replyTo.content;
  }, [replyTo.content]);
  return (
    <div className="px-4 py-2">
      <div
        className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-muted/30 text-muted-foreground"
      >
        <svg
          className="w-3.5 h-3.5 flex-shrink-0"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6"
          />
        </svg>

        <div className="flex items-center gap-1.5 min-w-0 flex-1">
          <span className="text-xs font-medium text-foreground flex-shrink-0">
            {displaySender}
          </span>
          <span className="text-xs flex-shrink-0">•</span>

          {isImageMsg ? (
            <>
              <Image className="w-3 h-3 flex-shrink-0" />
              <span className="text-xs truncate">{replyTo.filename || 'Image'}</span>
            </>
          ) : isVideoMsg ? (
            <>
              <Video className="w-3 h-3 flex-shrink-0" />
              <span className="text-xs truncate">{replyTo.filename || 'Video'}</span>
            </>
          ) : isVoiceMsg ? (
            <>
              <Mic className="w-3 h-3 flex-shrink-0" />
              <span className="text-xs truncate">Voice message</span>
            </>
          ) : isFileMsg ? (
            <>
              <Paperclip className="w-3 h-3 flex-shrink-0" />
              <span className="text-xs truncate">{replyTo.filename || 'File'}</span>
            </>
          ) : (
            <span className="text-xs truncate">{contentPreview}</span>
          )}
        </div>

        <button
          className="flex-shrink-0 w-5 h-5 rounded hover:bg-muted/50 flex items-center justify-center transition-colors"
          onClick={onCancelReply}
          aria-label="Cancel reply"
        >
          <Cross2Icon className="h-3 w-3" />
        </button>
      </div>
    </div>
  );
}