import React, { useEffect, useCallback, useMemo } from "react";
import { createPortal } from "react-dom";
import { Avatar, AvatarFallback } from "../../../ui/avatar";
import { format } from "date-fns";
import { cn } from "../../../../lib/utils/shared-utils";
import { Download } from "lucide-react";
import { Message } from "../types";
import { MessageReceipt } from "../MessageReceipt";
import { VoiceMessage } from "../../calls/VoiceMessage";
import { copyTextToClipboard } from "../../../../lib/clipboard";
import { useFileUrl } from "../../../../hooks/file-handling/useFileUrl";
import { formatFileSize, hasExtension, isSafeFileUrl, createDownloadLink } from "../../../../lib/utils/file-utils";
import { IMAGE_EXTENSIONS, VIDEO_EXTENSIONS, AUDIO_EXTENSIONS } from "../../../../lib/constants";

interface FileMessageProps {
  readonly message: Message;
  readonly isCurrentUser?: boolean;
  readonly onReply?: (message: Message) => void;
  readonly onDelete?: (message: Message) => void;
  readonly onEdit?: (message: Message) => void;
  readonly secureDB?: any;
}

interface FileContentProps {
  readonly message: Message;
  readonly isCurrentUser: boolean;
  readonly secureDB?: any;
  readonly onRendered?: () => void;
}

// Component to render file content based on type
export const FileContent: React.FC<FileContentProps> = ({ message, isCurrentUser, secureDB, onRendered }) => {
  const { content, filename, fileSize, mimeType, originalBase64Data } = message;
  const [imageError, setImageError] = React.useState(false);
  const [videoError, setVideoError] = React.useState(false);
  const [audioError, setAudioError] = React.useState(false);
  const [lightboxOpen, setLightboxOpen] = React.useState(false);
  const [imageLoaded, setImageLoaded] = React.useState(false);

  const isImage = useMemo(() => hasExtension(filename || "", IMAGE_EXTENSIONS), [filename]);

  useEffect(() => {
    if (!isImage) {
      onRendered?.();
    }
  }, [isImage, onRendered]);

  const { url: resolvedFileUrl, loading: _fileLoading, error: _fileError } = useFileUrl({
    secureDB: secureDB || null,
    fileId: message.id,
    mimeType: mimeType || 'application/octet-stream',
    initialUrl: typeof content === 'string' ? content : '',
    originalBase64Data: originalBase64Data || null,
  });

  const rawContentUrl = typeof content === 'string' ? content : '';
  const safeContentUrl = isSafeFileUrl(rawContentUrl);
  // Don't use stale blob: URLs as fallback — they become invalid after
  // app restart and cause "Failed to load resource" errors in the browser.
  const nonBlobFallback = safeContentUrl && !safeContentUrl.startsWith('blob:') ? safeContentUrl : null;
  const effectiveFileUrl = resolvedFileUrl || nonBlobFallback;

  useEffect(() => {
    if (effectiveFileUrl) {
      setImageError(false);
      setVideoError(false);
      setAudioError(false);
    }
  }, [effectiveFileUrl]);

  const isImageFile = hasExtension(filename || "", IMAGE_EXTENSIONS);
  const isVideoFile = hasExtension(filename || "", VIDEO_EXTENSIONS);
  const isAudioFile = hasExtension(filename || "", AUDIO_EXTENSIONS) && !filename?.includes('voice-note');
  const isGenericFile = !isImageFile && !isVideoFile && !isAudioFile;

  const sizeLabel = formatFileSize(fileSize ?? 0);

  const downloadFile = () => {
    if (effectiveFileUrl) createDownloadLink(effectiveFileUrl, filename || 'download');
  };

  // Compact card shell shared by audio / generic files
  const fileCard = (children: React.ReactNode, onClick?: () => void) => (
    <div
      className="qor-file-card"
      role={onClick ? "button" : undefined}
      tabIndex={onClick ? 0 : undefined}
      onClick={onClick}
      onKeyDown={onClick ? (e) => { if (e.key === 'Enter') onClick(); } : undefined}
    >
      {children}
    </div>
  );

  return (
    <>
      {/* Images */}
      {isImageFile && (
        <>
          {!imageError ? (
            <div
              className="qor-file-image group"
              onClick={() => setLightboxOpen(true)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => { if (e.key === 'Enter') setLightboxOpen(true); }}
              title="Click to expand"
            >
              {!imageLoaded && <div className="qor-file-image-skeleton animate-pulse" />}
              <img
                src={effectiveFileUrl}
                alt={filename}
                className={cn("qor-file-image-img", imageLoaded ? "opacity-100" : "opacity-0")}
                draggable={false}
                onLoad={() => { setImageLoaded(true); onRendered?.(); }}
                onError={() => { setImageError(true); setImageLoaded(true); onRendered?.(); }}
              />
            </div>
          ) : (
            <div className="qor-file-error">Image cannot be loaded</div>
          )}

          {lightboxOpen && effectiveFileUrl && createPortal(
            <div
              className="fixed inset-0 flex items-center justify-center bg-black/80"
              style={{ zIndex: 9999 }}
              onClick={() => setLightboxOpen(false)}
              onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); }}
            >
              <img
                src={effectiveFileUrl}
                alt={filename}
                className="object-contain select-none pointer-events-none rounded-lg"
                style={{ maxWidth: '92vw', maxHeight: '92vh' }}
                draggable={false}
              />
            </div>,
            document.body
          )}
        </>
      )}

      {/* Videos */}
      {isVideoFile && (
        !videoError ? (
          <div className="qor-file-media">
            <video controls className="qor-file-video" onError={() => setVideoError(true)}>
              <source src={effectiveFileUrl} />
            </video>
            <div className="qor-file-media-foot">
              <span className="qor-file-name" title={filename}>{filename}</span>
              <span className="qor-file-size">{sizeLabel}</span>
            </div>
          </div>
        ) : (
          <div className="qor-file-error">Video cannot be loaded</div>
        )
      )}

      {/* Audio (non-voice) */}
      {isAudioFile && (
        !audioError ? (
          fileCard(
            <div className="qor-file-meta">
              <span className="qor-file-name" title={filename}>{filename}</span>
              <audio controls className="qor-file-audio" onError={() => setAudioError(true)}>
                <source src={effectiveFileUrl} />
              </audio>
              <span className="qor-file-size">{sizeLabel}</span>
            </div>
          )
        ) : (
          <div className="qor-file-error">Audio cannot be loaded</div>
        )
      )}

      {/* Generic files */}
      {isGenericFile && fileCard(
        <>
          <div className="qor-file-meta">
            <span className="qor-file-name" title={filename}>{filename || 'File'}</span>
            <span className="qor-file-size">{sizeLabel}</span>
          </div>
          <div className="qor-file-dl" aria-hidden="true"><Download className="w-[18px] h-[18px]" /></div>
        </>,
        downloadFile
      )}
    </>
  );
}

// Main file message component with sender info and actions
export function FileMessage({ message, isCurrentUser, onReply, onDelete, secureDB }: FileMessageProps) {
  const { content, sender, timestamp, filename, fileSize: _fileSize, mimeType, originalBase64Data } = message;

  useEffect(() => {
    if (typeof content === 'string' && content.startsWith('blob:')) {
      return () => {
        try { URL.revokeObjectURL(content); } catch { }
      };
    }
    return undefined;
  }, [content]);

  const isVoiceNote = useMemo(() => {
    const name = (filename || '').toLowerCase();
    return name.includes('voice-note');
  }, [filename]);

  // Copy filename to clipboard
  const handleCopyFilename = useCallback((): void => {
    void copyTextToClipboard(filename || 'File');
  }, [filename]);

  // Handle reply action
  const handleReply = useCallback((): void => {
    onReply?.(message);
  }, [onReply, message]);

  // Handle delete action
  const handleDelete = useCallback((): void => {
    onDelete?.(message);
  }, [onDelete, message]);

  // Handle mouse enter for action buttons
  const handleActionMouseEnter = useCallback((e: React.MouseEvent<HTMLButtonElement>): void => {
    e.currentTarget.style.backgroundColor = 'var(--color-accent-primary)';
    e.currentTarget.style.color = 'white';
  }, []);

  // Handle mouse leave for action buttons
  const handleActionMouseLeave = useCallback((e: React.MouseEvent<HTMLButtonElement>): void => {
    e.currentTarget.style.backgroundColor = 'transparent';
    e.currentTarget.style.color = 'var(--color-text-secondary)';
  }, []);

  // Handle mouse enter for delete button
  const handleDeleteMouseEnter = useCallback((e: React.MouseEvent<HTMLButtonElement>): void => {
    e.currentTarget.style.backgroundColor = '#ef4444';
    e.currentTarget.style.color = 'white';
  }, []);

  // Handle mouse leave for delete button
  const handleDeleteMouseLeave = useCallback((e: React.MouseEvent<HTMLButtonElement>): void => {
    e.currentTarget.style.backgroundColor = 'transparent';
    e.currentTarget.style.color = 'var(--color-text-secondary)';
  }, []);

  if (isVoiceNote) {
    return (
      <VoiceMessage
        audioUrl={typeof content === 'string' ? content : ''}
        timestamp={timestamp}
        isCurrentUser={Boolean(isCurrentUser)}
        filename={filename}
        originalBase64Data={originalBase64Data}
        mimeType={mimeType}
        messageId={message.id}
        secureDB={secureDB}
      />
    );
  }

  return (
    <div className={cn("flex items-start gap-2 mb-4 group", isCurrentUser ? "flex-row-reverse" : "")}>
      <Avatar className="w-8 h-8">
        <AvatarFallback className={cn(isCurrentUser ? "bg-blue-500 text-white" : "bg-muted")}>
          {sender.charAt(0).toUpperCase()}
        </AvatarFallback>
      </Avatar>

      <div className={cn("flex flex-col", isCurrentUser ? "items-end" : "items-start")}>
        <div className="flex items-center gap-2 mb-1">
          <span className="text-sm font-medium">{sender}</span>
          <span className="text-xs text-muted-foreground">{format(timestamp, "h:mm a")}</span>
        </div>

        <FileContent message={message} isCurrentUser={isCurrentUser || false} secureDB={secureDB} />

        <div
          className={cn(
            "flex items-center gap-1 mt-2 opacity-0 group-hover:opacity-100 transition-opacity duration-200",
            isCurrentUser ? "justify-end" : "justify-start"
          )}
        >
          <button
            onClick={handleCopyFilename}
            aria-label="Copy filename"
            className="p-1 rounded hover:bg-opacity-80 transition-colors"
            style={{ color: 'var(--color-text-secondary)' }}
            onMouseEnter={handleActionMouseEnter}
            onMouseLeave={handleActionMouseLeave}
          >
            <svg
              width="15"
              height="15"
              viewBox="0 0 15 15"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M1 9.50006C1 10.3285 1.67157 11.0001 2.5 11.0001H4L4 10.0001H2.5C2.22386 10.0001 2 9.7762 2 9.50006L2 2.50006C2 2.22392 2.22386 2.00006 2.5 2.00006L9.5 2.00006C9.77614 2.00006 10 2.22392 10 2.50006V4.00002H5.5C4.67158 4.00002 4 4.67159 4 5.50002V12.5C4 13.3284 4.67158 14 5.5 14H12.5C13.3284 14 14 13.3284 14 12.5V5.50002C14 4.67159 13.3284 4.00002 12.5 4.00002H11V2.50006C11 1.67163 10.3284 1.00006 9.5 1.00006H2.5C1.67157 1.00006 1 1.67163 1 2.50006V9.50006ZM5 5.50002C5 5.22388 5.22386 5.00002 5.5 5.00002H12.5C12.7761 5.00002 13 5.22388 13 5.50002V12.5C13 12.7762 12.7761 13 12.5 13H5.5C5.22386 13 5 12.7762 5 12.5V5.50002Z"
                fill="currentColor"
                fillRule="evenodd"
                clipRule="evenodd"
              />
            </svg>
          </button>

          <button
            onClick={handleReply}
            aria-label="Reply to file"
            className="p-1 rounded hover:bg-opacity-80 transition-colors"
            style={{ color: 'var(--color-text-secondary)' }}
            onMouseEnter={handleActionMouseEnter}
            onMouseLeave={handleActionMouseLeave}
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              fill="none"
              viewBox="0 0 24 24"
              strokeWidth={1.5}
              stroke="currentColor"
              className="w-4 h-4"
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 15 3 9m0 0 6-6M3 9h12a6 6 0 0 1 0 12h-3" />
            </svg>
          </button>

          {isCurrentUser && (
            <button
              onClick={handleDelete}
              aria-label="Delete file"
              className="p-1 rounded hover:bg-opacity-80 transition-colors"
              style={{ color: 'var(--color-text-secondary)' }}
              onMouseEnter={handleDeleteMouseEnter}
              onMouseLeave={handleDeleteMouseLeave}
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                strokeWidth={1.5}
                stroke="currentColor"
                className="w-4 h-4"
              >
                <path strokeLinecap="round" strokeLinejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0" />
              </svg>
            </button>
          )}
        </div>

        <MessageReceipt
          receipt={message.receipt}
          isCurrentUser={isCurrentUser || false}
          className="mt-1"
        />
      </div>
    </div>
  );
}