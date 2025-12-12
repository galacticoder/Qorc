import React, { useEffect, useCallback, useMemo } from "react";
import { createPortal } from "react-dom";
import { Avatar, AvatarFallback } from "../../ui/avatar";
import { format } from "date-fns";
import { cn } from "../../../lib/utils";
import { PaperclipIcon } from "../icons.tsx";
import { Message } from "../types.ts";
import { MessageReceipt } from "../MessageReceipt.tsx";
import { VoiceMessage } from "../VoiceMessage";
import { copyTextToClipboard } from "../../../lib/clipboard";
import { sanitizeFilename } from "../../../lib/sanitizers";
import { useFileUrl } from "../../../hooks/useFileUrl";

interface ElectronSaveFileData {
  readonly filename: string;
  readonly data: string;
  readonly mimeType: string;
}

interface ElectronSaveFileResult {
  readonly success: boolean;
  readonly path?: string;
  readonly error?: string;
  readonly canceled?: boolean;
}

declare global {
  interface Window {
    electronAPI?: any;
  }
}

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
}

const MAX_FILENAME_LENGTH = 255;
const FILENAME_SANITIZE_REGEX = /[^\w.-]/g;

export const IMAGE_EXTENSIONS = ["jpg", "jpeg", "png", "gif", "webp"];
export const VIDEO_EXTENSIONS = ["mp4", "webm", "ogg"];
export const AUDIO_EXTENSIONS = ["mp3", "wav", "ogg", "m4a", "webm"];

export const hasExtension = (filename: string, extensions: readonly string[]): boolean => {
  if (!filename || typeof filename !== 'string' || filename.length > MAX_FILENAME_LENGTH) {
    return false;
  }

  const sanitizedFilename = filename.replace(FILENAME_SANITIZE_REGEX, '');
  const lowerFilename = sanitizedFilename.toLowerCase();
  return extensions.some(ext => lowerFilename.endsWith('.' + ext.toLowerCase()));
};

const FILE_SIZE_UNITS = ["Bytes", "KB", "MB", "GB"] as const;
const FILE_SIZE_BASE = 1024;

export const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return "0 Bytes";
  if (bytes < 0 || !Number.isFinite(bytes)) return "Unknown";

  const i = Math.min(
    Math.floor(Math.log(bytes) / Math.log(FILE_SIZE_BASE)),
    FILE_SIZE_UNITS.length - 1
  );
  const value = bytes / Math.pow(FILE_SIZE_BASE, i);
  return `${value.toFixed(1)} ${FILE_SIZE_UNITS[i]}`;
};

const extractBase64Data = (dataUrl: string): string => {
  if (!dataUrl.startsWith('data:')) return dataUrl;
  const commaIndex = dataUrl.indexOf(',');
  return commaIndex !== -1 ? dataUrl.substring(commaIndex + 1) : dataUrl;
};

const createDownloadLink = (href: string, filename: string): void => {
  const link = document.createElement('a');
  link.href = href;
  link.download = sanitizeFilename(filename || 'download');
  link.rel = 'noopener noreferrer';
  link.style.display = 'none';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
};

const isSafeFileUrl = (url: string | null | undefined): string | null => {
  if (!url || typeof url !== 'string') return null;
  try {
    const parsed = new URL(url, 'http://localhost');
    const protocol = parsed.protocol.toLowerCase();
    if (protocol === 'blob:' || protocol === 'http:' || protocol === 'https:') {
      return url;
    }
    return null;
  } catch {
    return null;
  }
};

export const FileContent: React.FC<FileContentProps> = ({ message, isCurrentUser, secureDB }) => {
  const { content, filename, fileSize, mimeType, originalBase64Data } = message;
  const [imageError, setImageError] = React.useState(false);
  const [videoError, setVideoError] = React.useState(false);
  const [audioError, setAudioError] = React.useState(false);
  const [lightboxOpen, setLightboxOpen] = React.useState(false);
  const [imageDimensions, setImageDimensions] = React.useState<{ width: number; height: number } | null>(null);
  const [imageLoaded, setImageLoaded] = React.useState(false);

  const { url: resolvedFileUrl, loading: fileLoading, error: fileError } = useFileUrl({
    secureDB: secureDB || null,
    fileId: message.id,
    mimeType: mimeType || 'application/octet-stream',
    initialUrl: typeof content === 'string' ? content : '',
    originalBase64Data: originalBase64Data || null,
  });

  const rawContentUrl = typeof content === 'string' ? content : '';
  const safeContentUrl = isSafeFileUrl(rawContentUrl);
  const effectiveFileUrl = resolvedFileUrl || safeContentUrl;

  useEffect(() => {
    if (effectiveFileUrl) {
      setImageError(false);
      setVideoError(false);
      setAudioError(false);
    }
  }, [effectiveFileUrl]);

  const fallbackDownload = useCallback((): void => {
    const safeUrl = isSafeFileUrl(rawContentUrl);
    if (!safeUrl) return;
    try {
      createDownloadLink(safeUrl, filename || 'download');
    } catch { }
  }, [rawContentUrl, filename]);

  const handleDownload = useCallback(async (e: React.MouseEvent): Promise<void> => {
    e.preventDefault();

    if (window.electronAPI?.isElectron && filename) {
      try {
        let base64Data = '';

        if (originalBase64Data) {
          base64Data = extractBase64Data(originalBase64Data);
        } else if (secureDB) {
          const blob = await secureDB.getFile(message.id);
          if (blob) {
            const buffer = await blob.arrayBuffer();
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
              binary += String.fromCharCode(bytes[i]);
            }
            base64Data = btoa(binary);
          }
        }

        if (base64Data) {
          const result = await window.electronAPI.saveFile({
            filename,
            data: base64Data,
            mimeType: mimeType || 'application/octet-stream'
          });

          if (!result.success && !result.canceled) {
            fallbackDownload();
          }
        } else {
          fallbackDownload();
        }
      } catch {
        fallbackDownload();
      }
    } else {
      fallbackDownload();
    }
  }, [originalBase64Data, filename, mimeType, fallbackDownload, secureDB, message.id]);

  return (
    <>
      {/* Images */}
      {hasExtension(filename || "", IMAGE_EXTENSIONS) && (
        <>
          <div
            className="relative cursor-pointer group"
            onClick={() => setLightboxOpen(true)}
            title="Click to expand"
          >
            {!imageError ? (
              <div
                className="rounded-xl overflow-hidden relative"
                style={{
                  width: '280px',
                  height: '200px',
                  backgroundColor: 'var(--color-surface)'
                }}
              >
                {!imageLoaded && (
                  <div
                    className="absolute inset-0 w-full h-full animate-pulse"
                    style={{ backgroundColor: 'var(--color-secondary)' }}
                  />
                )}
                <img
                  src={effectiveFileUrl}
                  alt={filename}
                  className={`w-full h-full object-cover select-none transition-opacity duration-200 ${imageLoaded ? 'opacity-100' : 'opacity-0'}`}
                  draggable={false}
                  onLoad={(e) => {
                    const img = e.target as HTMLImageElement;
                    setImageDimensions({ width: img.naturalWidth, height: img.naturalHeight });
                    setImageLoaded(true);
                  }}
                  onError={() => {
                    setImageError(true);
                    setImageLoaded(true);
                  }}
                />
              </div>
            ) : (
              <div
                className="px-3 py-2 rounded-lg text-sm italic select-none"
                style={{
                  backgroundColor: 'var(--color-surface)',
                  color: 'var(--color-text-secondary)',
                  border: '1px dashed rgba(255,255,255,0.22)'
                }}
              >
                Image cannot be loaded
              </div>
            )}
          </div>

          {/* Lightbox Modal */}
          {lightboxOpen && effectiveFileUrl && createPortal(
            <div
              className="fixed inset-0 flex items-center justify-center bg-black/70"
              style={{ zIndex: 9999 }}
              onClick={() => setLightboxOpen(false)}
              onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); }}
            >
              <img
                src={effectiveFileUrl}
                alt={filename}
                className="object-contain select-none pointer-events-none"
                style={{
                  maxWidth: '90vw',
                  maxHeight: '90vh'
                }}
                draggable={false}
              />
            </div>,
            document.body
          )}
        </>
      )}

      {/* Videos */}
      {hasExtension(filename || "", VIDEO_EXTENSIONS) && (
        !videoError ? (
          <div
            className={cn(
              "rounded-lg text-sm break-words",
              isCurrentUser ? "bg-primary text-primary-foreground" : "bg-muted"
            )}
          >
            <div className="flex flex-col gap-2">
              <video
                controls
                className="max-w-full rounded-md"
                onError={() => setVideoError(true)}
              >
                <source src={effectiveFileUrl} />
                Your browser does not support the video tag.
              </video>

              <div className="flex items-center gap-2 text-sm">
                <span className="font-medium break-all ml-1 mb-1">{filename}</span>
                <span className="text-xs text-muted-foreground">({formatFileSize(fileSize ?? 0)})</span>
              </div>
            </div>
          </div>
        ) : (
          <div
            className="px-3 py-2 rounded-lg text-sm italic select-none"
            style={{
              backgroundColor: 'var(--color-surface)',
              color: 'var(--color-text-secondary)',
              border: '1px dashed var(--color-border)'
            }}
          >
            Video cannot be loaded
          </div>
        )
      )}

      {/* Audio files */}
      {hasExtension(filename || "", AUDIO_EXTENSIONS) && !filename?.includes('voice-note') && (
        !audioError ? (
          <div
            className="rounded-lg text-sm break-words"
            style={{
              backgroundColor: isCurrentUser ? 'var(--color-accent-primary)' : 'var(--chat-bubble-received-bg)',
              color: isCurrentUser ? 'white' : 'var(--color-text-primary)',
              borderRadius: 'var(--message-bubble-radius)'
            }}
          >
            <div className="flex flex-col gap-1">
              <audio
                controls
                className="w-full rounded-md"
                onError={() => setAudioError(true)}
              >
                <source src={effectiveFileUrl} />
                Your browser does not support the audio element.
              </audio>

              <div className={cn(
                "flex items-center gap-1 text-sm",
                isCurrentUser ? "text-white" : "text-blue-500"
              )}>
                <span className="truncate max-w-[250px] ml-1" title={filename}>
                  {filename}
                </span>
              </div>

              <span className="text-xs text-muted-foreground">({formatFileSize(fileSize ?? 0)})</span>
            </div>
          </div>
        ) : (
          <div
            className="px-3 py-2 rounded-lg text-sm italic select-none"
            style={{
              backgroundColor: 'var(--color-surface)',
              color: 'var(--color-text-secondary)',
              border: '1px dashed var(--color-border)'
            }}
          >
            Audio cannot be loaded
          </div>
        )
      )}

      {/* Other files */}
      {!hasExtension(filename || "", [...IMAGE_EXTENSIONS, ...VIDEO_EXTENSIONS, ...AUDIO_EXTENSIONS]) && (
        <div
          className="rounded-lg px-1 py-1 text-sm break-words"
          style={{
            backgroundColor: isCurrentUser ? 'var(--color-accent-primary)' : 'var(--chat-bubble-received-bg)',
            borderRadius: 'var(--message-bubble-radius)'
          }}
        >
          <div
            className="flex items-start gap-2 w-full"
            style={{
              color: isCurrentUser ? 'white' : 'var(--color-link)'
            }}
          >
            <PaperclipIcon className="h-5 w-5 shrink-0 mt-1" />
            <div className="flex flex-col min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm truncate max-w-[250px] w-full" title={filename}>
                  {filename}
                </span>
              </div>
              <span
                className="text-xs leading-tight"
                style={{
                  color: isCurrentUser ? 'rgba(255,255,255,0.8)' : 'var(--color-text-secondary)'
                }}
              >({formatFileSize(fileSize ?? 0)})</span>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export function FileMessage({ message, isCurrentUser, onReply, onDelete, secureDB }: FileMessageProps) {
  const { content, sender, timestamp, filename, fileSize, mimeType, originalBase64Data } = message;

  useEffect(() => {
    if (typeof content === 'string' && content.startsWith('blob:')) {
      return () => {
        try { URL.revokeObjectURL(content); } catch { }
      };
    }
    return undefined;
  }, [content]);

  const fallbackDownload = useCallback((): void => {
    if (!content) return;
    try {
      createDownloadLink(content, filename || 'download');
    } catch {
      try {
        window.open(content, '_blank', 'noopener,noreferrer');
      } catch { }
    }
  }, [content, filename]);

  const isVoiceNote = useMemo(() => {
    const name = (filename || '').toLowerCase();
    return name.includes('voice-note');
  }, [filename]);

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

        {/* Use FileContent for all file types */}
        <FileContent message={message} isCurrentUser={isCurrentUser || false} secureDB={secureDB} />

        <div
          className={cn(
            "flex items-center gap-1 mt-2 opacity-0 group-hover:opacity-100 transition-opacity duration-200",
            isCurrentUser ? "justify-end" : "justify-start"
          )}
        >
          <button
            onClick={useCallback(() => { void copyTextToClipboard(filename || 'File'); }, [filename])}
            aria-label="Copy filename"
            className="p-1 rounded hover:bg-opacity-80 transition-colors"
            style={{ color: 'var(--color-text-secondary)' }}
            onMouseEnter={useCallback((e: React.MouseEvent<HTMLButtonElement>) => {
              e.currentTarget.style.backgroundColor = 'var(--color-accent-primary)';
              e.currentTarget.style.color = 'white';
            }, [])}
            onMouseLeave={useCallback((e: React.MouseEvent<HTMLButtonElement>) => {
              e.currentTarget.style.backgroundColor = 'transparent';
              e.currentTarget.style.color = 'var(--color-text-secondary)';
            }, [])}
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
            onClick={useCallback(() => onReply?.(message), [onReply, message])}
            aria-label="Reply to file"
            className="p-1 rounded hover:bg-opacity-80 transition-colors"
            style={{ color: 'var(--color-text-secondary)' }}
            onMouseEnter={useCallback((e: React.MouseEvent<HTMLButtonElement>) => {
              e.currentTarget.style.backgroundColor = 'var(--color-accent-primary)';
              e.currentTarget.style.color = 'white';
            }, [])}
            onMouseLeave={useCallback((e: React.MouseEvent<HTMLButtonElement>) => {
              e.currentTarget.style.backgroundColor = 'transparent';
              e.currentTarget.style.color = 'var(--color-text-secondary)';
            }, [])}
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
              onClick={useCallback(() => onDelete?.(message), [onDelete, message])}
              aria-label="Delete file"
              className="p-1 rounded hover:bg-opacity-80 transition-colors"
              style={{ color: 'var(--color-text-secondary)' }}
              onMouseEnter={useCallback((e: React.MouseEvent<HTMLButtonElement>) => {
                e.currentTarget.style.backgroundColor = '#ef4444';
                e.currentTarget.style.color = 'white';
              }, [])}
              onMouseLeave={useCallback((e: React.MouseEvent<HTMLButtonElement>) => {
                e.currentTarget.style.backgroundColor = 'transparent';
                e.currentTarget.style.color = 'var(--color-text-secondary)';
              }, [])}
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