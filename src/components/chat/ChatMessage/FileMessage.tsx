import React from "react";
import { Avatar, AvatarFallback } from "../../ui/avatar";
import { format } from "date-fns";
import { cn } from "../../../lib/utils";
import { DownloadIcon, PaperclipIcon } from "../icons.tsx";
import { Message } from "../types.ts";
import { MessageReceipt } from "../MessageReceipt.tsx";
import { VoiceMessage } from "../VoiceMessage";
import { copyTextToClipboard } from "@/lib/clipboard";


// Type declaration for electronAPI
declare global {
  interface Window {
    electronAPI?: {
      isElectron: boolean;
      saveFile: (data: { filename: string; data: string; mimeType: string }) => Promise<{ success: boolean; path?: string; error?: string; canceled?: boolean }>;
    };
  }
}

interface FileMessageProps {
  message: Message;
  isCurrentUser?: boolean;
  onReply?: (message: Message) => void;
  onDelete?: (message: Message) => void;
  onEdit?: (message: Message) => void;
}

export const IMAGE_EXTENSIONS = ["jpg", "jpeg", "png", "gif", "webp"];
export const VIDEO_EXTENSIONS = ["mp4", "webm", "ogg"];
export const AUDIO_EXTENSIONS = ["mp3", "wav", "ogg", "m4a", "webm"];

export function hasExtension(filename: string, extensions: string[]) {
  // SECURITY: Prevent ReDoS attacks by validating filename length and format
  if (!filename || typeof filename !== 'string' || filename.length > 255) {
    return false;
  }

  // SECURITY: Sanitize filename to prevent regex injection
  const sanitizedFilename = filename.replace(/[^\w.-]/g, '');

  // SECURITY: Use simple string matching instead of complex regex to prevent ReDoS
  const lowerFilename = sanitizedFilename.toLowerCase();
  return extensions.some(ext => lowerFilename.endsWith('.' + ext.toLowerCase()));
}

export function formatFileSize(bytes: number) {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

// Component for just the file content without user info (for embedding in ChatMessage)
export function FileContent({ message, isCurrentUser }: { message: Message; isCurrentUser: boolean }) {
  const { content, filename, fileSize, mimeType, originalBase64Data } = message;

  const handleDownload = async (e: React.MouseEvent) => {
    e.preventDefault();

    // Check if running in Electron
    if (window.electronAPI?.isElectron && originalBase64Data && filename) {
      try {
        // Extract base64 data if it's a data URL
        let base64Data = originalBase64Data;
        if (originalBase64Data.startsWith('data:')) {
          const base64Index = originalBase64Data.indexOf(',');
          if (base64Index !== -1) {
            base64Data = originalBase64Data.substring(base64Index + 1);
          }
        }

        const result = await window.electronAPI.saveFile({
          filename,
          data: base64Data,
          mimeType: mimeType || 'application/octet-stream'
        });

        if (result.success) {
          console.log('File saved to:', result.path);
        } else if (!result.canceled) {
          console.error('Failed to save file:', result.error);
          // Fallback to browser download
          fallbackDownload();
        }
      } catch (error) {
        console.error('[FileContent] Electron save failed:', error);
        fallbackDownload();
      }
    } else {
      // Browser download
      fallbackDownload();
    }

    function fallbackDownload() {
      if (content) {
        const link = document.createElement('a');
        link.href = content;
        link.download = filename || 'download';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
      }
    }
  };

  return (
    <div className="flex flex-col gap-2">
      {/* Images */}
      {hasExtension(filename || "", IMAGE_EXTENSIONS) && (
        <div className={cn("rounded-lg px-0 py-0 text-sm break-words", "bg-muted")}>
          <div className="relative group">
            <img src={content} alt={filename} className="max-w-full rounded-md" />
            <button
              onClick={handleDownload}
              className="absolute top-2 right-2 bg-white p-1 rounded-full shadow hidden group-hover:block"
              aria-label={`Download ${filename}`}
            >
              <DownloadIcon />
            </button>
          </div>
        </div>
      )}

      {/* Videos */}
      {hasExtension(filename || "", VIDEO_EXTENSIONS) && (
        <div
          className={cn(
            "rounded-lg text-sm break-words",
            isCurrentUser ? "bg-primary text-primary-foreground" : "bg-muted"
          )}
        >
          <div className="flex flex-col gap-2">
            <video controls className="max-w-full rounded-md">
              <source src={content} />
              Your browser does not support the video tag.
            </video>

            <div className="flex items-center gap-2 text-sm">
              <span className="font-medium break-all ml-1 mb-1">{filename}</span>
              <span className="text-xs text-muted-foreground">({formatFileSize(fileSize ?? 0)})</span>
              <button
                onClick={handleDownload}
                className="text-blue-500 hover:text-blue-700"
                title="Download"
              >
                <DownloadIcon className="w-5 h-5 hover:scale-110 transition-transform duration-100 ease-in-out" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Audio files */}
      {hasExtension(filename || "", AUDIO_EXTENSIONS) && !filename?.includes('voice-note') && (
        <div
          className={cn(
            "rounded-lg text-sm break-words",
            isCurrentUser ? "bg-primary text-primary-foreground" : "bg-muted"
          )}
        >
          <div className="flex flex-col gap-1">
            <audio controls className="w-full rounded-md">
              <source src={content} />
              Your browser does not support the audio element.
            </audio>

            <div className="flex justify-between items-center gap-1 text-sm text-blue-500">
              <span className="truncate max-w-[250px] ml-1" title={filename}>
                {filename}
              </span>
              <button onClick={handleDownload} title="Download" aria-label={`Download ${filename}`}>
                <DownloadIcon className="w-5 h-5 hover:scale-110 transition-transform duration-100 ease-in-out" />
              </button>
            </div>

            <span className="text-xs text-muted-foreground">({formatFileSize(fileSize ?? 0)})</span>
          </div>
        </div>
      )}

      {/* Other files */}
      {!hasExtension(filename || "", [...IMAGE_EXTENSIONS, ...VIDEO_EXTENSIONS, ...AUDIO_EXTENSIONS]) && (
        <div
          className={cn(
            "rounded-lg px-1 py-1 text-sm break-words",
            isCurrentUser ? "bg-primary text-primary-foreground" : "bg-muted"
          )}
        >
          <div className="flex items-start gap-2 w-full text-blue-500">
            <PaperclipIcon className="h-5 w-5 shrink-0 mt-1" />
            <div className="flex flex-col min-w-0">
              <div className="flex justify-between items-center gap-2">
                <span className="text-sm truncate max-w-[250px] w-full" title={filename}>
                  {filename}
                </span>
                <button onClick={handleDownload} title="Download" aria-label={`Download ${filename}`}>
                  <DownloadIcon className="w-5 h-5 hover:scale-110 transition-transform duration-100 ease-in-out" />
                </button>
              </div>
              <span className="text-xs text-muted-foreground leading-tight">({formatFileSize(fileSize ?? 0)})</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export function FileMessage({ message, isCurrentUser, onReply, onDelete, onEdit }: FileMessageProps) {
  const { content, sender, timestamp, filename, fileSize, mimeType, originalBase64Data } = message;

  const handleDownload = async (e: React.MouseEvent) => {
    e.preventDefault();
    
    console.log('[FileMessage] Download clicked:', { 
      filename, 
      hasOriginalBase64Data: !!originalBase64Data, 
      isElectron: !!window.electronAPI?.isElectron,
      contentUrl: content?.substring(0, 50) + '...'
    });
    
    // Check if running in Electron
    if (window.electronAPI?.isElectron && originalBase64Data && filename) {
      try {
        // Extract base64 data if it's a data URL
        let base64Data = originalBase64Data;
        if (originalBase64Data.startsWith('data:')) {
          const base64Index = originalBase64Data.indexOf(',');
          if (base64Index !== -1) {
            base64Data = originalBase64Data.substring(base64Index + 1);
          }
        }
        
        console.log('[FileMessage] Calling Electron saveFile with:', {
          filename,
          dataLength: base64Data.length,
          mimeType: mimeType || 'application/octet-stream'
        });
        
        const result = await window.electronAPI.saveFile({
          filename,
          data: base64Data,
          mimeType: mimeType || 'application/octet-stream'
        });
        
        console.log('[FileMessage] Save result:', result);
        
        if (result.success) {
          console.log('File saved to:', result.path);
          // Could show a toast notification here
        } else if (!result.canceled) {
          console.error('Failed to save file:', result.error);
          // Fallback to browser download
          fallbackDownload();
        }
      } catch (error) {
        console.error('Error saving file:', error);
        fallbackDownload();
      }
    } else {
      console.log('[FileMessage] Using fallback download - conditions not met:', {
        isElectron: !!window.electronAPI?.isElectron,
        hasOriginalBase64Data: !!originalBase64Data,
        hasFilename: !!filename
      });
      fallbackDownload();
    }
  };
  
  const fallbackDownload = () => {
    console.log('[FileMessage] Fallback download:', { content, filename });
    
    try {
      // Create a temporary link for browser download
      const link = document.createElement('a');
      link.href = content;
      link.download = filename || 'download';
      link.rel = 'noopener';
      link.style.display = 'none';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      console.log('[FileMessage] Fallback download triggered successfully');
    } catch (error) {
      console.error('[FileMessage] Fallback download failed:', error);
      
      // Last resort: try to open in new tab
      try {
        window.open(content, '_blank');
      } catch (openError) {
        console.error('[FileMessage] Failed to open file in new tab:', openError);
      }
    }
  };

  // Voice note detection: filename contains voice-note or MIME is audio/*
  const isVoiceNote = Boolean(
    (filename && filename.toLowerCase().includes('voice-note')) ||
    (mimeType && mimeType.startsWith('audio/')) ||
    (filename && hasExtension(filename, AUDIO_EXTENSIONS))
  );

  if (isVoiceNote) {
    return (
      <VoiceMessage
        audioUrl={content}
        sender={sender}
        timestamp={timestamp}
        isCurrentUser={Boolean(isCurrentUser)}
        filename={filename}
        originalBase64Data={originalBase64Data}
        mimeType={mimeType}
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

        {hasExtension(filename || "", IMAGE_EXTENSIONS) && (
          <div className={cn("rounded-lg px-0 py-0 text-sm max-w-[60%] break-words", "bg-muted")}>
            <div className="relative group">
              <img src={content} alt={filename} className="max-w-full rounded-md" />
              <button
                onClick={handleDownload}
                className="absolute top-2 right-2 bg-white p-1 rounded-full shadow hidden group-hover:block"
                aria-label={`Download ${filename}`}
              >
                <DownloadIcon />
              </button>
            </div>
          </div>
        )}

        {hasExtension(filename || "", VIDEO_EXTENSIONS) && (
          <div
            className={cn(
              "rounded-lg text-sm max-w-[60%] break-words",
              isCurrentUser ? "bg-primary text-primary-foreground" : "bg-muted"
            )}
          >
            <div className="flex flex-col gap-2">
              <video controls className="max-w-full rounded-md">
                <source src={content} />
                Your browser does not support the video tag.
              </video>

              <div className="flex items-center gap-2 text-sm">
                <span className="font-medium break-all ml-1 mb-1">{filename}</span>
                <span className="text-xs text-muted-foreground">({formatFileSize(fileSize ?? 0)})</span>
                <button
                  onClick={handleDownload}
                  className="text-blue-500 hover:text-blue-700"
                  title="Download"
                >
                  <DownloadIcon className="w-5 h-5 hover:scale-110 transition-transform duration-100 ease-in-out" />
                </button>
              </div>
            </div>
          </div>
        )}

        {hasExtension(filename || "", AUDIO_EXTENSIONS) && (
          <div
            className={cn(
              "rounded-lg mr-1 py-0 text-sm max-w-[75%] break-words",
              isCurrentUser ? "bg-primary text-primary-foreground" : "bg-muted"
            )}
          >
            <div className="flex flex-col gap-1">
              <audio controls className="w-full rounded-md">
                <source src={content} />
                Your browser does not support the audio element.
              </audio>

              <div className="flex justify-between items-center gap-1 text-sm text-blue-500">
                <span className="truncate max-w-[250px] ml-1" title={filename}>
                  {filename}
                </span>
                <button onClick={handleDownload} title="Download" aria-label={`Download ${filename}`}>
                  <DownloadIcon className="w-5 h-5 hover:scale-110 transition-transform duration-100 ease-in-out" />
                </button>
              </div>

              <span className="text-xs text-muted-foreground">({formatFileSize(fileSize ?? 0)})</span>
            </div>
          </div>
        )}

        {!hasExtension(filename || "", [...IMAGE_EXTENSIONS, ...VIDEO_EXTENSIONS, ...AUDIO_EXTENSIONS]) && (
          <div
            className={cn(
              "rounded-lg px-1 py-1 text-sm max-w-[60%] break-words",
              isCurrentUser ? "bg-primary text-primary-foreground" : "bg-muted"
            )}
          >
            <div className="flex items-start gap-2 w-full text-blue-500">
              <PaperclipIcon className="h-5 w-5 shrink-0 mt-1" />
              <div className="flex flex-col min-w-0">
                <div className="flex justify-between items-center gap-2">
                  <span className="text-sm truncate max-w-[250px] w-full" title={filename}>
                    {filename}
                  </span>
                  <button onClick={handleDownload} title="Download" aria-label={`Download ${filename}`}>
                    <DownloadIcon className="w-5 h-5 hover:scale-110 transition-transform duration-100 ease-in-out" />
                  </button>
                </div>
                <span className="text-xs text-muted-foreground leading-tight">({formatFileSize(fileSize ?? 0)})</span>
              </div>
            </div>
          </div>
        )}

        {/* Action buttons */}
        <div
          className={cn(
            "flex items-center gap-1 mt-2 opacity-0 group-hover:opacity-100 transition-opacity duration-200",
            isCurrentUser ? "justify-end" : "justify-start"
          )}
        >
          <button
            onClick={() => { void copyTextToClipboard(filename || 'File'); }}
            aria-label="Copy filename"
            className="p-1 rounded hover:bg-opacity-80 transition-colors"
            style={{ color: 'var(--color-text-secondary)' }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = 'var(--color-accent-primary)';
              e.currentTarget.style.color = 'white';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = 'transparent';
              e.currentTarget.style.color = 'var(--color-text-secondary)';
            }}
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
            onClick={() => onReply?.(message)}
            aria-label="Reply to file"
            className="p-1 rounded hover:bg-opacity-80 transition-colors"
            style={{ color: 'var(--color-text-secondary)' }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = 'var(--color-accent-primary)';
              e.currentTarget.style.color = 'white';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = 'transparent';
              e.currentTarget.style.color = 'var(--color-text-secondary)';
            }}
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
              onClick={() => onDelete?.(message)}
              aria-label="Delete file"
              className="p-1 rounded hover:bg-opacity-80 transition-colors"
              style={{ color: 'var(--color-text-secondary)' }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = '#ef4444';
                e.currentTarget.style.color = 'white';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'transparent';
                e.currentTarget.style.color = 'var(--color-text-secondary)';
              }}
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

        {/* Message Receipt */}
        <MessageReceipt
          receipt={message.receipt}
          isCurrentUser={isCurrentUser || false}
          className="mt-1"
        />
      </div>
    </div>
  );
}