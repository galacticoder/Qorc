import React from "react";
import { Avatar, AvatarFallback } from "../../ui/avatar";
import { format } from "date-fns";
import { cn } from "../../../lib/utils";
import { DownloadIcon, PaperclipIcon } from "../icons.tsx";
import { Message } from "../types.ts";
import { MessageReceipt } from "../MessageReceipt.tsx";
import { VoiceMessage } from "../VoiceMessage";


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

export function FileMessage({ message, isCurrentUser }: FileMessageProps) {
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
    <div className={cn("flex items-start gap-2 mb-4", isCurrentUser ? "flex-row-reverse" : "")}> 
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