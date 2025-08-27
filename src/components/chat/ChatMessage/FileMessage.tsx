import React from "react";
import { cn } from "@/lib/utils";
import { Avatar, AvatarFallback } from "../../ui/avatar";
import { format } from "date-fns";
import * as icons from "../icons";
import { Message } from "../types";

interface FileMessageProps {
  message: Message;
  isCurrentUser?: boolean;
}

export const IMAGE_EXTENSIONS = ["jpg", "jpeg", "png", "gif", "webp"];
export const VIDEO_EXTENSIONS = ["mp4", "webm", "ogg"];
export const AUDIO_EXTENSIONS = ["mp3", "wav", "ogg", "m4a"];

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
  const { content, sender, timestamp, filename, fileSize } = message;

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
              <a
                href={content}
                download={filename}
                className="absolute top-2 right-2 bg-white p-1 rounded-full shadow hidden group-hover:block"
                aria-label={`Download ${filename}`}
              >
                <icons.DownloadIcon />
              </a>
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
                <a
                  href={content}
                  download={filename}
                  className="text-blue-500 hover:text-blue-700"
                  title="Download"
                >
                  <icons.DownloadIcon className="w-5 h-5 hover:scale-110 transition-transform duration-100 ease-in-out" />
                </a>
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
                <a href={content} download={filename} title="Download" aria-label={`Download ${filename}`}>
                  <icons.DownloadIcon className="w-5 h-5 hover:scale-110 transition-transform duration-100 ease-in-out" />
                </a>
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
              <icons.PaperclipIcon className="h-5 w-5 shrink-0 mt-1" />
              <div className="flex flex-col min-w-0">
                <div className="flex justify-between items-center gap-2">
                  <span className="text-sm truncate max-w-[250px] w-full" title={filename}>
                    {filename}
                  </span>
                  <a href={content} download={filename} title="Download" aria-label={`Download ${filename}`}>
                    <icons.DownloadIcon className="w-5 h-5 hover:scale-110 transition-transform duration-100 ease-in-out" />
                  </a>
                </div>
                <span className="text-xs text-muted-foreground leading-tight">({formatFileSize(fileSize ?? 0)})</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
