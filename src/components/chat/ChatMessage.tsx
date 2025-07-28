import { cn } from "@/lib/utils";
import { Avatar, AvatarFallback } from "../ui/avatar";
import { format } from "date-fns";
import * as icons from "./icons";
import { User } from "./UserList";
import { SignalType } from "@/lib/signals";
import { ProgressBar } from './ProgressBar';
import Linkify from 'linkify-react';

export interface Message {
  id: string;
  content: string;
  sender: string;
  timestamp: Date;
  isCurrentUser: boolean;
  isSystemMessage?: boolean;
  type?: SignalType;
  filename?: string;
  fileSize?: number;
}

interface ChatMessageProps {
  message: Message;
}

const IMAGE_EXTENSIONS = ["jpg", "jpeg", "png", "gif", "webp"];
const VIDEO_EXTENSIONS = ["mp4", "webm", "ogg"];
const AUDIO_EXTENSIONS = ["mp3", "wav", "ogg", "m4a"];

function hasExtension(filename: string, extensions: string[]) {
  const regex = new RegExp(`\\.(${extensions.join("|")})$`, "i");
  return regex.test(filename);
}


export function ChatMessage({ message }: ChatMessageProps) {
  const { content, sender, timestamp, isCurrentUser, isSystemMessage } = message;

  if (isSystemMessage) {
    return (
      <div className="flex items-center justify-center my-2">
        <div className="bg-muted text-muted-foreground text-xs rounded-full px-3 py-1">
          {content}
        </div>
      </div>
    );
  }

  if (message.type === SignalType.FILE_MESSAGE) {
  return (
    <div
      className={cn(
        "flex items-start gap-2 mb-4",
        message.isCurrentUser ? "flex-row-reverse" : ""
      )}
    >
      <Avatar className="w-8 h-8">
        <AvatarFallback
          className={cn(
            isCurrentUser ? "bg-blue-500 text-white" : "bg-muted"
          )}
        >
          {sender.charAt(0).toUpperCase()}
        </AvatarFallback>
      </Avatar>
      <div
        className={cn(
          "flex flex-col",
          message.isCurrentUser ? "items-end" : "items-start"
        )}
      >
        <div className="flex items-center gap-2 mb-1">
          <span className="text-sm font-medium">{sender}</span>
          <span className="text-xs text-muted-foreground">
            {format(timestamp, "h:mm a")}
          </span>
        </div>

        {hasExtension(message.filename || "", IMAGE_EXTENSIONS) && (
          <div
            className={cn(
              "rounded-lg px-0 py-0 text-sm max-w-[60%] break-words","bg-muted"
            )}
          >
            <div className="relative group">
              <img
                src={message.content}
                alt={message.filename}
                className="max-w-full rounded-md"
              />
              <a
                href={message.content}
                download={message.filename}
                className="absolute top-2 right-2 bg-white p-1 rounded-full shadow hidden group-hover:block"
                aria-label={`Download ${message.filename}`}
              >
                <icons.DownloadIcon />
              </a>
            </div>
          </div>
        )}

        {hasExtension(message.filename || "", VIDEO_EXTENSIONS) && (
          <div
            className={cn(
              "rounded-lg text-sm max-w-[60%] break-words",
              message.isCurrentUser
                ? "bg-primary text-primary-foreground"
                : "bg-muted"
            )}
          >
            <div className="flex flex-col gap-2">
              <video controls className="max-w-full rounded-md">
                <source src={message.content} />
                Your browser does not support the video tag.
              </video>

              <div className="flex items-center gap-2 text-sm">
                <span className="font-medium break-all ml-1 mb-1">{message.filename}</span>
                <span className="text-xs text-muted-foreground">
                  ({formatFileSize(message.fileSize ?? 0)})
                </span>
                <a
                  href={message.content}
                  download={message.filename}
                  className="text-blue-500 hover:text-blue-700"
                  title="Download"
                >
                  <icons.DownloadIcon className="w-5 h-5 hover:scale-110 transition-transform duration-1 ease-in-out" />
                </a>
              </div>
            </div>
          </div>
        )}

        {hasExtension(message.filename || "", AUDIO_EXTENSIONS) && (
          <div
            className={cn(
              "rounded-lg mr-1 py-0 text-sm max-w-[75%] break-words",
              message.isCurrentUser
                ? "bg-primary text-primary-foreground"
                : "bg-muted"
            )}
          >
            <div className="flex flex-col gap-1">
              <audio controls className="w-full rounded-md">
                <source src={message.content} />
                Your browser does not support the audio element.
              </audio>
              <div className="flex justify-between items-center gap-1 text-sm text-blue-500">
                <span className="truncate max-w-[250px] ml-1" title={message.filename}>
                  {message.filename}
                </span>
                <a           
                  href={message.content}
                  download={message.filename}
                  title="Download"
                  aria-label={`Download ${message.filename}`}
                 >
                  <icons.DownloadIcon className="w-5 h-5 hover:scale-110 transition-transform duration-1 ease-in-out" />
                </a>
              </div>
              <span className="text-xs text-muted-foreground">
                ({formatFileSize(message.fileSize ?? 0)})
              </span>
            </div>
          </div>
        )}

        {!hasExtension(message.filename || "", [...IMAGE_EXTENSIONS, ...VIDEO_EXTENSIONS, ...AUDIO_EXTENSIONS]) && (
          <div
            className={cn(
              "rounded-lg px-1 py-1 text-sm max-w-[60%] break-words",
              message.isCurrentUser
                ? "bg-primary text-primary-foreground"
                : "bg-muted"
            )}
          >
            <div className="flex items-start gap-2 w-full text-blue-500">
              <icons.PaperclipIcon className="h-5 w-5 shrink-0 mt-1" />
              <div className="flex flex-col min-w-0">
                <div className="flex justify-between items-center gap-2">
                  <span
                    className="text-sm truncate max-w-[250px] w-full"
                    title={message.filename}
                  >
                    {message.filename}
                  </span>
                  <a
                    href={message.content}
                    download={message.filename}
                    title="Download"
                    aria-label={`Download ${message.filename}`}
                  >
                  <icons.DownloadIcon className="w-5 h-5 hover:scale-110 transition-transform duration-1 ease-in-out" />
                  </a>
                </div>
                <span className="text-xs text-muted-foreground leading-tight">
                  ({formatFileSize(message.fileSize ?? 0)})
                </span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

return (
  <div
    className={cn(
      "flex items-start gap-2 mb-4",
      isCurrentUser ? "flex-row-reverse" : ""
    )}
  >
    <Avatar className="w-8 h-8">
      <AvatarFallback
        className={cn(
          isCurrentUser ? "bg-blue-500 text-white" : "bg-muted"
        )}
      >
        {sender.charAt(0).toUpperCase()}
      </AvatarFallback>
    </Avatar>

    <div
      className={cn(
        "flex flex-col min-w-0",
        isCurrentUser ? "items-end" : "items-start"
      )}
      style={{ maxWidth: "75%" }}
    >
      <div className="flex items-center gap-2 mb-1">
        <span className="text-sm font-medium">{sender}</span>
        <span className="text-xs text-muted-foreground">
          {format(timestamp, "h:mm a")}
        </span>
      </div>

      <div
        className={cn(
          "rounded-lg px-3 py-2 text-sm min-w-[5rem] whitespace-pre-wrap break-words",
          isCurrentUser ? "bg-primary text-primary-foreground" : "bg-muted"
        )}
        style={{ wordBreak: "break-word", whiteSpace: "pre-wrap" }}
      >
        <Linkify options={{ target: '_blank', rel: 'noopener noreferrer' }}>
          {content}
        </Linkify>
      </div>
    </div>
  </div>
);

}

function formatFileSize(bytes: number) {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}
