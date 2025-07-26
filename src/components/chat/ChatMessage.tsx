import { cn } from "@/lib/utils";
import { Avatar, AvatarFallback } from "../ui/avatar";
import { format } from "date-fns";
import { PaperclipIcon } from "./icons";
import { User } from "./UserList";
import { SignalType } from "@/lib/signals";
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

          <div
            className={cn(
              "rounded-lg px-3 py-2 text-sm max-w-[75%] break-words",
              message.isCurrentUser
                ? "bg-primary text-primary-foreground"
                : "bg-muted"
            )}
          >
            {hasExtension(message.filename || "", IMAGE_EXTENSIONS) ? (
              <img
                src={message.content}
                alt={message.filename}
                className="max-w-full rounded-md"
              />
            ) : hasExtension(message.filename || "", VIDEO_EXTENSIONS) ? (
              <video controls className="max-w-full rounded-md">
                <source src={message.content} />
                Your browser does not support the video tag.
              </video>
            ) : (
              <a
                href={message.content}
                download={message.filename}
                className="flex items-start gap-2 w-full text-blue-500"
              >
                <PaperclipIcon className="h-5 w-5 shrink-0 mt-1" />

                <div className="flex flex-col min-w-0">
                  <span
                    className="text-sm truncate max-w-[300px] w-full"
                    title={message.filename}
                  >
                    {message.filename}
                  </span>

                  <span className="text-xs text-muted-foreground leading-tight">
                    ({formatFileSize(message.fileSize ?? 0)})
                  </span>
                </div>
              </a>



            )}
          </div>
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
