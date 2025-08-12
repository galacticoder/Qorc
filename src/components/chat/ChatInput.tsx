import { useState, useRef, useEffect } from "react";
import { Button } from "../ui/button";
import { Textarea } from "../ui/textarea";
import { PaperPlaneIcon, LockClosedIcon } from "@radix-ui/react-icons";
import { PaperclipIcon } from "./icons";
import * as cm from "./ChatMessage";
import { cn } from "@/lib/utils";
import { User } from "./UserList";
import { SignalType } from "../../lib/signals";
import { ProgressBar } from "./ProgressBar";
import { Message } from "./ChatMessage";

import { EditingBanner } from "./ChatInput/EditingBanner";
import { ReplyBanner } from "./ChatInput/ReplyBanner";
import { useFileSender } from "./ChatInput/useFileSender";

interface ChatInputProps {
  onSendMessage: (message: string, replyTo?: cm.Message | null) => void;
  onSendFile: (fileData: any) => void;
  isEncrypted: boolean;
  currentUsername: string;
  users: User[];
  replyTo: cm.Message | null;
  onCancelReply: () => void;
  editingMessage?: Message | null;
  onCancelEdit?: () => void;
  onEditMessage?: (newContent: string) => void;
}

export function ChatInput({
  onSendMessage,
  onSendFile,
  isEncrypted,
  currentUsername,
  users,
  replyTo,
  onCancelReply,
  editingMessage,
  onCancelEdit,
  onEditMessage,
}: ChatInputProps) {
  const [message, setMessage] = useState("");
  const [isSending, setIsSending] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const { sendFile, progress, isSendingFile } = useFileSender(currentUsername, users);

  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
      textareaRef.current.style.height = Math.min(textareaRef.current.scrollHeight, 120) + "px";
    }
  }, [message]);

  useEffect(() => {
    if (editingMessage) {
      setMessage(editingMessage.content);
      textareaRef.current?.focus();
    }
  }, [editingMessage]);

  async function handleSend() {
    if (!message.trim() || isSending) return;

    try {
      setIsSending(true);
      console.log("send msg")
      if (editingMessage && onEditMessage) {
        console.log("edit")
        await onEditMessage(message.trim());
        onCancelEdit?.();
      } else {
        console.log("reply")
        await onSendMessage(message.trim(), replyTo);
        onCancelReply?.();
      }
      setMessage("");
    } catch (e) {
      console.error("Failed to send message:", e);
    } finally {
      setIsSending(false);
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      await sendFile(file);
      const fileUrl = URL.createObjectURL(file);
      onSendFile({
        id: crypto.randomUUID(),
        content: fileUrl,
        timestamp: new Date(),
        isCurrentUser: true,
        isSystemMessage: false,
        type: SignalType.FILE_MESSAGE,
        filename: file.name,
        fileSize: file.size,
        sender: currentUsername,
      });
    } catch (error) { //in hook already handled
    } finally {
      e.target.value = "";
    }
  };

  return (
    <div className={cn("relative border-t", "bg-white border-slate-200")}>
      {editingMessage && <EditingBanner onCancelEdit={onCancelEdit} />}
      {replyTo && <ReplyBanner replyTo={replyTo} onCancelReply={onCancelReply} />}

      {progress > 0 && progress < 1 && (
        <div className="px-4 pt-2">
          <ProgressBar progress={progress} />
        </div>
      )}

      <div className="p-4">
        <div
          className={cn(
            "flex items-end gap-3 rounded-2xl border shadow-sm transition-all duration-200",
            "bg-slate-50 border-slate-200 focus-within:border-slate-400"
          )}
        >
          <div className="flex-shrink-0 p-2">
            <Button
              variant="ghost"
              size="sm"
              className={cn(
                "h-10 w-10 rounded-full transition-all duration-200",
                isSendingFile && "opacity-50 cursor-not-allowed",
                "hover:bg-slate-200 text-slate-500 hover:text-slate-700"
              )}
              onClick={() => !isSendingFile && fileInputRef.current?.click()}
              disabled={isSendingFile}
              type="button"
            >
              <PaperclipIcon className="h-5 w-5" />
            </Button>
            <input ref={fileInputRef} type="file" className="hidden" onChange={handleFileChange} />
          </div>

          <Textarea
            ref={textareaRef}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Type a message..."
            className={cn(
              "min-h-[39px] max-h-[100px] resize-none border-0 bg-transparent px-0 py-2 text-sm",
              "focus-visible:ring-0 focus-visible:ring-offset-0",
              "text-slate-900 placeholder:text-slate-500"
            )}
            rows={1}
          />

          <Button
            onClick={handleSend}
            size="sm"
            disabled={!message.trim() || isSending}
            className={cn(
              "h-10 w-10 rounded-full text-white shadow-md transition-all duration-200",
              (!message.trim() || isSending) ? "opacity-50 cursor-not-allowed bg-gray-400" :
              editingMessage ? "bg-yellow-500 hover:bg-yellow-600" : "bg-slate-600 hover:bg-slate-700"
            )}
          >
            {isSending ? (
              <svg className="h-5 w-5 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
            ) : editingMessage ? (
              <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
              </svg>
            ) : (
              <PaperPlaneIcon className="h-5 w-5" />
            )}
          </Button>
        </div>

        {isEncrypted && (
          <div className={cn("flex items-center gap-1 mt-2 text-xs", "text-slate-500")}>
            <LockClosedIcon className="h-3 w-3" />
            <span>End-to-end encrypted</span>
          </div>
        )}
      </div>
    </div>
  );
}
