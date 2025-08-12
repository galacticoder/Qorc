import { useState, useRef, useEffect } from "react";
import { cn } from "@/lib/utils";
import { User } from "./UserList";
import { SignalType } from "../../lib/signals";
import { Message } from "./types";
import { EditingBanner } from "./ChatInput/EditingBanner";
import { ReplyBanner } from "./ChatInput/ReplyBanner";

import { LockClosedIcon } from "./icons.tsx";
import { useFileSender } from "./ChatInput/useFileSender";
import { ProgressBar } from "./ChatInput/ProgressBar.tsx";

import { FileUploader } from "./ChatInput/FileUploader.tsx";
import { MessageTextarea } from "./ChatInput/MessageTextarea.tsx";
import { SendButton } from "./ChatInput/SendButton.tsx";

interface ChatInputProps {
  onSendMessage: (message: string, replyTo?: Message | null) => void;
  onSendFile: (fileData: any) => void;
  isEncrypted: boolean;
  currentUsername: string;
  users: User[];
  replyTo: Message | null;
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
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const { sendFile, progress, isSendingFile } = useFileSender(currentUsername, users);

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
      if (editingMessage && onEditMessage) {
        await onEditMessage(message.trim());
        onCancelEdit?.();
      } else {
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

  const handleFileChange = async (file: File) => {
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
    } catch {
      // error handled in hook
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
          <FileUploader onFileSelected={handleFileChange} disabled={isSendingFile} />

          <MessageTextarea
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            onKeyDown={handleKeyDown}
            textareaRef={textareaRef}
          />

          <SendButton
            disabled={!message.trim() || isSending}
            isSending={isSending}
            editingMessage={editingMessage}
            onClick={handleSend}
          />
        </div>
      </div>
    </div>
  );
}
