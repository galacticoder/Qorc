import { useState, useRef, useEffect } from "react";
import { Button } from "../ui/button";
import { Textarea } from "../ui/textarea";
import { PaperPlaneIcon, LockClosedIcon, Cross2Icon } from "@radix-ui/react-icons";
import { PaperclipIcon } from "./icons";
import * as cm from "./ChatMessage"
import * as pako from "pako";
import wsClient from '@/lib/websocket';
import { CryptoUtils } from "@/lib/unified-crypto";
import { SignalType } from "@/lib/signals";
import { cn } from "@/lib/utils";
import { User } from "./UserList";
import { ProgressBar } from './ProgressBar';
import { Message } from "./ChatMessage";

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
  const lastTypingTime = useRef<number>(0);
  const typingTimeout = 2000;

  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = Math.min(textareaRef.current.scrollHeight, 120) + 'px';
    }
  }, [message]);

  const handleSend = async () => {
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
    } catch (error) {
      console.error("Failed to send message:", error);
    } finally {
      setIsSending(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const CHUNK_SIZE = 256 * 1024;
  const [progress, setProgress] = useState(0);
  const [isSendingFile, setIsSendingFile] = useState(false);
  
  const handleFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    
    if (!file) return;
    if (!users || users.length === 0) return;

    try {
      setIsSendingFile(true);
      setProgress(0);

      const arrayBuffer = await file.arrayBuffer();
      const rawBytes = new Uint8Array(arrayBuffer);

      const aesKey = await CryptoUtils.Keys.generateAESKey();
      const rawAes = await window.crypto.subtle.exportKey("raw", aesKey);

      const userKeys = await Promise.all(
        users
          .filter(user => user.username !== currentUsername && user.publicKey)
          .map(async user => {
            const recipientKey = await CryptoUtils.Keys.importPublicKeyFromPEM(user.publicKey);
            const encryptedAes = await CryptoUtils.Encrypt.encryptWithRSA(rawAes, recipientKey);
            return {
              username: user.username,
              encryptedAESKeyBase64: btoa(String.fromCharCode(...new Uint8Array(encryptedAes))),
            };
          })
      );

      const totalChunks = Math.ceil(rawBytes.length / CHUNK_SIZE);
      const totalBytes = rawBytes.length * userKeys.length;
      let bytesSent = 0;

      for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
        const start = chunkIndex * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, rawBytes.length);
        const chunk = rawBytes.slice(start, end);

        const compressedChunk = pako.deflate(chunk);

        console.log(`Chunk ${chunkIndex + 1}: Original = ${chunk.length} bytes, Compressed = ${compressedChunk.length} bytes`);

        const { iv, authTag, encrypted } = await CryptoUtils.Encrypt.encryptBinaryWithAES(compressedChunk.buffer, aesKey);

        const serializedChunk = CryptoUtils.Encrypt.serializeEncryptedData(iv, authTag, encrypted);
        const chunkDataBase64 = btoa(String.fromCharCode(...Uint8Array.from(atob(serializedChunk), c => c.charCodeAt(0))));

        for (const userKey of userKeys) {
          const payload = {
            type: SignalType.FILE_MESSAGE_CHUNK,
            from: currentUsername,
            to: userKey.username,
            encryptedAESKey: userKey.encryptedAESKeyBase64,
            chunkIndex,
            totalChunks,
            chunkData: chunkDataBase64,
            filename: file.name,
            isLastChunk: chunkIndex === totalChunks - 1,
          };

          wsClient.send(JSON.stringify(payload));
        }

        bytesSent += chunk.length * userKeys.length;
        const progressValue = bytesSent / totalBytes;
        setProgress(progressValue);

      }

      setProgress(1);
      console.log("File sent.");

      const fileUrl = URL.createObjectURL(file);

      const payload: cm.Message =
        {
          id: crypto.randomUUID(),
          content: fileUrl,
          timestamp: new Date(),
          isCurrentUser: true,
          isSystemMessage: false,
          type: SignalType.FILE_MESSAGE,
          filename: file.name,
          fileSize: file.size,
          sender: currentUsername 
        }
        onSendFile(payload);
    } catch (error) {
      console.error("Failed to process and send file:", error);
    } finally {
      setIsSendingFile(false);
      event.target.value = "";
    }
  };

  useEffect(() => {
    if (editingMessage) {
      setMessage(editingMessage.content);
      textareaRef.current?.focus();
    }
  }, [editingMessage]);


  return (
    <div className={cn("relative border-t", "bg-white border-slate-200")}>
      {editingMessage && (
        <div className="px-4 pt-3 pb-0">
          <div className={cn(
            "flex items-center justify-between p-3 border-l-4 rounded-lg shadow-sm", 
            "bg-gradient-to-r from-yellow-50 to-yellow-100 border-yellow-400 text-yellow-900"
          )}>
            <span className="text-sm font-medium">Editing message</span>
            <Button
              variant="ghost"
              size="sm"
              className="h-8 w-8 p-0 text-yellow-600 hover:text-yellow-800"
              onClick={onCancelEdit}
            >
              <Cross2Icon className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}

      {replyTo && (
        <div className="px-4 pt-3 pb-0">
          <div className={cn(
            "flex items-start gap-3 p-3 border-l-4 rounded-lg shadow-sm transition-colors duration-200", "bg-gradient-to-r from-slate-50 to-slate-100 border-slate-400 text-slate-900"
          )}>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <svg className={cn("w-4 h-4", "text-slate-500")} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6" />
                </svg>
                <span className={cn("text-sm font-semibold", "text-slate-700")}>{replyTo.sender}</span>
              </div>
              <p className={cn("text-sm line-clamp-2", "text-slate-600")}>
                {replyTo.content.slice(0, 100)}
                {replyTo.content.length > 100 && "..."}
              </p>
            </div>
            <Button
              variant="ghost"
              size="sm"
              className={cn(
                "h-8 w-8 p-0 transition-colors", "hover:bg-slate-200 text-slate-500 hover:text-slate-700"
              )}
              onClick={onCancelReply}
            >
              <Cross2Icon className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}

      {progress > 0 && progress < 1 && (
        <div className="px-4 pt-2">
          <ProgressBar progress={progress} />
        </div>
      )}

      <div className="p-4">
        <div className={cn(
          "flex items-end gap-3 rounded-2xl border shadow-sm transition-all duration-200", "bg-slate-50 border-slate-200 focus-within:border-slate-400"
        )}>
          {/* file Upload Button */}
          <div className="flex-shrink-0 p-2">
            <Button
              variant="ghost"
              size="sm"
              className={cn(
                "h-10 w-10 rounded-full transition-all duration-200",
                isSendingFile && "opacity-50 cursor-not-allowed", "hover:bg-slate-200 text-slate-500 hover:text-slate-700"
              )}
              type="button"
              onClick={() => !isSendingFile && fileInputRef.current?.click()}
              disabled={isSendingFile}
            >
              <PaperclipIcon className="h-5 w-5" />
            </Button>
            <input
              ref={fileInputRef}
              type="file"
              className="hidden"
              onChange={handleFileChange}
            />
          </div>

          {/* textarea */}
          <div className="flex-1 py-2">
            <Textarea
              ref={textareaRef}
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Type a message..."
              className={cn(
                "min-h-[39px] max-h-[100px] resize-none border-0 bg-transparent px-0 py-2 text-sm focus-visible:ring-0 focus-visible:ring-offset-0", "text-slate-900 placeholder:text-slate-500"
              )}
              rows={1}
            />
          </div>

          {/* send Button */}
          <Button
            onClick={handleSend}
            size="sm"
            disabled={!message.trim() || isSending}
            className={cn(
              "h-10 w-10 rounded-full text-white shadow-md transition-all duration-200",
              (!message.trim() || isSending) && "opacity-50 cursor-not-allowed bg-gray-400",
              message.trim() && !isSending && editingMessage ? "bg-yellow-500 hover:bg-yellow-600" : "bg-slate-600 hover:bg-slate-700"
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

        {/* encryption indicator */}
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