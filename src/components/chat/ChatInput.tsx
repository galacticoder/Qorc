import { useState, useRef, useEffect } from "react";
import { Button } from "../ui/button";
import { Textarea } from "../ui/textarea";
import { PaperPlaneIcon, LockClosedIcon } from "@radix-ui/react-icons";
import { PaperclipIcon } from "./icons";
import * as pako from "pako";
import wsClient from '@/lib/websocket';
import * as crypto from "@/lib/unified-crypto";
import { SignalType } from "@/lib/signals";
import { cn } from "@/lib/utils";
import { User } from "./UserList";
import { ProgressBar } from './ProgressBar';


interface ChatInputProps {
  onSendMessage: (message: string) => void;
  onSendFile: (fileData: any) => void;
  onTyping: () => void;
  isEncrypted: boolean;
  currentUsername: string;
  users: User[];
}


export function ChatInput({
  onSendMessage,
  onSendFile,
  onTyping,
  isEncrypted,
  currentUsername,
  users,
}: ChatInputProps) {
  const [message, setMessage] = useState("");
  const [isSending, setIsSending] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const lastTypingTime = useRef<number>(0);
  const typingTimeout = 2000;

  useEffect(() => {
    const currentTime = Date.now();
    if (message && currentTime - lastTypingTime.current > typingTimeout) {
      lastTypingTime.current = currentTime;
      onTyping();
    }
  }, [message, onTyping]);

  const handleSend = async () => {
    if (!message.trim() || isSending) return;

    try {
      setIsSending(true);
      await onSendMessage(message.trim());
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

  const CHUNK_SIZE = 128 * 1024;
  const [progress, setProgress] = useState(0);
  const [isSendingFile, setIsSendingFile] = useState(false);
  
  const handleFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    if (isSendingFile) {
      console.warn("A file is already being sent.");
      return;
    }

    const file = event.target.files?.[0];
    if (!file) return;

    if (!users || users.length === 0) {
      console.error("No users available to send the file.");
      return;
    }

    try {
      setIsSendingFile(true);
      setProgress(0);

      const arrayBuffer = await file.arrayBuffer();
      const rawBytes = new Uint8Array(arrayBuffer);

      const aesKey = await crypto.generateAESKey();
      const rawAes = await window.crypto.subtle.exportKey("raw", aesKey);

      const userKeys = await Promise.all(
        users
          .filter(user => user.username !== currentUsername && user.publicKey)
          .map(async user => {
            const recipientKey = await crypto.importPublicKeyFromPEM(user.publicKey);
            const encryptedAes = await crypto.encryptWithRSA(rawAes, recipientKey);
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

        const { iv, authTag, encrypted } = await crypto.encryptBinaryWithAES(chunk.buffer, aesKey);

        const serializedChunk = crypto.serializeEncryptedData(iv, authTag, encrypted);
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
    } catch (error) {
      console.error("Failed to process and send file:", error);
    } finally {
      setIsSendingFile(false);
      event.target.value = "";
    }
  };


 return (
  <div className="flex flex-col p-4 border-t bg-background">
    {progress > 0 && progress < 1 && <ProgressBar progress={progress} />}

    <div className="flex items-center gap-2">
      {/* File Upload Button */}
      <Button
        variant="ghost"
        size="icon"
        className="h-8 w-8 rounded-full"
        type="button"
        onClick={() => !isSendingFile && fileInputRef.current?.click()}
        disabled={isSendingFile}
      >
        <PaperclipIcon className="h-4 w-4" />
      </Button>

      <input
        ref={fileInputRef}
        type="file"
        className="hidden"
        onChange={handleFileChange}
      />

      {/* Textarea */}
      <Textarea
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="Type a message..."
        className="min-h-[32px] resize-none flex-grow rounded-md border border-gray-300 px-2 py-1 text-sm"
        rows={1}
      />

      {/* Send Button */}
      <Button
        onClick={handleSend}
        size="icon"
        disabled={!message.trim() || isSending}
        className={cn(
          "h-8 w-8 rounded-full",
          isSending && "opacity-50 cursor-not-allowed"
        )}
      >
        <PaperPlaneIcon className="h-4 w-4" />
      </Button>
    </div>
  </div>
);}
