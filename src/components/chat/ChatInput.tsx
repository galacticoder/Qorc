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

  const handleFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    if (!users || users.length === 0) {
      console.error("No users available to send the file.");
      return;
    }

    try {
      console.log("File size in bytes:", file.size);
      const arrayBuffer = await file.arrayBuffer();
      // const compressed = pako.deflate(new Uint8Array(arrayBuffer));
      
      
      const aesKey = await crypto.generateAESKey();
      
      const { iv, authTag, encrypted } = await crypto.encryptBinaryWithAES(arrayBuffer, aesKey);

      console.log(`encrypted: ${encrypted}`)
      console.log(`encrypted size: ${encrypted.size}`)
      const encryptedData = crypto.serializeEncryptedData(iv, authTag, encrypted);
      console.log(`encrypteddata: ${encryptedData}`)
      console.log(`encrypteddata size after serilization: ${encryptedData.size}`)
      
      const rawAes = await window.crypto.subtle.exportKey("raw", aesKey);
      
      for (const user of users) {
        if (user.username === currentUsername || !user.publicKey) continue;
        
        const recipientKey = await crypto.importPublicKeyFromPEM(user.publicKey);
        const encryptedAes = await crypto.encryptWithRSA(rawAes, recipientKey);
        const encryptedAESKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedAes)));
        
        const payload = {
          type: SignalType.FILE_MESSAGE,
          from: currentUsername,
          to: user.username,
          encryptedAESKey: encryptedAESKeyBase64,
          encryptedFile: encryptedData,
          filename: file.name,
        };
        
        console.log("File payload to send:", JSON.stringify(payload, null, 2));

        wsClient.send(JSON.stringify(payload));
      }
    } catch (error) {
      console.error("Failed to process and send file:", error);
    }
  };


  return (
    <div className="flex items-end gap-2 p-4 border-t bg-background">
      {isEncrypted && (
        <div className="flex items-center text-xs gap-1 text-green-600 mb-2">
          <LockClosedIcon className="h-3 w-3" />
          <span>End-to-end encrypted</span>
        </div>
      )}
      <div className="flex items-end gap-2 flex-1">
        {/* File Upload Button */}
        <Button
          variant="ghost"
          size="icon"
          className="h-10 w-10 rounded-full"
          type="button"
          onClick={() => fileInputRef.current?.click()}
        >
          <PaperclipIcon className="h-4 w-4" />
        </Button>
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          onChange={handleFileChange}
        />

        <Textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Type a message..."
          className="min-h-10 resize-none"
          rows={1}
        />
      </div>
      <Button
        onClick={handleSend}
        size="icon"
        disabled={!message.trim() || isSending}
        className={cn(
          "h-10 w-10 rounded-full",
          isSending && "opacity-50 cursor-not-allowed"
        )}
      >
        <PaperPlaneIcon className="h-4 w-4" />
      </Button>
    </div>
  );
}
