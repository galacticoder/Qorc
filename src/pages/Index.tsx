import { useState, useEffect, useRef, useCallback } from "react";
import { Login } from "@/components/chat/Login";
import { UserList, User } from "@/components/chat/UserList";
import { ChatInterface } from "@/components/chat/ChatInterface";
import { Message } from "@/components/chat/ChatMessage";
import { useLocalStorage } from "@/hooks/use-local-storage";
import { 
  generateRSAKeyPair,
  exportPublicKeyToPEM, 
  exportPrivateKeyToPEM,
  importPublicKeyFromPEM,
  importPrivateKeyFromPEM,
  importAESKey,
  generateAESKey,
  deserializeEncryptedDataFromUint8Array,
  encryptWithAES,
  decryptWithAES,
  decryptWithAESRaw,
  encryptWithRSA,
  decryptWithRSA,
  serializeEncryptedData,
  deserializeEncryptedData,
  uint8ToBase64,
  base64ToArrayBuffer,
  decryptAESKeyWithRSA,
  decryptMessage
} from "@/lib/unified-crypto";
import websocketClient from "@/lib/websocket";
import { SignalType } from "@/lib/signals";
import { v4 as uuidv4 } from 'uuid';
import * as pako from "pako";
import { Console } from "console";


interface MessageData {
  type: SignalType;
  message: string;
}



const SERVER_ID = 'SecureChat-Server';

export default function Index() {
  // User state
  const [username, setUsername] = useState<string>("");
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [isGeneratingKeys, setIsGeneratingKeys] = useState(false);
  const [loginError, setLoginError] = useState<string>("");
  
  // Encryption keys
  const [privateKeyPEM, setPrivateKeyPEM] = useLocalStorage<string>("private_key", "");
  const [publicKeyPEM, setPublicKeyPEM] = useLocalStorage<string>("public_key", "");
  const privateKeyRef = useRef<CryptoKey | null>(null);
  const publicKeyRef = useRef<CryptoKey | null>(null);
  const aesKeyRef = useRef<CryptoKey | null>(null);
  
  // Users and messages
  const [users, setUsers] = useState<User[]>([]);
  const [messages, setMessages] = useState<Message[]>([]);
  
  const decryptServerAESEncryptedData = useCallback(async (
    encryptedData: string, 
    aesKey: CryptoKey
  ): Promise<string> => {
    const combined = new Uint8Array(
      window.atob(encryptedData).split('').map(c => c.charCodeAt(0))
    );
    
    const ivLength = combined[0];
    const iv = combined.slice(1, 1 + ivLength);
    const authTagLength = combined[1 + ivLength];
    const authTag = combined.slice(1 + ivLength + 1, 1 + ivLength + 1 + authTagLength);
    const encryptedContent = combined.slice(1 + ivLength + 1 + authTagLength);
    
    const dataForDecryption = new Uint8Array(
      encryptedContent.length + authTag.length
    );
    dataForDecryption.set(encryptedContent);
    dataForDecryption.set(authTag, encryptedContent.length);
    
    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv,
        tagLength: 128
      },
      aesKey,
      dataForDecryption
    );
    
    return new TextDecoder().decode(decrypted);
  }, []);

  // const handleFileMessage = async (payload: any, message: any) => {
  //   try {
  //     console.log("File has been received. Decrypting...")
  //     if (!privateKeyRef.current) {
  //       throw new Error("Private key is not available");
  //     }

  //     console.log("📥 Received file metadata:");
  //     console.log("Filename:", payload.filename);
  //     console.log("Sender:", message.from);
  //     console.log("Timestamp:", payload.timestamp || Date.now());
  //     console.log("Encrypted AES Key:", payload.encryptedAESKey);
  //     console.log("Encrypted File Data (string length):", payload.encryptedFile.length);

  //     console.log("step 1")
  //     const decryptedAESKey = await decryptWithRSA(
  //       base64ToArrayBuffer(payload.encryptedAESKey),
  //       privateKeyRef.current
  //     );
  //     // then:
  //     await importAESKey(decryptedAESKey)


  //     console.log("step 2")
      
  //     const { iv, authTag, encrypted } = deserializeEncryptedData(payload.encryptedFile);
  //     console.log("step 3")
      
  //     const decrypted = await decryptWithAESRaw(
  //       new Uint8Array(encrypted),
  //       new Uint8Array(iv),
  //       new Uint8Array(authTag),
  //       await importAESKey(decryptedAESKey)
  //     );

  //     console.log("Decrypted ArrayBuffer byteLength:", decrypted.byteLength);
      
  //     console.log("step 4")
  //     // const decompressed = pako.inflate(new Uint8Array(decrypted));
      
  //     // if (!decompressed) {
  //     //   throw new Error("Failed to decompress file data.");
  //     // }
  //     console.log("step 5")
      
  //     // const blob = new Blob([decompressed], { type: "application/octet-stream" });
      
  //     // const downloadLink = document.createElement("a");
  //     // downloadLink.href = URL.createObjectURL(blob);
  //     // downloadLink.download = payload.filename || "downloaded_file";
  //     // downloadLink.click();

      
  //     const blob = new Blob([decrypted], { type: "application/octet-stream" });
  //     const fileUrl = URL.createObjectURL(blob);

  //     // Remove auto-download
  //     // const downloadLink = document.createElement("a");
  //     // downloadLink.href = fileUrl;
  //     // downloadLink.download = payload.filename || "downloaded_file";
  //     // downloadLink.click();

  //     console.log("step 6");

  //     setMessages(prev => [
  //       ...prev,
  //       {
  //         id: uuidv4(),
  //         content: fileUrl,
  //         sender: message.from,
  //         timestamp: new Date(payload.timestamp || Date.now()),
  //         isCurrentUser: false,
  //         isSystemMessage: false,
  //         type: SignalType.FILE_MESSAGE,
  //         filename: payload.filename,
  //         fileSize: blob.size
  //       }
  //     ]);


  //   } catch (err) {
  //     console.error("Error handling FILE_MESSAGE:", err);
  //   }
  // };

  const incomingFileChunksRef = useRef<{
    [key: string]: {
      decryptedChunks: Blob[],
      totalChunks: number,
      encryptedAESKey: string,
      filename: string,
      aesKey?: CryptoKey;
      receivedCount: number
    }
  }>({});

  const [fileProgressMap, setFileProgressMap] = useState<{ [fileKey: string]: number }>({});

  const handleFileMessageChunk = async (payload: any, message: any) => {
    try {
      const { from } = message;
      const {
        chunkIndex,
        totalChunks,
        chunkData,
        encryptedAESKey,
        filename
      } = payload;

      const fileKey = `${from}-${filename}`;

      let fileEntry = incomingFileChunksRef.current[fileKey];
      if (!fileEntry) {
        fileEntry = {
          decryptedChunks: new Array(totalChunks),
          totalChunks,
          encryptedAESKey,
          filename,
          receivedCount: 0
        };
        incomingFileChunksRef.current[fileKey] = fileEntry;
      }

      const encryptedBytes = Uint8Array.from(atob(chunkData), c => c.charCodeAt(0));

      const { iv, authTag, encrypted } = deserializeEncryptedDataFromUint8Array(encryptedBytes);

      if (!fileEntry.aesKey) {
        const decryptedAESKeyBytes = await decryptWithRSA(
          base64ToArrayBuffer(fileEntry.encryptedAESKey),
          privateKeyRef.current
        );

        const aesKey = await importAESKey(decryptedAESKeyBytes);
        fileEntry.aesKey = aesKey;
      }

      const decryptedChunk = await decryptWithAESRaw(
        new Uint8Array(encrypted),
        new Uint8Array(iv),
        new Uint8Array(authTag),
        fileEntry.aesKey
      );

      fileEntry.decryptedChunks[chunkIndex] = new Blob([decryptedChunk]);
      fileEntry.receivedCount++;

      const progress = fileEntry.receivedCount / fileEntry.totalChunks;

      setFileProgressMap(prev => ({
        ...prev,
        [fileKey]: progress
      }));

      console.log(`File ${filename} progress: ${(progress * 100).toFixed(2)}%`);

      console.log(`Received and decrypted chunk ${chunkIndex + 1}/${totalChunks} for ${filename} from ${from}`);

      if (fileEntry.receivedCount === totalChunks) {
        const fileBlob = new Blob(fileEntry.decryptedChunks, { type: "application/octet-stream" });
        const fileUrl = URL.createObjectURL(fileBlob);

        setMessages(prev => [
          ...prev,
          {
            id: uuidv4(),
            content: fileUrl,
            sender: from,
            timestamp: new Date(),
            isCurrentUser: false,
            isSystemMessage: false,
            type: SignalType.FILE_MESSAGE,
            filename,
            fileSize: fileBlob.size
          }
        ]);

        delete incomingFileChunksRef.current[fileKey];
        console.log(`File ${filename} from ${from} fully reassembled and available.`);
      }
    } catch (err) {
      console.error("Error handling FILE_MESSAGE_CHUNK:", err);
    }
  };
  
  const handleEncryptedMessageObject = useCallback(async (message: any) => {
    try {
      if (!privateKeyRef.current) {
        throw new Error("Private key not available for decryption");
      }

      if (message.from === SERVER_ID) {
        console.log("Server message received. Starting decryption");
        const encryptedAesKey = base64ToArrayBuffer(message.encryptedAESKey);
        const decryptedAesKey = await decryptWithRSA(encryptedAesKey, privateKeyRef.current);

        const aesKey = await window.crypto.subtle.importKey(
          "raw",
          decryptedAesKey,
          { name: "AES-GCM" },
          true,
          ["decrypt"]
        );

        const decrypted = await decryptServerAESEncryptedData(message.encryptedMessage, aesKey);
        const payload = JSON.parse(decrypted);

        if (payload.type === 'system') {
          const systemMessage: Message = {
            id: uuidv4(),
            content: payload.content,
            sender: "Server",
            timestamp: new Date(payload.timestamp || Date.now()),
            isCurrentUser: false,
            isSystemMessage: true
          };
          setMessages(prev => [...prev, systemMessage]);
        }

      } else {
        console.log("User message received. Starting decryption");
        const encryptedAesKey = base64ToArrayBuffer(message.encryptedAESKey);
        const aesKey = await decryptAESKeyWithRSA(encryptedAesKey, privateKeyRef.current);

        const decryptedMessage = await decryptMessage(message.encryptedMessage, aesKey);
        const payload = JSON.parse(decryptedMessage);

        if (payload.type === 'system') {
          const systemMessage: Message = {
            id: uuidv4(),
            content: payload.content,
            sender: "Server",
            timestamp: new Date(payload.timestamp || Date.now()),
            isCurrentUser: false,
            isSystemMessage: true
          };
          setMessages(prev => [...prev, systemMessage]);
        }
        
        else {
          const userMessage: Message = {
            id: uuidv4(),
            content: payload.content,
            sender: message.from,
            timestamp: new Date(payload.timestamp || Date.now()),
            isCurrentUser: false,
            isSystemMessage: false
          };
          setMessages(prev => [...prev, userMessage]);
        }
      }
    } catch (error) {
      console.error("Error handling encrypted message:", error);
    }
  }, [decryptServerAESEncryptedData]);

  
  useEffect(() => {
    const generateKeys = async () => {
      if (!privateKeyPEM || !publicKeyPEM) {
        setIsGeneratingKeys(true);
        try {
          const keyPair = await generateRSAKeyPair();
          const publicKeyString = await exportPublicKeyToPEM(keyPair.publicKey);
          const privateKeyString = await exportPrivateKeyToPEM(keyPair.privateKey);
          
          setPublicKeyPEM(publicKeyString);
          setPrivateKeyPEM(privateKeyString);
          
          publicKeyRef.current = keyPair.publicKey;
          privateKeyRef.current = keyPair.privateKey;
        } catch (error) {
          console.error("Error generating keys:", error);
        } finally {
          setIsGeneratingKeys(false);
        }
      } else {
        try {
          const publicKey = await importPublicKeyFromPEM(publicKeyPEM);
          const privateKey = await importPrivateKeyFromPEM(privateKeyPEM);
          
          publicKeyRef.current = publicKey;
          privateKeyRef.current = privateKey;
        } catch (error) {
          console.error("Error importing existing keys:", error);

          setPublicKeyPEM("");
          setPrivateKeyPEM("");
        }
      }
    };
    
    generateKeys();
  }, [privateKeyPEM, publicKeyPEM, setPublicKeyPEM, setPrivateKeyPEM]);
  
  const handleServerMessage = useCallback((data: MessageData) => {
    const { type, message } = data;
    
    switch (type) {      
      case SignalType.TYPING: {
        const typingUser = message.replace(SignalType.TYPING, "");
        if (typingUser !== username) {
          setUsers(prevUsers => 
            prevUsers.map(user => 
              user.username === typingUser 
              ? { ...user, isTyping: true } 
              : user
            )
          );
          
          setTimeout(() => {
            setUsers(prevUsers => 
              prevUsers.map(user => 
                user.username === typingUser 
                ? { ...user, isTyping: false } 
                : user
              )
            );
          }, 3000);
        }
        break;
      }
      
      case SignalType.PUBLICKEYS:
        try {
          console.log("Parsing public keys...");
          const keyData = JSON.parse(message) as Record<string, string>;
          const newUsers: User[] = [];
          
          for (const [username, publicKey] of Object.entries(keyData)) {
            newUsers.push({
              id: uuidv4(),
              username,
              isTyping: false,
              isOnline: true,
              publicKey: publicKey
            });
          }
          
          setUsers(newUsers);
          console.log("Parsed public keys successfully");
        } catch (error) {
          console.error("Error parsing public keys:", error);
        }
        break;
        
      case SignalType.NAMEEXISTSERR:
        setLoginError("Username already exists");
        break;
        
      case SignalType.INVALIDNAMELENGTH:
        setLoginError("Username must be between 3 and 16 characters");
        break;
        
      case SignalType.INVALIDNAME:
        setLoginError("Username contains invalid characters");
        break;
        
      case SignalType.SERVERLIMIT:
        setLoginError("Server has reached the maximum number of users");
        break;
        
      default:
      }
    }, []);

  useEffect(() => {
    if (isLoggedIn) {
      console.log("User logged in, registering message handlers...");

      const handler = async (data: unknown) => {
        console.log("Raw message received:", data);
        try {
        } catch (err) {
          console.error("Error handling raw WebSocket message:", err);
        }
      };

      websocketClient.registerMessageHandler(SignalType.ENCRYPTED_MESSAGE, handleEncryptedMessageObject);
      // websocketClient.registerMessageHandler(SignalType.FILE_MESSAGE, handleEncryptedMessageObject);
      websocketClient.registerMessageHandler(SignalType.FILE_MESSAGE_CHUNK, async (data) => {
        await handleFileMessageChunk(data, { from: data.from });
      });

      // websocketClient.registerMessageHandler(SignalType.FILE_MESSAGE, async (data) => {
      //   await handleFileMessage(data, {
      //     from: data.from, // or whatever structure your message uses
      //   });
      // });
      websocketClient.registerMessageHandler(SignalType.PUBLICKEYS, (data) => {
        console.log("PublicKeys received:", data);
        handleServerMessage(data as MessageData);
      });

      websocketClient.registerMessageHandler("raw", handler);

      return () => {
        console.log("Unregistering message handlers...");
        websocketClient.unregisterMessageHandler("raw");
        websocketClient.unregisterMessageHandler(SignalType.ENCRYPTED_MESSAGE);
        // websocketClient.unregisterMessageHandler(SignalType.FILE_MESSAGE);
        websocketClient.unregisterMessageHandler(SignalType.FILE_MESSAGE_CHUNK);
        websocketClient.unregisterMessageHandler(SignalType.PUBLICKEYS);
      };
    }
  }, [isLoggedIn, handleEncryptedMessageObject, handleServerMessage]);

  const handleLogin = async (username: string) => {
    setLoginError("");

    if (!publicKeyRef.current || !privateKeyRef.current) {
      setLoginError("Encryption keys not ready. Please try again.");
      return;
    }

    try {
      console.log("Connecting to secure WebSocket server...");
      await websocketClient.connect().catch(error => {
        console.warn("WebSocket connection error:", error);
        throw new Error("Could not connect to chat server.");
      });

      console.log("Connected successfully, establishing secure channel...");

      console.log("Sending username to server...");
      websocketClient.send(username);

      websocketClient.send(publicKeyPEM);

      const aesKey = await generateAESKey();
      aesKeyRef.current = aesKey;

      setUsername(username);
      setIsLoggedIn(true);

      const welcomeMessage: Message = {
        id: uuidv4(),
        content: `Welcome to SecureChat, ${username}! Your messages are secured with this encryption:
• RSA-4096 for key exchange
• AES-256-GCM for message encryption
• SHA-512 for integrity verification`,
        sender: "System",
        timestamp: new Date(),
        isCurrentUser: false,
        isSystemMessage: true
      };

      const secureConnectionMessage: Message = {
        id: uuidv4(),
        content: "Connected to secure WebSocket server with end-to-end encryption.",
        sender: "System",
        timestamp: new Date(),
        isCurrentUser: false,
        isSystemMessage: true
      };

      setMessages([welcomeMessage, secureConnectionMessage]);

    } catch (error) {
      console.error("Login failed: ", error);
    }
  };
  
  const handleTyping = () => {
  };
  
  const handleSendMessage = async (content: string) => {
    if (!isLoggedIn || !content.trim()) return;

    try {
      const messageId = uuidv4();
      
      const newMessage: Message = {
        id: messageId,
        content,
        sender: username,
        timestamp: new Date(),
        isCurrentUser: true
      };
      setMessages(prev => [...prev, newMessage]);
      
      for (const user of users) {
        if (user.username === username || !user.publicKey) continue;
        
        const recipientKey = await importPublicKeyFromPEM(user.publicKey);
        const aesKey = await generateAESKey();

        const messagePayload = {
          content,
          timestamp: Date.now(),
          type: "chat"
        };

        const { iv, authTag, encrypted } = await encryptWithAES(
          JSON.stringify(messagePayload),
          aesKey
        );

        const encryptedMessage = serializeEncryptedData(iv, authTag, encrypted);
        const rawAes = await window.crypto.subtle.exportKey('raw', aesKey);
        const encryptedAes = await encryptWithRSA(rawAes, recipientKey);
        const encryptedAESKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedAes)));
        
        console.log("Preparing to send message:", encryptedMessage);
        
        const payload = {
          type: SignalType.ENCRYPTED_MESSAGE,
          from: username,
          to: user.username,
          encryptedAESKey: encryptedAESKeyBase64,
          encryptedMessage
        };
        
        console.log(`Sending encrypted payload: ${JSON.stringify(payload)}`);
        websocketClient.send(JSON.stringify(payload));
        console.log(`Sent payload`);
      }
    } catch (error) {
      console.error("E2EE send error:", error);
      const errorMsg: Message = {
        id: uuidv4(),
        content: `Failed to send message: ${error instanceof Error ? error.message : "Unknown error"}`,
        sender: "System",
        timestamp: new Date(),
        isCurrentUser: false,
        isSystemMessage: true
      };
      setMessages(prev => [...prev, errorMsg]);
    }
  };

  if (!isLoggedIn) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4 bg-gradient-to-r from-gray-50 to-slate-50">
        <Login
          onLogin={handleLogin}
          isGeneratingKeys={isGeneratingKeys}
          error={loginError}
        />
      </div>
    );
  }
  
  return (
    <div className="flex flex-col h-screen p-4 md:p-6 bg-gradient-to-r from-gray-50 to-slate-50">
      <header className="mb-4">
        <h1 className="text-2xl font-bold">SecureChat</h1>
        <p className="text-muted-foreground">End-to-end encrypted messaging</p>
      </header>
      
      <div className="flex flex-1 gap-4 h-[calc(100vh-150px)]">
        <div className="hidden md:block w-64">
          <UserList users={users} currentUser={username} />
        </div>
        
        <div className="flex-1">
         <ChatInterface
            messages={messages}
            onSendMessage={handleSendMessage}
            onTyping={handleTyping}
            isEncrypted={true}
            currentUsername={username}
            users={users}
          />
        </div>
      </div>
    </div>
  );
}