import { useState, useEffect, useRef, useCallback } from "react";
import { Login } from "@/components/chat/Login";
import { UserList, User } from "@/components/chat/UserList";
import { ChatInterface } from "@/components/chat/ChatInterface";
import { Message } from "@/components/chat/ChatMessage";
import { useLocalStorage } from "@/hooks/use-local-storage";
import * as crypto from "@/lib/unified-crypto";
import websocketClient from "@/lib/websocket";
import { SignalType } from "@/lib/signals";
import { v4 as uuidv4 } from 'uuid';


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
  const [serverPublicKeyPEM, setServerPublicKeyPEM] = useState<string | null>(null);
  const serverPublicKeyRef = useRef<CryptoKey | null>(null);
  const [isServerKeyReady, setIsServerKeyReady] = useState(false);

  // Users and messages
  const [users, setUsers] = useState<User[]>([]);
  const [messages, setMessages] = useState<Message[]>([]);
  const loginUsernameRef = useRef<string>("");

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

      const { iv, authTag, encrypted } = crypto.deserializeEncryptedDataFromUint8Array(encryptedBytes);

      if (!fileEntry.aesKey) {
        const decryptedAESKeyBytes = await crypto.decryptWithRSA(
          crypto.base64ToArrayBuffer(fileEntry.encryptedAESKey),
          privateKeyRef.current
        );

        const aesKey = await crypto.importAESKey(decryptedAESKeyBytes);
        fileEntry.aesKey = aesKey;
      }

      const decryptedChunk = await crypto.decryptWithAESRaw(
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
  
  const handleEncryptedMessagePayload = useCallback(async (message: any) => {
    try {
      console.log("Message received. Starting decryption...");
      const payload = await crypto.decryptAndFormatPayload(message, privateKeyRef.current);
      console.log("Payload decrypted. Message type: ", payload.type)

      if (message.type == SignalType.USER_DISCONNECT) {
        setUsers(prevUsers => prevUsers.filter(user => user.username !== payload.content.split(' ')[0]))
      }
      
      const payloadFull: Message = { //display on screen
        id: uuidv4(),
        content: payload.content,
        sender: message.from,
        timestamp: new Date(payload.timestamp || Date.now()),
        isCurrentUser: false,
        isSystemMessage: payload.typeInside == 'system' //if sys message set true
      };
        
      setMessages(prev => [...prev, payloadFull]);
    } catch (error) {
      console.error("Error handling encrypted message:", error);
    }
  }, []);

  
  useEffect(() => {
    const generateKeys = async () => {
      if (!privateKeyPEM || !publicKeyPEM) {
        setIsGeneratingKeys(true);
        try {
          const keyPair = await crypto.generateRSAKeyPair();
          const publicKeyString = await crypto.exportPublicKeyToPEM(keyPair.publicKey);
          const privateKeyString = await crypto.exportPrivateKeyToPEM(keyPair.privateKey);
          
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
          const publicKey = await crypto.importPublicKeyFromPEM(publicKeyPEM);
          const privateKey = await crypto.importPrivateKeyFromPEM(privateKeyPEM);
          
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
  
  const handleServerMessage = useCallback(async (data: MessageData) => {
    const { type, message } = data;

    switch (type) {
      case SignalType.PUBLICKEYS:
        try {
          console.log("Parsing public keys...");
          console.log("PublicKeys received:", data);
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
      
      case SignalType.SERVER_PUBLIC_KEY:
        try {
          const pem = (data as any).publicKey; // safely extract
          setServerPublicKeyPEM(pem);
          console.log("pem key extract: "+ pem)
          const key = await crypto.importPublicKeyFromPEM(pem);
          serverPublicKeyRef.current = key;
          console.log("Server public key imported.");
        } catch (e) {
          console.error("Failed to import server public key:", e);
        }
        break;
      
      case SignalType.AUTH_SUCCESS:
        console.log(message)

        setUsername(loginUsernameRef.current);
        setIsLoggedIn(true);

        const welcomeMessage: Message = {
          id: uuidv4(),
          content: `Welcome to SecureChat, ${loginUsernameRef.current}! Your messages are secured with this encryption:
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
        break;

      case SignalType.ENCRYPTED_MESSAGE:
      case SignalType.USER_DISCONNECT:
        await handleEncryptedMessagePayload(data);
        break;

      case SignalType.FILE_MESSAGE_CHUNK:
        await handleFileMessageChunk(data, { from: data.from });
        break;

      case SignalType.NAMEEXISTSERROR:
      case SignalType.INVALIDNAMELENGTH:
      case SignalType.INVALIDNAME:
      case SignalType.AUTH_ERROR:
      case SignalType.SERVERLIMIT:
        setIsLoggedIn(false);
        setLoginError("Login error: " + message);
        console.log("You have been disconnected")
        break;

      default:
        console.warn("Unhandled signal type:", type);
    }
  }, [handleEncryptedMessagePayload]);

  useEffect(() => {
    console.log("User logged in, registering message handlers...");
    
    const handler = async (data: unknown) => {
      console.log("Raw message received:", data);
      try {
      } catch (err) {
        console.error("Error handling raw WebSocket message:", err);
      }
    };

    const registeredSignalTypes = Object.values(SignalType);


    registeredSignalTypes.forEach(signal => { //register all signal types so the function can axtually work without individually setting up a handler for each type
      websocketClient.registerMessageHandler(signal, async (data: unknown) => {
          await handleServerMessage(data);
      });
    });

    websocketClient.registerMessageHandler("raw", handler);

    return () => {
      console.log("Unregistering message handlers...");
      registeredSignalTypes.forEach(signal => {
        websocketClient.unregisterMessageHandler(signal);
      });
      websocketClient.unregisterMessageHandler("raw");
    };
  }, [handleEncryptedMessagePayload, handleServerMessage]);

  const handleLogin = async (username: string, password: string) => {
    setLoginError("");

    if (!publicKeyRef.current || !privateKeyRef.current) {
      setLoginError("Encryption keys not ready");
      return;
    }

    try {
      console.log("Connecting to WebSocket server...");
      await websocketClient.connect();
      
      if (!serverPublicKeyPEM) {
        console.error("Server public key not available");
        return;
      }

      const passwordPayload = await crypto.encryptAndFormatPayload({
        recipientPEM: serverPublicKeyPEM,
        type: SignalType.SERVER_PASSWORD_ENCRYPTED,
        content: password
      });

      const userPayload = await crypto.encryptAndFormatPayload({
        recipientPEM: serverPublicKeyPEM,
        usernameSent: username,
        publicKey: publicKeyPEM
      });

      const loginInfo = {
        type: SignalType.LOGIN_INFO,
        userData: userPayload,
        passwordData: passwordPayload
      };

      console.log("Sending combined login info: ", loginInfo);
      websocketClient.send(JSON.stringify(loginInfo));
      
      loginUsernameRef.current = username;
    } catch (error) {
      console.error("Login failed: ", error);
    }
  };

  
  const handleTyping = () => {
  };
  
  const handleSendMessage = async (content: string) => {
    if (!isLoggedIn || !content.trim()) return;

    try {      
      const newMessage: Message = {
        id: uuidv4(),
        content,
        sender: loginUsernameRef.current,
        timestamp: new Date(),
        isCurrentUser: true
      };
      setMessages(prev => [...prev, newMessage]);
      
      for (const user of users) {
        if (user.username === username || !user.publicKey) continue;
        
        const payload = await crypto.encryptAndFormatPayload({
          recipientPEM: user.publicKey,
          from: loginUsernameRef.current,
          to: user.username,
          type: SignalType.ENCRYPTED_MESSAGE,
          content: content,
          timestamp: Date.now(),
          typeInside: "chat"
        });

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
          <UserList users={users} currentUser={loginUsernameRef.current} />
        </div>
        
        <div className="flex-1">
         <ChatInterface
            messages={messages}
            onSendMessage={handleSendMessage}
            onTyping={handleTyping}
            isEncrypted={true}
            currentUsername={loginUsernameRef.current}
            users={users}
          />
        </div>
      </div>
    </div>
  );
}