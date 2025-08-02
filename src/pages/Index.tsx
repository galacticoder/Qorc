import { useState, useEffect, useRef, useCallback } from "react";
import { Login } from "@/components/chat/Login";
import { UserList, User } from "@/components/chat/UserList";
import { ChatInterface } from "@/components/chat/ChatInterface";
import { Message } from "@/components/chat/ChatMessage";
import { CryptoUtils } from "@/lib/unified-crypto";
import websocketClient from "@/lib/websocket";
import { SignalType } from "@/lib/signals";
import { v4 as uuidv4 } from 'uuid';
import * as pako from 'pako';
import { AuthProps, IncomingFileChunks } from "./types";

import { useAuth } from "@/hooks/useAuth";
import { useFileHandler, handleSendFile } from "@/hooks/useFileHandler";
import { useMessageSender } from "@/hooks/useMessageSender";
import { useWebSocket } from "@/hooks/useWebsocket";

interface ChatAppProps {
  onNavigate: (page: 'home' | 'server' | 'chat') => void;
}

const ChatApp: React.FC<ChatAppProps> = ({ onNavigate }) => {
  const {
    username,
    serverPublicKeyPEM,
    setServerPublicKeyPEM,
    isLoggedIn,
    setIsLoggedIn,
    isGeneratingKeys,
    loginError,
    accountAuthenticated,
    handleAccountSubmit: authHandleAccountSubmit,
    handleServerPasswordSubmit: authHandleServerPasswordSubmit,
    handleAuthSuccess,
    privateKeyRef,
    publicKeyRef,
    loginUsernameRef,
    initializeKeys,
    setAccountAuthenticated,
    serverPublicKeyRef,
    setLoginError
  } = useAuth();
  
  const [messages, setMessages] = useState<Message[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  
  useEffect(() => { //make keys
    initializeKeys();
  }, [initializeKeys]);
  
  const { handleFileMessageChunk } = useFileHandler(
    privateKeyRef,
    setMessages,
    setLoginError
  );

  const { handleSendMessage, handleDeleteMessage, handleEditMessage } = useMessageSender(
    isLoggedIn,
    users,
    loginUsernameRef,
    setMessages
  );

  const handleEncryptedMessagePayload = useCallback(async (message: any) => {
    try {
      console.log("Message received. Starting decryption...");
      const payload = await CryptoUtils.Decrypt.decryptAndFormatPayload(message, privateKeyRef.current);
      console.log("Payload decrypted. Message type: ", payload.type)

      if (message.type == SignalType.USER_DISCONNECT) {
        setUsers(prevUsers => prevUsers.filter(user => user.username !== payload.content.split(' ')[0]))
      }

      if (payload.type === SignalType.DELETE_MESSAGE) {
        setMessages(prev => prev.map(msg => 
          msg.id === payload.messageId 
            ? { ...msg, isDeleted: true, content: "Message deleted" } 
            : msg
        ));
        return;
      }

      if (payload.type === SignalType.EDIT_MESSAGE) {
        setMessages(prev => prev.map(msg => 
          msg.id === payload.messageId 
            ? { 
                ...msg, 
                content: payload.newContent, 
                isEdited: true,
                timestamp: new Date(payload.timestamp)
              } 
            : msg
        ));
        return;
      }

      console.log("Message ID received: ", payload.id)

      const payloadFull: Message = {
        id: payload.typeInside === 'system' ? uuidv4() : (payload.id ?? uuidv4()),
        content: payload.content,
        sender: message.from,
        timestamp: new Date(payload.timestamp),
        isCurrentUser: false,
        isSystemMessage: payload.typeInside === 'system',
        ...(payload.replyTo && {
          replyTo: {
            id: payload.replyTo.id,
            sender: payload.replyTo.sender,
            content: payload.replyTo.content,
          },
        }),
      };

      console.log("Reply field: ", payloadFull.replyTo)
      setMessages(prev => [...prev, payloadFull]);
    } catch (error) {
      console.error("Error handling encrypted message:", error);
    }
  }, []);

  const handleSignalMessages = useCallback(async (data: any) => {
    const { type, message } = data;
    try {
      switch (type) {
        case SignalType.PUBLICKEYS:
          const keyData = JSON.parse(message) as Record<string, string>;
          setUsers(Object.entries(keyData).map(([username, publicKey]) => ({
            id: uuidv4(),
            username,
            isTyping: false,
            isOnline: true,
            publicKey
          })));
          break;
        
        case SignalType.SERVER_PUBLIC_KEY:
          const pem = (data as any).publicKey;
          setServerPublicKeyPEM(pem);
          console.log("Server public key received: ", pem)
          serverPublicKeyRef.current = await CryptoUtils.Keys.importPublicKeyFromPEM(pem);
          break;
        
        case SignalType.AUTH_SUCCESS:
          handleAuthSuccess(loginUsernameRef.current, (welcomeMessages) => {
            setMessages(welcomeMessages);
          });
          break;

        case SignalType.ENCRYPTED_MESSAGE:
        case SignalType.USER_DISCONNECT:
        case SignalType.EDIT_MESSAGE:
        case SignalType.DELETE_MESSAGE:
          await handleEncryptedMessagePayload(data);
          break;

        case SignalType.IN_ACCOUNT:
          setAccountAuthenticated(true);
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
          break;

        default:
          console.warn("Unhandled signal type:", type);
      }
    } catch (error) {
      console.error("Error handling server message:", error);
      setLoginError("Error processing server message");
    }
  }, [
    handleEncryptedMessagePayload,
    handleAuthSuccess,
    setAccountAuthenticated,
    setIsLoggedIn,
    setLoginError,
    loginUsernameRef
  ]);
  
  useWebSocket(handleSignalMessages, handleEncryptedMessagePayload, setLoginError); //to connect to the server

  if (!isLoggedIn) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4 bg-gradient-to-r from-gray-50 to-slate-50">
        <Login
          isGeneratingKeys={isGeneratingKeys}
          error={loginError}
          onAccountSubmit={authHandleAccountSubmit}
          onServerPasswordSubmit={authHandleServerPasswordSubmit}
          accountAuthenticated={accountAuthenticated}
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
            onSendFile={(fileMessage) => handleSendFile(fileMessage, loginUsernameRef, setMessages)}//put in wrapper because i want to pass in 2 other args
            isEncrypted={true}
            currentUsername={loginUsernameRef.current}
            users={users}
            onDeleteMessage={handleDeleteMessage}
            onEditMessage={handleEditMessage}
          />
        </div>
      </div>
    </div>
  );
}

export default ChatApp;
