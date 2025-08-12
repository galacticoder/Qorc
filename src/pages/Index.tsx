import { useState, useEffect, useRef, useCallback } from "react";
import { Login } from "@/components/chat/Login";
import { UserList, User } from "@/components/chat/UserList";
import { ChatInterface } from "@/components/chat/ChatInterface";
import { Message } from "@/components/chat/types";
import { CryptoUtils } from "@/lib/unified-crypto";
import websocketClient from "@/lib/websocket";
import { SignalType } from "@/lib/signals";
import { v4 as uuidv4 } from 'uuid';
import { SecureDB } from "@/lib/secureDB";

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
    handlePassphraseSubmit,
    handleServerPasswordSubmit: authHandleServerPasswordSubmit,
    handleAuthSuccess,
    privateKeyRef,
    publicKeyRef,
    loginUsernameRef,
    initializeKeys,
    setAccountAuthenticated,
    passwordRef,
    serverPublicKeyRef, //pass this to the useMessage hook
    setLoginError,
    setPassphraseHashParams,
    passphrasePlaintextRef, //clear this later maybe
    passphraseRef
  } = useAuth();
  
  const [messages, setMessages] = useState<Message[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const secureDBRef = useRef<SecureDB | null>(null);
  const [dbInitialized, setDbInitialized] = useState(false);
  const [showPassphrasePrompt, setShowPassphrasePrompt] = useState(false);
  const aesKeyRef = useRef<CryptoKey | null>(null);

  
  useEffect(() => {
    initializeKeys();
  }, [initializeKeys]);

  useEffect(() => { //init db after login
    if (isLoggedIn && username && passwordRef.current) {
      secureDBRef.current = new SecureDB(username);
      secureDBRef.current.initialize(passwordRef.current)
        .then(() => setDbInitialized(true))
        .catch(error => {
          console.error("Database initialization failed:", error);
          setLoginError("Failed to initialize secure storage");
        });
    }
  }, [isLoggedIn, username]);

  useEffect(() => {  //load from data secure db
    if (!isLoggedIn || !dbInitialized || !secureDBRef.current) return;
    
    const loadData = async () => {
      try {
        const savedMessages = await secureDBRef.current!.loadMessages();
        const savedUsers = await secureDBRef.current!.loadUsers();
        
        const processedMessages = savedMessages.map((msg: any) => ({
          ...msg,
          timestamp: new Date(msg.timestamp),
          isCurrentUser: msg.sender === loginUsernameRef.current
        }));
        
        setMessages(processedMessages);
        
        if (savedUsers.length > 0) {
          setUsers(savedUsers);
        }
      } catch (error) {
        console.error("Secure DB load error:", error);
        setLoginError("Failed to load secure data");
      }
    };
    
    loadData();
  }, [isLoggedIn, dbInitialized]);

  useEffect(() => {
    if (!isLoggedIn || users.length === 0 || !dbInitialized || !secureDBRef.current) return;
    
    secureDBRef.current.saveUsers(users)
      .catch(error => console.error("Failed to save users:", error));
  }, [users, isLoggedIn, dbInitialized]);

  const handleNewMessage = useCallback(async (message: Message) => {
    if (!dbInitialized || !secureDBRef.current) return;
    
    const shouldPersist = !message.isSystemMessage || 
                         (message.content.includes('joined') || 
                          message.content.includes('left'));
                          
    if (shouldPersist) {
      try {
        setMessages(prev => [...prev, message]);
        
        const currentMessages = await secureDBRef.current!.loadMessages();
        const newMessages = [...currentMessages, message];
        
        await secureDBRef.current!.saveMessages(newMessages);
      } catch (error) {
        console.error("Failed to save message:", error);
      }
    } else {
      setMessages(prev => [...prev, message]);
    }
  }, [dbInitialized]);

  
  const { handleFileMessageChunk } = useFileHandler(
    privateKeyRef,
    handleNewMessage,
    setLoginError
  );

  const { handleSendMessage, handleDeleteMessage, handleEditMessage } = useMessageSender(
    isLoggedIn,
    users,
    loginUsernameRef,
    handleNewMessage,
    setMessages,
    aesKeyRef.current,
    serverPublicKeyPEM
  );

  const handleEncryptedMessagePayload = useCallback(async (message: any) => {
    try {
      console.log("Message received. Starting decryption...");
      const payload = await CryptoUtils.Decrypt.decryptAndFormatPayload(message, privateKeyRef.current);
      console.log("Payload decrypted. Message type: ", payload.type)

      if (message.type == SignalType.USER_DISCONNECT) {
        setUsers(prevUsers => prevUsers.filter(user => user.username !== payload.content.split(' ')[0]))
      }

      if (payload.typeInside === SignalType.DELETE_MESSAGE) {
        console.log("payload delete: ", payload)
        setMessages(prev => prev.map(msg => 
          msg.id === payload.id 
            ? { ...msg, isDeleted: true, content: "Message deleted" } 
            : msg
        ));
        return;
      }

      if (payload.typeInside === SignalType.EDIT_MESSAGE) {
        console.log("payload edit: ", payload)
        setMessages(prev => prev.map(msg => 
          msg.id === payload.id 
            ? { 
                ...msg, 
                content: payload.content, 
                isEdited: true,
                timestamp: new Date(payload.timestamp)
              } 
            : msg
        ));
        return;
      }

      const isJoinLeave = payload.content.includes('joined') || payload.content.includes('left');

      console.log("Message ID received: ", payload.id)

      const payloadFull: Message = {
        id: payload.typeInside === 'system' ? uuidv4() : (payload.id ?? uuidv4()),
        content: payload.content,
        sender: message.from,
        timestamp: new Date(payload.timestamp),
        isCurrentUser: false,
        isSystemMessage: payload.typeInside === 'system',
        shouldPersist: isJoinLeave,
        ...(payload.replyTo && {
          replyTo: {
            id: payload.replyTo.id,
            sender: payload.replyTo.sender,
            content: payload.replyTo.content,
          },
        }),
      };

      console.log("Reply field: ", payloadFull.replyTo)
      await handleNewMessage(payloadFull);
    } catch (error) {
      console.error("Error handling encrypted message:", error);
    }
  }, [handleNewMessage]);

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
          console.log("Auth success message: ", data)
          handleAuthSuccess(loginUsernameRef.current, (welcomeMessages) => {
            welcomeMessages.forEach(msg => handleNewMessage(msg));
          });
          break;
        
        case SignalType.PASSPHRASE_HASH:
          console.log("Passphrase hash signal received")
          if (data && typeof data === "object") {
            const {
              version,
              algorithm,
              salt,
              memoryCost,
              timeCost,
              parallelism,
              message: serverMessage
            } = data || {};

            if (
              version !== undefined &&
              algorithm !== undefined &&
              salt !== undefined &&
              memoryCost !== undefined &&
              timeCost !== undefined &&
              parallelism !== undefined &&
              serverMessage !== undefined
            ) {
              setPassphraseHashParams({
                version,
                algorithm,
                salt,
                memoryCost,
                timeCost,
                parallelism,
                message: serverMessage
              });

              console.log("Received Passphrase hash info: ", data);
            }
          }
          setShowPassphrasePrompt(true);
          break;
        
        case SignalType.PASSPHRASE_SUCCESS:
          //genrtaye aes key here from passphrase
          console.log("passphraseref: ", passphrasePlaintextRef.current)

          const salt = CryptoUtils.Hash.extractSaltBase64FromEncodedHash(passphraseRef.current)

          console.log(`Hash: ${passphraseRef.current}\nSalt extracted base64: ${salt}`)
          
          const { aesKey: derivedKey } = await CryptoUtils.Keys.deriveAESKeyFromPassphrase(passphrasePlaintextRef.current, salt);
          aesKeyRef.current = derivedKey;

          console.log("AES key derived and stored!");

          setShowPassphrasePrompt(false);
          break;

        case SignalType.ENCRYPTED_MESSAGE:
        case SignalType.USER_DISCONNECT:
        case SignalType.EDIT_MESSAGE:
        case SignalType.DELETE_MESSAGE:
          await handleEncryptedMessagePayload(data);
          break;

        case SignalType.IN_ACCOUNT:
          console.log("In account signal received")
          setAccountAuthenticated(true);
          // setIsLoggedIn(true);
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
    loginUsernameRef,
    handleNewMessage,
    handleFileMessageChunk,
    setServerPublicKeyPEM,
    setUsers
  ]);

  useWebSocket(handleSignalMessages, handleEncryptedMessagePayload, setLoginError);

  const handleSendFileWrapper = useCallback((fileMessage: Message) => {
    handleSendFile(
      fileMessage,
      loginUsernameRef,
      handleNewMessage,
      users
    );
  }, [loginUsernameRef, handleNewMessage, users]);

  const handleLogout = useCallback(() => {
    if (secureDBRef.current) {
      secureDBRef.current = null;
      passwordRef.current = "";
    }
    
    setIsLoggedIn(false);
    setMessages([]);
    setUsers([]);
    setLoginError("");
  }, []);

  if (!isLoggedIn) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4 bg-gradient-to-r from-gray-50 to-slate-50">
        <Login
          isGeneratingKeys={isGeneratingKeys}
          error={loginError}
          onAccountSubmit={authHandleAccountSubmit}
          onServerPasswordSubmit={authHandleServerPasswordSubmit}
          accountAuthenticated={accountAuthenticated}
          showPassphrasePrompt={showPassphrasePrompt}
          setShowPassphrasePrompt={setShowPassphrasePrompt}
          onPassphraseSubmit={handlePassphraseSubmit}
        />
      </div>
    );
  }
  
  return (
    <div className="flex flex-col h-screen p-4 md:p-6 bg-gradient-to-r from-gray-50 to-slate-50">
      
      <header className="mb-4 flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold">SecureChat</h1>
          <p className="text-muted-foreground">End-to-end encrypted messaging</p>
        </div>
        <button 
          onClick={handleLogout}
          className="px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition"
        >
          Logout
        </button>
      </header>
      
      <div className="flex flex-1 gap-4 h-[calc(100vh-150px)]">
        <div className="hidden md:block w-64">
          <UserList users={users} currentUser={loginUsernameRef.current} />
        </div>
        
        <div className="flex-1">
          <ChatInterface
            messages={messages}
            onSendMessage={handleSendMessage}
            onSendFile={handleSendFileWrapper}
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