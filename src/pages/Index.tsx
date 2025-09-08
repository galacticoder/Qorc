import React, { useState, useCallback, useEffect } from "react";
import { Login } from "../components/chat/Login";
import { Sidebar } from "../components/chat/UserList";
import { ConversationList } from "../components/chat/ConversationList";
import { ChatInterface } from "../components/chat/ChatInterface";
import { AppSettings } from "../components/settings/AppSettings";
import { Message } from "../components/chat/types";
import { cn } from "../lib/utils";
import { formatFileSize } from "../components/chat/ChatMessage/FileMessage";

import { useAuth } from "../hooks/useAuth";
import { useSecureDB } from "../hooks/useSecureDB";
import { useFileHandler } from "../hooks/useFileHandler";
import { useMessageSender } from "../hooks/useMessageSender";
import { useEncryptedMessageHandler } from "../hooks/useEncryptedMessageHandler";
import { useChatSignals } from "../hooks/useChatSignals";
import { useWebSocket } from "../hooks/useWebsocket";
import { useConversations } from "../hooks/useConversations";
import { useMessageHistory } from "../hooks/useMessageHistory";
import { useUsernameDisplay } from "../hooks/useUsernameDisplay";
import { storeUsernameMapping } from "../lib/username-display";
import { TypingIndicatorProvider } from "../contexts/TypingIndicatorContext";
import { torNetworkManager } from "../lib/tor-network";
import { TorAutoSetup } from "../components/setup/TorAutoSetup";
import { ServerSelection } from "../components/setup/ServerSelection";
import { getTorAutoSetup } from "../lib/tor-auto-setup";
import { SignalType } from "../lib/signals";

// Helper function to generate appropriate reply content for different message types
const getReplyContent = (message: Message): string => {
  // Handle file messages
  if (message.type === 'file' || message.type === 'file-message' || message.filename) {
    // For images
    if (message.filename && /\.(jpg|jpeg|png|gif|bmp|webp|svg|ico|tiff)$/i.test(message.filename)) {
      const fileSize = message.fileSize ? ` (${formatFileSize(message.fileSize)})` : '';
      return `📷 ${message.filename}${fileSize}`;
    }
    // For videos
    else if (message.filename && /\.(mp4|webm|ogg|avi|mov|wmv|flv|mkv)$/i.test(message.filename)) {
      const fileSize = message.fileSize ? ` (${formatFileSize(message.fileSize)})` : '';
      return `🎬 ${message.filename}${fileSize}`;
    }
    // For voice notes
    else if (message.filename && (message.filename.toLowerCase().includes('voice-note') || /\.(mp3|wav|ogg|webm|m4a|aac|flac)$/i.test(message.filename))) {
      return `🎤 Voice message`;
    }
    // For other files
    else {
      const filename = message.filename || 'File';
      const fileSize = message.fileSize ? ` (${formatFileSize(message.fileSize)})` : '';
      return `📎 ${filename}${fileSize}`;
    }
  }

  // For regular text messages, return the content as-is
  return message.content || '';
};

interface ChatAppProps {
  onNavigate: (page: "home" | "server" | "chat") => void;
}

const ChatApp: React.FC<ChatAppProps> = () => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [sidebarActiveTab, setSidebarActiveTab] = useState<string>("messages");
  const [showTorSetup, setShowTorSetup] = useState(false);
  const [showServerSelection, setShowServerSelection] = useState(false);
  const [selectedServerUrl, setSelectedServerUrl] = useState<string>('');
  const [, setTorSetupComplete] = useState(false);
  const [showSettings, setShowSettings] = useState(false);


  // Initialize Authentication first (without SecureDB dependency)
  const Authentication = useAuth();
  
  const Database = useSecureDB({
    Authentication,
    setMessages,
  });

  // Initialize all hooks before any conditional returns
  const fileHandler = useFileHandler(
    Authentication.getKeysOnDemand,
    Database.saveMessageToLocalDB,
    Authentication.setLoginError
  );

  const messageSender = useMessageSender(
    [], // Do not rely on in-memory user list for scalability
    Authentication.loginUsernameRef,
    Authentication.originalUsernameRef,
    (message: Message) => {
      // Add the message to the UI state
      setMessages(prev => [...prev, message]);
    },
    Authentication.serverHybridPublic,
    Authentication.getKeysOnDemand,
    Authentication.aesKeyRef,
    Authentication.keyManagerRef,
    Authentication.passphrasePlaintextRef,
    Authentication.isLoggedIn
  );

  const encryptedHandler = useEncryptedMessageHandler(
    Authentication.loginUsernameRef,
    setMessages,
    Database.saveMessageToLocalDB,
    Authentication.isLoggedIn && Authentication.accountAuthenticated
  );

  // Message history synchronization
  const messageHistory = useMessageHistory(
    Authentication.loginUsernameRef.current || '',
    Authentication.isLoggedIn,
    setMessages,
    Database.saveMessageToLocalDB,
    Authentication.isLoggedIn && Authentication.accountAuthenticated
  );

  const signalHandler = useChatSignals({
    Authentication,
    Database,
    fileHandler,
    encryptedHandler,
    handleMessageHistory: messageHistory.handleMessageHistory
  });

  // Conversation management
  const {
    conversations,
    selectedConversation,
    addConversation,
    selectConversation,
    removeConversation,
    getConversationMessages,
  } = useConversations(Authentication.loginUsernameRef.current || '', Database.users, messages, Database.secureDBRef.current || undefined);

  // Username display system
  const usernameDisplay = useUsernameDisplay(
    Database.secureDBRef.current,
    Authentication.originalUsernameRef.current
  );
  

  // Store username mapping for current user only when SecureDB is available
  useEffect(() => {
    if (Database.secureDBRef.current && Authentication.originalUsernameRef.current) {
      const storeCurrentUserMapping = async () => {
        try {
          await Authentication.storeUsernameMapping(Database.secureDBRef.current!);
          console.log('[Index] Stored current user mapping');
        } catch (error) {
          console.error('[Index] Failed to store current user mapping:', error);
        }
      };
      storeCurrentUserMapping();
    }
  }, [Database.secureDBRef.current, Authentication.originalUsernameRef.current]);

  // Get messages for the selected conversation
  const conversationMessages = getConversationMessages(selectedConversation || '');

  const handleSendFileWrapper = useCallback(
    (fileMessage: Message) => {
      return fileHandler.handleSendFile(
        fileMessage,
        Authentication.loginUsernameRef.current,
        Database.saveMessageToLocalDB
      );
    },
    [fileHandler, Authentication.loginUsernameRef, Database.saveMessageToLocalDB]
  );

  // Handle conversation message clearing
  useEffect(() => {
    const handleClearConversationMessages = (event: CustomEvent) => {
      const { username } = event.detail;
      setMessages(prev => prev.filter(msg => 
        !(msg.sender === username || msg.recipient === username)
      ));
    };

    window.addEventListener('clear-conversation-messages', handleClearConversationMessages as EventListener);
    return () => {
      window.removeEventListener('clear-conversation-messages', handleClearConversationMessages as EventListener);
    };
  }, []);

  // Handle settings open/close events
  useEffect(() => {
    const handleOpenSettings = () => {
      setShowSettings(true);
    };

    const handleCloseSettings = () => {
      setShowSettings(false);
    };

    window.addEventListener('openSettings', handleOpenSettings);
    window.addEventListener('closeSettings', handleCloseSettings);

    return () => {
      window.removeEventListener('openSettings', handleOpenSettings);
      window.removeEventListener('closeSettings', handleCloseSettings);
    };
  }, []);

  // Check if Tor setup is needed on app start
  useEffect(() => {
    const checkTorSetup = async () => {
      console.log('[TOR-SETUP] Checking Tor setup requirements...');
      console.log('[TOR-SETUP] Window object keys:', Object.keys(window));
      console.log('[TOR-SETUP] electronAPI available?', !!(window as any).electronAPI);
      console.log('[TOR-SETUP] electronAPI object:', (window as any).electronAPI);
      console.log('[TOR-SETUP] Tor supported?', torNetworkManager.isSupported());

      // Only show Tor setup in Electron environment
      if (!torNetworkManager.isSupported()) {
        console.log('[TOR] Browser environment detected - Tor setup not available');
        // In browser environment, mark Tor setup as complete immediately
        try {
          await (window as any).edgeApi?.torSetupComplete?.();
        } catch (error) {
          // edgeApi not available in browser, which is expected
          console.log('[TOR-SETUP] edgeApi not available (browser environment)');
        }
        return;
      }

      const torStatus = getTorAutoSetup().getStatus();
      const userWantsTor = localStorage.getItem('tor_enabled') !== 'false'; // Default to true

      console.log('[TOR-SETUP] Tor status:', torStatus);
      console.log('[TOR-SETUP] User wants Tor:', userWantsTor);

      // Force show Tor setup in Electron environment for testing
      if (torNetworkManager.isSupported()) {
        console.log('[TOR-SETUP] Showing Tor setup screen (forced for testing)');
        setShowTorSetup(true);
      } else if (torStatus.isRunning) {
        console.log('[TOR-SETUP] Tor already running, initializing network manager');
        setTorSetupComplete(true);

        // Notify Electron main process that Tor setup is complete
        try {
          await (window as any).edgeApi?.torSetupComplete?.();
        } catch (error) {
          console.error('[TOR-SETUP] Failed to notify main process:', error);
        }

        // Initialize the network manager with existing Tor
        torNetworkManager.updateConfig({ enabled: true });
        await torNetworkManager.initialize();
      }
    };

    checkTorSetup();

    // Cleanup on unmount
    return () => {
      if (torNetworkManager.isSupported()) {
        torNetworkManager.shutdown();
      }
    };
  }, []);

  // Handle Tor setup completion
  const handleTorSetupComplete = async (success: boolean) => {
    if (success) {
      console.log('[TOR-SETUP] Tor setup completed successfully');
      setTorSetupComplete(true);
      
      // Notify Electron main process that Tor setup is complete
      try {
        await (window as any).edgeApi?.torSetupComplete?.();
      } catch (error) {
        console.error('[TOR-SETUP] Failed to notify main process:', error);
      }
      
      // No automatic tunnel URL fetching - clients will enter their preferred server URLs
      
      // Initialize Tor network manager after successful setup
      torNetworkManager.updateConfig({ enabled: true });
      await torNetworkManager.initialize();
      
      // Move to server selection
      setShowTorSetup(false);
      setShowServerSelection(true);
    } else {
      console.error('[TOR-SETUP] Tor setup failed');
    }
  };

  // Handle server selection
  const handleServerSelected = async (serverUrl: string) => {
    console.log('[SERVER-SELECTION] Server selected:', serverUrl);
    setSelectedServerUrl(serverUrl);
    
    // Update Electron with the selected server URL
    try {
      const electronAPI = (window as any).electronAPI;
      if (electronAPI && electronAPI.setServerUrl) {
        await electronAPI.setServerUrl(serverUrl);
      } else {
        // Fallback to edgeApi
        const edgeApi = (window as any).edgeApi;
        if (edgeApi && edgeApi.setServerUrl) {
          await edgeApi.setServerUrl(serverUrl);
        }
      }
    } catch (error) {
      console.error('[SERVER-SELECTION] Failed to set server URL:', error);
    }
    
    setShowServerSelection(false);
    
    // Initialize WebSocket connection
    try {
      await (window as any).edgeApi?.wsConnect?.();
    } catch (error) {
      console.error('[SERVER-SELECTION] Failed to connect WebSocket:', error);
    }
  };

  // Initialize WebSocket only after server selection is complete
  useEffect(() => {
    if (!showTorSetup && !showServerSelection && selectedServerUrl) {
      const initializeConnection = async () => {
        try {
          // Connect WebSocket first
          await (window as any).edgeApi?.wsConnect?.();
          
          // Then attempt authentication recovery if there's a stored username
          const hasStoredAuth = localStorage.getItem('last_authenticated_username');
          if (hasStoredAuth && !Authentication.isLoggedIn) {
            console.log('[Index] Attempting automatic authentication recovery...');
            setTimeout(() => {
              Authentication.attemptAuthRecovery().catch(error => {
                console.log('[Index] Authentication recovery failed:', error);
                // Not a critical error, user can login manually
              });
            }, 1000); // Wait 1 second for connection to stabilize
          }
        } catch (error) {
          console.error('[Index] Connection initialization failed:', error);
        }
      };
      
      initializeConnection();
    }
  }, [showTorSetup, showServerSelection, selectedServerUrl, Authentication.isLoggedIn, Authentication.attemptAuthRecovery]);

  useWebSocket(signalHandler, encryptedHandler, Authentication.setLoginError);

  // Expose current user's original name for call signal encryption (renderer-only, safe variable)
  useEffect(() => {
    try {
      (window as any).currentUserOriginal = Authentication.originalUsernameRef.current || undefined;
    } catch {}
  }, [Authentication.originalUsernameRef.current]);

  // Store username mapping when user is logged in and SecureDB is ready
  useEffect(() => {
    if (Authentication.isLoggedIn && Database.secureDBRef.current && Authentication.originalUsernameRef.current) {
      Authentication.storeUsernameMapping(Database.secureDBRef.current);
    }
  }, [Authentication.isLoggedIn, Database.secureDBRef.current, Authentication.originalUsernameRef.current]);

  // Handle local message deletion events (for sender side)
  useEffect(() => {
    const handleLocalMessageDelete = (event: CustomEvent) => {
      // Defensive validation
      if (!event.detail || typeof event.detail !== 'object') {
        console.warn('[Index] Invalid delete event - missing or invalid detail');
        return;
      }
      
      const { messageId } = event.detail;
      if (!messageId || typeof messageId !== 'string') {
        console.warn('[Index] Invalid delete event - missing or invalid messageId');
        return;
      }
      
      console.log('[Index] Processing local message deletion:', messageId);
      
      setMessages(prev => {
        const updatedMessages = prev.map(msg => 
          msg.id === messageId 
            ? { ...msg, isDeleted: true, content: 'This message was deleted' }
            : msg
        );
        console.log('[Index] Local message marked as deleted:', messageId);
        return updatedMessages;
      });
    };

    const handleLocalMessageEdit = (event: CustomEvent) => {
      // Defensive validation
      if (!event.detail || typeof event.detail !== 'object') {
        console.warn('[Index] Invalid edit event - missing or invalid detail');
        return;
      }
      
      const { messageId, newContent } = event.detail;
      
      if (!messageId || typeof messageId !== 'string') {
        console.warn('[Index] Invalid edit event - missing or invalid messageId');
        return;
      }
      
      if (!newContent || typeof newContent !== 'string') {
        console.warn('[Index] Invalid edit event - missing or invalid newContent');
        return;
      }
      
      console.log('[Index] Processing local message edit:', messageId, newContent);
      
      setMessages(prev => {
        const updatedMessages = prev.map(msg => 
          msg.id === messageId 
            ? { ...msg, content: newContent, isEdited: true }
            : msg
        );
        console.log('[Index] Local message edited:', messageId);
        return updatedMessages;
      });
    };

    const handleLocalFileMessage = (event: CustomEvent) => {
      // Defensive validation
      if (!event.detail || typeof event.detail !== 'object') {
        console.warn('[Index] Invalid file message event - missing or invalid detail');
        return;
      }
      
      const fileMessage = event.detail;
      
      if (!fileMessage.id || typeof fileMessage.id !== 'string') {
        console.warn('[Index] Invalid file message event - missing or invalid id');
        return;
      }
      
      console.log('[Index] Processing local file message:', fileMessage);
      
      setMessages(prev => {
        // Safe timestamp handling
        let timestamp;
        try {
          timestamp = fileMessage.timestamp ? new Date(fileMessage.timestamp) : new Date();
          if (isNaN(timestamp.getTime())) {
            throw new Error('Invalid timestamp');
          }
        } catch (err) {
          console.warn('[Index] Invalid timestamp, using current time:', err);
          timestamp = new Date();
        }
        
        const newMessage = {
          ...fileMessage,
          isCurrentUser: true,
          recipient: fileMessage.recipient || '', // Safe fallback for recipient
          timestamp
        };
        console.log('[Index] Local file message added:', newMessage.id);
        return [...prev, newMessage];
      });
    };

    window.addEventListener('local-message-delete', handleLocalMessageDelete as EventListener);
    window.addEventListener('local-message-edit', handleLocalMessageEdit as EventListener);
    const handleLocalMessageReaction = (e: any) => {
      try {
        const { messageId, emoji, action } = e.detail || {};
        if (!messageId || !emoji) return;
        setMessages(prev => prev.map(msg => {
          if (msg.id !== messageId) return msg;
          const reactions = { ...(msg.reactions || {}) } as Record<string, string[]>;
          const arr = Array.isArray(reactions[emoji]) ? [...reactions[emoji]] : [];
          const actor = Authentication.loginUsernameRef.current;
          const has = arr.includes(actor);
          // Enforce one reaction per user: remove actor from any other emoji first
          for (const key of Object.keys(reactions)) {
            if (key !== emoji) {
              reactions[key] = (reactions[key] || []).filter(u => u !== actor);
              if (reactions[key].length === 0) delete reactions[key];
            }
          }
          if (action === 'reaction-add' && !has) arr.push(actor);
          if (action === 'reaction-remove' && has) reactions[emoji] = arr.filter(u => u !== actor);
          else reactions[emoji] = arr;
          if (reactions[emoji].length === 0) delete reactions[emoji];
          return { ...msg, reactions };
        }));
      } catch {}
    };
    window.addEventListener('local-message-reaction', handleLocalMessageReaction as EventListener);
    window.addEventListener('local-file-message', handleLocalFileMessage as EventListener);
    
    return () => {
      window.removeEventListener('local-message-delete', handleLocalMessageDelete as EventListener);
      window.removeEventListener('local-message-edit', handleLocalMessageEdit as EventListener);
      window.removeEventListener('local-file-message', handleLocalFileMessage as EventListener);
      window.removeEventListener('local-message-reaction', handleLocalMessageReaction as EventListener);
    };
  }, [setMessages]);


  // Show Tor setup screen first if needed
  if (showTorSetup) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4 bg-gradient-to-r from-gray-50 to-slate-50 dark:from-gray-900 dark:to-slate-900">
        <div className="w-full max-w-2xl">
          <TorAutoSetup
            onComplete={handleTorSetupComplete}
            autoStart={true}
          />
        </div>
      </div>
    );
  }

  // Show server selection screen after Tor setup
  if (showServerSelection) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4 bg-gradient-to-r from-gray-50 to-slate-50 dark:from-gray-900 dark:to-slate-900">
        <div className="w-full max-w-3xl">
          <ServerSelection
            onServerSelected={handleServerSelected}
          />
        </div>
      </div>
    );
  }

  if (!Authentication.isLoggedIn) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4 bg-gradient-to-r from-gray-50 to-slate-50 dark:from-gray-900 dark:to-slate-900">
        <Login
          isGeneratingKeys={Authentication.isGeneratingKeys}
          authStatus={Authentication.authStatus}
          error={Authentication.loginError}
          onAccountSubmit={Authentication.handleAccountSubmit}
          onServerPasswordSubmit={Authentication.handleServerPasswordSubmit}
          accountAuthenticated={Authentication.accountAuthenticated}
          isRegistrationMode={Authentication.isRegistrationMode}
          serverTrustRequest={Authentication.serverTrustRequest}
          onAcceptServerTrust={Authentication.acceptServerTrust}
          onRejectServerTrust={Authentication.rejectServerTrust}
          showPassphrasePrompt={Authentication.showPassphrasePrompt}
          setShowPassphrasePrompt={Authentication.setShowPassphrasePrompt}
          onPassphraseSubmit={Authentication.handlePassphraseSubmit}
        />
      </div>
    );
  }

  return (
    <TypingIndicatorProvider currentUsername={Authentication.loginUsernameRef.current || ''}>
      <div 
        className="flex h-screen relative"
        style={{ backgroundColor: 'var(--color-background)' }}
      >
        <Sidebar
          currentUsername={Authentication.originalUsernameRef.current || Authentication.loginUsernameRef.current || ''}
          onAddConversation={addConversation}
          onLogout={async () => await Authentication.logout(Database.secureDBRef)}
          onActiveTabChange={setSidebarActiveTab}
        >
          <ConversationList
            conversations={conversations}
            selectedConversation={selectedConversation || undefined}
            onSelectConversation={selectConversation}
            onRemoveConversation={removeConversation}
            getDisplayUsername={usernameDisplay.getDisplayUsername}
          />
        </Sidebar>

        <div 
          className="flex-1 flex flex-col transition-all duration-300"
          style={{
            marginLeft: sidebarActiveTab === "messages" ? 'calc(var(--sidebar-width) + var(--list-column-width))' : // sidebar + conversation list
                      'var(--sidebar-width)', // just sidebar
            maxWidth: 'var(--main-content-max-width)',
            padding: 'var(--main-content-padding)'
          }}
        >
          {showSettings ? (
            <AppSettings />
          ) : selectedConversation ? (
            <ChatInterface
              messages={conversationMessages}
              setMessages={setMessages}
              callingAuthContext={Authentication}
              getDisplayUsername={usernameDisplay.getDisplayUsername}
              onSendMessage={async (messageId, content, messageSignalType, replyTo) => {
                console.log('[Index] Attempting to send message:', {
                  messageId,
                  content,
                  messageSignalType,
                  selectedConversation,
                  usersCount: Database.users.length,
                  users: Database.users.map(u => u.username),
                  replyTo: replyTo,
                  replyToType: typeof replyTo,
                  replyToKeys: replyTo ? Object.keys(replyTo) : null
                });
                
                if (!selectedConversation) {
                  console.error('[Index] No conversation selected');
                  return;
                }
                
                // Handle reactions (no message bubble should be created)
                if (messageSignalType === SignalType.REACTION_ADD || messageSignalType === SignalType.REACTION_REMOVE) {
                  let targetUser = Database.users.find(user => user.username === selectedConversation);
                  if (!targetUser) {
                    targetUser = {
                      id: crypto.randomUUID(),
                      username: selectedConversation,
                      isOnline: false,
                      hybridPublicKeys: undefined
                    };
                    Database.setUsers(prev => [...prev, targetUser!]);
                  }
                  // Pass target message id via messageId -> originalMessageId param
                  return messageSender.handleSendMessage(targetUser, content, undefined, undefined, messageSignalType, messageId);
                }

                // Ensure conversation exists (auto-create if needed)
                addConversation(selectedConversation, false);
                
                // Handle typing indicator messages differently
                if (messageSignalType === 'typing-start' || messageSignalType === 'typing-stop') {
                  // For typing indicators, we need to send them as encrypted messages
                  // but they should not appear in the chat history
                  let targetUser = Database.users.find(user => user.username === selectedConversation);
                  
                  // If user not found in Database.users, create a placeholder user for messaging
                  if (!targetUser) {
                    console.log('[Index] User not in Database.users, creating placeholder for:', selectedConversation);
                    targetUser = {
                      id: crypto.randomUUID(),
                      username: selectedConversation,
                      isOnline: false,
                      hybridPublicKeys: undefined // Will be populated during key exchange
                    };
                  }
                  
                  console.log('[Index] Found/created target user for typing indicator:', targetUser);
                  // Send typing indicator as encrypted message but don't add to chat history
                  return messageSender.handleSendMessage(targetUser, content, replyTo ? { id: replyTo.id, sender: replyTo.sender, content: getReplyContent(replyTo) } : undefined, undefined, messageSignalType);
                }
                
                // Find the user object for the selected conversation
                let targetUser = Database.users.find(user => user.username === selectedConversation);
                
                // If user not found in Database.users, create a placeholder user for messaging
                if (!targetUser) {
                  console.log('[Index] User not in Database.users, creating placeholder for:', selectedConversation);
                  targetUser = {
                    id: crypto.randomUUID(),
                    username: selectedConversation,
                    isOnline: false,
                    hybridPublicKeys: undefined // Will be populated during key exchange
                  };
                  
                  // Add to Database.users so future messages can find the user
                  Database.setUsers(prev => [...prev, targetUser!]);
                }
                
                console.log('[Index] Found/created target user:', targetUser);
                
                // For delete messages, pass the messageId as originalMessageId
                if (messageSignalType === 'delete-message') {
                  return messageSender.handleSendMessage(targetUser, content, replyTo ? { id: replyTo.id, sender: replyTo.sender, content: replyTo.content } : undefined, undefined, messageSignalType, messageId);
                }
                
                // For edit messages, pass the messageId as editMessageId
                if (messageSignalType === 'edit-message') {
                  return messageSender.handleSendMessage(targetUser, content, replyTo ? { id: replyTo.id, sender: replyTo.sender, content: replyTo.content } : undefined, undefined, messageSignalType, undefined, messageId);
                }
                
                return messageSender.handleSendMessage(targetUser, content, replyTo ? { id: replyTo.id, sender: replyTo.sender, content: getReplyContent(replyTo) } : undefined, undefined, messageSignalType);
              }}
              onSendFile={handleSendFileWrapper}
              isEncrypted={true}
              currentUsername={Authentication.loginUsernameRef.current || ''}
              users={Database.users}
              selectedConversation={selectedConversation}
              saveMessageToLocalDB={Database.saveMessageToLocalDB}
            />
          ) : (
            <div 
              className="flex-1 flex items-center justify-center"
              style={{ backgroundColor: 'var(--color-background)' }}
            >
              <div className="text-center">
                <h2 
                  className="text-xl font-semibold mb-2"
                  style={{ color: 'var(--color-text-primary)' }}
                >
                  Welcome to endtoend
                </h2>
                <p style={{ color: 'var(--color-text-secondary)' }}>
                  Click the messages button to view conversations or add a new chat to begin
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </TypingIndicatorProvider>
  );
};

export default ChatApp;