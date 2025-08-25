import { useState, useCallback } from "react";
import { Login } from "@/components/chat/Login";
import { Sidebar } from "@/components/chat/UserList";
import { ConversationList } from "@/components/chat/ConversationList";
import { ChatInterface } from "@/components/chat/ChatInterface";
import { Message } from "@/components/chat/types";
import { cn } from "@/lib/utils";

import { useAuth } from "@/hooks/useAuth";
import { useSecureDB } from "@/hooks/useSecureDB";
import { useFileHandler } from "@/hooks/useFileHandler";
import { useMessageSender } from "@/hooks/useMessageSender";
import { useEncryptedMessageHandler } from "@/hooks/useEncryptedMessageHandler";
import { useChatSignals } from "@/hooks/useChatSignals";
import { useWebSocket } from "@/hooks/useWebsocket";
import { useConversations } from "@/hooks/useConversations";
import { TypingIndicatorProvider } from "@/contexts/TypingIndicatorContext";
// offline message queue removed

interface ChatAppProps {
  onNavigate: (page: "home" | "server" | "chat") => void;
}

const ChatApp: React.FC<ChatAppProps> = ({ onNavigate }) => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [sidebarActiveTab, setSidebarActiveTab] = useState<string>("messages");

  const Authentication = useAuth();

  const Database = useSecureDB({
    Authentication,
    messages,
    setMessages,
  });

  const fileHandler = useFileHandler(
    Authentication.getKeysOnDemand,
    Database.saveMessageToLocalDB,
    Authentication.setLoginError
  );

  // offline queue removed

  const messageSender = useMessageSender(
    Database.users,
    Authentication.loginUsernameRef,
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
    Authentication.getKeysOnDemand,
    Authentication.keyManagerRef,
    Authentication.loginUsernameRef,
    Database.setUsers,
    setMessages,
    Database.saveMessageToLocalDB
  );

  const signalHandler = useChatSignals({
    Authentication,
    Database,
    fileHandler,
    encryptedHandler
  });

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

  useWebSocket(signalHandler, encryptedHandler, Authentication.setLoginError);

  // Conversation management
  const {
    conversations,
    selectedConversation,
    addConversation,
    selectConversation,
    getConversationMessages,
  } = useConversations(Authentication.loginUsernameRef.current, Database.users, messages);

  // Get messages for the selected conversation
  const conversationMessages = getConversationMessages(selectedConversation);
  
  // Debug conversation state
  console.log('[Index] Conversation state:', {
    conversationsCount: conversations.length,
    selectedConversation,
    usersCount: Database.users.length,
    hasSelectedConversation: !!selectedConversation
  });

  // offline queue effects removed

  if (!Authentication.isLoggedIn) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4 bg-gradient-to-r from-gray-50 to-slate-50">
        <Login
          isGeneratingKeys={Authentication.isGeneratingKeys}
          error={Authentication.loginError}
          onAccountSubmit={Authentication.handleAccountSubmit}
          onServerPasswordSubmit={Authentication.handleServerPasswordSubmit}
          accountAuthenticated={Authentication.accountAuthenticated}
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
    <TypingIndicatorProvider currentUsername={Authentication.loginUsernameRef.current}>
      <div className="flex h-screen bg-gradient-to-r from-gray-50 to-slate-50 relative">
        <Sidebar
          currentUsername={Authentication.loginUsernameRef.current}
          onAddConversation={addConversation}
          onLogout={async () => await Authentication.logout(Database.secureDBRef)}
          onActiveTabChange={setSidebarActiveTab}
        >
          <ConversationList
            conversations={conversations}
            selectedConversation={selectedConversation}
            onSelectConversation={selectConversation}
            currentUsername={Authentication.loginUsernameRef.current}
          />
        </Sidebar>

        <div className={cn(
          "flex-1 flex flex-col transition-all duration-300",
          sidebarActiveTab === "messages" ? "ml-80" : "ml-16"
        )}>
          {selectedConversation ? (
            <ChatInterface
              messages={conversationMessages}
              setMessages={setMessages}
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
                
                // Handle typing indicator messages differently
                if (messageSignalType === 'typing-start' || messageSignalType === 'typing-stop') {
                  // For typing indicators, we need to send them as encrypted messages
                  // but they should not appear in the chat history
                  const targetUser = Database.users.find(user => user.username === selectedConversation);
                  if (!targetUser) {
                    console.error('[Index] User not found for conversation:', selectedConversation);
                    return;
                  }
                  
                  console.log('[Index] Found target user for typing indicator:', targetUser);
                  // Send typing indicator as encrypted message but don't add to chat history
                  return messageSender.handleSendMessage(targetUser, content, replyTo ? { id: replyTo.id, sender: replyTo.sender, content: replyTo.content } : undefined, undefined, messageSignalType);
                }
                
                // Find the user object for the selected conversation
                const targetUser = Database.users.find(user => user.username === selectedConversation);
                if (!targetUser) {
                  console.error('[Index] User not found for conversation:', selectedConversation);
                  return;
                }
                
                console.log('[Index] Found target user:', targetUser);
                return messageSender.handleSendMessage(targetUser, content, replyTo ? { id: replyTo.id, sender: replyTo.sender, content: replyTo.content } : undefined, undefined, messageSignalType);
              }}
              onSendFile={handleSendFileWrapper}
              isEncrypted={true}
              currentUsername={Authentication.loginUsernameRef.current}
              users={Database.users}
              selectedConversation={selectedConversation}
              saveMessageToLocalDB={Database.saveMessageToLocalDB}
            />
          ) : (
            <div className="flex-1 flex items-center justify-center">
              <div className="text-center text-gray-500">
                <h2 className="text-xl font-semibold mb-2">Welcome to endtoend</h2>
                <p>Click the messages button to view conversations or add a new chat to begin</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </TypingIndicatorProvider>
  );
};

export default ChatApp;