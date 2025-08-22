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
    Database.saveMessageToLocalDB,
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
    <TypingIndicatorProvider>
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
              onSendMessage={(messageId, content, messageSignalType, replyTo) =>
                messageSender.handleSendMessageType(messageId, content, messageSignalType, replyTo, selectedConversation)
              }
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