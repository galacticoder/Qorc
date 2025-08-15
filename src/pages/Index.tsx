import { useState, useRef, useCallback } from "react";
import { Login } from "@/components/chat/Login";
import { UserList } from "@/components/chat/UserList";
import { ChatInterface } from "@/components/chat/ChatInterface";
import { Message } from "@/components/chat/types";

import { useAuth } from "@/hooks/useAuth";
import { useSecureDB } from "@/hooks/useSecureDB";
import { useFileHandler } from "@/hooks/useFileHandler";
import { useMessageSender } from "@/hooks/useMessageSender";
import { useEncryptedMessageHandler } from "@/hooks/useEncryptedMessageHandler";
import { useChatSignals } from "@/hooks/useChatSignals";
import { useWebSocket } from "@/hooks/useWebsocket";

interface ChatAppProps {
  onNavigate: (page: "home" | "server" | "chat") => void;
}

const ChatApp: React.FC<ChatAppProps> = ({ onNavigate }) => {
  const [messages, setMessages] = useState<Message[]>([]);

  const Authentication = useAuth();
  const Database = useSecureDB({
    Authentication,
    messages,
    setMessages,
  });
  const fileHandler = useFileHandler(
    Authentication.privateKeyRef,
    Database.saveMessageToLocalDB,
    Authentication.setLoginError
  );

  const messageSender = useMessageSender(
    Database.users,
    Authentication.loginUsernameRef,
    Database.saveMessageToLocalDB,
    Authentication.aesKeyRef.current,
    Authentication.serverPublicKeyPEM,
  );

  const encryptedHandler = useEncryptedMessageHandler(
    Authentication.privateKeyRef,
    Database.setUsers,
    setMessages,
    Database.saveMessageToLocalDB
  );

  const signalHandler = useChatSignals({ Authentication, Database, fileHandler, encryptedHandler });

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

  if (!Authentication.isLoggedIn) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4 bg-gradient-to-r from-gray-50 to-slate-50">
        <Login
          isGeneratingKeys={Authentication.isGeneratingKeys}
          error={Authentication.loginError}
          onAccountSubmit={Authentication.handleAccountSubmit}
          onServerPasswordSubmit={Authentication.handleServerPasswordSubmit}
          accountAuthenticated={Authentication.accountAuthenticated}
          showPassphrasePrompt={Authentication.showPassphrasePrompt}
          setShowPassphrasePrompt={Authentication.setShowPassphrasePrompt}
          onPassphraseSubmit={Authentication.handlePassphraseSubmit}
        />
      </div>
    );
  }

  return (
    <div className="flex flex-col h-screen p-4 md:p-6 bg-gradient-to-r from-gray-50 to-slate-50">
      <header className="mb-4 flex justify-between items-center">
        <h1 className="text-2xl font-bold">SecureChat</h1>
        <button
          onClick={Authentication.useLogout}
          className="px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition"
        >
          Logout
        </button>
      </header>

      <div className="flex flex-1 gap-4 h-[calc(100vh-150px)]">
        <div className="hidden md:block w-64">
          <UserList users={Database.users} currentUser={Authentication.loginUsernameRef.current} />
        </div>

        <div className="flex-1">
          <ChatInterface
            messages={messages}
            onSendMessage={messageSender.handleSendMessageType}
            onSendFile={handleSendFileWrapper}
            isEncrypted={true}
            currentUsername={Authentication.loginUsernameRef.current}
            users={Database.users}
          />
        </div>
      </div>
    </div>
  );
};

export default ChatApp;
