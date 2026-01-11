import React, { useState, useCallback, useEffect, useRef, useMemo } from "react";
import { createPortal } from "react-dom";
import { useTheme } from "next-themes";
import { Login } from "../components/chat/Login";
import { User } from "../components/chat/messaging/UserList";
import { ConversationList } from "../components/chat/messaging/ConversationList";
import { ChatInterface } from "../components/chat/messaging/ChatInterface";
import { AppSettings } from "../components/settings/AppSettings";
import { Layout } from "../components/ui/Layout";
import { CallLogs } from "../components/chat/calls/CallLogs";
import { Message } from "../components/chat/messaging/types";
import { Dialog, DialogContent } from "../components/ui/dialog";
import { EmojiPickerProvider } from "../contexts/EmojiPickerContext";
import { useCallHistory } from "../contexts/CallHistoryContext";
import { useAuth } from "../hooks/auth/useAuth";
import { useSecureDB } from "../hooks/database/useSecureDB";
import { useFileHandler } from "../hooks/file-handling/useFileHandler";
import { useMessageSender } from "../hooks/message-sending/useMessageSender";
import { useEncryptedMessageHandler } from "../hooks/message-handling/useEncryptedMessageHandler";
import { useChatSignals } from "../hooks/useChatSignals";
import { useWebSocket } from "../hooks/useWebsocket";
import { useConversations } from "../hooks/message-sending/useConversations";
import { useUsernameDisplay } from "../hooks/database/useUsernameDisplay";
import { useP2PMessaging } from "../hooks/p2p/useP2PMessaging";
import { useP2PKeys } from "../hooks/p2p/useP2PKeys";
import { useMessageReceipts } from "../hooks/message-sending/useMessageReceipts";
import websocketClient from "../lib/websocket/websocket";
import { EventType } from "../lib/types/event-types";
import { TypingIndicatorProvider } from "../contexts/TypingIndicatorContext";
import { ConnectSetup } from "../components/setup/ConnectSetup";
import { SignalType } from "../lib/types/signal-types";
import { retrieveAuthTokens } from "../lib/signals/signals";
import { syncEncryptedStorage } from "../lib/database/encrypted-storage";
import { SecurityAuditLogger } from "../lib/cryptography/audit-logger";
import { PostQuantumUtils } from "../lib/utils/pq-utils";
import { unifiedSignalTransport } from "../lib/transport/unified-signal-transport";

import {
  LOCAL_EVENT_RATE_LIMIT_WINDOW_MS,
  LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS,
} from "../lib/constants";
import { useRateLimiter } from "../hooks/useRateLimiter";
import { useLocalMessageHandlers } from "../hooks/message-handling/useLocalMessageHandlers";
import { useP2PMessageHandlers } from "../hooks/p2p/useP2PMessageHandlers";
import { useP2PConnectionManager } from "../hooks/p2p/useP2PConnectionManager";
import { useP2PSignalHandlers } from "../hooks/p2p/useP2PSignalHandlers";
import { useEventHandlers } from "../hooks/useEventHandlers";
import { Toaster } from 'sonner';
import { TorIndicator } from "../components/ui/TorIndicator";
import { Button } from "../components/ui/button";
import { ComposeIcon } from "../components/chat/assets/icons";
import { useCalling } from "../hooks/calling/useCalling";
import { useCallEventHandlers } from "../hooks/app/useCallEventHandlers";
import { useAppInitialization } from "../hooks/app/useAppInitialization";
import { useMessageActions } from "../hooks/app/useMessageActions";
import { useTokenValidation } from "../hooks/app/useTokenValidation";
import { useEncryptionProvider } from "../hooks/app/useEncryptionProvider";
import { useOfflineMessages } from "../hooks/app/useOfflineMessages";
import { useConnectionSetup } from "../hooks/app/useConnectionSetup";
import { useBackgroundResume } from "../hooks/app/useBackgroundResume";
const CallModalLazy = React.lazy(() => import("../components/chat/calls/CallModal"));

const ChatApp: React.FC = () => {
  const { allowEvent } = useRateLimiter(LOCAL_EVENT_RATE_LIMIT_WINDOW_MS, LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS);
  const [messages, setMessages] = useState<Message[]>([]);
  const { theme } = useTheme();
  const [sidebarActiveTab, setSidebarActiveTab] = useState<'chats' | 'calls' | 'settings'>('chats');
  const [setupComplete, setSetupComplete] = useState(false);
  const [selectedServerUrl, setSelectedServerUrl] = useState<string>('');
  const [showSettings, setShowSettings] = useState(false);
  const [showNewChatInput, setShowNewChatInput] = useState(false);
  const [conversationPanelWidth, setConversationPanelWidth] = useState(320);
  const [isResizing, setIsResizing] = useState(false);
  const Authentication = useAuth();
  const callHistory = useCallHistory();

  // Background resume
  const {
    isResumingFromBackground,
    serverUrl: resumeServerUrl,
    setupComplete: resumeSetupComplete,
  } = useBackgroundResume(Authentication);

  // Sync background resume state
  useEffect(() => {
    if (resumeServerUrl) setSelectedServerUrl(resumeServerUrl);
    if (resumeSetupComplete) setSetupComplete(true);
  }, [resumeServerUrl, resumeSetupComplete]);

  const Database = useSecureDB({
    Authentication,
    setMessages,
  });

  const { loadMoreConversationMessages, flushPendingSaves } = Database;

  const usersRef = useRef<User[]>([]);
  useEffect(() => {
    usersRef.current = Database.users;
  }, [Database.users]);

  useEffect(() => {
    try {
      const saved = localStorage.getItem('conversationPanelWidth');
      if (saved) {
        const width = parseInt(saved, 10);
        if (!isNaN(width) && width >= 250 && width <= 600) {
          setConversationPanelWidth(width);
        }
      }
    } catch { }
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem('conversationPanelWidth', conversationPanelWidth.toString());
    } catch { }
  }, [conversationPanelWidth]);

  const handleIncomingFileMessage = useCallback((message: Message) => {
    setMessages(prev => (prev.some(m => m.id === message.id) ? prev : [...prev, message]));
    try { void Database.saveMessageToLocalDB(message); } catch { }
  }, [setMessages, Database]);

  const fileHandler = useFileHandler(
    Authentication.getKeysOnDemand,
    handleIncomingFileMessage,
    Authentication.setLoginError,
    Database.secureDBRef
  );

  const getPeerHybridKeysRef = useRef<((peerUsername: string) => Promise<{ kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64?: string } | null>) | null>(null);
  const p2pServiceRef = useRef<any>(null);

  const messageSender = useMessageSender(
    Database.users,
    Authentication.loginUsernameRef,
    Authentication.username || Authentication.loginUsernameRef.current || '',
    Authentication.originalUsernameRef,
    (message: Message) => {
      setMessages(prev => (prev.some(m => m.id === message.id) ? prev : [...prev, message]));
    },
    Authentication.serverHybridPublic,
    Authentication.getKeysOnDemand,
    Authentication.aesKeyRef,
    Authentication.keyManagerRef,
    Authentication.passphrasePlaintextRef,
    Authentication.isLoggedIn,
    async (hashedUsername: string) => {
      try {
        const db = Database.secureDBRef.current;
        if (!db) return false;
        const original = await db.getOriginalUsername(hashedUsername);
        return !!original;
      } catch {
        return false;
      }
    },
    Database.secureDBRef,
    async (peerUsername: string) => {
      if (getPeerHybridKeysRef.current) {
        return getPeerHybridKeysRef.current(peerUsername);
      }
      return null;
    },
    p2pServiceRef
  );


  const encryptedHandler = useEncryptedMessageHandler(
    Authentication.loginUsernameRef,
    setMessages,
    Database.saveMessageToLocalDB,
    Authentication.isLoggedIn && Authentication.accountAuthenticated,
    Authentication.getKeysOnDemand,
    usersRef,
    undefined,
    fileHandler.handleFileMessageChunk,
    Database.secureDBRef
  );

  const encryptedHandlerRef = useRef(encryptedHandler);
  useEffect(() => {
    encryptedHandlerRef.current = encryptedHandler;
  }, [encryptedHandler]);

  // Offline message handling
  useOfflineMessages({
    encryptedHandlerRef,
    hybridKeysRef: Authentication.hybridKeysRef,
  });

  const {
    sendReadReceipt: sendServerReadReceipt,
    markMessageAsRead,
    getSmartReceiptStatus,
  } = useMessageReceipts(
    messages,
    setMessages,
    Authentication.loginUsernameRef.current || '',
    Database.saveMessageToLocalDB,
    websocketClient,
    Database.users,
    Authentication.getKeysOnDemand,
    Database.secureDBRef,
  );

  const signalHandler = useChatSignals({
    Authentication,
    Database,
    fileHandler,
    encryptedHandler,
  });

  const {
    conversations,
    selectedConversation,
    addConversation,
    selectConversation,
    removeConversation,
    getConversationMessages,
  } = useConversations(Authentication.username || Authentication.loginUsernameRef.current || '', Database.users, messages, Database.secureDBRef.current);

  useEffect(() => {
    if (selectedConversation && typeof messageSender?.prefetchSessionForPeer === 'function') {
      try { messageSender.prefetchSessionForPeer(selectedConversation); } catch { }
    }
  }, [selectedConversation, messageSender]);

  const usernameDisplay = useUsernameDisplay(
    Database.secureDBRef.current,
    Authentication.originalUsernameRef.current
  );

  const getDisplayUsernameRef = useRef(usernameDisplay.getDisplayUsername);
  useEffect(() => {
    getDisplayUsernameRef.current = usernameDisplay.getDisplayUsername;
  }, [usernameDisplay.getDisplayUsername]);

  const stableGetDisplayUsername = useCallback(
    (username: string) => getDisplayUsernameRef.current(username),
    []
  );

  const [currentDisplayName, setCurrentDisplayName] = useState<string>('');
  useEffect(() => {
    (async () => {
      try {
        const raw = Authentication.originalUsernameRef.current || Authentication.loginUsernameRef.current || '';
        if (!raw) { setCurrentDisplayName(''); return; }
        const dn = await usernameDisplay.getDisplayUsername(raw);
        if (typeof dn === 'string') setCurrentDisplayName(dn);
      } catch { }
    })();
  }, [Authentication.originalUsernameRef.current, Authentication.loginUsernameRef.current, usernameDisplay]);

  const kyberSecretRefForSettings = useMemo(() => {
    const kyberSecret = Authentication.hybridKeysRef?.current?.kyber?.secretKey;
    return { current: kyberSecret || null };
  }, [Authentication.hybridKeysRef?.current?.kyber?.secretKey]);

  const {
    p2pHybridKeys,
    fetchPeerCertificates,
    getPeerHybridKeys,
    trustedIssuerDilithiumPublicKeyBase64,
    signalingTokenProvider,
    username: p2pUsername,
  } = useP2PKeys(
    {
      hybridKeysRef: Authentication.hybridKeysRef,
      loginUsernameRef: Authentication.loginUsernameRef,
      serverHybridPublic: Authentication.serverHybridPublic,
    },
    {
      secureDBRef: Database.secureDBRef,
      users: Database.users,
    }
  );

  useEffect(() => {
    getPeerHybridKeysRef.current = getPeerHybridKeys;
  }, [getPeerHybridKeys]);

  const callingHook = useCalling(Authentication, { getPeerKeys: getPeerHybridKeys });

  const p2pMessaging = useP2PMessaging(
    p2pUsername,
    p2pHybridKeys,
    {
      fetchPeerCertificates,
      signalingTokenProvider,
      trustedIssuerDilithiumPublicKeyBase64,
      onServiceReady: (service) => {
        try { (window as any).p2pService = service; } catch { }
        p2pServiceRef.current = service;
      }
    }
  );

  // Update P2P sender whenever sendP2PMessage changes or service becomes ready
  useEffect(() => {
    if (p2pMessaging.sendP2PMessage && p2pServiceRef.current && p2pMessaging.p2pStatus.isInitialized) {
      unifiedSignalTransport.setP2PSender(async (to, payload, type) => {
        await p2pMessaging.sendP2PMessage(to, payload, undefined, { messageType: type as any });
      });
    } else {
      unifiedSignalTransport.setP2PSender(null as any);
    }
  }, [p2pMessaging.sendP2PMessage, p2pMessaging.p2pStatus.isInitialized]);

  const getOrCreateUser = useCallback((username: string): User => {
    let targetUser = Database.users.find(user => user.username === username);
    if (!targetUser) {
      targetUser = {
        id: crypto.randomUUID(),
        username,
        isOnline: false,
        hybridPublicKeys: undefined
      };
      Database.setUsers(prev => [...prev, targetUser!]);
    }
    return targetUser;
  }, [Database.users, Database.setUsers]);

  const saveMessageWithContext = useCallback(
    (message: Message) => {
      const peer = selectedConversation || undefined;
      return Database.saveMessageToLocalDB(message, peer);
    },
    [selectedConversation, Database.saveMessageToLocalDB]
  );

  // Event handling
  useLocalMessageHandlers({
    setMessages,
    saveMessageWithContext,
    secureDBRef: Database.secureDBRef,
    allowEvent,
  });

  useP2PMessageHandlers({
    p2pMessaging,
    setMessages,
    saveMessageWithContext,
    loginUsernameRef: Authentication.loginUsernameRef,
  });

  // Pre-fetch peer keys for calling when conversation opens
  useEffect(() => {
    if (selectedConversation && getPeerHybridKeys && callingHook?.callingService) {
      getPeerHybridKeys(selectedConversation).then(keys => {
        if (keys && callingHook.callingService) {
          const service = callingHook.callingService;
          const peer = selectedConversation;

          try {
            const peerKeys = {
              username: peer,
              dilithiumPublicKey: PostQuantumUtils.base64ToUint8Array(keys.dilithiumPublicBase64),
              kyberPublicKey: PostQuantumUtils.base64ToUint8Array(keys.kyberPublicBase64),
              x25519PublicKey: keys.x25519PublicBase64 ? PostQuantumUtils.base64ToUint8Array(keys.x25519PublicBase64) : undefined
            };

            if (peerKeys.dilithiumPublicKey.length > 0 && peerKeys.kyberPublicKey.length > 0) {
              service.setPeerKeys(peer, peerKeys as any);
            }
          } catch (e) {
            console.warn('[Index] Failed to pre-cache keys for calling:', e);
          }
        }
      }).catch(() => { });
    }
  }, [selectedConversation, getPeerHybridKeys, callingHook.callingService]);

  useP2PConnectionManager({
    isLoggedIn: Authentication.isLoggedIn,
    selectedServerUrl,
    p2pHybridKeys,
    selectedConversation,
    p2pMessaging,
  });

  useP2PSignalHandlers({ p2pMessaging });

  useEventHandlers({
    allowEvent,
    users: Database.users,
    setUsers: Database.setUsers,
    setMessages,
    messageSender,
    Authentication,
    Database,
  });

  // E2E Encryption Provider
  useEncryptionProvider({
    isLoggedIn: Authentication.isLoggedIn,
    loginUsernameRef: Authentication.loginUsernameRef,
    getPeerHybridKeys,
    users: Database.users,
  });

  // Message actions
  const { onSendMessage, onSendFile } = useMessageActions({
    selectedConversation,
    getOrCreateUser,
    messageSender,
    p2pMessaging,
    setMessages,
    saveMessageWithContext,
    loginUsernameRef: Authentication.loginUsernameRef,
    users: Database.users,
    saveMessageToLocalDB: Database.saveMessageToLocalDB,
  });

  // Call event handlers
  useCallEventHandlers({
    stableGetDisplayUsername,
    setMessages,
    selectedConversation,
    saveMessageToLocalDB: Database.saveMessageToLocalDB,
    startCall: callingHook.startCall,
    callHistory,
  });

  // App initialization
  useAppInitialization({
    Authentication,
    Database,
    fileHandler,
    encryptedHandlerRef,
    flushPendingSaves,
    setShowSettings,
  });

  // Token validation
  useTokenValidation({
    Authentication,
    setupComplete,
    selectedServerUrl,
  });

  // Get messages for the selected conversation
  const conversationMessagesCacheRef = useRef(new Map<string, { arr: Message[]; length: number; lastId?: string; lastTs?: number; receiptHash?: string; reactionHash?: string; contentHash?: string }>());
  const conversationMessages = useMemo(() => {
    const peer = selectedConversation || '';
    if (!peer) return [] as Message[];
    const fresh = getConversationMessages(peer);
    const last = fresh[fresh.length - 1];
    const lastId = last?.id;
    const lastTs = last?.timestamp instanceof Date ? last.timestamp.getTime() : (last?.timestamp ? new Date(last.timestamp as any).getTime() : undefined);
    const receiptHash = fresh
      .filter(m => m.receipt)
      .map(m => `${m.id}:${m.receipt?.delivered ? 'd' : ''}${m.receipt?.read ? 'r' : ''}`)
      .join('|');
    const reactionHash = fresh
      .filter(m => m.reactions && Object.keys(m.reactions).length > 0)
      .map(m => {
        const sorted = Object.entries(m.reactions || {})
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([emoji, users]) => `${emoji}:${users.sort().join(',')}`);
        return `${m.id}:${sorted.join(';')}`;
      })
      .join('|');

    const contentHash = fresh
      .map(m => `${m.id}:${m.isEdited ? 'e' : ''}${m.isDeleted ? 'd' : ''}:${m.content?.substring(0, 50)}`)
      .join('|');
    const cache = conversationMessagesCacheRef.current.get(peer);
    if (cache && cache.length === fresh.length && cache.lastId === lastId && cache.lastTs === lastTs && cache.receiptHash === receiptHash && cache.reactionHash === reactionHash && cache.contentHash === contentHash) {
      return cache.arr;
    }
    conversationMessagesCacheRef.current.set(peer, { arr: fresh, length: fresh.length, lastId, lastTs, receiptHash, reactionHash, contentHash });
    return fresh;
  }, [selectedConversation, messages]);

  const p2pConnectedPeers = p2pMessaging?.p2pStatus?.connectedPeers ?? [];
  const p2pConnectedStatus = useMemo(() => {
    if (!selectedConversation || !p2pMessaging?.isPeerConnected) return false;
    return p2pMessaging.isPeerConnected(selectedConversation);
  }, [selectedConversation, p2pConnectedPeers.includes(selectedConversation)]);

  const handleConnectSetupComplete = async (serverUrl: string) => {
    try {
      const storedUsername = syncEncryptedStorage.getItem('last_authenticated_username');
      const tokens = await retrieveAuthTokens();
      const hasExistingSession = !!(storedUsername || (tokens?.accessToken && tokens?.refreshToken));

      if (hasExistingSession) {
        Authentication.setTokenValidationInProgress(true);
      }

      setSelectedServerUrl(serverUrl);
      await (window as any).edgeApi?.wsConnect?.();
      setSetupComplete(true);
    } catch (_error) {
      SecurityAuditLogger.log(SignalType.ERROR, 'connect-setup-failed', { error: _error instanceof Error ? _error.message : 'unknown' });
    }
  };

  // Connection setup
  useConnectionSetup({
    setupComplete,
    selectedServerUrl,
    Authentication,
    Database,
  });

  useWebSocket(signalHandler, encryptedHandler, Authentication.setLoginError);

  useEffect(() => {
    const handleAuthUiBack = async (event: CustomEvent) => {
      try {
        const to = (event as any).detail?.to as 'server' | undefined;
        if (to === 'server') {
          try { await (window as any).electronAPI?.wsDisconnect?.(); } catch { }
          setSelectedServerUrl('');
          setSetupComplete(false);
        }
      } catch (_e) {
        console.error('[Index] Failed to handle auth-ui-back (server):', _e);
      }
    };
    window.addEventListener(EventType.AUTH_UI_BACK, handleAuthUiBack as EventListener);
    return () => window.removeEventListener(EventType.AUTH_UI_BACK, handleAuthUiBack as EventListener);
  }, []);

  if (isResumingFromBackground) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4 bg-white dark:bg-[hsl(var(--background))] select-none">
        <div className="text-center text-sm" style={{ color: 'var(--color-text-secondary)' }}>
          Resuming...
        </div>
      </div>
    );
  }

  if (!setupComplete || !selectedServerUrl) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4 bg-white dark:bg-[hsl(var(--background))]">
        <div className="w-full max-w-2xl">
          <ConnectSetup onComplete={handleConnectSetupComplete} initialServerUrl={selectedServerUrl} />
        </div>
        <Toaster position="top-right" theme={theme as any} richColors toastOptions={{ className: 'select-none', style: { width: 'fit-content', maxWidth: '400px', minWidth: '0px' } }} />
      </div>
    );
  }

  const isFullyAuthenticated = Authentication.isLoggedIn && Authentication.accountAuthenticated;
  const showValidationScreen = Authentication.tokenValidationInProgress && !isFullyAuthenticated;
  const showLoginScreen = !showValidationScreen && (
    !Authentication.isLoggedIn ||
    (!isFullyAuthenticated && (Authentication.showPassphrasePrompt || Authentication.showPasswordPrompt))
  );

  if (showValidationScreen) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4 bg-white dark:bg-[hsl(var(--background))] select-none">
        <div className="text-center text-sm" style={{ color: 'var(--color-text-secondary)' }}>
          Validating session...
        </div>
      </div>
    );
  }

  if (showLoginScreen) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4 bg-white dark:bg-[hsl(var(--background))]">
        <Login
          isGeneratingKeys={Authentication.isGeneratingKeys}
          authStatus={Authentication.authStatus}
          error={Authentication.loginError}
          onAccountSubmit={Authentication.handleAccountSubmit}
          onServerPasswordSubmit={Authentication.handleServerPasswordSubmit}
          onPasswordHashSubmit={Authentication.handlePasswordHashSubmit}
          accountAuthenticated={Authentication.accountAuthenticated}
          isRegistrationMode={Authentication.isRegistrationMode}
          serverTrustRequest={Authentication.serverTrustRequest}
          onAcceptServerTrust={Authentication.acceptServerTrust}
          onRejectServerTrust={Authentication.rejectServerTrust}
          showPassphrasePrompt={Authentication.showPassphrasePrompt}
          setShowPassphrasePrompt={Authentication.setShowPassphrasePrompt}
          showPasswordPrompt={Authentication.showPasswordPrompt}
          setShowPasswordPrompt={Authentication.setShowPasswordPrompt}
          onPassphraseSubmit={Authentication.handlePassphraseSubmit}
          initialUsername={Authentication.originalUsernameRef.current || ''}
          initialPassword={Authentication.passwordRef.current || ''}
          maxStepReached={Authentication.maxStepReached}

          pseudonym={Authentication.loginUsernameRef.current || ''}
        />
        <Toaster position="top-right" theme={theme as any} richColors toastOptions={{ className: 'select-none', style: { width: 'fit-content', maxWidth: '400px', minWidth: '0px' } }} />
      </div>
    );
  }

  // Wait for DB initialization before showing the main app
  if (!Database.dbInitialized) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4 bg-white dark:bg-[hsl(var(--background))] select-none">
        <div className="text-center text-sm" style={{ color: 'var(--color-text-secondary)' }}>
          Initializing secure storage...
        </div>
      </div>
    );
  }

  return (
    <TypingIndicatorProvider currentUsername={Authentication.loginUsernameRef.current || ''}>
      <Layout
        activeTab={sidebarActiveTab as 'chats' | 'calls' | 'settings'}
        onTabChange={(tab) => {
          if (tab === 'settings') {
            setShowSettings(true);
          } else {
            setSidebarActiveTab(tab);
          }
        }}
        currentUser={{
          username: currentDisplayName || Authentication.originalUsernameRef.current || Authentication.loginUsernameRef.current || '',
          avatarUrl: undefined
        }}
        onLogout={async () => await Authentication.logout(Database.secureDBRef)}
      >
        <div className="h-full w-full relative">
          <div className={sidebarActiveTab === 'chats' ? 'h-full w-full' : 'hidden'}>
            <div className="flex h-full">
              <div
                className="border-r border-border hidden md:flex flex-col relative"
                style={{ width: `${conversationPanelWidth}px`, minWidth: '200px', maxWidth: '600px', backgroundColor: 'var(--chats-section-bg)' }}
              >
                {/* Resize Handle */}
                <div
                  className="absolute top-0 right-0 w-1 h-full cursor-col-resize hover:bg-primary/30 transition-colors select-none z-10"
                  onMouseDown={(e) => {
                    e.preventDefault();
                    setIsResizing(true);
                    const startX = e.clientX;
                    const startWidth = conversationPanelWidth;

                    const handleMouseMove = (moveEvent: MouseEvent) => {
                      requestAnimationFrame(() => {
                        const delta = moveEvent.clientX - startX;
                        const newWidth = Math.min(600, Math.max(250, startWidth + delta));
                        setConversationPanelWidth(newWidth);
                      });
                    };

                    const handleMouseUp = () => {
                      setIsResizing(false);
                      document.removeEventListener('mousemove', handleMouseMove);
                      document.removeEventListener('mouseup', handleMouseUp);
                    };

                    document.addEventListener('mousemove', handleMouseMove);
                    document.addEventListener('mouseup', handleMouseUp);
                  }}
                  style={{ cursor: isResizing ? 'col-resize' : undefined }}
                />

                <div className="p-4 border-b border-border flex items-center justify-between">
                  <h2 className="font-semibold text-lg select-none">Chats</h2>
                  <div className="flex items-center gap-2">
                    <TorIndicator />
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => setShowNewChatInput(!showNewChatInput)}
                      className="h-8 w-8"
                      onMouseEnter={(e) => {
                        e.currentTarget.style.transform = 'scale(1.15) rotate(0deg)';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.transform = 'scale(1) rotate(0deg)';
                      }}
                      style={{ transition: 'transform 0.2s cubic-bezier(0.34, 1.56, 0.64, 1)', transformOrigin: 'center' }}
                    >
                      <ComposeIcon className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
                <div className="flex-1 overflow-hidden">
                  <ConversationList
                    conversations={conversations}
                    selectedConversation={selectedConversation || undefined}
                    onSelectConversation={selectConversation}
                    onAddConversation={async (username) => {
                      await addConversation(username);
                      setShowNewChatInput(false);
                    }}
                    getDisplayUsername={stableGetDisplayUsername}
                    showNewChatInput={showNewChatInput}
                    onRemoveConversation={removeConversation}
                  />
                </div>
              </div>

              <div className="flex-1 flex flex-col min-w-0 bg-background">
                {selectedConversation ? (
                  <EmojiPickerProvider>
                    <ChatInterface
                      messages={conversationMessages}
                      setMessages={setMessages}
                      callingAuthContext={Authentication}
                      currentCall={callingHook.currentCall}
                      startCall={callingHook.startCall}
                      currentUsername={Authentication.loginUsernameRef.current || ''}
                      getDisplayUsername={stableGetDisplayUsername}
                      getKeysOnDemand={Authentication.getKeysOnDemand}
                      getPeerHybridKeys={getPeerHybridKeys}
                      p2pConnected={p2pConnectedStatus}
                      loadMoreMessages={loadMoreConversationMessages}
                      sendP2PReadReceipt={p2pMessaging.sendP2PReadReceipt}
                      sendServerReadReceipt={sendServerReadReceipt}
                      markMessageAsRead={markMessageAsRead}
                      getSmartReceiptStatus={getSmartReceiptStatus}
                      secureDB={Database.secureDBRef.current}
                      onSendMessage={onSendMessage}
                      onSendFile={onSendFile}
                      isEncrypted={true}
                      users={Database.users}
                      selectedConversation={selectedConversation}
                      saveMessageToLocalDB={saveMessageWithContext}
                    />
                  </EmojiPickerProvider>
                ) : (
                  <div className="flex-1 flex items-center justify-center text-muted-foreground">
                    <div className="text-center">
                      <div className="w-12 h-12 mx-auto mb-4 opacity-20 bg-gray-400 rounded-full flex items-center justify-center">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a 2 2 0 0 1 2 -2h14a2 2 0 0 1 2 2z" /></svg>
                      </div>
                      <p className="select-none">Select a conversation to start chatting</p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className={sidebarActiveTab === 'calls' ? 'h-full w-full' : 'hidden'}>
            <CallLogs getDisplayUsername={stableGetDisplayUsername} />
          </div>
        </div>

        {/* Settings Modal */}
        <Dialog open={showSettings} onOpenChange={setShowSettings}>
          <DialogContent className="max-w-4xl max-h-[90vh] overflow-hidden p-0">
            <AppSettings
              passphraseRef={Authentication.passphrasePlaintextRef}
              kyberSecretRef={kyberSecretRefForSettings as any}
              getDisplayUsername={stableGetDisplayUsername}
              currentUsername={Authentication.loginUsernameRef.current || ''}
              currentDisplayName={currentDisplayName || Authentication.originalUsernameRef.current || ''}
            />
          </DialogContent>
        </Dialog>
      </Layout>
      <Toaster position="top-right" theme={theme as any} richColors toastOptions={{ className: 'select-none', style: { width: 'fit-content', maxWidth: '400px', minWidth: '0px' } }} />
      {
        callingHook.currentCall && createPortal(
          <React.Suspense fallback={null}>
            <CallModalLazy
              call={callingHook.currentCall}
              localStream={callingHook.localStream}
              remoteStream={callingHook.remoteStream}
              remoteScreenStream={callingHook.remoteScreenStream}
              onAnswer={() => callingHook.currentCall && callingHook.answerCall(callingHook.currentCall.id, callingHook.currentCall.peer)}
              onDecline={() => callingHook.currentCall && callingHook.declineCall(callingHook.currentCall.id)}
              onEndCall={callingHook.endCall}
              onToggleMute={callingHook.toggleMute}
              onToggleVideo={callingHook.toggleVideo}
              onStartScreenShare={callingHook.startScreenShare}
              onStopScreenShare={callingHook.stopScreenShare}
              onGetAvailableScreenSources={callingHook.getAvailableScreenSources}
              isScreenSharing={callingHook.isScreenSharing}
              onSwitchCamera={callingHook.switchCamera}
              onSwitchMicrophone={callingHook.switchMicrophone}
              getDisplayUsername={async (u) => stableGetDisplayUsername(u)}
            />
          </React.Suspense>,
          document.body
        )
      }
    </TypingIndicatorProvider>
  );
};

export default ChatApp;