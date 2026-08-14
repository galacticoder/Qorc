import React, { useState, useCallback, useEffect, useLayoutEffect, useRef, useMemo } from "react";
import { createPortal } from "react-dom";
import { useTheme } from '../contexts/ThemeContext';
import { Login } from "../components/chat/Login";
import { PeerIdentityVerificationAlert } from "../components/chat/PeerIdentityVerificationAlert";
import { User } from "../components/chat/messaging/UserList";
import { ConversationList } from "../components/chat/messaging/ConversationList";
import { ChatInterface } from "../components/chat/messaging/ChatInterface";
import { EmptyChatView } from "../components/chat/messaging/EmptyChatView";
import { Layout } from "../components/ui/Layout";
import { Message } from "../components/chat/messaging/types";
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
import { useDisplayUsername } from "../hooks/database/useDisplayUsername";
import { useP2PMessaging } from "../hooks/p2p/useP2PMessaging";
import { useP2PKeys } from "../hooks/p2p/useP2PKeys";
import { useMessageReceipts } from "../hooks/message-sending/useMessageReceipts";
import websocketClient from "../lib/websocket/websocket";
import { EventType } from "../lib/types/event-types";
import { blockingSystem } from "../lib/blocking/blocking-system";
import { TypingIndicatorProvider } from "../contexts/TypingIndicatorContext";
import { ConnectSetup } from "../components/setup/ConnectSetup";
import { SignalType } from "../lib/types/signal-types";
import { isExplicitlyLoggedOut } from "../lib/auth/logout-marker";
import { loadLastAuthenticatedAccount } from "../lib/security/local-account-scope";
import { shouldAttemptDiscovery } from "../lib/utils/discovery-utils";
import { computePeerCertificateFingerprint, isSelfSignedPeerCertificate } from "../lib/utils/peer-certificate-utils";
import { resolveTrustedPeerHybridPublicKeys } from "../lib/utils/signal-bundle-utils";
import { isLiveOnlySignalType, unifiedSignalTransport } from "../lib/transport/unified-signal-transport";
import { websocket, isTauri, tray } from "../lib/tauri-bindings";
import type { PeerCertificateBundle } from "../lib/types/p2p-types";

import {
  LOCAL_EVENT_RATE_LIMIT_WINDOW_MS,
  LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS,
} from "../lib/constants";
import { useRateLimiter } from "../hooks/useRateLimiter";
import { useLocalMessageHandlers } from "../hooks/message-handling/useLocalMessageHandlers";
import { useEventHandlers } from "../hooks/useEventHandlers";
import { Toaster, toast } from 'sonner';
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
import { useDiscovery } from "../hooks/discovery/useDiscovery";
import { keyTransparencyClient } from "../lib/key-transparency/client";
import { captureKeyTransparencyPeerAuthorization } from "../lib/key-transparency/verified-material";
import { getInstanceLocalStorageItem, setInstanceLocalStorageItem } from "../lib/runtime/instance-storage";
import { boundMessageState, releaseUnretainedVaultEntries } from "../lib/utils/message-state-limits";
import { hasResumeToken } from "../lib/signals/resume-tokens";
import { p2pTransport } from "../lib/transport/p2p-transport";
import { loadPersistedPeerEndpoint } from "../lib/p2p/persisted-peer-cert";

const COLD_SEND_P2P_DIAL_BUDGET_MS = 3000;

const CallModalLazy = React.lazy(() => import("../components/chat/calls/CallModal"));
const AppSettingsLazy = React.lazy(() =>
  import("../components/settings/AppSettings").then(({ AppSettings }) => ({ default: AppSettings }))
);
const CallLogsLazy = React.lazy(() =>
  import("../components/chat/calls/CallLogs").then(({ CallLogs }) => ({ default: CallLogs }))
);

const ChatApp: React.FC = () => {
  const { allowEvent } = useRateLimiter(LOCAL_EVENT_RATE_LIMIT_WINDOW_MS, LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS);
  const [messages, setMessagesState] = useState<Message[]>([]);
  const messagesRef = useRef<Message[]>([]);
  const setMessages = useMemo(() => {
    const fn = ((action: React.SetStateAction<Message[]>) => {
      const prev = messagesRef.current;
      const next = typeof action === 'function'
        ? (action as (p: Message[]) => Message[])(prev)
        : action;
      const bounded = boundMessageState(next);
      releaseUnretainedVaultEntries(prev, next, bounded);
      messagesRef.current = bounded;
      setMessagesState(bounded);
    }) as React.Dispatch<React.SetStateAction<Message[]>> & { __peek: () => Message[] };
    fn.__peek = () => messagesRef.current;
    return fn;
  }, []);
  
  useEffect(() => { messagesRef.current = messages; }, [messages]);
  const { theme } = useTheme();
  const [sidebarActiveTab, setSidebarActiveTab] = useState<'chats' | 'calls' | 'settings'>('chats');
  const [setupComplete, setSetupComplete] = useState(false);
  const [showServerSetup, setShowServerSetup] = useState(false);
  const [selectedServerUrl, setSelectedServerUrl] = useState<string>('');
  const [showSettings, setShowSettings] = useState(false);
  const [showNewChatInput, setShowNewChatInput] = useState(false);
  const [conversationPanelWidth, setConversationPanelWidth] = useState(344);
  const [isResizing, setIsResizing] = useState(false);
  const Authentication = useAuth();
  const callHistory = useCallHistory();

  // Discovery Service
  const discoveryUsername = Authentication.isLoggedIn ? Authentication.loginUsernameRef.current || undefined : undefined;
  const { findUser, ensurePublished } = useDiscovery(
    discoveryUsername,
    Authentication.hybridKeysRef
  );
  const [authorizationRestoreReadyFor, setAuthorizationRestoreReadyFor] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setAuthorizationRestoreReadyFor(null);
    if (!Authentication.isLoggedIn || !discoveryUsername) return;
    keyTransparencyClient.startContactMonitoring(discoveryUsername);

    void keyTransparencyClient.restorePersistedAuthorizations(discoveryUsername)
      .then(() => {
        if (!cancelled) setAuthorizationRestoreReadyFor(discoveryUsername);
      })
      .catch(() => {
        if (!cancelled) setAuthorizationRestoreReadyFor(discoveryUsername);
      });
    return () => {
      cancelled = true;
      keyTransparencyClient.stopContactMonitoring(discoveryUsername);
    };
  }, [Authentication.isLoggedIn, discoveryUsername]);

  // Background resume
  const {
    isResumingFromBackground,
    serverUrl: resumeServerUrl,
    setupComplete: resumeSetupComplete,
  } = useBackgroundResume(Authentication);

  // Sync background resume state
  useEffect(() => {
    if (resumeServerUrl) setSelectedServerUrl(resumeServerUrl);
    if (resumeSetupComplete) {
      setSetupComplete(true);
      setShowServerSetup(false);
    }
  }, [resumeServerUrl, resumeSetupComplete]);

  // Clear tray unread badge when window gains focus
  useEffect(() => {
    const handleFocus = () => {
      tray.clearUnread().catch(() => { });
    };
    window.addEventListener('focus', handleFocus);
    return () => window.removeEventListener('focus', handleFocus);
  }, []);

  const Database = useSecureDB({
    Authentication,
    setMessages,
  });

  const { loadMoreConversationMessages, flushPendingSaves } = Database;

  const usersRef = useRef<User[]>([]);
  const discoveryWarmedPeersRef = useRef<Set<string>>(new Set());
  const p2pWarmedPeersRef = useRef<Set<string>>(new Set());
  const activeConversationRef = useRef<string | null>(null);
  useLayoutEffect(() => {
    usersRef.current = Database.users;
  }, [Database.users]);
  const fetchPeerCertificates = useCallback(async (peer: string, bypassCache = false): Promise<PeerCertificateBundle | null> => {
    if (!peer) return null;
    try {
      const account = Authentication.loginUsernameRef.current || '';
      if (!account) return null;
      if (!shouldAttemptDiscovery(peer)) {
        return null;
      }
      const material = await findUser(peer, { forceRefresh: bypassCache });
      if (Authentication.loginUsernameRef.current !== account) return null;
      const cert = material?.peerCertificate || null;
      if (!cert) {
        return null;
      }
      if (!isSelfSignedPeerCertificate(cert)) {
        return null;
      }
      const trusted = await resolveTrustedPeerHybridPublicKeys(account, peer, material);
      if (
        Authentication.loginUsernameRef.current !== account ||
        !trusted.valid ||
        !trusted.hybridKeys
      ) return null;
      const fingerprint = computePeerCertificateFingerprint(cert);
      if (
        trusted.peerCertificateFingerprint !== fingerprint ||
        !trusted.identityRootFingerprint
      ) return null;

      const verifiedAt = Date.now();
      Database.setUsers(prev => {
        const idx = prev.findIndex(u => u.username === peer);
        const nextUser: User = {
          ...(idx >= 0 ? prev[idx] : { id: crypto.randomUUID(), username: peer }),
          hybridPublicKeys: trusted.hybridKeys!,
          peerCertificateFingerprint: fingerprint,
          peerCertificateVerifiedAt: verifiedAt,
          identityRootFingerprint: trusted.identityRootFingerprint,
          identityBundleFingerprint: trusted.identityBundleFingerprint,
        };
        if (idx < 0) return [...prev, nextUser];
        const next = [...prev];
        next[idx] = nextUser;
        return next;
      });

      return cert;
    } catch {
      return null;
    }
  }, [findUser, Database.users, Database.setUsers]);

  useEffect(() => {
    (async () => {
      try {
        const savedUrl = await websocket.getServerUrl();
        if (savedUrl) {
          setSelectedServerUrl(savedUrl);
        }
      } catch (err) {
        console.error('[Index] Failed to load initial server URL:', err);
      }
    })();
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const saved = await getInstanceLocalStorageItem('conversationPanelWidth');
        if (cancelled || !saved) return;
        const width = parseInt(saved, 10);
        if (!isNaN(width) && width >= 260 && width <= 520) {
          setConversationPanelWidth(width);
        }
      } catch { }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    void setInstanceLocalStorageItem('conversationPanelWidth', conversationPanelWidth.toString()).catch(() => { });
  }, [conversationPanelWidth]);

  const handleIncomingFileMessage = useCallback((message: Message) => {
    setMessages(prev => (prev.some(m => m.id === message.id) ? prev : [...prev, message]));
  }, [setMessages]);

  const fileHandler = useFileHandler(
    Authentication.getKeysOnDemand,
    handleIncomingFileMessage,
    Authentication.setLoginError,
    Database.secureDBRef,
    usersRef,
    findUser,
    Authentication.isLoggedIn
      ? (Authentication.loginUsernameRef.current || Authentication.username || null)
      : null
  );

  const p2pServiceRef = useRef<any>(null);

  const messageSender = useMessageSender(
    Database.users,
    Authentication.loginUsernameRef,
    Authentication.loginUsernameRef.current || '',
    (message: Message) => {
      setMessages(prev => (prev.some(m => m.id === message.id) ? prev : [...prev, message]));
    },
    Authentication.isLoggedIn,
    Database.secureDBRef,
    findUser
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
    Database.secureDBRef,
    findUser,
    Database.dbInitialized,
    activeConversationRef,
  );

  const encryptedHandlerRef = useRef(encryptedHandler);
  useLayoutEffect(() => {
    encryptedHandlerRef.current = encryptedHandler;
  }, [encryptedHandler]);

  useOfflineMessages({
    encryptedHandlerRef,
    hybridKeysRef: Authentication.hybridKeysRef,
    username: Authentication.loginUsernameRef.current,
    isReady: Authentication.isLoggedIn &&
      Authentication.accountAuthenticated &&
      Authentication.vaultReady &&
      Database.dbInitialized &&
      !!Authentication.loginUsernameRef.current,
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
    Database.secureDBRef,
  );

  const signalHandler = useChatSignals({
    Authentication,
    encryptedHandler,
  });

  const {
    conversations,
    selectedConversation,
    addConversation,
    selectConversation,
    removeConversation,
    getConversationMessages,
    toggleConversationPin,
  } = useConversations(
    Authentication.loginUsernameRef.current || '',
    Database.users,
    messages,
    setMessages,
    Database.secureDBRef.current,
    findUser
  );

  useLayoutEffect(() => {
    activeConversationRef.current = selectedConversation;
  }, [selectedConversation]);

  useEffect(() => {
    if (selectedConversation && typeof messageSender?.prefetchSessionForPeer === 'function') {
      try { messageSender.prefetchSessionForPeer(selectedConversation); } catch { }
    }
  }, [selectedConversation, messageSender]);

  const currentDisplayName = useDisplayUsername({
    username: Authentication.originalUsernameRef.current || Authentication.loginUsernameRef.current || ''
  });

  const stableGetDisplayUsername = useCallback(
    async (username: string) => username,
    []
  );

  // Block / unblock user from add conversation modal
  const handleToggleBlock = useCallback(async (username: string, nextBlocked: boolean) => {
    try {
      if (nextBlocked) {
        await blockingSystem.blockUser(username);
        toast.success('User blocked');
      } else {
        await blockingSystem.unblockUser(username);
        toast.success('User unblocked');
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to update block list');
    }
  }, []);

  const {
    p2pHybridKeys,
    getPeerHybridKeys,
    username: p2pUsername,
  } = useP2PKeys(
    {
      hybridKeysRef: Authentication.hybridKeysRef,
      loginUsernameRef: Authentication.loginUsernameRef,
    },
    {
      users: Database.users,
    }
  );

  const callingHook = useCalling(Authentication, {
    getPeerCertificate: fetchPeerCertificates,
    ensurePeerSession: messageSender.prefetchSessionForPeer,
    secureDBRef: Database.secureDBRef,
  });

  const p2pMessaging = useP2PMessaging(
    Database.dbInitialized ? p2pUsername : '',
    Database.dbInitialized ? p2pHybridKeys : null,
    {
      fetchPeerCertificates,
      handleEncryptedMessagePayload: encryptedHandler,
      ensureDiscoveryPublished: ensurePublished,
      onServiceReady: (service) => {
        p2pServiceRef.current = service;
      }
    }
  );

  // Update P2P sender whenever service becomes ready
  useEffect(() => {
    const service = p2pServiceRef.current;
    if (service && p2pMessaging.p2pStatus.isInitialized) {
      unifiedSignalTransport.setP2PSender(async (to, payload, type) => {
        if (!p2pMessaging.isPeerConnected(to)) {
          const dial = p2pMessaging.connectToPeer(to).catch(() => { });
          if (!isLiveOnlySignalType(type)) {
            let deadline: ReturnType<typeof setTimeout> | undefined;
            try {
              await Promise.race([
                dial,
                new Promise<void>((resolve) => {
                  deadline = setTimeout(resolve, COLD_SEND_P2P_DIAL_BUDGET_MS);
                }),
              ]);
            } finally {
              if (deadline !== undefined) clearTimeout(deadline);
            }
          }
          if (!p2pMessaging.isPeerConnected(to)) {
            throw new Error('P2P connection not ready');
          }
        }
        if (type !== SignalType.SEALED_ENVELOPE) {
          throw new Error('Invalid message type');
        }
        if (service !== p2pServiceRef.current) {
          throw new Error('P2P service changed during account transition');
        }
        await service.sendMessage(to, payload, SignalType.SEALED_ENVELOPE);
      });
    } else {
      unifiedSignalTransport.setP2PSender(null);
    }
    return () => unifiedSignalTransport.setP2PSender(null);
  }, [p2pMessaging.p2pStatus.isInitialized, p2pMessaging.connectToPeer, p2pMessaging.isPeerConnected]);
  
  useEffect(() => {
    if (!Authentication.isLoggedIn || !p2pMessaging.p2pStatus.isInitialized) return;

    void ensurePublished(false).catch(() => { });
    const onResume = () => { void ensurePublished(false).catch(() => { }); };
    window.addEventListener('focus', onResume);
    window.addEventListener('online', onResume);

    return () => {
      window.removeEventListener('focus', onResume);
      window.removeEventListener('online', onResume);
    };
  }, [Authentication.isLoggedIn, p2pMessaging.p2pStatus.isInitialized, ensurePublished]);

  // Warm discovery
  useEffect(() => {
    if (!Authentication.isLoggedIn) {
      discoveryWarmedPeersRef.current.clear();
      return;
    }
    if (!findUser) return;
    const activeAccount = Authentication.loginUsernameRef.current || '';
    if (!activeAccount || authorizationRestoreReadyFor !== activeAccount) return;
    const peers = Database.users
      .map((user) => user?.username)
      .filter((name): name is string => typeof name === 'string' && name.length > 0);
    if (peers.length === 0) return;

    const pending = peers.filter((peer) =>
      !discoveryWarmedPeersRef.current.has(peer) &&
      !captureKeyTransparencyPeerAuthorization(activeAccount, peer)
    );
    if (pending.length === 0) return;
    for (const peer of pending) discoveryWarmedPeersRef.current.add(peer);

    let cancelled = false;
    void (async () => {
      for (const peer of pending) {
        if (cancelled) return;
        await findUser(peer).catch(() => null);
      }
    })();
    return () => { cancelled = true; };
  }, [
    Authentication.isLoggedIn,
    Authentication.loginUsernameRef,
    authorizationRestoreReadyFor,
    findUser,
    Database.users,
  ]);

  useEffect(() => {
    if (!Authentication.isLoggedIn) {
      p2pWarmedPeersRef.current.clear();
      return;
    }
    if (!p2pMessaging.p2pStatus.isInitialized) return;
    const activeAccount = Authentication.loginUsernameRef.current || '';
    if (!activeAccount || authorizationRestoreReadyFor !== activeAccount) return;

    const pending = Database.users
      .map((user) => user?.username)
      .filter((name): name is string =>
        typeof name === 'string' &&
        name.length > 0 &&
        !p2pWarmedPeersRef.current.has(name) &&
        !p2pMessaging.isPeerConnected(name)
      );
    if (pending.length === 0) return;
    for (const peer of pending) p2pWarmedPeersRef.current.add(peer);

    let cancelled = false;
    void (async () => {
      for (const peer of pending) {
        if (cancelled) return;
        const hasRoute = p2pTransport.hasAuthenticatedEndpoint(peer) ||
          !!(await loadPersistedPeerEndpoint(activeAccount, peer).catch(() => null));
        if (cancelled) return;
        if (!hasRoute) continue;
        await p2pMessaging.connectToPeer(peer).catch(() => { });
      }
    })();
    return () => { cancelled = true; };
  }, [
    Authentication.isLoggedIn,
    Authentication.loginUsernameRef,
    authorizationRestoreReadyFor,
    p2pMessaging.p2pStatus.isInitialized,
    p2pMessaging.connectToPeer,
    p2pMessaging.isPeerConnected,
    Database.users,
  ]);

  const getOrCreateUser = useCallback((username: string): User => {
    let targetUser = Database.users.find(user => user.username === username);
    if (!targetUser) {
      targetUser = {
        id: crypto.randomUUID(),
        username,
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
    allowEvent,
    currentUsername: Authentication.loginUsernameRef.current || '',
  });

  useEventHandlers({
    allowEvent,
    setUsers: Database.setUsers,
    currentUsername: Authentication.loginUsernameRef.current || '',
  });

  // E2E Encryption Provider
  useEncryptionProvider({
    isLoggedIn: Authentication.isLoggedIn,
    loginUsernameRef: Authentication.loginUsernameRef,
    getPeerHybridKeys,
    users: Database.users,
    getKeysOnDemand: Authentication.getKeysOnDemand,
    findUser,
    ensureDiscoveryPublished: ensurePublished
  });

  // Message actions
  const { onSendMessage } = useMessageActions({
    selectedConversation,
    getOrCreateUser,
    messageSender,
    p2pMessaging,
  });

  // Call event handlers
  useCallEventHandlers({
    currentUsername: Authentication.loginUsernameRef.current || '',
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
    flushPendingSaves,
    setShowSettings,
  });

  useEffect(() => {
    if (showSettings) {
      setSidebarActiveTab('settings');
      setShowSettings(false);
    }
  }, [showSettings]);

  // Token validation
  useTokenValidation({
    Authentication,
    setupComplete,
    selectedServerUrl,
  });

  // Get messages for the selected conversation
  const conversationMessages = useMemo(() => {
    const peer = selectedConversation || '';
    if (!peer) return [] as Message[];
    return getConversationMessages(peer);
  }, [selectedConversation, messages, getConversationMessages]);

  const p2pConnectedPeers = p2pMessaging?.p2pStatus?.connectedPeers ?? [];
  const p2pConnectedStatus = useMemo(() => {
    if (!selectedConversation || !p2pMessaging?.isPeerConnected) return false;
    return p2pMessaging.isPeerConnected(selectedConversation);
  }, [selectedConversation, p2pConnectedPeers.includes(selectedConversation)]);

  const handleConnectSetupComplete = async (serverUrl: string) => {
    const wasConnected = websocketClient.isConnectedToServer();
    try {
      setSelectedServerUrl(serverUrl);
      if (!(wasConnected && selectedServerUrl === serverUrl)) {
        await websocketClient.connect({ autoReconnectOnFailure: false });
      }

      const storedUsername = (await loadLastAuthenticatedAccount()).username;

      let canResume = false;
      try {
        canResume = storedUsername ? await hasResumeToken(storedUsername) : false;
      } catch { canResume = false; }
      const explicitLogout = await isExplicitlyLoggedOut();
      const hasExistingSession = !explicitLogout && !!storedUsername && canResume;
      const serverEntryRequired = (
        websocketClient.isServerPasswordRequired()
        && !websocketClient.isServerAuthGranted()
      );

      if (serverEntryRequired) {
        Authentication.setTokenValidationInProgress(false);
        Authentication.setAuthStatus('');
        Authentication.setShowPasswordPrompt(true);
      } else if (hasExistingSession) {
        Authentication.setTokenValidationInProgress(true);
      } else {
        Authentication.setIsRegistrationMode(true);
      }
      setSetupComplete(true);
      setShowServerSetup(false);
    } catch (error) {
      Authentication.setTokenValidationInProgress(false);
      if (!wasConnected) {
        setSetupComplete(false);
        try {
          await websocketClient.close();
        } catch { }
        try {
          if (isTauri()) {
            await websocket.disconnect();
          }
        } catch { }
      }
      throw (error instanceof Error ? error : new Error('Failed to connect after setup'));
    }
  };

  const handleSetupDisconnect = async () => {
    try {
      await websocketClient.close();
    } catch { }
    try {
      if (isTauri()) {
        await websocket.disconnect();
      }
    } catch { }
    Authentication.setTokenValidationInProgress(false);
    setSelectedServerUrl('');
    setSetupComplete(false);
    setShowServerSetup(true);
  };

  // Connection setup
  useConnectionSetup({
    setupComplete,
    selectedServerUrl,
    Authentication,
    Database,
  });

  useWebSocket(
    signalHandler,
    encryptedHandler,
    Authentication.setLoginError,
    Authentication.isLoggedIn ? (Authentication.loginUsernameRef.current || '') : '',
  );

  useEffect(() => {
    const handleAuthUiBack = async (event: CustomEvent) => {
      try {
        const to = (event as any).detail?.to as 'server' | undefined;
        if (to === 'server') {
          setShowServerSetup(true);
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
      <div className="flex items-center justify-center min-h-screen p-4 bg-background select-none">
        <div className="text-center text-sm text-muted-foreground">
          Resuming...
        </div>
      </div>
    );
  }

  if (showServerSetup || !setupComplete || !selectedServerUrl) {
    return (
      <div className="min-h-screen bg-white dark:bg-[hsl(var(--background))]">
        <ConnectSetup
          onComplete={handleConnectSetupComplete}
          onDisconnect={handleSetupDisconnect}
          initialServerUrl={selectedServerUrl}
          isConnected={setupComplete && !!selectedServerUrl}
        />
        <Toaster position="top-right" theme={theme as any} richColors toastOptions={{ className: 'select-none', style: { width: 'fit-content', maxWidth: '400px', minWidth: '0px' } }} />
      </div>
    );
  }

  const isFullyAuthenticated = Authentication.isLoggedIn
    && Authentication.accountAuthenticated
    && Authentication.vaultReady
    && !Authentication.showPassphrasePrompt
    && !Authentication.showPasswordPrompt;
  const authPromptVisible = Authentication.showPassphrasePrompt || Authentication.showPasswordPrompt;
  const showValidationScreen = Authentication.tokenValidationInProgress && !isFullyAuthenticated && !authPromptVisible;
  const showLoginScreen = !showValidationScreen && (
    !Authentication.isLoggedIn ||
    !Authentication.accountAuthenticated ||
    Authentication.showPassphrasePrompt ||
    Authentication.showPasswordPrompt
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
    const registrationMode = Authentication.isRegistrationMode && !Authentication.showPassphrasePrompt;
    return (
      <div className="min-h-screen bg-white dark:bg-[hsl(var(--background))]">
        <Login
          isGeneratingKeys={Authentication.isGeneratingKeys}
          authStatus={Authentication.authStatus}
          error={Authentication.loginError}
          onAccountSubmit={Authentication.handleAccountSubmit}
          accountAuthenticated={Authentication.accountAuthenticated}
          isRegistrationMode={registrationMode}
          setIsRegistrationMode={Authentication.setIsRegistrationMode}
          showPasswordPrompt={Authentication.showPasswordPrompt}
          handleServerPasswordSubmit={Authentication.handleServerPasswordSubmit}
          initialUsername={Authentication.loginUsernameRef.current || ''}
        />
        <Toaster position="top-right" theme={theme as any} richColors toastOptions={{ className: 'select-none', style: { width: 'fit-content', maxWidth: '400px', minWidth: '0px' } }} />
      </div>
    );
  }

  // Wait for DB init before showing the main app
  if (!Database.dbInitialized || !Authentication.vaultReady) {
    if (Database.dbInitError) {
      return (
        <div className="flex items-center justify-center min-h-screen p-4 bg-white dark:bg-[hsl(var(--background))] select-none">
          <div className="w-full max-w-sm text-center space-y-4">
            <div className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>
              Secure storage could not start
            </div>
            <div className="text-xs break-words" style={{ color: 'var(--color-text-secondary)' }}>
              {Database.dbInitError}
            </div>
            <div className="flex items-center justify-center gap-2">
              <button
                type="button"
                className="px-3 py-2 rounded border border-border text-sm hover:bg-accent"
                onClick={Database.retryInitializeDB}
              >
                Retry
              </button>
              <button
                type="button"
                className="px-3 py-2 rounded border border-border text-sm hover:bg-accent"
                onClick={() => Authentication.logout(Database.secureDBRef)}
              >
                Sign out
              </button>
            </div>
          </div>
        </div>
      );
    }

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
          setSidebarActiveTab(tab);
          setShowSettings(false);
        }}
        currentUser={{
          username: currentDisplayName || Authentication.originalUsernameRef.current || Authentication.loginUsernameRef.current || '',
          avatarUrl: undefined
        }}
        onLogout={async () => await Authentication.logout(Database.secureDBRef)}
      >
        <div className="qor-chat-stage">
          <PeerIdentityVerificationAlert />
          <div className={sidebarActiveTab === 'chats' ? 'h-full w-full' : 'hidden'}>
            <div className="flex h-full">
              <div
                className="qor-chats-panel hidden md:flex flex-col relative"
                style={{ width: `${conversationPanelWidth}px` }}
              >
                {/* Resize Handle */}
                <div
                  className="qor-resize-line"
                  onMouseDown={(e) => {
                    e.preventDefault();
                    setIsResizing(true);
                    const startX = e.clientX;
                    const startWidth = conversationPanelWidth;

                    const handleMouseMove = (moveEvent: MouseEvent) => {
                      requestAnimationFrame(() => {
                        const delta = moveEvent.clientX - startX;
                        const newWidth = Math.min(520, Math.max(260, startWidth + delta));
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

                <div className="qor-chats-head">
                  <h2>Chats</h2>
                  <div className="qor-head-actions">
                    <TorIndicator />
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => setShowNewChatInput(true)}
                      className="qor-icon-btn qor-compose-btn"
                      aria-label="Add conversation"
                    >
                      <ComposeIcon className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
                <div className="flex-1 overflow-hidden">
                  <ConversationList
                    currentUsername={Authentication.loginUsernameRef.current || ''}
                    conversations={conversations}
                    selectedConversation={selectedConversation || undefined}
                    onSelectConversation={selectConversation}
                    onAddConversation={async (username) => {
                      await addConversation(username);
                      setShowNewChatInput(false);
                    }}
                    getDisplayUsername={stableGetDisplayUsername}
                    showNewChatInput={showNewChatInput}
                    onNewChatOpenChange={setShowNewChatInput}
                    onRemoveConversation={removeConversation}
                    onTogglePin={toggleConversationPin}
                    onStartCall={(username, type) => { void callingHook.startCall(username, type); }}
                    onToggleBlock={handleToggleBlock}
                  />
                </div>
              </div>

              <div className="qor-chat-pane">
                {selectedConversation ? (
                  <EmojiPickerProvider>
                    <ChatInterface
                      messages={conversationMessages}
                      setMessages={setMessages}
                      currentCall={callingHook.currentCall}
                      startCall={callingHook.startCall}
                      currentUsername={Authentication.loginUsernameRef.current || ''}
                      getDisplayUsername={stableGetDisplayUsername}
                      getKeysOnDemand={Authentication.getKeysOnDemand}
                      getPeerHybridKeys={getPeerHybridKeys}
                      findUser={findUser}
                      ensurePeerSession={messageSender.prefetchSessionForPeer}
                      p2pConnected={p2pConnectedStatus}
                      loadMoreMessages={loadMoreConversationMessages}
                      sendServerReadReceipt={sendServerReadReceipt}
                      markMessageAsRead={markMessageAsRead}
                      getSmartReceiptStatus={getSmartReceiptStatus}
                      secureDB={Database.secureDBRef.current}
                      onSendMessage={onSendMessage}
                      isEncrypted={true}
                      users={Database.users}
                      selectedConversation={selectedConversation}
                      saveMessageToLocalDB={saveMessageWithContext}
                    />
                  </EmojiPickerProvider>
                ) : (
                  <EmptyChatView onCreateChat={() => setShowNewChatInput(true)} />
                )}
              </div>
            </div>
          </div>

          <div className={sidebarActiveTab === 'calls' ? 'h-full w-full' : 'hidden'}>
            {sidebarActiveTab === 'calls' && (
              <React.Suspense fallback={null}>
                <CallLogsLazy getDisplayUsername={stableGetDisplayUsername} />
              </React.Suspense>
            )}
          </div>

          <div className={sidebarActiveTab === 'settings' ? 'h-full w-full' : 'hidden'}>
            {sidebarActiveTab === 'settings' && (
              <React.Suspense fallback={null}>
                <AppSettingsLazy
                  currentUsername={Authentication.loginUsernameRef.current || ''}
                  currentDisplayName={currentDisplayName || Authentication.originalUsernameRef.current || ''}
                  onLogout={async () => await Authentication.logout(Database.secureDBRef)}
                  findUser={findUser}
                />
              </React.Suspense>
            )}
          </div>
        </div>
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
            />
          </React.Suspense>,
          document.body
        )
      }
    </TypingIndicatorProvider>
  );
};

export default ChatApp;
