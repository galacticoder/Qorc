import React, { useState, useCallback, useEffect, useRef, useMemo } from "react";
import { createPortal } from "react-dom";
import { useTheme } from "next-themes";
import { Login } from "../components/chat/Login";
import { User } from "../components/chat/messaging/UserList";
import { ConversationList } from "../components/chat/messaging/ConversationList";
import { ChatInterface } from "../components/chat/messaging/ChatInterface";
import { EmptyChatView } from "../components/chat/messaging/EmptyChatView";
import { AppSettings } from "../components/settings/AppSettings";
import { Layout } from "../components/ui/Layout";
import { CallLogs } from "../components/chat/calls/CallLogs";
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
import { SecurityAuditLogger } from "../lib/cryptography/audit-logger";
import { PostQuantumUtils } from "../lib/utils/pq-utils";
import { isExplicitlyLoggedOut } from "../lib/auth/logout-marker";
import { shouldAttemptDiscovery } from "../lib/utils/discovery-utils";
import { computePeerCertificateFingerprint, isSelfSignedPeerCertificate } from "../lib/utils/peer-certificate-utils";
import { unifiedSignalTransport } from "../lib/transport/unified-signal-transport";
import { websocket, isTauri, storage, tray } from "../lib/tauri-bindings";
import type { PeerCertificateBundle } from "../lib/types/p2p-types";

import {
  LOCAL_EVENT_RATE_LIMIT_WINDOW_MS,
  LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS,
} from "../lib/constants";
import { useRateLimiter } from "../hooks/useRateLimiter";
import { useLocalMessageHandlers } from "../hooks/message-handling/useLocalMessageHandlers";
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
import { useDiscovery } from "../hooks/discovery/useDiscovery";
import { getInstanceLocalStorageItem, setInstanceLocalStorageItem } from "../lib/runtime/instance-storage";
const CallModalLazy = React.lazy(() => import("../components/chat/calls/CallModal"));

const ChatApp: React.FC = () => {
  const { allowEvent } = useRateLimiter(LOCAL_EVENT_RATE_LIMIT_WINDOW_MS, LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS);
  const [messages, setMessages] = useState<Message[]>([]);
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
  const discoveryHandle = Authentication.isLoggedIn ? Authentication.pseudonym || undefined : undefined;
  const discoveryUsername = Authentication.isLoggedIn ? Authentication.loginUsernameRef.current || undefined : undefined;
  const { findUser, ensurePublished } = useDiscovery(
    discoveryHandle,
    discoveryUsername,
    Authentication.hybridKeysRef
  );

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
  useEffect(() => {
    usersRef.current = Database.users;
  }, [Database.users]);
  const peerCertMismatchLoggedRef = useRef<Set<string>>(new Set());

  const fetchPeerCertificates = useCallback(async (peer: string, bypassCache = false): Promise<PeerCertificateBundle | null> => {
    if (!peer) return null;
    try {
      if (!shouldAttemptDiscovery(peer, Database.users.map(u => u.username).filter(Boolean))) {
        return null;
      }
      const material = await findUser(peer, { forceRefresh: bypassCache });
      const cert = material?.peerCertificate || null;
      if (!cert) {
        return null;
      }
      if (!isSelfSignedPeerCertificate(cert)) {
        return null;
      }
      if (
        material?.publicKeys?.dilithiumPublicBase64 !== cert.dilithiumPublicKey ||
        material?.publicKeys?.kyberPublicBase64 !== cert.kyberPublicKey ||
        material?.publicKeys?.x25519PublicBase64 !== cert.x25519PublicKey
      ) {
        return null;
      }

      const fingerprint = computePeerCertificateFingerprint(cert);
      const identityRootFingerprint = typeof material.identityRootFingerprint === 'string'
        ? material.identityRootFingerprint.trim().toLowerCase()
        : '';
      if (!identityRootFingerprint) {
        return null;
      }
      const existingUser = Database.users.find(u => u.username === peer);
      const pinned = existingUser?.peerCertificateFingerprint;
      const pinnedRoot = existingUser?.identityRootFingerprint;

      if (pinned && pinned !== fingerprint) {
        if (!peerCertMismatchLoggedRef.current.has(peer)) {
          peerCertMismatchLoggedRef.current.add(peer);
        }
        return null;
      }
      if (pinnedRoot && pinnedRoot !== identityRootFingerprint) {
        if (!peerCertMismatchLoggedRef.current.has(peer)) {
          peerCertMismatchLoggedRef.current.add(peer);
        }
        return null;
      }

      if (!pinned || !pinnedRoot) {
        const pinnedAt = Date.now();
        Database.setUsers(prev => {
          const idx = prev.findIndex(u => u.username === peer);
          if (idx === -1) {
            return [...prev, {
              id: crypto.randomUUID(),
              username: peer,
              isOnline: false,
              peerCertificateFingerprint: fingerprint,
              peerCertificatePinnedAt: pinnedAt,
              identityRootFingerprint,
              identityBundleFingerprint: material.identityBundleFingerprint
            } as User];
          }
          const next = [...prev];
          next[idx] = {
            ...next[idx],
            peerCertificateFingerprint: fingerprint,
            peerCertificatePinnedAt: pinnedAt,
            identityRootFingerprint,
            identityBundleFingerprint: material.identityBundleFingerprint || next[idx].identityBundleFingerprint
          };
          return next;
        });
      }

      return cert;
    } catch (err) {
      console.warn('[P2P][Cert] Failed to fetch discovery cert', { error: String(err) });
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
    try { void Database.saveMessageToLocalDB(message); } catch { }
  }, [setMessages, Database]);

  const fileHandler = useFileHandler(
    Authentication.getKeysOnDemand,
    handleIncomingFileMessage,
    Authentication.setLoginError,
    Database.secureDBRef,
    usersRef,
    findUser
  );

  const getPeerHybridKeysRef = useRef<((peerUsername: string) => Promise<{ kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64?: string } | null>) | null>(null);
  const p2pServiceRef = useRef<any>(null);

  const messageSender = useMessageSender(
    Database.users,
    Authentication.loginUsernameRef,
    Authentication.loginUsernameRef.current || '',
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
    undefined,
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
    findUser
  );

  const encryptedHandlerRef = useRef(encryptedHandler);
  useEffect(() => {
    encryptedHandlerRef.current = encryptedHandler;
  }, [encryptedHandler]);

  // Offline message handling
  useOfflineMessages({
    encryptedHandlerRef,
    hybridKeysRef: Authentication.hybridKeysRef,
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
    findUser,
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
    Database.secureDBRef.current,
    findUser
  );

  useEffect(() => {
    if (selectedConversation && typeof messageSender?.prefetchSessionForPeer === 'function') {
      try { messageSender.prefetchSessionForPeer(selectedConversation); } catch { }
    }
  }, [selectedConversation, messageSender]);

  const currentDisplayName = useDisplayUsername({
    username: Authentication.originalUsernameRef.current || Authentication.loginUsernameRef.current || ''
  });

  const stableGetDisplayUsername = useCallback(
    async (username: string) => {
      const { getCachedDisplayName } = await import('../lib/utils/database-utils');
      return getCachedDisplayName(username) || username;
    },
    []
  );

  const kyberSecretRefForSettings = useMemo(() => {
    const kyberSecret = Authentication.hybridKeysRef?.current?.kyber?.secretKey;
    return { current: kyberSecret || null };
  }, [Authentication.hybridKeysRef?.current?.kyber?.secretKey]);

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
      secureDBRef: Database.secureDBRef,
      users: Database.users,
    }
  );

  useEffect(() => {
    getPeerHybridKeysRef.current = getPeerHybridKeys;
  }, [getPeerHybridKeys]);

  const callingHook = useCalling(Authentication, {
    getPeerKeys: getPeerHybridKeys,
    getPeerCertificate: fetchPeerCertificates
  });

  const p2pMessaging = useP2PMessaging(
    p2pUsername,
    p2pHybridKeys,
    {
      fetchPeerCertificates,
      handleEncryptedMessagePayload: encryptedHandler,
      ensureDiscoveryPublished: ensurePublished,
      onServiceReady: (service) => {
        try { (window as any).p2pService = service; } catch { }
        p2pServiceRef.current = service;
      }
    }
  );

  // Update P2P sender whenever service becomes ready
	  useEffect(() => {
	    if (p2pServiceRef.current && p2pMessaging.p2pStatus.isInitialized) {
	      unifiedSignalTransport.setP2PSender(async (to, payload, type) => {
	        const isConnected = p2pMessaging.isPeerConnected(to);
	        if (!isConnected) {
	          void p2pMessaging.connectToPeer(to).catch(() => { });
	          throw new Error(`P2P connection to ${to} not ready`);
	        }
	        if (p2pServiceRef.current) {
	          const mId = (payload && typeof payload === 'object') ? (payload.messageId || payload.id) : undefined;
	          if (type !== SignalType.SEALED_ENVELOPE) {
	            throw new Error('Invalid message type');
	          }
	          await p2pServiceRef.current.sendMessage(to, payload, SignalType.SEALED_ENVELOPE, mId);
	        }
	      });
	    } else {
	      unifiedSignalTransport.setP2PSender(null as any);
	    }
	  }, [p2pMessaging.p2pStatus.isInitialized, p2pMessaging.connectToPeer, p2pMessaging.isPeerConnected, ensurePublished]);

  // warm P2P channels to recent conversation peers
  const warmConversationsRef = useRef(conversations);
  warmConversationsRef.current = conversations;
  useEffect(() => {
    if (!Authentication.isLoggedIn || !p2pMessaging.p2pStatus.isInitialized) return;

    const RECENT_PEER_WARM_LIMIT = 10;
    const warm = () => {
      const peers = [...warmConversationsRef.current]
        .sort((a, b) => (b.lastMessageTime?.getTime() || 0) - (a.lastMessageTime?.getTime() || 0))
        .slice(0, RECENT_PEER_WARM_LIMIT)
        .map(c => c.username)
        .filter(Boolean);
      for (const peer of peers) {
        if (blockingSystem.isBlockedSync(peer)) continue;
        if (!p2pMessaging.isPeerConnected(peer)) {
          void p2pMessaging.connectToPeer(peer).catch(() => { });
        }
      }
    };

    // Force fresh self publish
    void ensurePublished(true).catch(() => { });
    warm();

    const interval = setInterval(warm, 25_000);
    const onResume = () => { void ensurePublished(false).catch(() => { }); warm(); };
    
    const onUnblocked = (evt: Event) => {
      const username = (evt as CustomEvent)?.detail?.username;
      if (typeof username === 'string' && username && !p2pMessaging.isPeerConnected(username)) {
        void p2pMessaging.connectToPeer(username).catch(() => { });
      }
    };
    window.addEventListener('focus', onResume);
    window.addEventListener('online', onResume);
    window.addEventListener(EventType.USER_UNBLOCKED, onUnblocked as EventListener);

    return () => {
      clearInterval(interval);
      window.removeEventListener('focus', onResume);
      window.removeEventListener('online', onResume);
      window.removeEventListener(EventType.USER_UNBLOCKED, onUnblocked as EventListener);
    };
  }, [Authentication.isLoggedIn, p2pMessaging.p2pStatus.isInitialized, p2pMessaging.connectToPeer, p2pMessaging.isPeerConnected, ensurePublished]);

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

  // Pre fetch peer keys for calling when conversation opens
  useEffect(() => {
    if (selectedConversation && getPeerHybridKeys && callingHook?.callingService) {
      const service = callingHook.callingService;
      const peer = selectedConversation;

      getPeerHybridKeys(peer).then(keys => {
        if (!callingHook.callingService || callingHook.callingService !== service) {
          return;
        }

        if (keys) {
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
    getKeysOnDemand: Authentication.getKeysOnDemand,
    secureDBRef: Database.secureDBRef,
    findUser,
    ensureDiscoveryPublished: ensurePublished
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
    const wasConnected = websocketClient.isConnectedToServer();
    try {
      const storedUsername = await storage.get('last_authenticated_username');

      let canResume = false;
      try {
        const { hasResumeToken } = await import('../lib/signals/resume-tokens');
        canResume = await hasResumeToken();
      } catch { canResume = false; }
      const explicitLogout = await isExplicitlyLoggedOut();
      const hasExistingSession = !explicitLogout && !!storedUsername && canResume;

      if (hasExistingSession) {
        Authentication.setTokenValidationInProgress(true);
      } else {
        Authentication.setIsRegistrationMode(true);
      }

      setSelectedServerUrl(serverUrl);
      if (!(wasConnected && selectedServerUrl === serverUrl)) {
        await websocketClient.connect({ autoReconnectOnFailure: false });
      }
      setSetupComplete(true);
      setShowServerSetup(false);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'unknown';
      SecurityAuditLogger.log(SignalType.ERROR, 'connect-setup-failed', { error: message });
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

  useWebSocket(signalHandler, encryptedHandler, Authentication.setLoginError);

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
    return (
      <div className="min-h-screen bg-white dark:bg-[hsl(var(--background))]">
        <Login
          isGeneratingKeys={Authentication.isGeneratingKeys}
          authStatus={Authentication.authStatus}
          error={Authentication.loginError}
          onAccountSubmit={Authentication.handleAccountSubmit}
          accountAuthenticated={Authentication.accountAuthenticated}
          isRegistrationMode={Authentication.isRegistrationMode}
          setIsRegistrationMode={Authentication.setIsRegistrationMode}
          serverTrustRequest={Authentication.serverTrustRequest}
          onAcceptServerTrust={Authentication.acceptServerTrust}
          onRejectServerTrust={Authentication.rejectServerTrust}
          showPassphrasePrompt={Authentication.showPassphrasePrompt}
          setShowPassphrasePrompt={Authentication.setShowPassphrasePrompt}
          onPassphraseSubmit={Authentication.handlePassphraseSubmit}
          showPasswordPrompt={Authentication.showPasswordPrompt}
          setShowPasswordPrompt={Authentication.setShowPasswordPrompt}
          handleServerPasswordSubmit={Authentication.handleServerPasswordSubmit}
          initialUsername={''}
          initialPassword={''}
          maxStepReached={Authentication.maxStepReached}
          pseudonym={Authentication.loginUsernameRef.current || ''}
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
                  />
                </div>
              </div>

              <div className="qor-chat-pane">
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
                  <EmptyChatView onCreateChat={() => setShowNewChatInput(true)} />
                )}
              </div>
            </div>
          </div>

          <div className={sidebarActiveTab === 'calls' ? 'h-full w-full' : 'hidden'}>
            <CallLogs getDisplayUsername={stableGetDisplayUsername} />
          </div>

          <div className={sidebarActiveTab === 'settings' ? 'h-full w-full' : 'hidden'}>
            <AppSettings
              passphraseRef={Authentication.passphrasePlaintextRef}
              kyberSecretRef={kyberSecretRefForSettings as any}
              currentUsername={Authentication.loginUsernameRef.current || ''}
              currentDisplayName={currentDisplayName || Authentication.originalUsernameRef.current || ''}
              onLogout={async () => await Authentication.logout(Database.secureDBRef)}
            />
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
