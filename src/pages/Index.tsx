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
import { Message, MessageReply } from "../components/chat/messaging/types";
import { Dialog, DialogContent } from "../components/ui/dialog";
import { EmojiPickerProvider } from "../contexts/EmojiPickerContext";
import { useCallHistory } from "../contexts/CallHistoryContext";
import { formatFileSize } from "../lib/utils/file-utils";
import { useAuth } from "../hooks/auth/useAuth";
import { useSecureDB } from "../hooks/database/useSecureDB";
import { useFileHandler } from "../hooks/file-handling/useFileHandler";
import { useMessageSender } from "../hooks/message-sending/useMessageSender";
import { useEncryptedMessageHandler } from "../hooks/message-handling/useEncryptedMessageHandler";
import { useChatSignals } from "../hooks/useChatSignals";
import { useWebSocket } from "../hooks/useWebsocket";
import { useConversations } from "../hooks/message-sending/useConversations";
import { useUsernameDisplay } from "../hooks/database/useUsernameDisplay";
import { storeUsernameMapping } from "../lib/username-display";
import { useP2PMessaging, type EncryptedMessage } from "../hooks/p2p/useP2PMessaging";
import { useP2PKeys } from "../hooks/p2p/useP2PKeys";
import { useMessageReceipts } from "../hooks/message-sending/useMessageReceipts";
import { p2pConfig, getSignalingServerUrl } from "../config/p2p.config";
import websocketClient from "../lib/websocket";
import { EventType } from "../lib/types/event-types";
import { TypingIndicatorProvider } from "../contexts/TypingIndicatorContext";
import { torNetworkManager } from "../lib/tor-network";
import { ConnectSetup } from "../components/setup/ConnectSetup";
import { SignalType } from "../lib/types/signal-types";
import { blockingSystem } from "../lib/blocking/blocking-system";
import { retrieveAuthTokens } from "../lib/signals";
import { syncEncryptedStorage } from "../lib/encrypted-storage";
import { secureMessageQueue } from "../lib/secure-message-queue";
import { initializeOfflineMessageQueue, offlineMessageQueue } from "../lib/offline-message-queue";
import { isValidKyberPublicKeyBase64, sanitizeHybridKeys } from "../lib/utils/messaging-validators";
import { SecurityAuditLogger } from "../lib/cryptography/audit-logger";
import { PostQuantumUtils } from "../lib/utils/pq-utils";
import { CryptoUtils } from "../lib/utils/crypto-utils";
import { unifiedSignalTransport } from "../lib/transport/unified-signal-transport";

import { sanitizeFilename, isPlainObject, hasPrototypePollutionKeys, isUnsafeObjectKey, sanitizeNonEmptyText } from "../lib/sanitizers";
import { useRateLimiter } from "../hooks/useRateLimiter";
import { useLocalMessageHandlers } from "../hooks/message-handling/useLocalMessageHandlers";
import { useP2PMessageHandlers } from "../hooks/p2p/useP2PMessageHandlers";
import { useP2PConnectionManager } from "../hooks/p2p/useP2PConnectionManager";
import { useP2PSignalHandlers } from "../hooks/p2p/useP2PSignalHandlers";
import { useEventHandlers } from "../hooks/useEventHandlers";
import { toast, Toaster } from 'sonner';
import { TorIndicator } from "../components/ui/TorIndicator";
import { Button } from "../components/ui/button";
import { ComposeIcon } from "../components/chat/assets/icons";
import { useCalling } from "../hooks/calling/useCalling";
import { truncateUsername } from "../lib/utils/avatar-utils";
import { resolveDisplayUsername } from "../lib/unified-username-display";
const CallModalLazy = React.lazy(() => import("../components/chat/calls/CallModal"));

const getReplyContent = (message: Message): string => {
  if (message.type === SignalType.FILE || message.type === SignalType.FILE_MESSAGE || message.filename) {
    const fileSize = message.fileSize ? ` (${formatFileSize(message.fileSize)})` : '';
    const filename = message.filename || 'File';

    // For images
    if (message.filename && /\.(jpg|jpeg|png|gif|bmp|webp|svg|ico|tiff)$/i.test(message.filename)) {
      return `Image: ${message.filename}${fileSize}`;
    }
    // For videos
    else if (message.filename && /\.(mp4|webm|ogg|avi|mov|wmv|flv|mkv)$/i.test(message.filename)) {
      return `Video: ${message.filename}${fileSize}`;
    }
    // For voice notes
    else if (message.filename && (message.filename.toLowerCase().includes('voice-note') || /\.(mp3|wav|ogg|webm|m4a|aac|flac)$/i.test(message.filename))) {
      return `Voice message`;
    }
    // For other files
    else {
      return `File: ${filename}${fileSize}`;
    }
  }

  return message.content || '';
};

const LOCAL_EVENT_RATE_LIMIT_WINDOW_MS = 10_000;
const LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS = 120;
const MAX_LOCAL_MESSAGE_ID_LENGTH = 160;
const MAX_LOCAL_MESSAGE_LENGTH = 10_000;
const MAX_LOCAL_USERNAME_LENGTH = 256;
const MAX_LOCAL_MIMETYPE_LENGTH = 128;
const MAX_LOCAL_EMOJI_LENGTH = 32;
const MAX_LOCAL_FILE_SIZE_BYTES = 50 * 1024 * 1024;
const MAX_INLINE_BASE64_BYTES = 10 * 1024 * 1024;


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
  const [isResumingFromBackground, setIsResumingFromBackground] = useState(true); // Start true to avoid flash
  const uiEventRateRef = useRef({ windowStart: Date.now(), count: 0 });

  const Authentication = useAuth();
  const callHistory = useCallHistory();

  useEffect(() => {
    const checkBackgroundState = async () => {
      try {
        const api = (window as any).edgeApi;
        const electronApi = (window as any).electronAPI;
        if (api?.getBackgroundSessionState) {
          const state = await api.getBackgroundSessionState();

          if (state && state.isBackgroundMode) {
            try {
              const pqKeysResult = await api.getPQSessionKeys?.();
              if (pqKeysResult?.success && pqKeysResult.keys) {
                const restored = websocketClient.importSessionKeys(pqKeysResult.keys);
                if (restored) {
                  await api.clearPQSessionKeys?.();
                }
              }
            } catch (pqErr) {
              console.error('[Resume] Failed to restore PQ session keys:', pqErr);
            }

            try {
              const torStatus = await electronApi?.getTorStatus?.();
              if (torStatus?.isRunning || torStatus?.bootstrapped) {
                torNetworkManager.updateConfig({
                  enabled: true,
                  socksPort: torStatus.socksPort || 9150,
                  controlPort: torStatus.controlPort || 9151,
                  host: '127.0.0.1'
                });
                await torNetworkManager.initialize();
              }
            } catch (torErr) {
              console.error('[Resume] Failed to re-sync Tor:', torErr);
            }

            const serverResult = await api.getServerUrl?.();
            if (serverResult?.serverUrl) {
              setSelectedServerUrl(serverResult.serverUrl);
              setSetupComplete(true);

              const storedUsername = state.username ||
                Authentication.loginUsernameRef.current ||
                (await import('../lib/encrypted-storage')).syncEncryptedStorage.getItem('last_authenticated_username');

              let localAuthRestored = false;

              if (storedUsername) {
                try {
                  const { loadVaultKeyRaw, loadWrappedMasterKey, ensureVaultKeyCryptoKey } = await import('../lib/cryptography/vault-key');
                  const { AES } = await import('../lib/utils/crypto-utils');

                  let vaultKey: CryptoKey | null = null;
                  const rawVaultKey = await loadVaultKeyRaw(storedUsername);
                  if (rawVaultKey && rawVaultKey.length === 32) {
                    vaultKey = await AES.importAesKey(rawVaultKey);
                  } else {
                    vaultKey = await ensureVaultKeyCryptoKey(storedUsername);
                  }

                  if (vaultKey) {
                    const masterKeyBytes = await loadWrappedMasterKey(storedUsername, vaultKey);

                    if (masterKeyBytes && masterKeyBytes.length === 32) {
                      const masterKey = await AES.importAesKey(masterKeyBytes);

                      Authentication.aesKeyRef.current = masterKey;
                      Authentication.loginUsernameRef.current = storedUsername;

                      if (!Authentication.keyManagerRef.current) {
                        const { SecureKeyManager } = await import('../lib/secure-key-manager');
                        Authentication.keyManagerRef.current = new SecureKeyManager(storedUsername);
                      }
                      try {
                        await Authentication.keyManagerRef.current.initializeWithMasterKey(masterKeyBytes);
                      } catch { }

                      try { masterKeyBytes.fill(0); } catch { }

                      Authentication.setUsername(storedUsername);
                      Authentication.setIsLoggedIn(true);
                      Authentication.setAccountAuthenticated(true);
                      Authentication.setShowPassphrasePrompt(false);
                      Authentication.setRecoveryActive(false);
                      Authentication.setMaxStepReached('server');
                      Authentication.setTokenValidationInProgress(false);
                      Authentication.setAuthStatus('');

                      localAuthRestored = true;
                    }
                  }
                } catch (vaultErr) {
                  console.error('[Resume] Vault key restoration failed:', vaultErr);
                }
              }

              // Only trigger server auth recovery if local restoration failed
              if (!localAuthRestored) {
                try {
                  Authentication.setTokenValidationInProgress(true);
                  await websocketClient.attemptTokenValidationOnce?.('background-resume');
                } catch (tvErr) {
                  console.error('[Resume] Token validation on resume failed:', tvErr);
                }

                try {
                  await Authentication.attemptAuthRecovery();
                } catch (authErr) {
                  console.error('[Resume] Auth recovery failed:', authErr);
                }
              }
              setTimeout(async () => {
                try {
                  await api.requestPendingMessages?.();
                } catch (e) {
                  console.error('[Resume] Failed to request pending messages:', e);
                }
              }, 2000);

              await api.clearBackgroundSessionState?.();
            }
          }
        }
      } catch (e) {
        console.error('[Resume] Error checking background state:', e);
      } finally {
        setIsResumingFromBackground(false);
      }
    };
    checkBackgroundState();
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

  useEffect(() => {
    // no-op: this effect is split below to avoid re-registering callbacks on each render
  }, []);

  const offlineCallbackSetRef = useRef(false);
  useEffect(() => {
    if (offlineCallbackSetRef.current) return;
    offlineCallbackSetRef.current = true;

    try {
      offlineMessageQueue.setIncomingOfflineEncryptedMessageCallback(async (msg: any) => {
        await encryptedHandlerRef.current(msg);
      });
    } catch { }
  }, []);

  const offlineDbInitializedRef = useRef(false);
  useEffect(() => {
    if (!Authentication.isLoggedIn) {
      offlineDbInitializedRef.current = false;
      return;
    }

    if (offlineDbInitializedRef.current) return;
    const db = Database.secureDBRef?.current;
    if (!db) {
      return;
    }

    offlineDbInitializedRef.current = true;
    try {
      initializeOfflineMessageQueue(db);
    } catch { }
  }, [Authentication.isLoggedIn, Database.dbInitialized]);

  useEffect(() => {
    const applyKey = () => {
      const kyberSecret = Authentication.hybridKeysRef?.current?.kyber?.secretKey;
      if (kyberSecret && kyberSecret instanceof Uint8Array) {
        try {
          offlineMessageQueue.setDecryptionKey(kyberSecret);
        } catch { }
      } else {
        try {
          offlineMessageQueue.clearDecryptionKey();
        } catch { }
      }
    };

    applyKey();

    const onKeysUpdated = () => applyKey();
    try {
      window.addEventListener(EventType.HYBRID_KEYS_UPDATED, onKeysUpdated as EventListener);
    } catch { }
    return () => {
      try {
        window.removeEventListener(EventType.HYBRID_KEYS_UPDATED, onKeysUpdated as EventListener);
      } catch { }
    };
  }, [Authentication.hybridKeysRef.current]);

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
  const saveMessageWithContextRef = useRef(saveMessageWithContext);
  useEffect(() => { saveMessageWithContextRef.current = saveMessageWithContext; }, [saveMessageWithContext]);

  // Use extracted hooks for event handling
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

  // Register the E2E Encryption Provider for UnifiedSignalTransport
  useEffect(() => {
    if (!Authentication.isLoggedIn) return;

    unifiedSignalTransport.setEncryptionProvider(async (to, payload, type) => {
      try {
        const currentUser = Authentication.loginUsernameRef.current;
        if (!currentUser || to === 'SERVER') return null;

        let peerKeys = await getPeerHybridKeys(to);
        let resolvedUsername = to;

        if ((!peerKeys || !peerKeys.kyberPublicBase64) && to.length === 32) {
          const usersList = Array.isArray(Database.users) ? Database.users : [];
          const found = usersList.find((u: any) =>
            (u.id === to || u.pixelId === to || u.uuid === to) && u.username
          );
          if (found) {
            resolvedUsername = found.username;
            peerKeys = await getPeerHybridKeys(resolvedUsername);

            try {
              const { quicTransport } = await import('../lib/transport/quic-transport');
              quicTransport.registerUsernameAlias(resolvedUsername, to);
            } catch { }
          } else {
            try {
              const { quicTransport } = await import('../lib/transport/quic-transport');
              const alias = quicTransport.resolveUsernameAlias(to);
              if (alias && alias !== to) {
                console.debug('[UnifiedTransport] Resolved hash', to, 'via QuicTransport alias to', alias);
                resolvedUsername = alias;
                peerKeys = await getPeerHybridKeys(resolvedUsername);
              }
            } catch (err) {
              console.warn('[UnifiedTransport] Failed to query QuicTransport alias:', err);
            }
          }
        }

        if (!peerKeys?.kyberPublicBase64) {
          console.warn('[UnifiedTransport] Auto-encryption failed: No peer keys for', to, resolvedUsername !== to ? `(alias: ${resolvedUsername})` : '');
          return null;
        }

        const signalPayload = {
          type: 'signal-fallback',
          kind: type,
          content: payload.content || JSON.stringify(payload),
          from: currentUser,
          timestamp: Date.now(),
          ...payload
        };

        const result = await (window as any).edgeApi?.encrypt?.({
          fromUsername: currentUser,
          toUsername: resolvedUsername,
          plaintext: JSON.stringify(signalPayload),
          recipientKyberPublicKey: peerKeys.kyberPublicBase64,
          recipientHybridKeys: peerKeys
        });

        if (result?.success && result?.encryptedPayload) {
          return {
            encryptedPayload: result.encryptedPayload,
            messageId: payload.messageId || crypto.randomUUID().replace(/-/g, '')
          };
        }
      } catch (e) {
        console.error('[UnifiedTransport] Auto-encryption provider failed:', e);
      }
      return null;
    });

    return () => {
      (unifiedSignalTransport as any).encryptionProvider = null;
      (unifiedSignalTransport as any).p2pEncryptionProvider = null;
    };
  }, [Authentication.isLoggedIn, getPeerHybridKeys, p2pHybridKeys]);


  const onSendMessage = useCallback(async (
    messageId: string,
    content: string,
    messageSignalType: string,
    replyTo?: MessageReply | null
  ) => {
    if (!selectedConversation) return;

    const targetUser = getOrCreateUser(selectedConversation);

    const replyToMessage = replyTo ? {
      id: replyTo.id,
      sender: replyTo.sender,
      content: replyTo.content,
      timestamp: new Date(),
      type: SignalType.TEXT as const,
      isCurrentUser: false,
      version: '1'
    } as Message : undefined;

    if (messageSignalType === SignalType.TYPING_START || messageSignalType === SignalType.TYPING_STOP) {
      return messageSender.handleSendMessage(targetUser as any, content, replyToMessage, undefined, messageSignalType);
    }

    if (messageSignalType === SignalType.DELETE_MESSAGE || messageSignalType === SignalType.EDIT_MESSAGE) {
      return messageSender.handleSendMessage(targetUser as any, content, replyToMessage, undefined, messageSignalType, messageId);
    }

    // Standard message send
    const isConnected = p2pMessaging.isPeerConnected(selectedConversation);

    if (messageSignalType === SignalType.REACTION_ADD || messageSignalType === SignalType.REACTION_REMOVE) {
      if (p2pConfig.features.textMessages && isConnected && targetUser.hybridPublicKeys) {
        try {
          const result = await p2pMessaging.sendP2PMessage(
            selectedConversation,
            content,
            {
              dilithiumPublicBase64: targetUser.hybridPublicKeys.dilithiumPublicBase64,
              kyberPublicBase64: targetUser.hybridPublicKeys.kyberPublicBase64,
              x25519PublicBase64: targetUser.hybridPublicKeys.x25519PublicBase64,
            },
            {
              messageType: SignalType.REACTION,
              metadata: {
                targetMessageId: messageId,
                action: messageSignalType
              }
            }
          );

          if (result.status === 'sent') {
            window.dispatchEvent(new CustomEvent(EventType.LOCAL_REACTION_UPDATE, {
              detail: {
                messageId,
                emoji: content,
                isAdd: messageSignalType === SignalType.REACTION_ADD,
                username: Authentication.loginUsernameRef.current
              }
            }));
            return;
          }
        } catch { }
      }
      // Fallback to server
      return messageSender.handleSendMessage(targetUser as any, content, replyToMessage, undefined, messageSignalType, messageId);
    }

    if (p2pConfig.features.textMessages && isConnected) {
      try {
        if (targetUser.hybridPublicKeys) {
          const result = await p2pMessaging.sendP2PMessage(
            selectedConversation,
            content,
            {
              dilithiumPublicBase64: targetUser.hybridPublicKeys.dilithiumPublicBase64,
              kyberPublicBase64: targetUser.hybridPublicKeys.kyberPublicBase64,
              x25519PublicBase64: targetUser.hybridPublicKeys.x25519PublicBase64,
            },
            {
              metadata: replyTo ? {
                replyTo: {
                  id: replyTo.id,
                  sender: replyTo.sender,
                  content: replyTo.content
                }
              } : undefined
            }
          );

          if (result.status === 'sent') {
            const newMessage: Message = {
              id: result.messageId || crypto.randomUUID(),
              content: content,
              sender: Authentication.loginUsernameRef.current || '',
              recipient: selectedConversation,
              timestamp: new Date(),
              type: SignalType.TEXT,
              isCurrentUser: true,
              p2p: true,
              transport: 'p2p',
              encrypted: true,
              receipt: { delivered: false, read: false },
              ...(replyTo && { replyTo: { id: replyTo.id, sender: replyTo.sender, content: getReplyContent(replyTo as Message) } })
            } as Message;

            setMessages(prev => [...prev, newMessage]);
            saveMessageWithContext(newMessage);
            return;
          }
        }
      } catch { }
    }

    try {
      await messageSender.handleSendMessage(
        targetUser as any,
        content,
        replyToMessage,
        undefined,
        messageSignalType,
        messageId
      );
    } catch (error) {
      console.error("Failed to send message:", error);
      toast.error(error instanceof Error ? error.message : "Failed to send message", {
        duration: 5000
      });
    }
  }, [selectedConversation, getOrCreateUser, messageSender, p2pMessaging, setMessages, saveMessageWithContext, Authentication.loginUsernameRef]);

  const handleCallLog = useCallback(async (e: Event) => {
    try {
      const now = Date.now();
      const bucket = uiEventRateRef.current;
      if (now - bucket.windowStart > LOCAL_EVENT_RATE_LIMIT_WINDOW_MS) {
        bucket.windowStart = now;
        bucket.count = 0;
      }
      bucket.count += 1;
      if (bucket.count > LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS) {
        return;
      }

      if (!(e instanceof CustomEvent)) return;
      const detail = e.detail;
      if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

      const peer = (detail as any).peer;
      if (typeof peer !== 'string') return;

      const eventType = (detail as any).type;
      if (typeof eventType !== 'string') return;

      const callId = (detail as any).callId || crypto.randomUUID();
      const at = (detail as any).at || Date.now();
      const durationMs = (detail as any).durationMs || 0;
      const isVideo = (detail as any).isVideo === true;
      const isOutgoing = (detail as any).isOutgoing === true;

      const displayPeerName = truncateUsername(await resolveDisplayUsername(peer, stableGetDisplayUsername));
      const durationSeconds = Math.round(durationMs / 1000);

      const { addCallLog } = callHistory;
      if (['ended', 'missed', 'declined'].includes(eventType)) {
        addCallLog({
          peerUsername: peer,
          type: isVideo ? 'video' : 'audio',
          direction: isOutgoing ? 'outgoing' : 'incoming',
          status: eventType === 'missed' ? 'missed' : eventType === 'declined' ? 'declined' : 'completed',
          startTime: at,
          ...(eventType === 'ended' && durationSeconds > 0 ? { duration: durationSeconds } : {})
        });
      }

      const label = eventType === 'incoming' ? `Incoming call from ${displayPeerName}`
        : eventType === 'connected' ? `Call connected with ${displayPeerName}`
          : eventType === 'started' ? `Calling ${displayPeerName}...`
            : eventType === 'ended' ? `Call with ${displayPeerName} ended`
              : eventType === 'declined' ? (isOutgoing ? `${displayPeerName} missed your call` : `You missed ${displayPeerName}'s call`)
                : eventType === 'missed' ? (isOutgoing ? `${displayPeerName} missed your call` : `You missed ${displayPeerName}'s call`)
                  : eventType === 'not-answered' ? (isOutgoing ? `${displayPeerName} missed your call` : `You missed ${displayPeerName}'s call`)
                    : `Call event: ${eventType}`;

      const shouldHaveActions = ['missed', 'not-answered', 'ended', 'declined'].includes(eventType);
      const actions = shouldHaveActions
        ? [{ label: 'Call back', onClick: () => callingHook.startCall(peer, 'audio').catch(() => { }) }]
        : undefined;

      const newMessage: Message = {
        id: `call-log-${callId}-${eventType}-${at}`,
        content: JSON.stringify({ label, actionsType: actions ? 'callback' : undefined, isError: eventType === 'missed' }),
        sender: peer,
        recipient: peer,
        timestamp: new Date(at),
        isCurrentUser: false,
        isSystemMessage: true,
        type: 'system'
      } as Message;

      if (peer === selectedConversation) {
        setMessages((prev) => [...prev, newMessage]);
      }
      void Database.saveMessageToLocalDB(newMessage, peer);
    } catch { }
  }, [stableGetDisplayUsername, setMessages, selectedConversation, Database.saveMessageToLocalDB, callingHook.startCall, callHistory]);

  useEffect(() => {
    window.addEventListener(EventType.UI_CALL_LOG, handleCallLog as EventListener);
    return () => window.removeEventListener(EventType.UI_CALL_LOG, handleCallLog as EventListener);
  }, [handleCallLog]);

  const handleCallRequest = useCallback((e: Event) => {
    try {
      const now = Date.now();
      const bucket = uiEventRateRef.current;
      if (now - bucket.windowStart > LOCAL_EVENT_RATE_LIMIT_WINDOW_MS) {
        bucket.windowStart = now;
        bucket.count = 0;
      }
      bucket.count += 1;
      if (bucket.count > LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS) {
        return;
      }

      if (!(e instanceof CustomEvent)) return;
      const detail = e.detail;
      if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

      const peer = (detail as any).peer;
      if (typeof peer !== 'string') return;

      const requestedType = (detail as any).type;
      const callType = requestedType === 'video' ? 'video' : 'audio';

      callingHook.startCall(peer, callType).catch(() => { });
    } catch { }
  }, [callingHook.startCall]);

  useEffect(() => {
    window.addEventListener(EventType.UI_CALL_REQUEST, handleCallRequest as EventListener);
    return () => window.removeEventListener(EventType.UI_CALL_REQUEST, handleCallRequest as EventListener);
  }, [handleCallRequest]);

  // Store username mapping for current user only when SecureDB is available
  useEffect(() => {
    if (Database.secureDBRef.current && Authentication.originalUsernameRef.current) {
      const storeCurrentUserMapping = async () => {
        try {
          await Authentication.storeUsernameMapping(Database.secureDBRef.current!);
        } catch {
          SecurityAuditLogger.log(SignalType.ERROR, 'user-mapping-store-failed', { error: 'unknown' });
        }
      };
      storeCurrentUserMapping();
    }
  }, [Database.secureDBRef.current, Authentication.originalUsernameRef.current]);

  // Restore original username from SecureDB after auth recovery (when username appears hashed)
  useEffect(() => {
    const restoreOriginalUsername = async () => {
      const db = Database.secureDBRef.current;
      const hashedUsername = Authentication.loginUsernameRef.current;
      const currentOriginal = Authentication.originalUsernameRef.current;

      // Skip if DB not ready or not logged in
      if (!db || !hashedUsername || !Authentication.isLoggedIn) {
        return;
      }

      // Skip if we already have a valid original username (different from hashed)
      if (currentOriginal && currentOriginal !== hashedUsername) {
        return;
      }

      try {
        const original = await db.getOriginalUsername(hashedUsername);
        if (original && original !== hashedUsername) {
          Authentication.originalUsernameRef.current = original;
          // Trigger re-render for components using the username
          window.dispatchEvent(new CustomEvent(EventType.USERNAME_MAPPING_UPDATED, {
            detail: { username: hashedUsername, original }
          }));
          SecurityAuditLogger.log('info', 'original-username-restored', {});
        }
      } catch {
        SecurityAuditLogger.log('warn', 'original-username-restore-failed', {});
      }
    };

    restoreOriginalUsername();
  }, [Database.secureDBRef.current, Authentication.isLoggedIn, Authentication.loginUsernameRef.current]);

  // Initialize secure message queue when SecureDB is ready
  useEffect(() => {
    if (Database.secureDBRef.current && Authentication.loginUsernameRef.current) {
      const initMessageQueue = async () => {
        try {
          await secureMessageQueue.initialize(
            Authentication.loginUsernameRef.current,
            Database.secureDBRef.current!
          );
          SecurityAuditLogger.log('info', 'message-queue-initialized', {});
        } catch {
          SecurityAuditLogger.log(SignalType.ERROR, 'message-queue-init-failed', { error: 'unknown' });
        }
      };
      initMessageQueue();
    }
  }, [Database.secureDBRef.current, Authentication.loginUsernameRef.current]);

  // Initialize profile picture system when SecureDB is ready
  useEffect(() => {
    if (Database.secureDBRef.current) {
      Promise.all([
        import('../lib/profile-picture-system'),
        import('../lib/websocket')
      ]).then(([{ profilePictureSystem }, { default: _websocketClient }]) => {
        profilePictureSystem.setSecureDB(Database.secureDBRef.current);
        profilePictureSystem.initialize().catch(() => { });
      }).catch(() => { });
    }
  }, [Database.secureDBRef.current]);

  // Set keys for profile picture system
  useEffect(() => {
    if (Authentication.hybridKeysRef.current?.kyber?.publicKeyBase64 && Authentication.hybridKeysRef.current?.kyber?.secretKey) {
      import('../lib/profile-picture-system').then(({ profilePictureSystem }) => {
        profilePictureSystem.setKeys(
          Authentication.hybridKeysRef.current!.kyber!.publicKeyBase64,
          Authentication.hybridKeysRef.current!.kyber!.secretKey
        );
      });
    }
  }, [Authentication.hybridKeysRef.current]);

  // Bridge P2P file chunks into file handler
  useEffect(() => {
    const onP2PChunk = (e: Event) => {
      try {
        const d: any = (e as CustomEvent).detail || {};
        if (d && d.payload) {
          fileHandler.handleFileMessageChunk(d.payload, { from: d.from, to: d.to });
        }
      } catch { }
    };
    window.addEventListener(EventType.P2P_FILE_CHUNK, onP2PChunk as EventListener);
    return () => window.removeEventListener(EventType.P2P_FILE_CHUNK, onP2PChunk as EventListener);
  }, [fileHandler]);


  // Ensure token-based auth recovery is attempted when validation is in progress
  const tokenRecoveryAttemptedRef = useRef(false);
  useEffect(() => {
    if (!Authentication.tokenValidationInProgress) {
      tokenRecoveryAttemptedRef.current = false;
      return;
    }
    if (Authentication.isLoggedIn || Authentication.accountAuthenticated) return;
    if (!setupComplete || !selectedServerUrl) return;
    if (tokenRecoveryAttemptedRef.current) return;

    tokenRecoveryAttemptedRef.current = true;
    (async () => {
      try {
        const recovered = await Authentication.attemptAuthRecovery();
        if (!recovered) {
          Authentication.setTokenValidationInProgress(false);
          Authentication.setAuthStatus('');
        }
      } catch {
        Authentication.setTokenValidationInProgress(false);
        Authentication.setAuthStatus('');
      }
    })();
  }, [Authentication.tokenValidationInProgress, Authentication.isLoggedIn, Authentication.accountAuthenticated, setupComplete, selectedServerUrl]);

  // Ensure token validation actually gets sent; retry once with session reset if needed
  const tokenValidationEnsureRef = useRef<{ attempts: number; retryTimer: NodeJS.Timeout | null }>({ attempts: 0, retryTimer: null });
  useEffect(() => {
    const state = tokenValidationEnsureRef.current;
    if (!Authentication.tokenValidationInProgress || Authentication.isLoggedIn || Authentication.accountAuthenticated) {
      state.attempts = 0;
      if (state.retryTimer) {
        clearTimeout(state.retryTimer);
        state.retryTimer = null;
      }
      return;
    }
    if (!setupComplete || !selectedServerUrl) return;

    const trySend = async (reason: string, resetFirst: boolean) => {
      try {
        await (window as any).edgeApi?.wsConnect?.();
      } catch { }
      try {
        if (resetFirst && (websocketClient as any)?.resetSessionKeys) {
          (websocketClient as any).resetSessionKeys(false);
        }
      } catch { }
      try {
        await websocketClient.attemptTokenValidationOnce?.(`ensure-${reason}`);
      } catch { }
    };

    if (state.attempts === 0) {
      state.attempts = 1;
      void trySend('initial', false);
      state.retryTimer = setTimeout(() => {
        state.retryTimer = null;
        if (Authentication.tokenValidationInProgress && !Authentication.isLoggedIn && !Authentication.accountAuthenticated && state.attempts === 1) {
          state.attempts = 2;
          void trySend('retry', true);
        }
      }, 8000);
    }

    return () => {
      if (state.retryTimer) {
        clearTimeout(state.retryTimer);
        state.retryTimer = null;
      }
    };
  }, [Authentication.tokenValidationInProgress, Authentication.isLoggedIn, Authentication.accountAuthenticated, setupComplete, selectedServerUrl]);




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



  // Restore encrypted block list from server when logged in and passphrase available
  useEffect(() => {
    const tryRestoreBlockList = async () => {
      const passphrase = Authentication.passphrasePlaintextRef?.current || '';
      const kyberSecret = Authentication.hybridKeysRef?.current?.kyber?.secretKey || null;
      const key = passphrase ? passphrase : (kyberSecret ? { kyberSecret } : null);
      if (!Authentication.isLoggedIn || !Authentication.accountAuthenticated || !key || !Database.dbInitialized) return;
      try {
        await blockingSystem.downloadFromServer(key as any);
      } catch { }
    };
    tryRestoreBlockList();
  }, [Authentication.isLoggedIn, Authentication.accountAuthenticated, Authentication.passphrasePlaintextRef?.current, Authentication.aesKeyRef?.current]);

  // Handle settings open/close events
  useEffect(() => {
    const handleOpenSettings = () => setShowSettings(true);
    const handleCloseSettings = () => setShowSettings(false);
    window.addEventListener(EventType.OPEN_SETTINGS, handleOpenSettings);
    window.addEventListener(EventType.CLOSE_SETTINGS, handleCloseSettings);
    return () => {
      window.removeEventListener(EventType.OPEN_SETTINGS, handleOpenSettings);
      window.removeEventListener(EventType.CLOSE_SETTINGS, handleCloseSettings);
    };
  }, []);

  useEffect(() => {
    try {
      const stored = syncEncryptedStorage.getItem('app_settings_v1');
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.notifications) {
          (window as any).edgeApi?.setNotificationsEnabled?.(parsed.notifications.desktop !== false).catch(() => { });
        }
      }
    } catch { }
  }, []);

  const isEnteringBackgroundRef = useRef(false);

  useEffect(() => {
    const handleEnteringBackground = async () => {
      isEnteringBackgroundRef.current = true;

      try {
        await flushPendingSaves();
      } catch (e) {
        console.error('[App] Failed to flush pending saves:', e);
      }

      const currentUsername = Authentication.loginUsernameRef.current ||
        syncEncryptedStorage.getItem('last_authenticated_username');
      if (currentUsername) {
        try {
          await (window as any).edgeApi?.setBackgroundUsername?.(currentUsername);
        } catch (e) {
          console.error('[App] Failed to store background username:', e);
        }
      }

      try {
        const sessionKeys = websocketClient.exportSessionKeys();
        if (sessionKeys) {
          await (window as any).edgeApi?.storePQSessionKeys?.(sessionKeys);
        }
      } catch (e) {
        console.error('[App] Failed to store PQ session keys:', e);
      }
    };
    window.addEventListener(EventType.APP_ENTERING_BACKGROUND, handleEnteringBackground);

    return () => {
      window.removeEventListener(EventType.APP_ENTERING_BACKGROUND, handleEnteringBackground);
      if (!isEnteringBackgroundRef.current && torNetworkManager.isSupported()) {
        torNetworkManager.shutdown();
      }
    };
  }, []);

  const handleConnectSetupComplete = async (serverUrl: string) => {
    try {
      SecurityAuditLogger.log('info', 'connect-setup-completed', {});

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

  // Initialize WebSocket after setup is complete
  const attemptedRecoveryRef = useRef(false);
  useEffect(() => {
    if (!selectedServerUrl || !setupComplete) return;

    const initializeConnection = async () => {
      try {
        await (window as any).edgeApi?.wsConnect?.();

        const hasEncryptedAuth = Database.secureDBRef.current !== null;
        let storedUsername: string | null = null;
        let hasStoredTokens = false;
        try {
          storedUsername = syncEncryptedStorage.getItem('last_authenticated_username') || null;
        } catch { }
        try {
          const tokens = await retrieveAuthTokens();
          hasStoredTokens = !!(tokens?.accessToken && tokens?.refreshToken);
        } catch { }

        const canRecover = (
          (hasEncryptedAuth || !!storedUsername || hasStoredTokens) &&
          !Authentication.isLoggedIn &&
          !Authentication.isRegistrationMode &&
          !Authentication.showPassphrasePrompt &&
          !Authentication.showPasswordPrompt &&
          !Authentication.isSubmittingAuth &&
          !Authentication.accountAuthenticated &&
          !Authentication.recoveryActive
        );

        if (canRecover && !attemptedRecoveryRef.current) {
          attemptedRecoveryRef.current = true;
          SecurityAuditLogger.log('info', 'auth-recovery-attempt', {});
          try {
            const recovered = await Authentication.attemptAuthRecovery();
            if (!recovered) {
              Authentication.setTokenValidationInProgress(false);
            }
          } catch (_e) {
            SecurityAuditLogger.log('warn', 'auth-recovery-failed', { error: (_e as any)?.message || 'unknown' });
            Authentication.setTokenValidationInProgress(false);
          }
        } else if (!canRecover && Authentication.tokenValidationInProgress && !Authentication.isLoggedIn) {
          if (!storedUsername && !hasStoredTokens && !hasEncryptedAuth) {
            Authentication.setTokenValidationInProgress(false);
          }
        }
      } catch (_error) {
        SecurityAuditLogger.log(SignalType.ERROR, 'connection-init-failed', { error: _error instanceof Error ? _error.message : 'unknown' });
      }
    };

    void initializeConnection();
  }, [setupComplete, selectedServerUrl, Authentication.isLoggedIn, Authentication.isRegistrationMode, Authentication.showPassphrasePrompt, Authentication.showPasswordPrompt, Authentication.isSubmittingAuth, Authentication.accountAuthenticated, Authentication.recoveryActive, Authentication.tokenValidationInProgress, Database.dbInitialized]);

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

  useEffect(() => {
    if (Authentication.isLoggedIn && Database.secureDBRef.current && Authentication.originalUsernameRef.current) {
      Authentication.storeUsernameMapping(Database.secureDBRef.current);
    }
  }, [Authentication.isLoggedIn, Database.secureDBRef.current, Authentication.originalUsernameRef.current]);

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
                      onSendFile={async (fileData: any) => {
                        const MAX_LOCAL_STORAGE_SIZE = 5 * 1024 * 1024; // 5MB

                        const dataToSave = { ...fileData };
                        if (fileData.size > MAX_LOCAL_STORAGE_SIZE) {
                          if (dataToSave.originalBase64Data) {
                            dataToSave.originalBase64Data = null;
                          }
                          if (typeof dataToSave.content === 'string' && dataToSave.content.startsWith('data:')) {
                            dataToSave.content = '';
                          }
                          dataToSave.isLocalStorageTruncated = true;
                        }

                        try {
                          // Try P2P file transfer if enabled and peer is connected
                          if (p2pConfig.features.fileTransfers && selectedConversation) {
                            let isConnected = p2pMessaging.isPeerConnected(selectedConversation);

                            // Try to connect if not connected
                            if (!isConnected) {
                              try {
                                await p2pMessaging.connectToPeer(selectedConversation);
                                isConnected = true;
                              } catch { }
                            }

                            if (isConnected) {
                              const targetUser = Database.users.find(user => user.username === selectedConversation);

                              if (targetUser && targetUser.hybridPublicKeys) {
                                try {
                                  const result = await p2pMessaging.sendP2PMessage(
                                    selectedConversation,
                                    JSON.stringify({
                                      filename: fileData.filename,
                                      size: fileData.size,
                                      type: fileData.type,
                                      url: fileData.url,
                                    }),
                                    {
                                      dilithiumPublicBase64: targetUser.hybridPublicKeys.dilithiumPublicBase64 || '',
                                      kyberPublicBase64: targetUser.hybridPublicKeys.kyberPublicBase64 || '',
                                      x25519PublicBase64: targetUser.hybridPublicKeys.x25519PublicBase64,
                                    },
                                    {
                                      messageType: SignalType.FILE,
                                      metadata: {
                                        filename: fileData.filename,
                                        size: fileData.size,
                                        type: fileData.type,
                                        url: fileData.url,
                                      }
                                    }
                                  );

                                  if (result.status === 'sent') {
                                    SecurityAuditLogger.log('info', 'p2p-file-sent', {});

                                    await Database.saveMessageToLocalDB(dataToSave);
                                    return;
                                  }
                                  SecurityAuditLogger.log('info', 'p2p-file-queued-or-not-sent', { status: result.status });
                                } catch {
                                  SecurityAuditLogger.log('info', 'p2p-file-failed-fallback-server', {});
                                }
                              }
                            }
                          }

                          await Database.saveMessageToLocalDB(dataToSave);

                        } catch (error) {
                          SecurityAuditLogger.log(SignalType.ERROR, 'file-transfer-failed', { error: error instanceof Error ? error.message : 'unknown' });
                          toast.error(error instanceof Error ? error.message : "Failed to send file", {
                            duration: 5000
                          });

                          await Database.saveMessageToLocalDB(dataToSave);
                        }
                      }}
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