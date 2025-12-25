import React, { useState, useCallback, useEffect, useRef, useMemo } from "react";
import { createPortal } from "react-dom";
import { useTheme } from "next-themes";
import { Login } from "../components/chat/Login";
import { User } from "../components/chat/UserList";
import { ConversationList } from "../components/chat/ConversationList";
import { ChatInterface } from "../components/chat/ChatInterface";
import { AppSettings } from "../components/settings/AppSettings";
import { Layout } from "../components/ui/Layout";
import { CallLogs } from "../components/chat/CallLogs";
import { Message, MessageReply } from "../components/chat/types";
import { Dialog, DialogContent } from "../components/ui/dialog";
import { EmojiPickerProvider } from "../contexts/EmojiPickerContext";
import { useCallHistory } from "../contexts/CallHistoryContext";
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
import { useP2PMessaging, type HybridKeys, type PeerCertificateBundle, type EncryptedMessage } from "../hooks/useP2PMessaging";
import { useMessageReceipts } from "../hooks/useMessageReceipts";
import { p2pConfig, getSignalingServerUrl } from "../config/p2p.config";
import websocketClient from "../lib/websocket";
import { TypingIndicatorProvider } from "../contexts/TypingIndicatorContext";
import { torNetworkManager } from "../lib/tor-network";
import { ConnectSetup } from "../components/setup/ConnectSetup";
import { SignalType } from "../lib/signal-types";
import { blockingSystem } from "../lib/blocking-system";
import { retrieveAuthTokens } from "../lib/signals";
import { syncEncryptedStorage } from "../lib/encrypted-storage";
import { secureMessageQueue } from "../lib/secure-message-queue";
import { initializeOfflineMessageQueue, offlineMessageQueue } from "../lib/offline-message-queue";
import { isValidKyberPublicKeyBase64, sanitizeHybridKeys } from "../lib/validators";
import { SecurityAuditLogger } from "../lib/post-quantum-crypto";
import { sanitizeFilename, isPlainObject, hasPrototypePollutionKeys, isUnsafeObjectKey, sanitizeNonEmptyText } from "../lib/sanitizers";
import { useRateLimiter } from "../hooks/useRateLimiter";
import { toast, Toaster } from 'sonner';
import { TorIndicator } from "../components/ui/TorIndicator";
import { Button } from "../components/ui/button";
import { ComposeIcon } from "../components/chat/icons";
import { useCalling } from "../hooks/useCalling";
import { truncateUsername } from "../lib/utils";
import { resolveDisplayUsername } from "../lib/unified-username-display";
const CallModalLazy = React.lazy(() => import("../components/chat/CallModal"));

const getReplyContent = (message: Message): string => {
  if (message.type === 'file' || message.type === 'file-message' || message.filename) {
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
  const callingHook = useCalling(Authentication);

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
                  const { loadVaultKeyRaw, loadWrappedMasterKey, ensureVaultKeyCryptoKey } = await import('../lib/vault-key');
                  const { AES } = await import('../lib/unified-crypto');

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
  usersRef.current = Database.users;

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
    }
  );

  const getPeerHybridKeys = useCallback(async (peerUsername: string) => {
    const existingUser = Database.users.find(u => u.username === peerUsername);
    if (existingUser?.hybridPublicKeys?.kyberPublicBase64 && existingUser?.hybridPublicKeys?.dilithiumPublicBase64) {
      return existingUser.hybridPublicKeys;
    }

    try {
      await websocketClient.sendSecureControlMessage({
        type: SignalType.P2P_FETCH_PEER_CERT,
        username: peerUsername
      });
      await websocketClient.sendSecureControlMessage({
        type: SignalType.CHECK_USER_EXISTS,
        username: peerUsername
      });
    } catch (e) {
      console.error('[Index] Failed to send key requests:', e);
      toast.error('Could not resolve recipient keys. P2P messaging may be unavailable.', {
        duration: 5000
      });
      return null;
    }

    return new Promise<{ kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64?: string } | null>((resolve) => {
      let settled = false;
      const timeout = setTimeout(() => {
        if (!settled) {
          console.warn('[Index] Key resolution timed out for:', peerUsername);
          settled = true;
          cleanup();
          resolve(null);
        }
      }, 5000);

      const cleanup = () => {
        window.removeEventListener('user-exists-response', onUserExists as EventListener);
        window.removeEventListener('p2p-peer-cert', onPeerCert as EventListener);
      };

      const handleCert = (pc: any) => {
        if (pc && pc.kyberPublicKey && pc.dilithiumPublicKey) {
          if (!settled) {
            settled = true;
            clearTimeout(timeout);
            cleanup();

            const keys = {
              kyberPublicBase64: pc.kyberPublicKey,
              dilithiumPublicBase64: pc.dilithiumPublicKey,
              x25519PublicBase64: pc.x25519PublicKey
            };

            if (Database.secureDBRef.current) {
              storeUsernameMapping(peerUsername, Database.secureDBRef.current).catch(() => { });
            }

            try {
              window.dispatchEvent(new CustomEvent('user-keys-available', {
                detail: { username: peerUsername, hybridKeys: keys }
              }));
            } catch { }

            resolve(keys);
          }
        }
      };

      const onUserExists = (e: Event) => {
        const d = (e as CustomEvent).detail || {};
        if (d?.username === peerUsername) {
          const pc = d?.peerCertificate || d?.p2pCertificate || d?.cert || null;
          if (pc) handleCert(pc);
        }
      };

      const onPeerCert = (e: Event) => {
        const d = (e as CustomEvent).detail || {};
        if (d?.username === peerUsername) {
          handleCert(d);
        }
      };

      window.addEventListener('user-exists-response', onUserExists as EventListener);
      window.addEventListener('p2p-peer-cert', onPeerCert as EventListener);
    });
  }, [Database.users, Database.secureDBRef]);

  getPeerHybridKeysRef.current = getPeerHybridKeys;

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
      window.addEventListener('hybrid-keys-updated', onKeysUpdated as EventListener);
    } catch { }
    return () => {
      try {
        window.removeEventListener('hybrid-keys-updated', onKeysUpdated as EventListener);
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

  const messageHistory = useMessageHistory(
    Authentication.username || Authentication.loginUsernameRef.current || '',
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

  const [p2pKeysVersion, setP2pKeysVersion] = useState(0);
  useEffect(() => {
    const bump = () => setP2pKeysVersion((v) => v + 1);
    window.addEventListener('hybrid-keys-updated', bump as EventListener);
    window.addEventListener('secure-chat:auth-success', bump as EventListener);
    return () => {
      window.removeEventListener('hybrid-keys-updated', bump as EventListener);
      window.removeEventListener('secure-chat:auth-success', bump as EventListener);
    };
  }, []);

  const p2pHybridKeys = useMemo<HybridKeys | null>(() => {
    const keys = Authentication.hybridKeysRef.current;
    if (!keys?.dilithium?.secretKey || !keys?.dilithium?.publicKeyBase64) {
      return null;
    }
    return {
      dilithium: {
        secretKey: keys.dilithium.secretKey,
        publicKeyBase64: keys.dilithium.publicKeyBase64,
      },
      kyber: keys.kyber ? {
        secretKey: keys.kyber.secretKey,
      } : undefined,
      x25519: keys.x25519 ? {
        private: keys.x25519.private,
      } : undefined,
    };
  }, [Authentication.hybridKeysRef.current, p2pKeysVersion]);

  const fetchPeerCertificates = useCallback(async (peerUsername: string): Promise<PeerCertificateBundle | null> => {
    try {
      return await new Promise<PeerCertificateBundle | null>(async (resolve) => {
        let settled = false;

        const wsHandler = (evt: Event) => {
          try {
            const msg: any = (evt as CustomEvent).detail || {};
            if (!msg || typeof msg !== 'object') return;
            if (msg.type !== 'p2p-peer-cert') return;
            if (typeof msg.username !== 'string' || msg.username !== peerUsername) return;
            if (typeof msg.dilithiumPublicKey !== 'string' || typeof msg.kyberPublicKey !== 'string' || typeof msg.signature !== 'string' || typeof msg.proof !== 'string') return;
            try { window.removeEventListener('p2p-peer-cert', wsHandler as EventListener); } catch { }
            try { window.removeEventListener('user-exists-response', userExistsHandler as EventListener); } catch { }
            const bundle = {
              username: msg.username,
              dilithiumPublicKey: msg.dilithiumPublicKey,
              kyberPublicKey: msg.kyberPublicKey,
              x25519PublicKey: msg.x25519PublicKey,
              proof: msg.proof,
              issuedAt: msg.issuedAt,
              expiresAt: msg.expiresAt,
              signature: msg.signature
            } as PeerCertificateBundle;

            if (Database.secureDBRef.current) {
              storeUsernameMapping(bundle.username, Database.secureDBRef.current).catch(() => { });
            }

            try {
              const hybridKeys = {
                kyberPublicBase64: bundle.kyberPublicKey,
                dilithiumPublicBase64: bundle.dilithiumPublicKey,
                x25519PublicBase64: bundle.x25519PublicKey,
              };
              window.dispatchEvent(new CustomEvent('user-keys-available', {
                detail: { username: bundle.username, hybridKeys },
              }));
            } catch { }

            settled = true;
            resolve(bundle);
          } catch { }
        };

        const userExistsHandler = (evt: Event) => {
          try {
            const data: any = (evt as CustomEvent).detail || {};
            if (typeof data?.username !== 'string' || data.username !== peerUsername) return;
            const pc = data?.peerCertificate || data?.p2pCertificate || data?.cert || null;
            if (!pc) return;
            const dpk = pc.dilithiumPublicKey;
            const kpk = pc.kyberPublicKey;
            const sig = pc.signature;
            const proof = pc.proof;
            if (typeof dpk !== 'string' || typeof kpk !== 'string' || typeof sig !== 'string' || typeof proof !== 'string') return;
            try { (websocketClient as any).unregisterMessageHandler?.('p2p-peer-cert'); } catch { }
            try { window.removeEventListener('user-exists-response', userExistsHandler as EventListener); } catch { }
            const bundle = {
              username: peerUsername,
              dilithiumPublicKey: dpk,
              kyberPublicKey: kpk,
              x25519PublicKey: pc.x25519PublicKey,
              proof,
              issuedAt: pc.issuedAt,
              expiresAt: pc.expiresAt,
              signature: sig
            } as PeerCertificateBundle;

            if (Database.secureDBRef.current) {
              storeUsernameMapping(bundle.username, Database.secureDBRef.current).catch(() => { });
            }
            try {
              const hybridKeys = {
                kyberPublicBase64: bundle.kyberPublicKey,
                dilithiumPublicBase64: bundle.dilithiumPublicKey,
                x25519PublicBase64: bundle.x25519PublicKey,
              };
              window.dispatchEvent(new CustomEvent('user-keys-available', {
                detail: { username: bundle.username, hybridKeys },
              }));
            } catch { }

            settled = true;
            resolve(bundle);
          } catch { }
        };

        try { window.addEventListener('p2p-peer-cert', wsHandler as EventListener); } catch { }
        try { window.addEventListener('user-exists-response', userExistsHandler as EventListener); } catch { }

        try {
          await websocketClient.sendSecureControlMessage({ type: SignalType.P2P_FETCH_PEER_CERT, username: peerUsername });
        } catch {
        }
        try {
          await websocketClient.sendSecureControlMessage({ type: SignalType.CHECK_USER_EXISTS, username: peerUsername });
        } catch {
        }

        setTimeout(() => {
          if (!settled) {
            try { window.removeEventListener('p2p-peer-cert', wsHandler as EventListener); } catch { }
            try { window.removeEventListener('user-exists-response', userExistsHandler as EventListener); } catch { }
            resolve(null);
          }
        }, 5000);
      });
    } catch {
      return null;
    }
  }, []);

  const p2pMessaging = useP2PMessaging(
    Authentication.loginUsernameRef.current || '',
    p2pHybridKeys,
    {
      fetchPeerCertificates,
      signalingTokenProvider: async () => {
        try {
          const tokens = await (window as any).edgeApi?.retrieveAuthTokens?.();
          return tokens?.accessToken || null;
        } catch {
          return null;
        }
      },
      trustedIssuerDilithiumPublicKeyBase64: Authentication.serverHybridPublic?.dilithiumPublicBase64 || '',
      onServiceReady: (service) => {
        try { (window as any).p2pService = service; } catch { }
      }
    }
  );

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
      type: 'text' as const,
      isCurrentUser: false,
      version: '1'
    } as Message : undefined;

    if (messageSignalType === 'typing-start' || messageSignalType === 'typing-stop') {
      return messageSender.handleSendMessage(targetUser as any, content, replyToMessage, undefined, messageSignalType);
    }

    if (messageSignalType === 'delete-message' || messageSignalType === 'edit-message') {
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
              messageType: 'reaction',
              metadata: {
                targetMessageId: messageId,
                action: messageSignalType
              }
            }
          );

          if (result.status === 'sent') {
            window.dispatchEvent(new CustomEvent('local-reaction-update', {
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
              type: 'text',
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
    window.addEventListener('ui-call-log', handleCallLog as EventListener);
    return () => window.removeEventListener('ui-call-log', handleCallLog as EventListener);
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
    window.addEventListener('ui-call-request', handleCallRequest as EventListener);
    return () => window.removeEventListener('ui-call-request', handleCallRequest as EventListener);
  }, [handleCallRequest]);

  // Store username mapping for current user only when SecureDB is available
  useEffect(() => {
    if (Database.secureDBRef.current && Authentication.originalUsernameRef.current) {
      const storeCurrentUserMapping = async () => {
        try {
          await Authentication.storeUsernameMapping(Database.secureDBRef.current!);
        } catch {
          SecurityAuditLogger.log('error', 'user-mapping-store-failed', { error: 'unknown' });
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
          window.dispatchEvent(new CustomEvent('username-mapping-updated', {
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
          SecurityAuditLogger.log('error', 'message-queue-init-failed', { error: 'unknown' });
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
    window.addEventListener('p2p-file-chunk', onP2PChunk as EventListener);
    return () => window.removeEventListener('p2p-file-chunk', onP2PChunk as EventListener);
  }, [fileHandler]);

  // Handle P2P reactions
  useEffect(() => {
    const rateRef = { windowStart: Date.now(), count: 0 };
    const onP2PReaction = (e: Event) => {
      try {
        const now = Date.now();
        if (now - rateRef.windowStart > LOCAL_EVENT_RATE_LIMIT_WINDOW_MS) {
          rateRef.windowStart = now;
          rateRef.count = 0;
        }
        rateRef.count += 1;
        if (rateRef.count > LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS) {
          return;
        }

        const detail = (e as CustomEvent).detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;
        const messageId = sanitizeNonEmptyText(detail.messageId, MAX_LOCAL_MESSAGE_ID_LENGTH, false);
        const reaction = sanitizeNonEmptyText(detail.reaction, MAX_LOCAL_EMOJI_LENGTH, false);
        const sender = sanitizeNonEmptyText(detail.sender, MAX_LOCAL_USERNAME_LENGTH, false);
        const action = typeof detail.action === 'string' ? detail.action : '';
        if (!messageId || !reaction || !sender) return;
        if (isUnsafeObjectKey(reaction)) return;
        if (action !== 'add' && action !== 'remove') return;

        setMessages(prev => prev.map(msg => {
          if (msg.id !== messageId) return msg;

          const reactions: Record<string, string[]> = Object.create(null);
          if (msg.reactions && typeof msg.reactions === 'object') {
            for (const [k, v] of Object.entries(msg.reactions as Record<string, unknown>)) {
              if (typeof k !== 'string' || isUnsafeObjectKey(k)) continue;
              if (!Array.isArray(v)) continue;
              const safeUsers: string[] = [];
              const seen = new Set<string>();
              for (const candidate of v as unknown[]) {
                if (safeUsers.length >= 250) break;
                const cleaned = sanitizeNonEmptyText(candidate, MAX_LOCAL_USERNAME_LENGTH, false);
                if (!cleaned) continue;
                if (seen.has(cleaned)) continue;
                seen.add(cleaned);
                safeUsers.push(cleaned);
              }
              if (safeUsers.length > 0) {
                reactions[k] = safeUsers;
              }
            }
          }

          // Remove sender from any previous reactions
          for (const key of Object.keys(reactions)) {
            reactions[key] = reactions[key].filter(u => u !== sender);
            if (reactions[key].length === 0) {
              delete reactions[key];
            }
          }

          if (action === 'add') {
            const arr = Array.isArray(reactions[reaction]) ? [...reactions[reaction]] : [];
            if (!arr.includes(sender) && arr.length < 250) {
              arr.push(sender);
            }
            if (arr.length > 0) {
              reactions[reaction] = arr;
            }
          }

          return { ...msg, reactions };
        }));
      } catch {
        console.error('[P2P] Failed to handle reaction');
      }
    };

    window.addEventListener('message-reaction', onP2PReaction as EventListener);
    return () => window.removeEventListener('message-reaction', onP2PReaction as EventListener);
  }, []);

  // Initialize P2P after login with bounded retries even if status doesn't change
  const p2pInitAttemptRef = useRef(0);
  useEffect(() => {
    let cancelled = false;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;

    if (!Authentication.isLoggedIn || !selectedServerUrl || !p2pHybridKeys) {
      p2pInitAttemptRef.current = 0;
      return () => {
        if (retryTimer) clearTimeout(retryTimer);
      };
    }

    const tryInit = () => {
      if (cancelled) return;
      if (p2pMessaging.p2pStatus?.isInitialized && p2pMessaging.p2pStatus?.signalingConnected) {
        p2pInitAttemptRef.current = 0;
        return;
      }
      if (p2pInitAttemptRef.current >= 5) return;

      p2pInitAttemptRef.current += 1;
      const attempt = p2pInitAttemptRef.current;
      const signalingUrl = getSignalingServerUrl(selectedServerUrl);

      p2pMessaging.initializeP2P(signalingUrl).catch(() => {
        SecurityAuditLogger.log('warn', 'p2p-init-retry-failed', { attempt });
      }).finally(() => {
        if (cancelled) return;
        if (p2pMessaging.p2pStatus?.isInitialized && p2pMessaging.p2pStatus?.signalingConnected) {
          p2pInitAttemptRef.current = 0;
          return;
        }
        const backoff = Math.min(2000 * attempt, 10000);
        retryTimer = setTimeout(tryInit, backoff);
      });
    };

    tryInit();

    return () => {
      cancelled = true;
      if (retryTimer) {
        clearTimeout(retryTimer);
        retryTimer = null;
      }
    };
  }, [Authentication.isLoggedIn, selectedServerUrl, p2pHybridKeys]);

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

  // Handle outgoing P2P control sends (session reset) requested by other subsystems
  useEffect(() => {
    const handler = async (evt: Event) => {
      try {
        const d: any = (evt as CustomEvent).detail || {};
        const to: string = d?.to;
        const reason: string | undefined = d?.reason;
        if (!to) return;
        try {
          if (!p2pMessaging.isPeerConnected(to)) {
            try { await p2pMessaging.connectToPeer(to); } catch { }
            await (p2pMessaging as any).waitForPeerConnection?.(to, 5000).catch(() => { });
          }

          await (p2pMessaging as any)?.p2pServiceRef?.current?.sendMessage?.(to, { kind: 'session-reset-request', reason }, 'signal');
        } catch { }
      } catch { }
    };
    try { window.addEventListener('p2p-session-reset-send', handler as EventListener); } catch { }
    return () => { try { window.removeEventListener('p2p-session-reset-send', handler as EventListener); } catch { } };
  }, [p2pMessaging]);

  // Handle outgoing P2P call-signal sends from calling service (P2P-first signaling)
  useEffect(() => {
    const handler = async (evt: Event) => {
      try {
        const d: any = (evt as CustomEvent).detail || {};
        const to: string = d?.to;
        const signalObj: any = d?.signal;
        const requestId: string = d?.requestId || '';
        if (!to || !signalObj) return;
        let success = false;
        try {
          if (!p2pMessaging.isPeerConnected(to)) {
            try { await p2pMessaging.connectToPeer(to); } catch { }
            try { await (p2pMessaging as any).waitForPeerConnection?.(to, 2000); } catch { }
          }
          const svc: any = (window as any).p2pService || (p2pMessaging as any)?.p2pServiceRef?.current || null;
          if (svc && typeof svc.sendMessage === 'function') {
            try {
              await svc.sendMessage(to, { kind: 'call-signal', signal: signalObj }, 'signal');
              success = true;
            } catch {
              await new Promise<void>((resolve) => {
                let settled = false;
                const t = setTimeout(() => { if (!settled) { settled = true; resolve(); } }, 1500);
                const on = (ev: Event) => {
                  const p = (ev as CustomEvent).detail?.peer;
                  if (p === to) { if (!settled) { settled = true; clearTimeout(t); } resolve(); }
                };
                window.addEventListener('p2p-pq-established', on as EventListener, { once: true });
              });
              try {
                await svc.sendMessage(to, { kind: 'call-signal', signal: signalObj }, 'signal');
                success = true;
              } catch { }
            }
          }
        } catch { }
        try {
          window.dispatchEvent(new CustomEvent('p2p-call-signal-result', { detail: { requestId, success } }));
        } catch { }
      } catch { }
    };
    try { window.addEventListener('p2p-call-signal-send', handler as EventListener); } catch { }
    return () => { try { window.removeEventListener('p2p-call-signal-send', handler as EventListener); } catch { } };
  }, [p2pMessaging]);

  // Handle incoming P2P messages 
  useEffect(() => {
    p2pMessaging.onMessage(async (encryptedMessage: EncryptedMessage) => {
      try {
        // Handle typing indicators
        if (encryptedMessage.messageType === 'typing') {
          const typingEvent = new CustomEvent('typing-indicator', {
            detail: {
              username: encryptedMessage.from,
              isTyping: encryptedMessage.content === 'typing-start',
            }
          });
          window.dispatchEvent(typingEvent);
          SecurityAuditLogger.log('info', 'p2p-typing-received', {});
          return;
        }

        // Handle reactions
        if (encryptedMessage.messageType === 'reaction') {
          const targetMessageId = encryptedMessage.metadata?.targetMessageId;
          const action = encryptedMessage.metadata?.action;
          const emoji = encryptedMessage.content;

          if (targetMessageId && emoji && (action === 'reaction-add' || action === 'reaction-remove')) {
            window.dispatchEvent(new CustomEvent('local-reaction-update', {
              detail: {
                messageId: targetMessageId,
                emoji: emoji,
                isAdd: action === 'reaction-add',
                username: encryptedMessage.from
              }
            }));
            SecurityAuditLogger.log('info', 'p2p-reaction-received', {});
          }
          return;
        }

        // Handle message deletion
        if (encryptedMessage.messageType === 'delete') {
          const targetMessageId = encryptedMessage.metadata?.targetMessageId;
          if (targetMessageId) {
            let messageToPersist: Message | null = null;
            setMessages(prev => prev.map(msg => {
              if (msg.id === targetMessageId) {
                const updated = { ...msg, isDeleted: true, content: 'This message was deleted' };
                messageToPersist = updated;
                return updated;
              }
              return msg;
            }));

            if (messageToPersist) {
              try { saveMessageWithContextRef.current(messageToPersist); } catch { }
            }

            try {
              const deleteEvent = new CustomEvent('remote-message-delete', {
                detail: { messageId: targetMessageId }
              });
              window.dispatchEvent(deleteEvent);
            } catch {
              console.error('[P2P] Failed to dispatch remote delete event');
            }

            SecurityAuditLogger.log('info', 'p2p-delete-received', {});
          }
          return;
        }

        // Handle message editing
        if (encryptedMessage.messageType === 'edit') {
          const targetMessageId = encryptedMessage.metadata?.targetMessageId;
          const newContent = encryptedMessage.metadata?.newContent || encryptedMessage.content;
          if (targetMessageId && newContent) {
            let messageToPersist: Message | null = null;
            setMessages(prev => prev.map(msg => {
              if (msg.id === targetMessageId) {
                const updated = { ...msg, content: newContent, isEdited: true };
                messageToPersist = updated;
                return updated;
              }
              return msg;
            }));

            if (messageToPersist) {
              try { saveMessageWithContextRef.current(messageToPersist); } catch { }
            }

            try {
              const editEvent = new CustomEvent('remote-message-edit', {
                detail: { messageId: targetMessageId, newContent }
              });
              window.dispatchEvent(editEvent);
            } catch {
              console.error('[P2P] Failed to dispatch remote edit event');
            }

            SecurityAuditLogger.log('info', 'p2p-edit-received', {});
          }
          return;
        }


        if (encryptedMessage.messageType === 'file') {
          SecurityAuditLogger.log('info', 'p2p-file-metadata-ignored', {});
          return;
        }

        const message: Message = {
          id: encryptedMessage.id,
          content: encryptedMessage.content,
          sender: encryptedMessage.from,
          recipient: encryptedMessage.to,
          timestamp: new Date(encryptedMessage.timestamp),
          type: 'text',
          isCurrentUser: false,
          p2p: true,
          transport: 'p2p',
          encrypted: encryptedMessage.encrypted,
          receipt: { delivered: true, read: false },
          ...(encryptedMessage.metadata?.replyTo && {
            replyTo: {
              id: encryptedMessage.metadata.replyTo.id,
              sender: encryptedMessage.metadata.replyTo.sender,
              content: encryptedMessage.metadata.replyTo.content
            }
          })
        } as Message;

        setMessages(prev => {
          const exists = prev.some(m => {
            if (m.id === message.id) {
              return true;
            }

            try {
              const sameSender = m.sender === message.sender;
              const sameRecipient = m.recipient === message.recipient;
              const sameType = m.type === message.type;
              const sameContent = m.content === message.content;
              const mt = m.timestamp instanceof Date ? m.timestamp.getTime() : (m.timestamp ? new Date(m.timestamp as any).getTime() : undefined);
              const tt = message.timestamp instanceof Date ? message.timestamp.getTime() : (message.timestamp ? new Date(message.timestamp as any).getTime() : undefined);
              const closeInTime = Math.abs(mt - tt) < 2000;
              return sameSender && sameRecipient && sameType && sameContent && closeInTime;
            } catch {
              return false;
            }
          });
          if (exists) {
            return prev;
          }
          return [...prev, message];
        });
        saveMessageWithContextRef.current(message);
        SecurityAuditLogger.log('info', `p2p-${encryptedMessage.messageType || 'message'}-received`, {});
      } catch {
        SecurityAuditLogger.log('error', 'p2p-message-handle-failed', { error: 'unknown' });
      }
    });
  }, []);

  // Connect to peer when conversation is selected
  const p2pMessagingRef = useRef(p2pMessaging);
  p2pMessagingRef.current = p2pMessaging;
  const p2pInitializedRef = useRef(false);
  const p2pSignalingConnectedRef = useRef(false);
  const userInitiatedSelectionRef = useRef(false);
  const lastSelectedConversationRef = useRef<string | null>(null);

  useEffect(() => {
    const isInit = p2pMessaging.p2pStatus?.isInitialized ?? false;
    const signaling = p2pMessaging.p2pStatus?.signalingConnected ?? false;

    if (p2pInitializedRef.current !== isInit || p2pSignalingConnectedRef.current !== signaling) {
      p2pInitializedRef.current = isInit;
      p2pSignalingConnectedRef.current = signaling;
    }
  }, [p2pMessaging.p2pStatus?.isInitialized, p2pMessaging.p2pStatus?.signalingConnected]);

  const connectionAttemptsRef = useRef<Map<string, { inProgress: boolean; lastAttempt: number }>>(new Map());
  const processedPeerConnectionsRef = useRef<Set<string>>(new Set());

  // Listen for successful peer connections to update state
  useEffect(() => {
    const handlePeerConnected = (evt: Event) => {
      try {
        const peer = (evt as CustomEvent).detail?.peer;
        if (peer) {
          if (processedPeerConnectionsRef.current.has(peer)) {
            return;
          }
          processedPeerConnectionsRef.current.add(peer);
          connectionAttemptsRef.current.set(peer, { inProgress: false, lastAttempt: Date.now() });
        }
      } catch { }
    };

    const handlePeerDisconnected = (evt: Event) => {
      try {
        const peer = (evt as CustomEvent).detail?.peer;
        if (peer) {
          processedPeerConnectionsRef.current.delete(peer);
        }
      } catch { }
    };

    window.addEventListener('p2p-peer-connected', handlePeerConnected as EventListener);
    window.addEventListener('p2p-peer-disconnected', handlePeerDisconnected as EventListener);
    return () => {
      window.removeEventListener('p2p-peer-connected', handlePeerConnected as EventListener);
      window.removeEventListener('p2p-peer-disconnected', handlePeerDisconnected as EventListener);
    };
  }, []);

  useEffect(() => {
    if (selectedConversation !== lastSelectedConversationRef.current) {
      if (lastSelectedConversationRef.current !== null) {
        userInitiatedSelectionRef.current = true;
      }
      lastSelectedConversationRef.current = selectedConversation;
    }

    const isInitialized = p2pMessaging.p2pStatus?.isInitialized ?? false;
    const signalingConnected = p2pMessaging.p2pStatus?.signalingConnected ?? false;

    if (!isInitialized || !signalingConnected) { return; }
    if (!selectedConversation || !p2pHybridKeys) { return; }
    if (!userInitiatedSelectionRef.current) { return; }

    const p2p = p2pMessagingRef.current;
    if (!p2p?.isPeerConnected || !p2p?.connectToPeer) return;

    const connected = p2p.isPeerConnected(selectedConversation);

    if (!connected) {
      const now = Date.now();
      const attemptInfo = connectionAttemptsRef.current.get(selectedConversation);

      if (attemptInfo?.inProgress) {
        return;
      }

      if (attemptInfo && (now - attemptInfo.lastAttempt) < 10000) {
        return;
      }

      connectionAttemptsRef.current.set(selectedConversation, { inProgress: true, lastAttempt: now });

      p2p.connectToPeer(selectedConversation)
        .then(() => {
          connectionAttemptsRef.current.set(selectedConversation, { inProgress: false, lastAttempt: now });
        })
        .catch(() => {
          connectionAttemptsRef.current.set(selectedConversation, { inProgress: false, lastAttempt: now });
          SecurityAuditLogger.log('info', 'p2p-connect-failed-fallback-server', {});
        });
    }
  }, [selectedConversation, p2pHybridKeys, p2pMessaging.p2pStatus?.isInitialized, p2pMessaging.p2pStatus?.signalingConnected]);

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
    if (!selectedConversation || !p2pMessagingRef.current?.isPeerConnected) return false;
    return p2pMessagingRef.current.isPeerConnected(selectedConversation);
  }, [selectedConversation, p2pConnectedPeers.includes(selectedConversation)]);

  // Handle conversation message clearing
  useEffect(() => {
    const lastHandled = new Map<string, number>();

    const handleClearConversationMessages = (event: CustomEvent) => {
      try {
        if (!allowEvent('clear-conversation-messages')) return;
        const detail = (event as CustomEvent).detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

        const username = sanitizeNonEmptyText((detail as any).username, MAX_LOCAL_USERNAME_LENGTH, false);
        if (!username || isUnsafeObjectKey(username)) return;

        if (lastHandled.size > 512) {
          lastHandled.clear();
        }
        const now = Date.now();
        const last = lastHandled.get(username) || 0;
        if (now - last < 2000) return;
        lastHandled.set(username, now);

        setMessages(prev => prev.filter(msg =>
          !(msg.sender === username || msg.recipient === username)
        ));
      } catch { }
    };

    window.addEventListener('clear-conversation-messages', handleClearConversationMessages as EventListener);
    return () => {
      window.removeEventListener('clear-conversation-messages', handleClearConversationMessages as EventListener);
    };
  }, []);

  // Handle queued message processing when user keys become available
  useEffect(() => {
    const processedKeysAvailableRef = new Map<string, number>();

    const handleUserKeysAvailable = async (event: CustomEvent) => {
      try {
        if (!allowEvent('user-keys-available')) return;
        const detail = (event as CustomEvent).detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

        const username = sanitizeNonEmptyText((detail as any).username, MAX_LOCAL_USERNAME_LENGTH, false);
        if (!username || isUnsafeObjectKey(username)) return;

        if (processedKeysAvailableRef.size > 512) {
          processedKeysAvailableRef.clear();
        }
        const now = Date.now();
        const last = processedKeysAvailableRef.get(username) || 0;
        if (now - last < 2000) return;
        processedKeysAvailableRef.set(username, now);

        const hybridKeysRaw = (detail as any).hybridKeys;
        if (!isPlainObject(hybridKeysRaw) || hasPrototypePollutionKeys(hybridKeysRaw)) return;

        const maybeKyber = (hybridKeysRaw as any).kyberPublicBase64;
        const maybeDilithium = (hybridKeysRaw as any).dilithiumPublicBase64;
        const maybeX25519 = (hybridKeysRaw as any).x25519PublicBase64;
        if ((typeof maybeKyber === 'string' && maybeKyber.length > 10_000) || (typeof maybeDilithium === 'string' && maybeDilithium.length > 10_000)) {
          return;
        }
        if (typeof maybeX25519 === 'string' && maybeX25519.length > 1_000) {
          return;
        }

        const hybridKeys = sanitizeHybridKeys(hybridKeysRaw as any) as any;
        if (!hybridKeys?.kyberPublicBase64 || !hybridKeys?.dilithiumPublicBase64) return;

        SecurityAuditLogger.log('info', 'user-keys-available', { hasKeys: true });

        let targetUser = Database.users.find(user => user.username === username);
        if (!targetUser) {
          targetUser = {
            id: crypto.randomUUID(),
            username,
            isOnline: true,
            hybridPublicKeys: hybridKeys
          };
          Database.setUsers(prev => [...prev, targetUser!]);
          SecurityAuditLogger.log('info', 'user-added-with-keys', {});
        } else if (!targetUser.hybridPublicKeys) {
          Database.setUsers(prev => prev.map(user =>
            user.username === username
              ? { ...user, hybridPublicKeys: hybridKeys, isOnline: true }
              : user
          ));
          targetUser = { ...targetUser, hybridPublicKeys: hybridKeys, isOnline: true };
          SecurityAuditLogger.log('info', 'user-keys-updated', {});
        }

        const queuedMessages = await secureMessageQueue.processQueueForUser(username);
        if (queuedMessages.length === 0) { return; }

        targetUser = Database.users.find(user => user.username === username) || targetUser;

        const sentIds: string[] = [];
        for (const queuedMsg of queuedMessages) {
          try {
            await messageSender.handleSendMessage(
              targetUser,
              queuedMsg.content,
              queuedMsg.replyTo,
              queuedMsg.fileData,
              queuedMsg.messageSignalType,
              queuedMsg.originalMessageId,
              queuedMsg.editMessageId
            );
            sentIds.push(queuedMsg.id);
            await new Promise<void>((r) => setTimeout(r, 0));
          } catch (_error) {
            SecurityAuditLogger.log('error', 'queued-message-send-failed', { error: _error instanceof Error ? _error.message : 'unknown' });
          }
        }

        if (sentIds.length) {
          setMessages(prev => prev.map(msg => (
            sentIds.includes(msg.id)
              ? { ...msg, pending: false, receipt: { delivered: true, read: false } }
              : msg
          )));
        }
      } catch { }
    };

    window.addEventListener('user-keys-available', handleUserKeysAvailable as EventListener);
    return () => {
      window.removeEventListener('user-keys-available', handleUserKeysAvailable as EventListener);
    };
  }, [Database.users, messageSender]);

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

  // Apply server-provided block list response
  useEffect(() => {

    const onBlockListResponse = async (e: Event) => {
      try {
        if (!allowEvent('block-list-response')) return;
        const detail = (e as CustomEvent).detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

        const passphrase = Authentication.passphrasePlaintextRef?.current || '';
        const kyberSecret = Authentication.hybridKeysRef?.current?.kyber?.secretKey || null;
        const key = passphrase ? passphrase : (kyberSecret ? { kyberSecret } : null);
        if (!key || !Database.dbInitialized) return;

        const encryptedDataRaw = typeof (detail as any).encryptedBlockList === 'string' ? (detail as any).encryptedBlockList : null;
        const saltRaw = typeof (detail as any).salt === 'string' ? (detail as any).salt : null;
        if (!encryptedDataRaw || !saltRaw) return;

        const maxChars = Math.ceil((MAX_INLINE_BASE64_BYTES * 4) / 3) + 128;
        const encryptedData = encryptedDataRaw.trim();
        if (!encryptedData || encryptedData.length > maxChars) return;
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encryptedData)) return;
        const pad = encryptedData.endsWith('==') ? 2 : encryptedData.endsWith('=') ? 1 : 0;
        const estimatedBytes = Math.floor((encryptedData.length * 3) / 4) - pad;
        if (estimatedBytes <= 0 || estimatedBytes > MAX_INLINE_BASE64_BYTES) return;

        const salt = saltRaw.trim();
        if (!salt || salt.length > 256) return;
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(salt)) return;

        const lastUpdated = typeof (detail as any).lastUpdated === 'number' && Number.isFinite((detail as any).lastUpdated)
          ? (detail as any).lastUpdated
          : null;
        const versionRaw = typeof (detail as any).version === 'number' && Number.isFinite((detail as any).version)
          ? (detail as any).version
          : 3;
        const version = versionRaw >= 3 ? Math.floor(versionRaw) : 3;
        await new Promise((r) => setTimeout(r, 0));
        await blockingSystem.handleServerBlockListData(encryptedData, salt, lastUpdated, version, key as any);
      } catch { }
    };
    window.addEventListener('block-list-response', onBlockListResponse as EventListener);
    return () => window.removeEventListener('block-list-response', onBlockListResponse as EventListener);
  }, [Authentication.passphrasePlaintextRef?.current]);

  useEffect(() => {
    const lastHandled = new Map<string, number>();

    const handleUserExistsResponse = async (event: Event) => {
      try {
        if (!allowEvent('user-exists-response')) return;
        const detail = (event as CustomEvent).detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

        const username = sanitizeNonEmptyText((detail as any).username, MAX_LOCAL_USERNAME_LENGTH, false);
        if (!username || isUnsafeObjectKey(username)) return;

        if (lastHandled.size > 512) {
          lastHandled.clear();
        }
        const now = Date.now();
        const last = lastHandled.get(username) || 0;
        if (now - last < 2000) {
          return;
        }
        lastHandled.set(username, now);

        await new Promise((r) => setTimeout(r, 0));

        const exists = (detail as any).exists === true;
        const hybridPublicKeys = (detail as any).hybridPublicKeys;

        if (!exists || !hybridPublicKeys) return;
        if (!isPlainObject(hybridPublicKeys) || hasPrototypePollutionKeys(hybridPublicKeys)) return;

        const maybeKyber = (hybridPublicKeys as any).kyberPublicBase64;
        const maybeDilithium = (hybridPublicKeys as any).dilithiumPublicBase64;
        if ((typeof maybeKyber === 'string' && maybeKyber.length > 10_000) || (typeof maybeDilithium === 'string' && maybeDilithium.length > 10_000)) {
          return;
        }

        const sanitized = sanitizeHybridKeys(hybridPublicKeys as any);
        if (!sanitized?.kyberPublicBase64 || !sanitized?.dilithiumPublicBase64) return;

        if (sanitized?.kyberPublicBase64 && isValidKyberPublicKeyBase64(sanitized.kyberPublicBase64)) {
          try {
            if (typeof (window as any).edgeApi?.storePQKeys === 'function') {
              await (window as any).edgeApi.storePQKeys({
                username,
                kyberPublicKey: sanitized.kyberPublicBase64,
                dilithiumPublicKey: sanitized.dilithiumPublicBase64,
                x25519PublicKey: sanitized.x25519PublicBase64
              });
            }
          } catch { }
        }

        setTimeout(() => {
          try {
            window.dispatchEvent(new CustomEvent('user-keys-available', {
              detail: { username, hybridKeys: sanitized }
            }));
          } catch { }
        }, 0);
      } catch { }
    };

    window.addEventListener('user-exists-response', handleUserExistsResponse as EventListener);
    return () => window.removeEventListener('user-exists-response', handleUserExistsResponse as EventListener);
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
    window.addEventListener('app:entering-background', handleEnteringBackground);

    return () => {
      window.removeEventListener('app:entering-background', handleEnteringBackground);
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
      SecurityAuditLogger.log('error', 'connect-setup-failed', { error: _error instanceof Error ? _error.message : 'unknown' });
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
        SecurityAuditLogger.log('error', 'connection-init-failed', { error: _error instanceof Error ? _error.message : 'unknown' });
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
    window.addEventListener('auth-ui-back', handleAuthUiBack as EventListener);
    return () => window.removeEventListener('auth-ui-back', handleAuthUiBack as EventListener);
  }, []);

  useEffect(() => {
    if (Authentication.isLoggedIn && Database.secureDBRef.current && Authentication.originalUsernameRef.current) {
      Authentication.storeUsernameMapping(Database.secureDBRef.current);
    }
  }, [Authentication.isLoggedIn, Database.secureDBRef.current, Authentication.originalUsernameRef.current]);

  useEffect(() => {

    const handleLocalMessageDelete = (event: CustomEvent) => {
      try {
        if (!allowEvent('local-message-delete')) return;
        const detail = (event as any).detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;
        const messageId = sanitizeNonEmptyText(detail.messageId, MAX_LOCAL_MESSAGE_ID_LENGTH, false);
        if (!messageId) return;

        let messageToPersist: Message | null = null;
        setMessages(prev => {
          const updatedMessages = prev.map(msg => {
            if (msg.id === messageId) {
              const updated = { ...msg, isDeleted: true, content: 'This message was deleted' } as Message;
              messageToPersist = updated;
              return updated;
            }
            return msg;
          });
          return updatedMessages;
        });

        if (messageToPersist) {
          try { void saveMessageWithContext(messageToPersist); } catch { }
        }
      } catch { }
    };

    const handleLocalMessageEdit = (event: CustomEvent) => {
      try {
        if (!allowEvent('local-message-edit')) return;
        const detail = (event as any).detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;
        const messageId = sanitizeNonEmptyText(detail.messageId, MAX_LOCAL_MESSAGE_ID_LENGTH, false);
        const newContent = sanitizeNonEmptyText(detail.newContent, MAX_LOCAL_MESSAGE_LENGTH, true);
        if (!messageId || !newContent) return;

        let messageToPersist: Message | null = null;
        setMessages(prev => {
          const updatedMessages = prev.map(msg => {
            if (msg.id === messageId) {
              const updated = { ...msg, content: newContent, isEdited: true } as Message;
              messageToPersist = updated;
              return updated;
            }
            return msg;
          });
          return updatedMessages;
        });

        if (messageToPersist) {
          try { void saveMessageWithContext(messageToPersist); } catch { }
        }
      } catch { }
    };

    const handleLocalFileMessage = async (event: CustomEvent) => {
      try {
        if (!allowEvent('local-file-message')) return;
        const detail = (event as any).detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

        const fileId = sanitizeNonEmptyText(detail.id, MAX_LOCAL_MESSAGE_ID_LENGTH, false);
        if (!fileId) return;

        const filenameRaw = typeof detail.filename === 'string' ? detail.filename : 'file';
        const filename = sanitizeFilename(filenameRaw, 128);
        const mimeType = sanitizeNonEmptyText(detail.mimeType, MAX_LOCAL_MIMETYPE_LENGTH, false) || 'application/octet-stream';
        const sender = sanitizeNonEmptyText(detail.sender, MAX_LOCAL_USERNAME_LENGTH, false) || '';
        const recipient = sanitizeNonEmptyText(detail.recipient, MAX_LOCAL_USERNAME_LENGTH, false) || '';

        const sizeCandidate = typeof detail.fileSize === 'number' ? detail.fileSize : typeof detail.size === 'number' ? detail.size : undefined;
        const fileSize =
          typeof sizeCandidate === 'number' && Number.isFinite(sizeCandidate) && sizeCandidate >= 0 && sizeCandidate <= MAX_LOCAL_FILE_SIZE_BYTES
            ? sizeCandidate
            : undefined;

        const content = sanitizeNonEmptyText(detail.content, 2048, false) || '';
        const blobUrl = content.startsWith('blob:') ? content : '';

        let secureDbSaveSucceeded = false;
        try {
          if (Database.secureDBRef.current && blobUrl) {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 15_000);
            try {
              const resp = await fetch(blobUrl, { signal: controller.signal });
              if (resp.ok) {
                const fetchedBlob = await resp.blob();
                if (fetchedBlob.size > 0 && fetchedBlob.size <= MAX_LOCAL_FILE_SIZE_BYTES) {
                  const saveResult = await Database.secureDBRef.current.saveFile(fileId, fetchedBlob);
                  secureDbSaveSucceeded = Boolean(saveResult?.success);
                  if (!saveResult.success && saveResult.quotaExceeded) {
                    toast.warning('Storage limit reached. This file will not persist after restart.', {
                      duration: 5000
                    });
                  }
                }
              }
            } finally {
              clearTimeout(timeout);
            }
          }
        } catch (err) {
          console.error('[Index] Failed to save file to SecureDB:', err);
        }

        let timestamp: Date;
        try {
          if (typeof detail.timestamp === 'number' && Number.isFinite(detail.timestamp)) {
            timestamp = new Date(detail.timestamp);
          } else if (typeof detail.timestamp === 'string') {
            timestamp = new Date(detail.timestamp);
          } else if (detail.timestamp instanceof Date) {
            timestamp = detail.timestamp;
          } else {
            timestamp = new Date();
          }
          if (isNaN(timestamp.getTime())) {
            timestamp = new Date();
          }
        } catch {
          timestamp = new Date();
        }

        const receiptDetail = detail.receipt;
        const receipt =
          isPlainObject(receiptDetail) && !hasPrototypePollutionKeys(receiptDetail)
            ? {
              delivered: typeof receiptDetail.delivered === 'boolean' ? receiptDetail.delivered : false,
              read: typeof receiptDetail.read === 'boolean' ? receiptDetail.read : false
            }
            : {
              delivered: false,
              read: false
            };

        let safeOriginalBase64Data: string | undefined;
        if (!secureDbSaveSucceeded && typeof detail.originalBase64Data === 'string') {
          const raw = detail.originalBase64Data;
          const maxChars = Math.ceil((MAX_INLINE_BASE64_BYTES * 4) / 3) + 128;
          if (raw.length > 0 && raw.length <= maxChars) {
            let normalized = raw.trim();
            const commaIndex = normalized.indexOf(',');
            if (commaIndex > 0 && commaIndex < 128) {
              normalized = normalized.slice(commaIndex + 1);
            }
            normalized = normalized.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
            if (/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
              const pad = normalized.endsWith('==') ? 2 : normalized.endsWith('=') ? 1 : 0;
              const estimatedBytes = Math.floor((normalized.length * 3) / 4) - pad;
              if (estimatedBytes > 0 && estimatedBytes <= MAX_INLINE_BASE64_BYTES) {
                safeOriginalBase64Data = normalized;
              }
            }
          }
        }

        const newMessage: Message = {
          id: fileId,
          content: blobUrl,
          sender,
          recipient,
          timestamp,
          isCurrentUser: true,
          type: 'file',
          filename,
          fileSize,
          mimeType,
          receipt,
          ...(safeOriginalBase64Data ? { originalBase64Data: safeOriginalBase64Data } : {}),
          version: typeof detail.version === 'string' && detail.version.length > 0 ? detail.version : '1'
        } as Message;

        let messageToPersist: Message | null = null;
        setMessages(prev => {
          const existingMessage = prev.find(msg => msg.id === fileId);
          if (existingMessage) {
            return prev;
          }
          messageToPersist = newMessage;
          return [...prev, newMessage];
        });

        if (messageToPersist) {
          try { void saveMessageWithContext(messageToPersist); } catch { }
        }
      } catch { }
    };

    window.addEventListener('local-message-delete', handleLocalMessageDelete as EventListener);
    window.addEventListener('local-message-edit', handleLocalMessageEdit as EventListener);
    window.addEventListener('local-file-message', handleLocalFileMessage as EventListener);

    const handleLocalReactionUpdate = (event: CustomEvent) => {
      try {
        if (!allowEvent('local-reaction-update')) return;
        const detail = (event as any).detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;
        const messageId = sanitizeNonEmptyText(detail.messageId, MAX_LOCAL_MESSAGE_ID_LENGTH, false);
        const emoji = sanitizeNonEmptyText(detail.emoji, MAX_LOCAL_EMOJI_LENGTH, false);
        const username = sanitizeNonEmptyText(detail.username, MAX_LOCAL_USERNAME_LENGTH, false);
        const isAdd = typeof detail.isAdd === 'boolean' ? detail.isAdd : null;
        if (!messageId || !emoji || !username) return;
        if (isAdd === null) return;
        if (isUnsafeObjectKey(emoji)) return;

        let updatedMessage: Message | null = null;

        setMessages(prev => prev.map(msg => {
          if (msg.id !== messageId) return msg;

          const currentReactions: Record<string, string[]> = Object.create(null);
          if (msg.reactions && typeof msg.reactions === 'object') {
            for (const [reactionKey, rawUsers] of Object.entries(msg.reactions as Record<string, unknown>)) {
              if (typeof reactionKey !== 'string' || isUnsafeObjectKey(reactionKey)) continue;
              if (!Array.isArray(rawUsers)) continue;
              const safeUsers: string[] = [];
              const seen = new Set<string>();
              for (const candidate of rawUsers as unknown[]) {
                if (safeUsers.length >= 250) break;
                const cleaned = sanitizeNonEmptyText(candidate, MAX_LOCAL_USERNAME_LENGTH, false);
                if (!cleaned) continue;
                if (seen.has(cleaned)) continue;
                seen.add(cleaned);
                safeUsers.push(cleaned);
              }
              if (safeUsers.length > 0) {
                currentReactions[reactionKey] = safeUsers;
              }
            }
          }

          const users = currentReactions[emoji] ? [...currentReactions[emoji]] : [];
          if (isAdd) {
            if (!users.includes(username) && users.length < 250) {
              users.push(username);
            }
          } else {
            const idx = users.indexOf(username);
            if (idx !== -1) {
              users.splice(idx, 1);
            }
          }

          if (users.length > 0) {
            currentReactions[emoji] = users;
          } else {
            delete currentReactions[emoji];
          }

          const updated = { ...msg, reactions: currentReactions };
          updatedMessage = updated;
          return updated;
        }));

        if (updatedMessage) {
          try {
            void saveMessageWithContext(updatedMessage);
          } catch (e) {
            console.error('[Index] Failed to persist reaction update:', e);
          }
        }
      } catch { }
    };

    window.addEventListener('local-reaction-update', handleLocalReactionUpdate as EventListener);

    return () => {
      window.removeEventListener('local-message-delete', handleLocalMessageDelete as EventListener);
      window.removeEventListener('local-message-edit', handleLocalMessageEdit as EventListener);
      window.removeEventListener('local-file-message', handleLocalFileMessage as EventListener);
      window.removeEventListener('local-reaction-update', handleLocalReactionUpdate as EventListener);
    };
  }, [setMessages, saveMessageWithContext]);


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
                                      messageType: 'file',
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
                          SecurityAuditLogger.log('error', 'file-transfer-failed', { error: error instanceof Error ? error.message : 'unknown' });
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
              onAnswer={() => callingHook.currentCall && callingHook.answerCall(callingHook.currentCall.id)}
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