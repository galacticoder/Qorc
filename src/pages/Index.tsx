import React, { useState, useCallback, useEffect, useRef, useMemo } from "react";
import { Login } from "../components/chat/Login";
import { Sidebar, User } from "../components/chat/UserList";
import { ConversationList } from "../components/chat/ConversationList";
import { ChatInterface } from "../components/chat/ChatInterface";
import { AppSettings } from "../components/settings/AppSettings";
import { Message } from "../components/chat/types";
import { EmojiPickerProvider } from "../contexts/EmojiPickerContext";
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
import { useP2PMessaging, type HybridKeys, type PeerCertificateBundle } from "../hooks/useP2PMessaging";
import { useMessageReceipts } from "../hooks/useMessageReceipts";
import { p2pConfig, getSignalingServerUrl } from "../config/p2p.config";
import websocketClient from "../lib/websocket";
import { TypingIndicatorProvider } from "../contexts/TypingIndicatorContext";
import { torNetworkManager } from "../lib/tor-network";
import { ConnectSetup } from '@/components/setup/ConnectSetup';
import { SignalType } from "../lib/signal-types";
import { blockingSystem } from "../lib/blocking-system";
import { secureMessageQueue } from "../lib/secure-message-queue";
import { isValidKyberPublicKeyBase64, sanitizeHybridKeys } from "../lib/validators";
import { SecurityAuditLogger } from "../lib/post-quantum-crypto";

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

interface ChatAppProps {
  onNavigate: (page: "home" | "server" | "chat") => void;
}

const ChatApp: React.FC<ChatAppProps> = () => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [sidebarActiveTab, setSidebarActiveTab] = useState<string>("messages");
  const [setupComplete, setSetupComplete] = useState(false);
  const [selectedServerUrl, setSelectedServerUrl] = useState<string>('');
  const [showSettings, setShowSettings] = useState(false);

  const Authentication = useAuth();
  
  const Database = useSecureDB({
    Authentication,
    setMessages,
  });

  const { loadMoreConversationMessages } = Database;

  const usersRef = useRef<User[]>([]);
  usersRef.current = Database.users;

  const handleIncomingFileMessage = useCallback((message: Message) => {
    setMessages(prev => (prev.some(m => m.id === message.id) ? prev : [...prev, message]));
    try { void Database.saveMessageToLocalDB(message); } catch {}
  }, [setMessages, Database]);

  const fileHandler = useFileHandler(
    Authentication.getKeysOnDemand,
    handleIncomingFileMessage,
    Authentication.setLoginError
  );

  const messageSender = useMessageSender(
    Database.users,
    Authentication.loginUsernameRef,
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
    Database.secureDBRef
  );

  const encryptedHandler = useEncryptedMessageHandler(
    Authentication.loginUsernameRef,
    setMessages,
    Database.saveMessageToLocalDB,
    Authentication.isLoggedIn && Authentication.accountAuthenticated,
    Authentication.getKeysOnDemand,
    usersRef,
    undefined,
    fileHandler.handleFileMessageChunk
  );

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
  } = useConversations(Authentication.loginUsernameRef.current || '', Database.users, messages, Database.secureDBRef.current);

  // Prefetch libsignal session for the selected conversation to minimize send latency
  useEffect(() => {
    if (selectedConversation && typeof messageSender?.prefetchSessionForPeer === 'function') {
      try { messageSender.prefetchSessionForPeer(selectedConversation); } catch {}
    }
  }, [selectedConversation, messageSender]);

  // Username display system
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
      } catch {}
    })();
  }, [Authentication.originalUsernameRef.current, Authentication.loginUsernameRef.current, usernameDisplay]);
  
  const kyberSecretRefForSettings = useMemo(() => {
    const kyberSecret = Authentication.hybridKeysRef?.current?.kyber?.secretKey;
    return { current: kyberSecret || null };
  }, [Authentication.hybridKeysRef?.current?.kyber?.secretKey]);
  
  // P2P Messaging system
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
  }, [Authentication.hybridKeysRef.current]);

  const fetchPeerCertificates = useCallback(async (peerUsername: string): Promise<PeerCertificateBundle | null> => {
    try {
      // Request cert through both channels: dedicated cert fetch + check-user-exists hint
      return await new Promise<PeerCertificateBundle | null>(async (resolve) => {
        let settled = false;

        const wsHandler = (evt: Event) => {
          try {
            const msg: any = (evt as CustomEvent).detail || {};
            if (!msg || typeof msg !== 'object') return;
            if (msg.type !== 'p2p-peer-cert') return;
            if (typeof msg.username !== 'string' || msg.username !== peerUsername) return;
            if (typeof msg.dilithiumPublicKey !== 'string' || typeof msg.kyberPublicKey !== 'string' || typeof msg.signature !== 'string' || typeof msg.proof !== 'string') return;
            try { window.removeEventListener('p2p-peer-cert', wsHandler as EventListener); } catch {}
            try { window.removeEventListener('user-exists-response', userExistsHandler as EventListener); } catch {}
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

            try {
              const hybridKeys = {
                kyberPublicBase64: bundle.kyberPublicKey,
                dilithiumPublicBase64: bundle.dilithiumPublicKey,
                x25519PublicBase64: bundle.x25519PublicKey,
              };
              window.dispatchEvent(new CustomEvent('user-keys-available', {
                detail: { username: bundle.username, hybridKeys },
              }));
            } catch {}

            settled = true;
            resolve(bundle);
          } catch {}
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
            try { (websocketClient as any).unregisterMessageHandler?.('p2p-peer-cert'); } catch {}
            try { window.removeEventListener('user-exists-response', userExistsHandler as EventListener); } catch {}
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
            try {
              const hybridKeys = {
                kyberPublicBase64: bundle.kyberPublicKey,
                dilithiumPublicBase64: bundle.dilithiumPublicKey,
                x25519PublicBase64: bundle.x25519PublicKey,
              };
              window.dispatchEvent(new CustomEvent('user-keys-available', {
                detail: { username: bundle.username, hybridKeys },
              }));
            } catch {}

            settled = true;
            resolve(bundle);
          } catch {}
        };

        try { window.addEventListener('p2p-peer-cert', wsHandler as EventListener); } catch {}
        try { window.addEventListener('user-exists-response', userExistsHandler as EventListener); } catch {}

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
            try { window.removeEventListener('p2p-peer-cert', wsHandler as EventListener); } catch {}
            try { window.removeEventListener('user-exists-response', userExistsHandler as EventListener); } catch {}
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
        try { (window as any).p2pService = service; } catch {}
      }
    }
  );

  // Helper to get or create user for messaging
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

  // Store username mapping for current user only when SecureDB is available
  useEffect(() => {
    if (Database.secureDBRef.current && Authentication.originalUsernameRef.current) {
      const storeCurrentUserMapping = async () => {
        try {
          await Authentication.storeUsernameMapping(Database.secureDBRef.current!);
        } catch (_error) {
          SecurityAuditLogger.log('error', 'user-mapping-store-failed', { error: _error instanceof Error ? _error.message : 'unknown' });
        }
      };
      storeCurrentUserMapping();
    }
  }, [Database.secureDBRef.current, Authentication.originalUsernameRef.current]);

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
        } catch (_error) {
          SecurityAuditLogger.log('error', 'message-queue-init-failed', { error: _error instanceof Error ? _error.message : 'unknown' });
        }
      };
      initMessageQueue();
    }
  }, [Database.secureDBRef.current, Authentication.loginUsernameRef.current]);

  // Bridge P2P file chunks into file handler
  useEffect(() => {
    const onP2PChunk = (e: Event) => {
      try {
        const d: any = (e as CustomEvent).detail || {};
        if (d && d.payload) {
          fileHandler.handleFileMessageChunk(d.payload, { from: d.from, to: d.to });
        }
      } catch {}
    };
    window.addEventListener('p2p-file-chunk', onP2PChunk as EventListener);
    return () => window.removeEventListener('p2p-file-chunk', onP2PChunk as EventListener);
  }, [fileHandler]);

  // Handle P2P reactions
  useEffect(() => {
    const onP2PReaction = (e: Event) => {
      try {
        const d: any = (e as CustomEvent).detail || {};
        const { messageId, reaction, action, sender } = d;
        if (!messageId || !reaction || !action || !sender) return;
        
        setMessages(prev => prev.map(msg => {
          if (msg.id !== messageId) return msg;
          const reactions = { ...(msg.reactions || {}) } as Record<string, string[]>;
          const isAdd = action === 'add';
          
          for (const key of Object.keys(reactions)) {
            reactions[key] = (reactions[key] || []).filter(u => u !== sender);
            if (reactions[key].length === 0) delete reactions[key];
          }
          
          if (isAdd) {
            const arr = Array.isArray(reactions[reaction]) ? [...reactions[reaction]] : [];
            if (!arr.includes(sender)) {
              arr.push(sender);
            }
            reactions[reaction] = arr;
          }
          
          return { ...msg, reactions };
        }));
        
      } catch (_error) {
        console.error('[P2P] Failed to handle reaction', _error);
      }
    };
    window.addEventListener('message-reaction', onP2PReaction as EventListener);
    return () => window.removeEventListener('message-reaction', onP2PReaction as EventListener);
  }, []);

  useEffect(() => {
      if (Authentication.isLoggedIn && selectedServerUrl && p2pHybridKeys) {
        const signalingUrl = getSignalingServerUrl(selectedServerUrl);
        p2pMessaging.initializeP2P(signalingUrl).catch((_error) => {
          SecurityAuditLogger.log('warn', 'p2p-init-failed', {});
        });
      } else {
      }
  }, [Authentication.isLoggedIn, selectedServerUrl, p2pHybridKeys]);

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
            try { await p2pMessaging.connectToPeer(to); } catch {}
            await (p2pMessaging as any).waitForPeerConnection?.(to, 5000).catch(() => {});
          }

          await (p2pMessaging as any)?.p2pServiceRef?.current?.sendMessage?.(to, { kind: 'session-reset-request', reason }, 'signal');
        } catch {}
      } catch {}
    };
    try { window.addEventListener('p2p-session-reset-send', handler as EventListener); } catch {}
    return () => { try { window.removeEventListener('p2p-session-reset-send', handler as EventListener); } catch {} };
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
            try { await p2pMessaging.connectToPeer(to); } catch {}
            try { await (p2pMessaging as any).waitForPeerConnection?.(to, 2000); } catch {}
          }
          const svc: any = (window as any).p2pService || (p2pMessaging as any)?.p2pServiceRef?.current || null;
          if (svc && typeof svc.sendMessage === 'function') {
            try {
              await svc.sendMessage(to, { kind: 'call-signal', signal: signalObj }, 'signal');
              success = true;
            } catch (_e) {
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
              } catch {}
            }
          }
        } catch {}
        try {
          window.dispatchEvent(new CustomEvent('p2p-call-signal-result', { detail: { requestId, success } }));
        } catch {}
      } catch {}
    };
    try { window.addEventListener('p2p-call-signal-send', handler as EventListener); } catch {}
    return () => { try { window.removeEventListener('p2p-call-signal-send', handler as EventListener); } catch {} };
  }, [p2pMessaging]);

  // Handle incoming P2P messages 
  useEffect(() => {
    p2pMessaging.onMessage((encryptedMessage) => {
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
          const reactionData = encryptedMessage.metadata;
          if (reactionData) {
            const reactionEvent = new CustomEvent('message-reaction', {
              detail: {
                messageId: reactionData.targetMessageId,
                reaction: reactionData.reaction,
                action: reactionData.action,
                sender: encryptedMessage.from,
              }
            });
            window.dispatchEvent(reactionEvent);
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
              try { saveMessageWithContextRef.current(messageToPersist); } catch {}
            }
            
            try {
              const deleteEvent = new CustomEvent('remote-message-delete', {
                detail: { messageId: targetMessageId }
              });
              window.dispatchEvent(deleteEvent);
            } catch (_error) {
              console.error('[P2P] Failed to dispatch remote delete event:', _error);
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
              try { saveMessageWithContextRef.current(messageToPersist); } catch {}
            }
            
            try {
              const editEvent = new CustomEvent('remote-message-edit', {
                detail: { messageId: targetMessageId, newContent }
              });
              window.dispatchEvent(editEvent);
            } catch (_error) {
              console.error('[P2P] Failed to dispatch remote edit event:', _error);
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
              const mt = m.timestamp instanceof Date ? m.timestamp.getTime() : new Date(m.timestamp as any).getTime();
              const tt = message.timestamp instanceof Date ? message.timestamp.getTime() : new Date(message.timestamp as any).getTime();
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
      } catch (_error) {
        SecurityAuditLogger.log('error', 'p2p-message-handle-failed', { error: _error instanceof Error ? _error.message : 'unknown' });
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
            const connectionKey = `${peer}-${Date.now()}`;
            if (processedPeerConnectionsRef.current.has(peer)) {
              return;
            }
            processedPeerConnectionsRef.current.add(peer);
            connectionAttemptsRef.current.set(peer, { inProgress: false, lastAttempt: Date.now() });
          }
      } catch {}
    };
    
    const handlePeerDisconnected = (evt: Event) => {
      try {
        const peer = (evt as CustomEvent).detail?.peer;
        if (peer) {
          processedPeerConnectionsRef.current.delete(peer);
        }
      } catch {}
    };
    
    window.addEventListener('p2p-peer-connected', handlePeerConnected as EventListener);
    window.addEventListener('p2p-peer-disconnected', handlePeerDisconnected as EventListener);
    return () => {
      window.removeEventListener('p2p-peer-connected', handlePeerConnected as EventListener);
      window.removeEventListener('p2p-peer-disconnected', handlePeerDisconnected as EventListener);
    };
  }, []);
  
  useEffect(() => {
    // Detect if this is a new user-initiated selection
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
      // Check if a connection is already in progress or recently attempted
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
        .catch((e) => {
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

  const selectedDisplayName = useMemo(() => {
    if (!selectedConversation) return '';
    const found = conversations.find(c => c.username === selectedConversation);
    return found?.displayName || '';
  }, [conversations, selectedConversation]);
  
  const p2pConnectedPeers = p2pMessaging?.p2pStatus?.connectedPeers ?? [];
  const p2pConnectedStatus = useMemo(() => {
    if (!selectedConversation || !p2pMessagingRef.current?.isPeerConnected) return false;
    return p2pMessagingRef.current.isPeerConnected(selectedConversation);
  }, [selectedConversation, p2pConnectedPeers.includes(selectedConversation)]);

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

  // Handle queued message processing when user keys become available
  useEffect(() => {
    const processedKeysAvailableRef = new Map<string, number>();
    const handleUserKeysAvailable = async (event: CustomEvent) => {
      const { username, hybridKeys } = event.detail;
      const now = Date.now();
      const last = processedKeysAvailableRef.get(username) || 0;
      if (now - last < 2000) return;
      processedKeysAvailableRef.set(username, now);
      SecurityAuditLogger.log('info', 'user-keys-available', { hasKeys: !!hybridKeys });
      
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
        // Batch-update UI once for all sent messages
        setMessages(prev => prev.map(msg => (
          sentIds.includes(msg.id)
            ? { ...msg, pending: false, receipt: { delivered: true, read: false } }
            : msg
        )));
      }
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
      if (!Authentication.isLoggedIn || !Authentication.accountAuthenticated || !key) return;
      try {
        await blockingSystem.downloadFromServer(key as any);
      } catch {}
    };
    tryRestoreBlockList();
  }, [Authentication.isLoggedIn, Authentication.accountAuthenticated, Authentication.passphrasePlaintextRef?.current, Authentication.aesKeyRef?.current]);

  // Apply server-provided block list response
  useEffect(() => {
    const onBlockListResponse = async (e: Event) => {
      try {
        const data: any = (e as CustomEvent).detail || {};
        const passphrase = Authentication.passphrasePlaintextRef?.current || '';
        const kyberSecret = Authentication.hybridKeysRef?.current?.kyber?.secretKey || null;
        const key = passphrase ? passphrase : (kyberSecret ? { kyberSecret } : null);
        if (!key) return;
        const encryptedData = data?.encryptedBlockList ?? null;
        const salt = data?.salt ?? null;
        const lastUpdated = typeof data?.lastUpdated === 'number' ? data.lastUpdated : null;
        const version = typeof data?.version === 'number' ? data.version : 3;
        await new Promise((r) => setTimeout(r, 0));
        await blockingSystem.handleServerBlockListData(encryptedData, salt, lastUpdated, version, key as any);
      } catch {}
    };
    window.addEventListener('block-list-response', onBlockListResponse as EventListener);
    return () => window.removeEventListener('block-list-response', onBlockListResponse as EventListener);
  }, [Authentication.passphrasePlaintextRef?.current]);

  // Throttle handling of user-exists-response to prevent UI stalls
  useEffect(() => {
    const lastHandled = new Map<string, number>();

    const handleUserExistsResponse = async (event: Event) => {
      try {
        const data: any = (event as CustomEvent).detail || {};
        const username: string | undefined = typeof data?.username === 'string' ? data.username : undefined;
        const now = Date.now();
        if (username) {
          const last = lastHandled.get(username) || 0;
          if (now - last < 2000) {
            return;
          }
          lastHandled.set(username, now);
        }
        await new Promise((r) => setTimeout(r, 0));

        const exists = Boolean(data?.exists);
        const hybridPublicKeys = data?.hybridPublicKeys;

        if (!exists || !username || !hybridPublicKeys) return;

        const sanitized = sanitizeHybridKeys(hybridPublicKeys);

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
          } catch {}
        }

        setTimeout(() => {
          try {
            window.dispatchEvent(new CustomEvent('user-keys-available', {
              detail: { username, hybridKeys: sanitized }
            }));
          } catch {}
        }, 0);
      } catch {}
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

  // setup is handled by ConnectSetup component
  useEffect(() => {
    return () => {
      if (torNetworkManager.isSupported()) {
        torNetworkManager.shutdown();
      }
    };
  }, []);

  // Handle setup completion
  const handleConnectSetupComplete = async (serverUrl: string) => {
    try {
      SecurityAuditLogger.log('info', 'connect-setup-completed', {});
      setSelectedServerUrl(serverUrl);
      await (window as any).edgeApi?.wsConnect?.();
      setSetupComplete(true);
    } catch (_error) {
      SecurityAuditLogger.log('error', 'connect-setup-failed', { error: _error instanceof Error ? _error.message : 'unknown' });
    }
  };

  // Initialize WebSocket only after setup is complete
  const attemptedRecoveryRef = useRef(false);
  useEffect(() => {
    if (!selectedServerUrl || !setupComplete) return;

    const initializeConnection = async () => {
      try {
        await (window as any).edgeApi?.wsConnect?.();
        
        const hasEncryptedAuth = Database.secureDBRef.current !== null;
        const canRecover = (
          hasEncryptedAuth &&
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
            await Authentication.attemptAuthRecovery();
          } catch (_e) {
            SecurityAuditLogger.log('warn', 'auth-recovery-failed', { error: (_e as any)?.message || 'unknown' });
          }
        }
      } catch (_error) {
        SecurityAuditLogger.log('error', 'connection-init-failed', { error: _error instanceof Error ? _error.message : 'unknown' });
      }
    };
    
    void initializeConnection();
  }, [setupComplete, selectedServerUrl, Authentication.isLoggedIn, Authentication.isRegistrationMode, Authentication.showPassphrasePrompt, Authentication.showPasswordPrompt, Authentication.isSubmittingAuth, Authentication.accountAuthenticated, Authentication.recoveryActive]);

  useWebSocket(signalHandler, encryptedHandler, Authentication.setLoginError);

  useEffect(() => {
    const handleAuthUiBack = async (event: CustomEvent) => {
      try {
        const to = (event as any).detail?.to as 'server' | undefined;
        if (to === 'server') {
          try { await (window as any).electronAPI?.wsDisconnect?.(); } catch {}
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
      if (!event.detail || typeof event.detail !== 'object') {
        return;
      }
      
      const { messageId } = event.detail;
      if (!messageId || typeof messageId !== 'string') {
        return;
      }
      
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
        try { void saveMessageWithContext(messageToPersist); } catch {}
      }
    };

    const handleLocalMessageEdit = (event: CustomEvent) => {
      if (!event.detail || typeof event.detail !== 'object') { return; }
      const { messageId, newContent } = event.detail;
      if (!messageId || typeof messageId !== 'string') { return; }
      if (!newContent || typeof newContent !== 'string') { return; }
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
        try { void saveMessageWithContext(messageToPersist); } catch {}
      }
    };

    const handleLocalFileMessage = (event: CustomEvent) => {
      if (!event.detail || typeof event.detail !== 'object') { return; }
      const fileMessage = event.detail;
      if (!fileMessage.id || typeof fileMessage.id !== 'string') { return; }
      
      setMessages(prev => {
        const existingMessage = prev.find(msg => msg.id === fileMessage.id);
        if (existingMessage) {
          return prev;
        }
        
        let timestamp;
        try {
          timestamp = fileMessage.timestamp ? new Date(fileMessage.timestamp) : new Date();
          if (isNaN(timestamp.getTime())) {
            throw new Error('Invalid timestamp');
          }
        } catch (_err) {
          timestamp = new Date();
        }
        
        const newMessage = {
          ...fileMessage,
          isCurrentUser: true,
          recipient: fileMessage.recipient || '',
          timestamp
        };
        return [...prev, newMessage];
      });
    };

    window.addEventListener('local-message-delete', handleLocalMessageDelete as EventListener);
    window.addEventListener('local-message-edit', handleLocalMessageEdit as EventListener);
    window.addEventListener('local-file-message', handleLocalFileMessage as EventListener);
    
    return () => {
      window.removeEventListener('local-message-delete', handleLocalMessageDelete as EventListener);
      window.removeEventListener('local-message-edit', handleLocalMessageEdit as EventListener);
      window.removeEventListener('local-file-message', handleLocalFileMessage as EventListener);
    };
  }, [setMessages, saveMessageWithContext]);

  if (!setupComplete || !selectedServerUrl) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4 bg-white dark:bg-[hsl(var(--background))]">
        <div className="w-full max-w-2xl">
          <ConnectSetup onComplete={handleConnectSetupComplete} initialServerUrl={selectedServerUrl} />
        </div>
      </div>
    );
  }

  // While validating existing token show a loading screen instead of login
  if (Authentication.tokenValidationInProgress) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4 bg-white dark:bg-[hsl(var(--background))]">
        <div className="text-center text-sm" style={{ color: 'var(--color-text-secondary)' }}>
          Validating session...
        </div>
      </div>
    );
  }

  // Show login screen if not logged in OR if passphrase/password is needed for recovery
  if (!Authentication.isLoggedIn || Authentication.showPassphrasePrompt || Authentication.showPasswordPrompt) {
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
          recoveryActive={Authentication.recoveryActive}
          pseudonym={Authentication.loginUsernameRef.current || ''}
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
          currentUsername={currentDisplayName || Authentication.originalUsernameRef.current || Authentication.loginUsernameRef.current || ''}
          onAddConversation={addConversation}
          onLogout={async () => await Authentication.logout(Database.secureDBRef)}
          onActiveTabChange={setSidebarActiveTab}
        >
          <ConversationList
            conversations={conversations}
            selectedConversation={selectedConversation || undefined}
            onSelectConversation={selectConversation}
            onRemoveConversation={removeConversation}
            getDisplayUsername={stableGetDisplayUsername}
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
            <AppSettings 
              passphraseRef={Authentication.passphrasePlaintextRef} 
              kyberSecretRef={kyberSecretRefForSettings as any}
              getDisplayUsername={stableGetDisplayUsername}
            />
          ) : selectedConversation ? (
            <EmojiPickerProvider>
              <ChatInterface
                 messages={conversationMessages}
                 setMessages={setMessages}
                 callingAuthContext={Authentication}
                 currentUsername={Authentication.loginUsernameRef.current || ''}
                 getDisplayUsername={stableGetDisplayUsername}
                 getKeysOnDemand={Authentication.getKeysOnDemand}
                 p2pConnected={p2pConnectedStatus}
                 selectedDisplayName={selectedDisplayName}
                 loadMoreMessages={loadMoreConversationMessages}
                 sendP2PReadReceipt={p2pMessaging.sendP2PReadReceipt}
                 sendServerReadReceipt={sendServerReadReceipt}
                 markMessageAsRead={markMessageAsRead}
                 getSmartReceiptStatus={getSmartReceiptStatus}
                 onSendMessage={async (messageId, content, messageSignalType, replyTo) => {
                if (!selectedConversation) {
                  SecurityAuditLogger.log('error', 'no-conversation-selected', {});
                  return;
                }
                
                if (messageSignalType !== 'typing-start' && messageSignalType !== 'typing-stop') {
                  try {
                    const passphrase = Authentication.passphrasePlaintextRef.current;
                    let keyArg: any = '';
                    if (passphrase) {
                      keyArg = passphrase;
                    } else {
                      let kyberSecret: Uint8Array | undefined = Authentication.hybridKeysRef?.current?.kyber?.secretKey;
                      if (!kyberSecret && typeof Authentication.getKeysOnDemand === 'function') {
                        try {
                          const keys = await Authentication.getKeysOnDemand();
                          kyberSecret = keys?.kyber?.secretKey;
                        } catch {}
                      }
                      if (kyberSecret instanceof Uint8Array && kyberSecret.length > 0) {
                        keyArg = { kyberSecret };
                      }
                    }
                    if (keyArg && selectedConversation) {
                      const canSend = await blockingSystem.canSendMessage(selectedConversation, keyArg);
                      if (!canSend) {
                        SecurityAuditLogger.log('info', 'message-blocked', { recipient: selectedConversation });
                        alert('You have blocked this user. Cannot send messages.');
                        return;
                      }
                    }
                  } catch (_error) {
                    SecurityAuditLogger.log('error', 'blocking-check-failed', { error: _error instanceof Error ? _error.message : 'unknown' });
                    console.error('[ChatApp] Blocking check failed:', _error);
                  }
                }
                
                if (messageSignalType === SignalType.REACTION_ADD || messageSignalType === SignalType.REACTION_REMOVE) {
                  const targetUser = getOrCreateUser(selectedConversation);

                  try {
                    const actor = Authentication.loginUsernameRef.current || '';
                    const isAdd = messageSignalType === SignalType.REACTION_ADD;
                    const emoji = content;
                    if (actor && typeof emoji === 'string' && emoji.length > 0 && messageId) {
                      setMessages(prev => prev.map(msg => {
                        if (msg.id !== messageId) return msg;
                        const reactions = { ...(msg.reactions || {}) } as Record<string, string[]>;
                        for (const key of Object.keys(reactions)) {
                          reactions[key] = (reactions[key] || []).filter(u => u !== actor);
                          if (reactions[key].length === 0) delete reactions[key];
                        }
                        if (isAdd) {
                          const arr = Array.isArray(reactions[emoji]) ? [...reactions[emoji]] : [];
                          if (!arr.includes(actor)) {
                            arr.push(actor);
                          }
                          reactions[emoji] = arr;
                        }
                        return { ...msg, reactions };
                      }));
                    }
                  } catch {}
                  
                  // Try P2P first for reactions if enabled and peer is connected
                  if (p2pConfig.features.reactions && 
                      p2pMessaging.isPeerConnected(selectedConversation) && 
                      targetUser.hybridPublicKeys) {
                    try {
                      const result = await p2pMessaging.sendP2PMessage(
                        selectedConversation,
                        content,
                        {
                          dilithiumPublicBase64: targetUser.hybridPublicKeys.dilithiumPublicBase64 || '',
                          kyberPublicBase64: targetUser.hybridPublicKeys.kyberPublicBase64 || '',
                          x25519PublicBase64: targetUser.hybridPublicKeys.x25519PublicBase64,
                        },
                        {
                          messageType: 'reaction',
                          metadata: {
                            targetMessageId: messageId,
                            reaction: content,
                            action: messageSignalType === SignalType.REACTION_ADD ? 'add' : 'remove',
                          }
                        }
                      );
                      if (result.status === 'sent') {
                        SecurityAuditLogger.log('info', 'p2p-reaction-sent', {});
                        return;
                      }
                      SecurityAuditLogger.log('info', 'p2p-reaction-queued-or-not-sent', { status: result.status });
                    } catch (_error) {
                      SecurityAuditLogger.log('info', 'p2p-reaction-failed-fallback-server', {});
                    }
                  }
                  
                  await messageSender.handleSendMessage(targetUser, content, undefined, undefined, messageSignalType, messageId);
                  return;
                }

                if (messageSignalType === 'typing-start' || messageSignalType === 'typing-stop') {
                  const targetUser = getOrCreateUser(selectedConversation);
                  
                  if (p2pConfig.features.typingIndicators && p2pMessaging.isPeerConnected(selectedConversation)) {
                    try {
                      const result = await p2pMessaging.sendP2PMessage(
                        selectedConversation,
                        messageSignalType,
                        targetUser.hybridPublicKeys ? {
                          dilithiumPublicBase64: targetUser.hybridPublicKeys.dilithiumPublicBase64 || '',
                          kyberPublicBase64: targetUser.hybridPublicKeys.kyberPublicBase64 || '',
                          x25519PublicBase64: targetUser.hybridPublicKeys.x25519PublicBase64,
                        } : undefined,
                        {
                          messageType: 'typing',
                        }
                      );
                      if (result.status === 'sent') {
                        SecurityAuditLogger.log('info', 'p2p-typing-sent', {});
                        return;
                      }
                      SecurityAuditLogger.log('info', 'p2p-typing-queued-or-not-sent', { status: result.status });
                    } catch (_error) {
                      console.error('[P2P][UI] typing P2P send failed, falling back to server', _error);
                      SecurityAuditLogger.log('info', 'p2p-typing-failed-fallback-server', {});
                    }
                  }
                  
                  // Fallback to server
                  return messageSender.handleSendMessage(targetUser, content, replyTo ? { id: replyTo.id, sender: replyTo.sender, content: getReplyContent(replyTo) } : undefined, undefined, messageSignalType);
                }
                
                const targetUser = getOrCreateUser(selectedConversation);
                
                // Check if user has encryption keys
                if (!targetUser.hybridPublicKeys) {
                  SecurityAuditLogger.log('info', 'queuing-message-no-keys', {});
                  
                  // Initiate P2P connection in background for faster delivery
                  if (p2pConfig.features.textMessages && !p2pMessaging.isPeerConnected(selectedConversation)) {
                    try {
                      p2pMessaging.connectToPeer(selectedConversation).catch(() => {});
                    } catch {}
                  }
                  
                  try {
                    // Queue the message in secure encrypted queue
                    const queuedMessageId = await secureMessageQueue.queueMessage(
                      selectedConversation,
                      content,
                      {
                        replyTo: replyTo ? { id: replyTo.id, sender: replyTo.sender, content: getReplyContent(replyTo) } : undefined,
                        messageSignalType
                      }
                    );
                    
                    const placeholderMessage: Message = {
                      id: queuedMessageId,
                      content: content,
                      sender: Authentication.loginUsernameRef.current || '',
                      recipient: selectedConversation,
                      timestamp: new Date(),
                      type: 'text',
                      isCurrentUser: true,
                      receipt: { delivered: false, read: false },
                      pending: true,
                      ...(replyTo && { replyTo: { id: replyTo.id, sender: replyTo.sender, content: getReplyContent(replyTo) } })
                    };
                    
                    setMessages(prev => (prev.some(m => m.id === placeholderMessage.id) ? prev : [...prev, placeholderMessage]));
                    saveMessageWithContext(placeholderMessage);
                    
                    SecurityAuditLogger.log('info', 'message-queued', {});
                    
                  } catch (_err) {
                    SecurityAuditLogger.log('error', 'message-queue-failed', { error: _err instanceof Error ? _err.message : 'unknown' });
                    // Show error to user
                    try {
                      if ((window as any).electronAPI?.showErrorDialog) {
                        await (window as any).electronAPI.showErrorDialog({
                          title: 'Failed to Queue Message',
                          message: 'Unable to queue your message. The queue may be full.'
                        });
                      } else {
                        alert('Failed to queue message. Please try again.');
                      }
                    } catch (_dialogErr) {
                    }
                  }
                  return;
                }
                
                // For delete messages
                if (messageSignalType === 'delete-message') {
                  let messageToPersist: Message | null = null;
                  setMessages(prev => prev.map(msg => {
                    if (msg.id === messageId) {
                      const updated = { ...msg, isDeleted: true, content: 'This message was deleted' };
                      messageToPersist = updated;
                      return updated;
                    }
                    return msg;
                  }));
                  if (messageToPersist) {
                    try { saveMessageWithContext(messageToPersist); } catch {}
                  }
                  
                  // Try P2P first if enabled and peer is connected
                  const p2pEnabled = p2pConfig.features.textMessages;
                  const peerConnected = p2pMessaging.isPeerConnected(selectedConversation);
                  const hasHybridKeys = !!targetUser.hybridPublicKeys;
                  
                  if (p2pEnabled && peerConnected && hasHybridKeys) {
                    try {
                      const result = await p2pMessaging.sendP2PMessage(
                        selectedConversation,
                        '',
                        {
                          dilithiumPublicBase64: targetUser.hybridPublicKeys.dilithiumPublicBase64 || '',
                          kyberPublicBase64: targetUser.hybridPublicKeys.kyberPublicBase64 || '',
                          x25519PublicBase64: targetUser.hybridPublicKeys.x25519PublicBase64,
                        },
                        {
                          messageType: 'delete',
                          metadata: {
                            targetMessageId: messageId,
                          }
                        }
                      );
                      if (result.status === 'sent') {
                        SecurityAuditLogger.log('info', 'p2p-delete-sent', {});
                        return;
                      }
                      SecurityAuditLogger.log('info', 'p2p-delete-queued-or-not-sent', { status: result.status });
                    } catch (_error) {
                      const errorMsg = _error instanceof Error ? _error.message : String(_error);
                      SecurityAuditLogger.log('info', 'p2p-delete-failed-fallback-server', { error: errorMsg });
                    }
                  }
                  
                  // Fallback to server
                  return messageSender.handleSendMessage(targetUser, content, replyTo ? { id: replyTo.id, sender: replyTo.sender, content: replyTo.content } : undefined, undefined, messageSignalType, messageId);
                }
                
                // For edit messages
                if (messageSignalType === 'edit-message') {
                  let messageToPersist: Message | null = null;
                  setMessages(prev => prev.map(msg => {
                    if (msg.id === messageId) {
                      const updated = { ...msg, content, isEdited: true };
                      messageToPersist = updated;
                      return updated;
                    }
                    return msg;
                  }));
                  if (messageToPersist) {
                    try { saveMessageWithContext(messageToPersist); } catch {}
                  }
                  
                  // Try P2P first if enabled and peer is connected
                  if (p2pConfig.features.textMessages && 
                      p2pMessaging.isPeerConnected(selectedConversation) && 
                      targetUser.hybridPublicKeys) {
                    try {
                      const result = await p2pMessaging.sendP2PMessage(
                        selectedConversation,
                        content,
                        {
                          dilithiumPublicBase64: targetUser.hybridPublicKeys.dilithiumPublicBase64 || '',
                          kyberPublicBase64: targetUser.hybridPublicKeys.kyberPublicBase64 || '',
                          x25519PublicBase64: targetUser.hybridPublicKeys.x25519PublicBase64,
                        },
                        {
                          messageType: 'edit',
                          metadata: {
                            targetMessageId: messageId,
                            newContent: content,
                          }
                        }
                      );
                      if (result.status === 'sent') {
                        SecurityAuditLogger.log('info', 'p2p-edit-sent', {});
                        return;
                      }
                      SecurityAuditLogger.log('info', 'p2p-edit-queued-or-not-sent', { status: result.status });
                    } catch (_error) {
                      SecurityAuditLogger.log('info', 'p2p-edit-failed-fallback-server', {});
                    }
                  }
                  
                  // Fallback to server
                  return messageSender.handleSendMessage(targetUser, content, replyTo ? { id: replyTo.id, sender: replyTo.sender, content: replyTo.content } : undefined, undefined, messageSignalType, undefined, messageId);
                }
                
                // Try P2P first for regular messages if P2P is enabled
                if ((!messageSignalType || messageSignalType === 'chat') && p2pConfig.features.textMessages) {
                  const trySendP2P = async (): Promise<boolean> => {
                    const result = await p2pMessaging.sendP2PMessage(
                      selectedConversation,
                      content,
                      targetUser.hybridPublicKeys ? {
                        dilithiumPublicBase64: targetUser.hybridPublicKeys.dilithiumPublicBase64 || '',
                        kyberPublicBase64: targetUser.hybridPublicKeys.kyberPublicBase64 || '',
                        x25519PublicBase64: targetUser.hybridPublicKeys.x25519PublicBase64,
                      } : undefined,
                      {
                        messageType: 'text',
                        metadata: replyTo ? {
                          replyTo: { id: replyTo.id, sender: replyTo.sender, content: getReplyContent(replyTo) }
                        } : undefined
                      }
                    );

                    if (result.status !== 'sent' || !result.messageId) {
                      SecurityAuditLogger.log('info', 'p2p-message-not-sent', { status: result.status });
                      return false;
                    }

                    const p2pMessageId = result.messageId;

                    const p2pMessage: Message = {
                      id: p2pMessageId,
                      content,
                      sender: Authentication.loginUsernameRef.current || '',
                      recipient: selectedConversation,
                      timestamp: new Date(),
                      type: 'text',
                      isCurrentUser: true,
                      p2p: true,
                      transport: 'p2p',
                      encrypted: true,
                      receipt: { delivered: false, read: false },
                      ...(replyTo && { replyTo: { id: replyTo.id, sender: replyTo.sender, content: getReplyContent(replyTo) } })
                    } as Message;

                    setMessages(prev => {
                      const exists = prev.some(m => m.id === p2pMessage.id);
                      if (exists) {
                        return prev;
                      }
                      return [...prev, p2pMessage];
                    });
                    saveMessageWithContext(p2pMessage);
                    SecurityAuditLogger.log('info', 'p2p-message-sent', {});
                    return true;
                  };

                  let p2pSucceeded = false;
                  try {
                    p2pSucceeded = await trySendP2P();
                  } catch (_error) {
                    SecurityAuditLogger.log('info', 'p2p-send-initial-failed', {});
                  }

                  if (p2pSucceeded) {
                    return;
                  }

                    try {
                      try {
                        if (!p2pMessaging.isPeerConnected(selectedConversation)) {
                          p2pMessaging.connectToPeer(selectedConversation).catch(() => {});
                        }
                      } catch {}

                    await new Promise(resolve => setTimeout(resolve, 1000));

                    try {
                      p2pSucceeded = await trySendP2P();
                    } catch (_error) {
                      console.error('[P2P][UI] P2P text retry failed', _error);
                      SecurityAuditLogger.log('info', 'p2p-send-retry-failed', {});
                    }

                    if (p2pSucceeded) {
                      return;
                    }
                  } catch {}
                }

                SecurityAuditLogger.log('info', 'p2p-send-failed-final-fallback-server', {});
                return messageSender.handleSendMessage(
                  targetUser,
                  content,
                  replyTo ? { id: replyTo.id, sender: replyTo.sender, content: getReplyContent(replyTo) } : undefined,
                  undefined,
                  messageSignalType
                );
              }}
              onSendFile={async (fileData: any) => {
                try {
                  // Try P2P file transfer if enabled and peer is connected
                  if (p2pConfig.features.fileTransfers && 
                      selectedConversation && 
                      p2pMessaging.isPeerConnected(selectedConversation)) {
                    const targetUser = Database.users.find(user => user.username === selectedConversation);
                    
                    if (targetUser?.hybridPublicKeys) {
                      try {
                        // Send file metadata via P2P
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
                          return;
                        }
                        SecurityAuditLogger.log('info', 'p2p-file-queued-or-not-sent', { status: result.status });
                      } catch (_error) {
                        SecurityAuditLogger.log('info', 'p2p-file-failed-fallback-server', {});
                        await Database.saveMessageToLocalDB(fileData);
                      }
                    } else {
                      await Database.saveMessageToLocalDB(fileData);
                    }
                  } else {
                    await Database.saveMessageToLocalDB(fileData);
                  }
                } catch (error) {
                  SecurityAuditLogger.log('error', 'file-transfer-failed', { error: error instanceof Error ? error.message : 'unknown' });
                  await Database.saveMessageToLocalDB(fileData);
                }
              }}
              isEncrypted={true}
              users={Database.users}
              selectedConversation={selectedConversation}
              saveMessageToLocalDB={saveMessageWithContext}
            />
            </EmojiPickerProvider>
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