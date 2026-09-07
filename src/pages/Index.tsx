import React, { useState, useCallback, useEffect, useLayoutEffect, useRef, useMemo } from "react";
import { createPortal } from "react-dom";
import { useTheme } from '../contexts/ThemeContext';
import { Login } from "../components/chat/Login";
import { PeerIdentityVerificationAlert } from "../components/chat/PeerIdentityVerificationAlert";
import { User } from "../components/chat/messaging/UserList";
import { ConversationList, type ConversationDialogMode } from "../components/chat/messaging/ConversationList";
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
import { WelcomeSetup } from "../components/setup/WelcomeSetup";
import { ConnectionIssueSheet } from "../components/setup/ConnectionIssueSheet";
import { SignalType } from "../lib/types/signal-types";
import { isExplicitlyLoggedOut } from "../lib/auth/logout-marker";
import { loadLastAuthenticatedAccount } from "../lib/security/local-account-scope";
import { shouldAttemptDiscovery } from "../lib/utils/discovery-utils";
import { computePeerCertificateFingerprint, isSelfSignedPeerCertificate } from "../lib/utils/peer-certificate-utils";
import { resolveTrustedPeerHybridPublicKeys } from "../lib/utils/signal-bundle-utils";
import { unifiedSignalTransport } from "../lib/transport/unified-signal-transport";
import { createPeerSignalSender } from "../lib/transport/peer-signal-sender";
import { websocket, tray } from "../lib/tauri-bindings";
import type { PeerCertificateBundle } from "../lib/types/p2p-types";
import type { CallState } from "../lib/types/calling-types";

import {
  LOCAL_EVENT_RATE_LIMIT_WINDOW_MS,
  LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS,
} from "../lib/constants";
import { useRateLimiter } from "../hooks/useRateLimiter";
import { useLocalMessageHandlers } from "../hooks/message-handling/useLocalMessageHandlers";
import { useEventHandlers } from "../hooks/useEventHandlers";
import { Toaster, toast } from 'sonner';
import { FullscreenSpinner } from "../components/ui/FullscreenSpinner";
import { CallLogsSkeleton, SettingsSkeleton } from "../components/ui/ViewSkeletons";
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
import { usePrefetchedComponent } from "../hooks/app/usePrefetchedComponent";
import { useStartupConnection } from "../hooks/app/useStartupConnection";
import { startupConnection } from "../lib/transport/startup-connection";
import { useBackgroundResume } from "../hooks/app/useBackgroundResume";
import { useStartupAvatarReadiness } from "../hooks/app/useStartupAvatarReadiness";
import { useDiscovery } from "../hooks/discovery/useDiscovery";
import { keyTransparencyClient } from "../lib/key-transparency/client";
import { getInstanceLocalStorageItem, setInstanceLocalStorageItem } from "../lib/runtime/instance-storage";
import { boundMessageState, releaseUnretainedVaultEntries } from "../lib/utils/message-state-limits";
import { hasResumeToken } from "../lib/signals/resume-tokens";

const loadCallModal = () => import("../components/chat/calls/CallModal").then((module) => module.default);
const loadAppSettings = () => import("../components/settings/AppSettings").then((module) => module.AppSettings);
const loadCallLogs = () => import("../components/chat/calls/CallLogs").then((module) => module.CallLogs);

const ChatApp: React.FC = () => {
  const { allowEvent } = useRateLimiter(LOCAL_EVENT_RATE_LIMIT_WINDOW_MS, LOCAL_EVENT_RATE_LIMIT_MAX_EVENTS);
  const [messages, setMessagesState] = useState<Message[]>([]);
  const messagesRef = useRef<Message[]>([]);
  const activeConversationRef = useRef<string | null>(null);
  const setMessages = useMemo(() => {
    const fn = ((action: React.SetStateAction<Message[]>) => {
      const prev = messagesRef.current;
      const next = typeof action === 'function'
        ? (action as (p: Message[]) => Message[])(prev)
        : action;
      const bounded = boundMessageState(next, activeConversationRef.current);
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
  const [serverUrlResolved, setServerUrlResolved] = useState(false);
  const [serverEntryPreflightInProgress, setServerEntryPreflightInProgress] = useState(true);
  const [showServerSetup, setShowServerSetup] = useState(false);
  const [selectedServerUrl, setSelectedServerUrl] = useState<string>('');
  const startup = useStartupConnection();
  const [showSettings, setShowSettings] = useState(false);
  const [showNewChatInput, setShowNewChatInput] = useState(false);
  const [conversationDialogMode, setConversationDialogMode] = useState<ConversationDialogMode>('manage');
  const [conversationPanelWidth, setConversationPanelWidth] = useState(344);
  const [isResizing, setIsResizing] = useState(false);
  const [floatingCallPosition, setFloatingCallPosition] = useState({ x: 20, bottom: 20 });
  const Authentication = useAuth();
  const callHistory = useCallHistory();

  const promptForServerEntryIfRequired = useCallback((): boolean => {
    if (
      !websocketClient.isServerPasswordRequired()
      || websocketClient.isServerAuthGranted()
    ) {
      return false;
    }
    websocketClient.setServerEntryPromptPending(true);
    Authentication.setTokenValidationInProgress(false);
    Authentication.setAuthStatus('');
    Authentication.setLoginError('');
    Authentication.setShowPasswordPrompt(true);
    return true;
  }, [
    Authentication.setAuthStatus,
    Authentication.setLoginError,
    Authentication.setShowPasswordPrompt,
    Authentication.setTokenValidationInProgress,
  ]);

  // Discovery Service
  const discoveryUsername = Authentication.isLoggedIn ? Authentication.loginUsernameRef.current || undefined : undefined;
  const { findUser } = useDiscovery(
    discoveryUsername,
    Authentication.hybridKeysRef
  );

  useEffect(() => {
    if (!Authentication.isLoggedIn || !discoveryUsername) return;
    let cancelled = false;
    void keyTransparencyClient.restorePersistedAuthorizations(discoveryUsername).then(() => {
      if (!cancelled) keyTransparencyClient.startContactMonitoring(discoveryUsername);
    }).catch((error) => {
      if (!cancelled) {
        Authentication.setLoginError(
          error instanceof Error ? error.message : 'Key-transparency state could not be restored'
        );
      }
    });
    return () => {
      cancelled = true;
      keyTransparencyClient.stopContactMonitoring(discoveryUsername);
    };
  }, [Authentication.isLoggedIn, Authentication.setLoginError, discoveryUsername]);

  // Background resume
  const {
    isResumingFromBackground,
    backgroundCheckComplete,
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
  useLayoutEffect(() => {
    usersRef.current = Database.users;
  }, [Database.users]);
  const fetchPeerCertificates = useCallback(async (peer: string, bypassCache = false): Promise<PeerCertificateBundle | null> => {
    if (!peer) return null;
    const account = Authentication.loginUsernameRef.current || '';
    if (!account) return null;
    if (!shouldAttemptDiscovery(peer)) {
      return null;
    }
    const material = await findUser(peer, { forceRefresh: bypassCache });
    if (Authentication.loginUsernameRef.current !== account) return null;
    const cert = material?.peerCertificate || null;
    if (!cert) return null;
    if (!isSelfSignedPeerCertificate(cert)) return null;
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
  }, [findUser, Database.users, Database.setUsers]);

  const startupBeganRef = useRef(false);
  useEffect(() => {
    if (!backgroundCheckComplete || startupBeganRef.current) return;
    startupBeganRef.current = true;
    let cancelled = false;

    void (async () => {
      const savedUrl = await startupConnection.loadConfiguredServerUrl();
      if (cancelled) return;

      setServerUrlResolved(true);
      if (!savedUrl) {
        setServerEntryPreflightInProgress(false);
        return;
      }

      setSelectedServerUrl(savedUrl);
      setSetupComplete(true);

      const explicitLogout = await isExplicitlyLoggedOut();
      const storedUsername = explicitLogout ? '' : (await loadLastAuthenticatedAccount()).username;
      const canResume = storedUsername ? await hasResumeToken(storedUsername) : false;
      if (cancelled) return;
      if (!Authentication.isLoggedIn || !Authentication.accountAuthenticated) {
        if (canResume) {
          Authentication.setTokenValidationInProgress(true);
        } else if (!storedUsername) {
          Authentication.setIsRegistrationMode(true);
        }
      }

      if (canResume) {
        // Recovery owns its unlinked connection attempt. Starting the normal
        // startup connection here would race it and turn recovery into a
        // foreground server-connect gate.
        setServerEntryPreflightInProgress(false);
        return;
      }

      try {
        await startupConnection.checkConnected();
        if (!cancelled) promptForServerEntryIfRequired();
      } catch { }
      finally {
        if (!cancelled) setServerEntryPreflightInProgress(false);
      }
    })().catch((error) => {
      if (cancelled) return;
      const message = error instanceof Error ? error.message : 'Startup state could not be loaded';
      console.error('[Index] Startup state could not be loaded:', error);
      Authentication.setLoginError(message);
      toast.error(message);
      setServerUrlResolved(true);
      setServerEntryPreflightInProgress(false);
    });

    return () => { cancelled = true; };
  }, [
    Authentication.accountAuthenticated,
    Authentication.isLoggedIn,
    Authentication.setIsRegistrationMode,
    Authentication.setLoginError,
    Authentication.setTokenValidationInProgress,
    backgroundCheckComplete,
    promptForServerEntryIfRequired,
  ]);

  useEffect(() => {
    if (startup.phase !== 'ready') return;
    if (Authentication.isLoggedIn || Authentication.accountAuthenticated) return;
    promptForServerEntryIfRequired();
  }, [
    startup.phase,
    Authentication.isLoggedIn,
    Authentication.accountAuthenticated,
    promptForServerEntryIfRequired,
  ]);

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
    fileHandler.handleFileMessageChunk,
    fileHandler.cancelIncomingFileTransfer,
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
    conversationsLoaded,
  } = useConversations(
    Authentication.loginUsernameRef.current || '',
    Database.users,
    messages,
    setMessages,
    Database.secureDBRef.current,
    findUser,
    Database.initialDataLoaded
  );

  useLayoutEffect(() => {
    activeConversationRef.current = selectedConversation;
  }, [selectedConversation]);

  const handleSelectConversation = useCallback((username: string) => {
    Database.hydratePreloadedConversationMessages(username);
    selectConversation(username);
  }, [Database.hydratePreloadedConversationMessages, selectConversation]);

  const handleRemoveConversation = useCallback(async (username: string) => {
    Database.discardPreloadedConversationMessages(username);
    await removeConversation(username);
  }, [Database.discardPreloadedConversationMessages, removeConversation]);

  useEffect(() => {
    if (selectedConversation) {
      void messageSender.prefetchSessionForPeer(selectedConversation).catch((error) => {
        console.error('[MessageSender] Session prefetch failed', error);
      });
    }
  }, [selectedConversation, messageSender.prefetchSessionForPeer]);

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

  const openConversationDialog = useCallback((mode: ConversationDialogMode) => {
    setConversationDialogMode(mode);
    setShowNewChatInput(true);
  }, []);

  const handleConversationDialogOpenChange = useCallback((open: boolean) => {
    setShowNewChatInput(open);
  }, []);

  const handleBlockConversationFromSettings = useCallback(async (username: string) => {
    if (!username) {
      throw new Error('That conversation cannot be blocked.');
    }
    if (blockingSystem.isBlockedSync(username)) {
      throw new Error('That user is already blocked.');
    }
    await blockingSystem.blockUser(username);
    toast.success('User blocked');
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
  const knownP2PPeers = useMemo(
    () => Database.users.map(user => user.username).sort(),
    [Database.users]
  );

  const p2pMessaging = useP2PMessaging(
    Database.dbInitialized ? p2pUsername : '',
    Database.dbInitialized ? p2pHybridKeys : null,
    {
      fetchPeerCertificates,
      handleEncryptedMessagePayload: encryptedHandler,
      onServiceReady: (service) => {
        p2pServiceRef.current = service;
      },
      knownPeers: knownP2PPeers,
    }
  );

  const callingHook = useCalling(Authentication, {
    getPeerCertificate: p2pMessaging.getPeerCertificateForCall,
    checkPeerSession: messageSender.prefetchSessionForPeer,
  });
  const currentCall = callingHook.currentCall;
  const currentCallIsDocked = Boolean(
    currentCall
    && sidebarActiveTab === 'chats'
    && selectedConversation === currentCall.peer
  );
  const foregroundIncomingCall = callingHook.pendingIncomingCalls[
    callingHook.pendingIncomingCalls.length - 1
  ] ?? null;
  const answerIncomingCall = useCallback(async (call: CallState) => {
    await callingHook.answerCall(call.id, call.peer);
  }, [callingHook.answerCall]);
  const declineIncomingCall = useCallback(async (call: CallState) => {
    await callingHook.declineCall(call.id);
  }, [callingHook.declineCall]);
  const answerForegroundIncomingCall = useCallback(async () => {
    if (!foregroundIncomingCall) return;
    await answerIncomingCall(foregroundIncomingCall);
  }, [answerIncomingCall, foregroundIncomingCall]);
  const declineForegroundIncomingCall = useCallback(() => {
    if (!foregroundIncomingCall) return;
    void declineIncomingCall(foregroundIncomingCall);
  }, [declineIncomingCall, foregroundIncomingCall]);
  const inactiveIncomingToggle = useCallback(() => false, []);
  const inactiveIncomingDeviceSwitch = useCallback((_deviceId: string) => Promise.resolve(), []);
  const answerCurrentCall = useCallback(() => {
    const call = currentCall;
    if (!call) return;
    return callingHook.answerCall(call.id, call.peer);
  }, [callingHook.answerCall, currentCall]);
  const declineCurrentCall = useCallback(() => {
    const call = currentCall;
    if (!call) return;
    callingHook.declineCall(call.id);
  }, [callingHook.declineCall, currentCall]);
  const handleOpenCallLogConversation = useCallback((username: string) => {
    handleSelectConversation(username);
    setSidebarActiveTab('chats');
  }, [handleSelectConversation]);
  const handleStartCallFromLog = useCallback((username: string, type: 'audio' | 'video') => {
    void callingHook.startCall(username, type);
  }, [callingHook.startCall]);

  // Update P2P sender whenever service becomes ready
  useEffect(() => {
    const service = p2pServiceRef.current;
    if (service && p2pMessaging.p2pStatus.isInitialized) {
      unifiedSignalTransport.setP2PSender(createPeerSignalSender({
        isCurrent: () => service === p2pServiceRef.current,
        isPeerConnected: p2pMessaging.isPeerConnected,
        connectToPeer: p2pMessaging.connectToPeer,
        sendMessage: (to, payload) => service.sendMessage(to, payload, SignalType.SEALED_ENVELOPE),
      }), async (to) => {
        if (service !== p2pServiceRef.current) return;
        await p2pMessaging.connectToPeer(to);
      });
    } else {
      unifiedSignalTransport.setP2PSender(null);
    }
    return () => unifiedSignalTransport.setP2PSender(null);
  }, [p2pMessaging.p2pStatus.isInitialized, p2pMessaging.connectToPeer, p2pMessaging.isPeerConnected]);
  
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
    getKeysOnDemand: Authentication.getKeysOnDemand,
    findUser
  });

  // Message actions
  const { onSendMessage } = useMessageActions({
    selectedConversation,
    getOrCreateUser,
    messageSender,
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
  const { avatarDataLoaded } = useAppInitialization({
    Authentication,
    Database,
    flushPendingSaves,
    setShowSettings,
  });

  const startupAvatarsLoaded = useStartupAvatarReadiness({
    secureDB: Database.secureDBRef.current,
    currentUsername: currentDisplayName || Authentication.originalUsernameRef.current || Authentication.loginUsernameRef.current || '',
    conversations,
    avatarDataLoaded,
    conversationsLoaded,
  });

  useEffect(() => {
    if (showSettings) {
      setSidebarActiveTab('settings');
      setShowSettings(false);
    }
  }, [showSettings]);

  // Token validation
  const recoveryValidation = useTokenValidation({
    Authentication,
    setupComplete,
    selectedServerUrl,
  });
  const recoveryConnectionIssue = recoveryValidation.connectionIssue;
  const retryAuthRecovery = recoveryValidation.retryRecovery;
  const clearRecoveryConnectionIssue = recoveryValidation.clearConnectionIssue;

  // Get messages for the selected conversation
  const conversationMessages = useMemo(() => {
    const peer = selectedConversation || '';
    if (!peer) return [] as Message[];
    return getConversationMessages(peer);
  }, [selectedConversation, messages, getConversationMessages]);

  const handleServerSelected = useCallback(async (serverUrl: string) => {
    clearRecoveryConnectionIssue();
    setSelectedServerUrl(serverUrl);
    setSetupComplete(true);
    setShowServerSetup(false);

    try {
      const explicitLogout = await isExplicitlyLoggedOut();
      const storedUsername = explicitLogout ? '' : (await loadLastAuthenticatedAccount()).username;
      const canResume = storedUsername ? await hasResumeToken(storedUsername) : false;
      if (promptForServerEntryIfRequired()) {
        return;
      } else if (canResume) {
        Authentication.setTokenValidationInProgress(true);
      } else {
        Authentication.setIsRegistrationMode(!storedUsername);
      }
    } catch (err) {
      console.error('[Index] Failed to resolve session state after server selection:', err);
      Authentication.setLoginError(
        err instanceof Error ? err.message : 'Stored session state could not be loaded'
      );
      throw err;
    }
  }, [Authentication, clearRecoveryConnectionIssue, promptForServerEntryIfRequired]);

  const handleChangeServer = useCallback(async () => {
    clearRecoveryConnectionIssue();
    setShowServerSetup(true);
    startupConnection.reset();
    Authentication.setTokenValidationInProgress(false);
    Authentication.setShowPasswordPrompt(false);
    Authentication.setAuthStatus('');
    try {
      await websocketClient.close();
    } catch { }
    try {
      await websocket.disconnect();
    } catch { }
  }, [Authentication, clearRecoveryConnectionIssue]);

  const handleRetryConnection = useCallback(async () => {
    if (recoveryConnectionIssue) {
      retryAuthRecovery();
      return;
    }
    const retryingFromServerSetup = showServerSetup || !selectedServerUrl;
    try {
      await startupConnection.retry();
      if (retryingFromServerSetup && startupConnection.getState().phase === 'ready') {
        const connectedServerUrl = startupConnection.getState().serverUrl || selectedServerUrl;
        if (connectedServerUrl) await handleServerSelected(connectedServerUrl);
      }
    } catch { }
  }, [handleServerSelected, recoveryConnectionIssue, retryAuthRecovery, selectedServerUrl, showServerSetup]);

  const handleKeepCurrentServer = useCallback(() => {
    setShowServerSetup(false);
    void startupConnection.checkConnected().catch(() => { });
  }, []);

  const connectedForAuth = useCallback(async (
    allowServerEntrySubmission = false,
  ): Promise<boolean> => {
    if (websocketClient.isConnectedToServer()) {
      return allowServerEntrySubmission || !promptForServerEntryIfRequired();
    }
    Authentication.setAuthStatus('Connecting to server...');
    try {
      await startupConnection.checkConnected();
      return allowServerEntrySubmission || !promptForServerEntryIfRequired();
    } catch {
      Authentication.setAuthStatus('');
      try {
        window.dispatchEvent(new CustomEvent(EventType.AUTH_ERROR, { detail: { type: 'CONNECTION_UNAVAILABLE' } }));
      } catch { }
      return false;
    }
  }, [Authentication, promptForServerEntryIfRequired]);

  const handleAccountSubmitWhenConnected = useCallback(async (
    mode: "login" | "register",
    username: string,
    password: string,
    passphrase: string,
  ) => {
    if (!await connectedForAuth()) return;
    await Authentication.handleAccountSubmit(mode, username, password, passphrase);
  }, [connectedForAuth, Authentication]);

  const handleServerPasswordSubmitWhenConnected = useCallback(async (password: string) => {
    if (!await connectedForAuth(true)) return;
    await Authentication.handleServerPasswordSubmit(password);
  }, [connectedForAuth, Authentication]);

  const mainAppReady = Authentication.isLoggedIn
    && Authentication.accountAuthenticated
    && Authentication.vaultReady
    && Database.dbInitialized;
  const CallLogsPanel = usePrefetchedComponent(loadCallLogs, mainAppReady);
  const AppSettingsPanel = usePrefetchedComponent(loadAppSettings, mainAppReady);
  const CallModalPanel = usePrefetchedComponent(loadCallModal, mainAppReady);

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
          startupConnection.reset();
        }
      } catch (_e) {
        console.error('[Index] Failed to handle auth-ui-back (server):', _e);
      }
    };
    window.addEventListener(EventType.AUTH_UI_BACK, handleAuthUiBack as EventListener);
    return () => window.removeEventListener(EventType.AUTH_UI_BACK, handleAuthUiBack as EventListener);
  }, []);

  if (isResumingFromBackground) {
    return <FullscreenSpinner />;
  }

  if (!serverUrlResolved && !selectedServerUrl) {
    return <FullscreenSpinner />;
  }

  const activeConnectionIssue = recoveryConnectionIssue ?? (
    startup.phase === 'failed'
      ? {
          error: startup.error,
          target: startup.failureTarget ?? 'server' as const,
        }
      : null
  );
  const connectionIssue = activeConnectionIssue ? (
    <ConnectionIssueSheet
      error={activeConnectionIssue.error}
      target={activeConnectionIssue.target}
      onRetry={handleRetryConnection}
      onChangeServer={handleChangeServer}
    />
  ) : null;

  if (showServerSetup || !selectedServerUrl) {
    return (
      <div className="min-h-screen bg-white dark:bg-[hsl(var(--background))]">
        <WelcomeSetup
          onConnected={handleServerSelected}
          onCancel={selectedServerUrl ? handleKeepCurrentServer : undefined}
          initialServerUrl={selectedServerUrl}
        />
        {connectionIssue}
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
  const showValidationScreen = (
    Authentication.tokenValidationInProgress
    || serverEntryPreflightInProgress
    || Boolean(recoveryConnectionIssue)
  ) && !isFullyAuthenticated && !authPromptVisible;
  const showLoginScreen = !showValidationScreen && (
    !Authentication.isLoggedIn ||
    !Authentication.accountAuthenticated ||
    Authentication.showPassphrasePrompt ||
    Authentication.showPasswordPrompt
  );

  if (showValidationScreen) {
    return (
      <>
        <FullscreenSpinner />
        {connectionIssue}
        <Toaster position="top-right" theme={theme as any} richColors toastOptions={{ className: 'select-none', style: { width: 'fit-content', maxWidth: '400px', minWidth: '0px' } }} />
      </>
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
          onAccountSubmit={handleAccountSubmitWhenConnected}
          accountAuthenticated={Authentication.accountAuthenticated}
          isRegistrationMode={registrationMode}
          setIsRegistrationMode={Authentication.setIsRegistrationMode}
          showPasswordPrompt={Authentication.showPasswordPrompt}
          handleServerPasswordSubmit={handleServerPasswordSubmitWhenConnected}
          initialUsername={Authentication.loginUsernameRef.current || ''}
        />
        {connectionIssue}
        <Toaster position="top-right" theme={theme as any} richColors toastOptions={{ className: 'select-none', style: { width: 'fit-content', maxWidth: '400px', minWidth: '0px' } }} />
      </div>
    );
  }

  if (
    !Database.dbInitialized ||
    !Authentication.vaultReady ||
    !Database.initialDataLoaded ||
    !conversationsLoaded ||
    !startupAvatarsLoaded
  ) {
    return <FullscreenSpinner />;
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
        <div className="qorc-stage">
          <PeerIdentityVerificationAlert />
          <div className={sidebarActiveTab === 'chats' ? 'h-full w-full' : 'hidden'}>
            <div className="flex h-full">
              <div
                className="qorc-conversations-panel hidden md:flex flex-col relative"
                style={{ width: `${conversationPanelWidth}px` }}
              >
                {/* Resize Handle */}
                <div
                  className="qorc-resize-line"
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

                <div className="qorc-conversations-head">
                  <div className="qorc-conversations-title">
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => openConversationDialog('manage')}
                      className="qorc-icon-btn qorc-compose-btn"
                      aria-label="Add conversation"
                    >
                      <ComposeIcon className="h-4 w-4" />
                    </Button>
                    <h2>Chats</h2>
                  </div>
                </div>
                <div className="flex-1 overflow-hidden">
                  <ConversationList
                    currentUsername={Authentication.loginUsernameRef.current || ''}
                    conversations={conversations}
                    selectedConversation={selectedConversation || undefined}
                    onSelectConversation={handleSelectConversation}
                    onAddConversation={async (username, signal) => {
                      await addConversation(username, true, signal);
                      handleConversationDialogOpenChange(false);
                    }}
                    showNewChatInput={showNewChatInput}
                    onNewChatOpenChange={handleConversationDialogOpenChange}
                    onRemoveConversation={handleRemoveConversation}
                    onTogglePin={toggleConversationPin}
                    onStartCall={(username, type) => { void callingHook.startCall(username, type); }}
                    onToggleBlock={handleToggleBlock}
                    conversationDialogMode={conversationDialogMode}
                    onBlockConversation={handleBlockConversationFromSettings}
                  />
                </div>
              </div>

              <div className="qorc-pane">
                {selectedConversation ? (
                  <EmojiPickerProvider>
                    <ChatInterface
                      messages={conversationMessages}
                      setMessages={setMessages}
                      currentCall={currentCall}
                      startCall={callingHook.startCall}
                      currentUsername={Authentication.loginUsernameRef.current || ''}
                      getDisplayUsername={stableGetDisplayUsername}
                      getKeysOnDemand={Authentication.getKeysOnDemand}
                      findUser={findUser}
                      checkPeerSession={messageSender.prefetchSessionForPeer}
                      loadMoreMessages={loadMoreConversationMessages}
                      sendServerReadReceipt={sendServerReadReceipt}
                      markMessageAsRead={markMessageAsRead}
                      getSmartReceiptStatus={getSmartReceiptStatus}
                      secureDB={Database.secureDBRef.current}
                      onSendMessage={onSendMessage}
                      onToggleBlock={handleToggleBlock}
                      users={Database.users}
                      selectedConversation={selectedConversation}
                      saveMessageToLocalDB={saveMessageWithContext}
                    />
                  </EmojiPickerProvider>
                ) : (
                  <EmptyChatView onCreateChat={() => openConversationDialog('manage')} />
                )}
              </div>
            </div>
          </div>

          <div className={sidebarActiveTab === 'calls' ? 'h-full w-full' : 'hidden'}>
            {sidebarActiveTab === 'calls' && (
              CallLogsPanel ? (
                <CallLogsPanel
                  getDisplayUsername={stableGetDisplayUsername}
                  onOpenConversation={handleOpenCallLogConversation}
                  onStartCall={handleStartCallFromLog}
                  callsDisabled={Boolean(currentCall)}
                />
              ) : <CallLogsSkeleton />
            )}
          </div>

          <div className={sidebarActiveTab === 'settings' ? 'h-full w-full' : 'hidden'}>
            {sidebarActiveTab === 'settings' && (
              AppSettingsPanel ? (
                <AppSettingsPanel
                  currentUsername={Authentication.loginUsernameRef.current || ''}
                  currentDisplayName={currentDisplayName || Authentication.originalUsernameRef.current || ''}
                  onLogout={async () => await Authentication.logout(Database.secureDBRef)}
                  onOpenBlockConversationChooser={() => openConversationDialog('block')}
                />
              ) : <SettingsSkeleton />
            )}
          </div>
        </div>
      </Layout>
      <Toaster position="top-right" theme={theme as any} richColors toastOptions={{ className: 'select-none', style: { width: 'fit-content', maxWidth: '400px', minWidth: '0px' } }} />
      {
        currentCall && CallModalPanel && createPortal(
          <CallModalPanel
            call={currentCall}
            localMediaActive={callingHook.localMediaActive}
            localVideoCanvas={callingHook.localVideoCanvas}
            localScreenCanvas={callingHook.localScreenCanvas}
            remoteVideoCanvas={callingHook.remoteVideoCanvas}
            remoteScreenCanvas={callingHook.remoteScreenCanvas}
            onAnswer={answerCurrentCall}
            onDecline={declineCurrentCall}
            onEndCall={callingHook.endCall}
            onToggleMute={callingHook.toggleMute}
            onToggleVideo={callingHook.toggleVideo}
            onStartScreenShare={callingHook.startScreenShare}
            onStopScreenShare={callingHook.stopScreenShare}
            isScreenSharing={callingHook.isScreenSharing}
            onSwitchCamera={callingHook.switchCamera}
            onSwitchMicrophone={callingHook.switchMicrophone}
            onSwitchSpeaker={callingHook.switchSpeaker}
            isAttached={currentCallIsDocked}
            floatingPosition={floatingCallPosition}
            onFloatingPositionChange={setFloatingCallPosition}
          />,
          document.body
        )
      }
      {
        foregroundIncomingCall && CallModalPanel && createPortal(
          <CallModalPanel
            key={foregroundIncomingCall.id}
            call={foregroundIncomingCall}
            localMediaActive={false}
            localVideoCanvas={null}
            localScreenCanvas={null}
            remoteVideoCanvas={null}
            remoteScreenCanvas={null}
            onAnswer={answerForegroundIncomingCall}
            onDecline={declineForegroundIncomingCall}
            onEndCall={declineForegroundIncomingCall}
            onToggleMute={inactiveIncomingToggle}
            onToggleVideo={inactiveIncomingToggle}
            onSwitchCamera={inactiveIncomingDeviceSwitch}
            onSwitchMicrophone={inactiveIncomingDeviceSwitch}
            onSwitchSpeaker={inactiveIncomingDeviceSwitch}
            isAttached={false}
            floatingPosition={currentCallIsDocked ? undefined : floatingCallPosition}
            onFloatingPositionChange={currentCallIsDocked ? undefined : setFloatingCallPosition}
            isForeground
          />,
          document.body
        )
      }
    </TypingIndicatorProvider>
  );
};

export default ChatApp;
