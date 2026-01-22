export const EventType = {
  // Username mapping events
  USERNAME_MAPPING_UPDATED: 'username-mapping-updated',
  USERNAME_MAPPING_RECEIVED: 'username-mapping-received',

  // Session events
  SESSION_RESET_RECEIVED: 'session-reset-received',
  SESSION_ESTABLISHED_RECEIVED: 'session-established-received',
  SESSION_KEY_REFRESH: 'session-key-refresh',
  LIBSIGNAL_SESSION_READY: 'libsignal-session-ready',
  LIBSIGNAL_BUNDLE_FAILED: 'libsignal-bundle-failed',
  LOCAL_INITIATED_RESET: 'local-initiated-reset',

  // P2P events
  P2P_SESSION_RESET_SEND: 'p2p-session-reset-send',
  P2P_SESSION_RESET: 'p2p-session-reset',
  P2P_SESSION_RESET_REQUEST: 'p2p-session-reset-request',
  P2P_SESSION_RESET_ACK: 'p2p-session-reset-ack',
  P2P_PQ_ESTABLISHED: 'p2p-pq-established',
  P2P_PEER_CONNECTED: 'p2p-peer-connected',
  P2P_PEER_DISCONNECTED: 'p2p-peer-disconnected',
  P2P_PEER_RECONNECTED: 'p2p-peer-reconnected',
  P2P_FETCH_PEER_CERT: 'p2p-fetch-peer-cert',
  P2P_PEER_CERT: 'p2p-peer-cert',
  P2P_CALL_SIGNAL_SEND: 'p2p-call-signal-send',
  P2P_CALL_SIGNAL_RESULT: 'p2p-call-signal-result',
  P2P_INIT_REQUIRED: 'p2p-init-required',
  P2P_FILE_CHUNK: 'p2p-file-chunk',
  P2P_CONNECTION_STATE_CHANGE: 'p2p-connection-state-change',
  P2P_MESSAGE_RECEIVED: 'p2p-message-received',


  // Message events
  MESSAGE: 'message',
  MESSAGE_READ: 'message-read',
  MESSAGE_DELIVERED: 'message-delivered',
  MESSAGE_REACTION: 'message-reaction',
  LOCAL_MESSAGE_EDIT: 'local-message-edit',
  LOCAL_MESSAGE_DELETE: 'local-message-delete',
  LOCAL_FILE_MESSAGE: 'local-file-message',
  REMOTE_MESSAGE_EDIT: 'remote-message-edit',
  REMOTE_MESSAGE_DELETE: 'remote-message-delete',
  LOCAL_REACTION_UPDATE: 'local-reaction-update',
  REMOTE_REACTION_UPDATE: 'remote-reaction-update',
  CLEAR_CONVERSATION_MESSAGES: 'clear-conversation-messages',

  // Typing events
  TYPING_INDICATOR: 'typing-indicator',

  // User events
  USER_EXISTS_RESPONSE: 'user-exists-response',
  USER_KEYS_AVAILABLE: 'user-keys-available',
  HYBRID_KEYS_UPDATED: 'hybrid-keys-updated',
  USER_BLOCKED: 'user-blocked',
  USER_UNBLOCKED: 'user-unblocked',

  // Offline events
  OFFLINE_LONGTERM_REQUIRED: 'offline-longterm-required',

  // Call events
  CALL_INCOMING: 'call-incoming',
  CALL_ANSWERED: 'call-answered',
  CALL_ENDED: 'call-ended',
  CALL_REJECTED: 'call-rejected',
  CALL_ICE_CANDIDATE: 'call-ice-candidate',
  CALL_SIGNAL: 'call-signal',
  CALL_SIGNAL_OUT: 'call-signal-out',
  UI_CALL_REQUEST: 'ui-call-request',

  // File events
  FILE_PROGRESS: 'file-progress',
  FILE_CHUNK_RECEIVED: 'file-chunk-received',
  FILE_TRANSFER_PROGRESS: 'file-transfer-progress',
  FILE_TRANSFER_COMPLETE: 'file-transfer-complete',
  FILE_TRANSFER_CANCELED: 'file-transfer-canceled',

  // Block list events
  BLOCK_LIST_UPDATED: 'block-list-updated',
  BLOCK_LIST_RESPONSE: 'block-list-response',

  // Avatar events
  AVATAR_UPDATED: 'avatar-updated',
  AVATAR_FETCH_COMPLETE: 'avatar-fetch-complete',

  // Settings events
  SETTINGS_OPEN: 'settings:open',
  SETTINGS_CLOSE: 'settings:close',
  OPEN_SETTINGS: 'openSettings',
  CLOSE_SETTINGS: 'closeSettings',

  // Edge events
  EDGE_SERVER_MESSAGE: 'edge:server-message',
  SECURE_SERVER_MESSAGE: 'edge:secure-server-message',

  // Error events
  SECURE_CRITICAL_ERROR: 'secure-critical-error',

  // App lifecycle events
  APP_ENTERING_BACKGROUND: 'app:entering-background',
  AUTH_UI_BACK: 'auth-ui-back',
  AUTH_UI_FORWARD: 'auth-ui-forward',
  SECURE_CHAT_AUTH_SUCCESS: 'secure-chat:auth-success',

  // UI events
  UI_CALL_LOG: 'ui-call-log',
  UI_CALL_STATUS: 'ui-call-status',
  UI_CALL_ENDED: 'ui-call-ended',
  OPEN_NEW_CHAT: 'open-new-chat',

  // WebSocket events
  WS_RECONNECTED: 'ws-reconnected',
  PQ_SESSION_ESTABLISHED: 'pq-session-established',
  AUTH_RATE_LIMITED: 'auth-rate-limited',
  AUTH_ERROR: 'auth-error',
  AUTH_UI_INPUT: 'auth-ui-input',
  TOKEN_VALIDATION_START: 'token-validation-start',
  TOKEN_VALIDATION_TIMEOUT: 'token-validation-timeout',

  // Signal events
  PASSWORD_HASH_PARAMS: 'password-hash-params',
  OFFLINE_MESSAGES_RESPONSE: 'offline-messages-response',
  BLOCK_TOKENS_UPDATED: 'block-tokens-updated',
  BLOCK_LIST_SYNCED: 'block-list-synced',
  BLOCK_LIST_UPDATE: 'block-list-update',
  GENERATE_PREKEYS_REQUEST: 'generate-prekeys-request',
  LIBSIGNAL_PUBLISH_STATUS: 'libsignal-publish-status',

  // Profile picture events
  PROFILE_PICTURE_UPDATED: 'profile-picture-updated',
  PROFILE_PICTURE_SYSTEM_INITIALIZED: 'profile-picture-system-initialized',
  PROFILE_SETTINGS_UPDATED: 'profile-settings-updated',

  // P2P file events
  P2P_FILE_ACK: 'p2p-file-ack',

  // Block events
  BLOCK_STATUS_CHANGED: 'block-status-changed',
  BLOCKED_MESSAGE: 'blocked-message',
} as const;

export type EventTypeName = typeof EventType[keyof typeof EventType];
