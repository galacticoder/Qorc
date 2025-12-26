export const EventType = {
  // Username mapping events
  USERNAME_MAPPING_UPDATED: 'username-mapping-updated',
  USERNAME_MAPPING_RECEIVED: 'username-mapping-received',

  // Session events
  SESSION_RESET_RECEIVED: 'session-reset-received',
  SESSION_ESTABLISHED_RECEIVED: 'session-established-received',
  LIBSIGNAL_SESSION_READY: 'libsignal-session-ready',
  LIBSIGNAL_BUNDLE_FAILED: 'libsignal-bundle-failed',

  // P2P events
  P2P_SESSION_RESET_SEND: 'p2p-session-reset-send',
  P2P_PQ_ESTABLISHED: 'p2p-pq-established',
  P2P_PEER_CONNECTED: 'p2p-peer-connected',
  P2P_PEER_RECONNECTED: 'p2p-peer-reconnected',
  P2P_FETCH_PEER_CERT: 'p2p-fetch-peer-cert',
  P2P_PEER_CERT: 'p2p-peer-cert',

  // Message events
  MESSAGE_READ: 'message-read',
  MESSAGE_DELIVERED: 'message-delivered',
  LOCAL_MESSAGE_EDIT: 'local-message-edit',
  LOCAL_MESSAGE_DELETE: 'local-message-delete',
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

  // File events
  FILE_PROGRESS: 'file-progress',
  FILE_CHUNK_RECEIVED: 'file-chunk-received',

  // Block list events
  BLOCK_LIST_UPDATED: 'block-list-updated',

  // Avatar events
  AVATAR_UPDATED: 'avatar-updated',
  AVATAR_FETCH_COMPLETE: 'avatar-fetch-complete',
} as const;

export type EventTypeName = typeof EventType[keyof typeof EventType];
