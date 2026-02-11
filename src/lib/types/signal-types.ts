export enum SignalType {
  // Account and Authentication
  AUTH_TOKEN_INIT = 'auth-token-init',
  AUTH_TOKEN_ROTATED = 'auth-token-rotated',
  AUTH_ERROR = 'AUTH_ERROR',
  TOKEN_VALIDATION = 'token-validation',
  TOKEN_VALIDATION_RESPONSE = 'token-validation-response',

  // Blocking System
  BLOCK_TOKENS_UPDATE = 'block-tokens-update',
  BLOCK_LIST_SYNC = 'block-list-sync',
  BLOCK_LIST_UPDATE = 'block-list-update',
  BLOCK_LIST_RESPONSE = 'block-list-response',
  RETRIEVE_BLOCK_LIST = 'retrieve-block-list',

  // Chat and Messages
  CHAT = 'chat',
  MESSAGE = 'message',
  TEXT = 'text',
  EDIT_MESSAGE = 'edit-message',
  DELETE_MESSAGE = 'delete-message',
  EDIT = 'edit',
  DELETE = 'delete',
  REACTION_ADD = 'reaction-add',
  REACTION_REMOVE = 'reaction-remove',
  REACTION = 'reaction',
  DELIVERY_ACK = 'delivery-ack',
  DELIVERY_RECEIPT = 'delivery-receipt',
  READ_RECEIPT = 'read-receipt',
  STORE_OFFLINE_MESSAGE = 'store-offline-message',
  RETRIEVE_OFFLINE_MESSAGES = 'retrieve-offline-messages',
  OFFLINE_MESSAGES_RESPONSE = 'offline-messages-response',

  // Encryption and Security
  ENCRYPTED_MESSAGE = 'encrypted-message',
  SERVER_PUBLIC_KEY = 'server-public-key',
  REQUEST_SERVER_PUBLIC_KEY = 'request-server-public-key',
  KEYS_STORED = 'keys-stored',

  // File Operations
  FILE = 'file',
  FILE_MESSAGE = 'file-message',
  FILE_MESSAGE_CHUNK = 'file-message-chunk',

  // Hybrid and Signal Protocol
  HYBRID_KEYS = 'hybrid-keys',
  HYBRID_KEYS_UPDATE = 'hybrid-keys-update',
  LIBSIGNAL_PUBLISH_BUNDLE = 'libsignal-publish-bundle',
  LIBSIGNAL_DELIVER_BUNDLE = 'libsignal-deliver-bundle',
  LIBSIGNAL_PUBLISH_STATUS = 'libsignal-publish-status',
  SIGNAL_PROTOCOL = 'signal-protocol',
  SIGNAL = 'signal',

  // P2P and WebRTC
  CALL_SIGNAL = 'call-signal',
  OFFER = 'offer',
  ANSWER = 'answer',
  ICE_CANDIDATE = 'ice-candidate',

  // Post-Quantum
  PQ_ENVELOPE = 'pq-envelope',
  PQ_HANDSHAKE_INIT = 'pq-handshake-init',
  PQ_HANDSHAKE_ACK = 'pq-handshake-ack',
  PQ_HEARTBEAT_PING = 'pq-heartbeat-ping',
  PQ_HEARTBEAT_PONG = 'pq-heartbeat-pong',

  // Server and Connection
  SERVERMESSAGE = 'server-message',
  ERROR = 'error',
  SESSION_ESTABLISHED = 'session-established',
  SESSION_RESET_REQUEST = 'session-reset-request',

  // Status and Control
  OK = 'ok',
  PING = 'ping',
  PONG = 'pong',
  RATE_LIMIT_STATUS = 'rate-limit-status',

  // Typing Indicators
  TYPING = 'typing',
  TYPING_START = 'typing-start',
  TYPING_STOP = 'typing-stop',
  TYPING_INDICATOR = 'typing-indicator',

  KEY_CHUNK = 'KEY_CHUNK',

  // Blind Routing
  BLIND_ROUTE = 'blind-route',
  BLIND_ROUTE_ACK = 'blind-route-ack',
  SEALED_ENVELOPE = 'sealed-envelope',
  CLAIM_INBOX = 'claim-inbox',
  CLAIM_INBOX_RESPONSE = 'claim-inbox-response',
  ROTATE_INBOX = 'rotate-inbox',
  ROTATE_INBOX_RESPONSE = 'rotate-inbox-response',
  OWNERSHIP_PROOF = 'ownership-proof',
  OWNERSHIP_PROOF_RESPONSE = 'ownership-proof-response',

  // Blind Credentials
  BLIND_SIGNATURE_REQUEST = 'blind-signature-request',
  BLIND_SIGNATURE_RESPONSE = 'blind-signature-response',

  // Total Blind Authentication
  AUTH_OT_REGISTER_REQUEST = 'auth-ot-register-request',
  AUTH_OT_REGISTER_RESPONSE = 'auth-ot-register-response',
  AUTH_OT_REGISTER_FINALIZE = 'auth-ot-register-finalize',
  PRIVACY_PASS_ISSUANCE = 'privacy-pass-issuance',
  PRIVACY_PASS_REDEMPTION = 'privacy-pass-redemption',
  ZK_REFRESH_CHALLENGE = 'zk-refresh-challenge',
  ZK_REFRESH_RESPONSE = 'zk-refresh-response',
  ZK_DEVICE_REGISTER = 'zk-device-register',
  ZK_DEVICE_REGISTER_RESPONSE = 'zk-device-register-response',
  AUTH_FULL_SUCCESS = 'AUTH_FULL_SUCCESS',
  PROFILE_UPDATE = 'profile-update',

  // OPRF-Based Discovery
  OPRF_DISCOVERY_PUBLIC_KEY = 'oprf-discovery-public-key',
  OPRF_BLIND_EVALUATE = 'oprf-blind-evaluate',
  OPRF_BLIND_EVALUATE_RESPONSE = 'oprf-blind-evaluate-response',
  PUBLISH_DISCOVERY = 'publish-discovery',
  QUERY_DISCOVERY = 'query-discovery',
  DISCOVERY_RESULT = 'discovery-result',
  SERVER_ENTRY_REQUEST = 'server-entry-request',
  SERVER_ENTRY_CHALLENGE = 'server-entry-challenge',
  SERVER_ENTRY_TOKEN_ISSUANCE = 'server-entry-token-issuance',
  AUTH_OT_REQUEST = 'auth-ot-request',
  AUTH_OT_RESPONSE = 'auth-ot-response',
  AUTH_OT_FINALIZE = 'auth-ot-finalize',
}
