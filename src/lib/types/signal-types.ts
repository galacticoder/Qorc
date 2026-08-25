export enum SignalType {
  // Account and Authentication
  AUTH_TOKEN_INIT = 'auth-token-init',
  AUTH_ERROR = 'AUTH_ERROR',
  TOKEN_VALIDATION = 'token-validation',
  TOKEN_VALIDATION_RESPONSE = 'token-validation-response',

  // Chat and Messages
  MESSAGE = 'message',
  TEXT = 'text',
  EDIT_MESSAGE = 'edit-message',
  DELETE_MESSAGE = 'delete-message',
  REACTION_ADD = 'reaction-add',
  REACTION_REMOVE = 'reaction-remove',
  RECEIPT_BATCH = 'receipt-batch',

  // Encryption and Security
  SERVER_PUBLIC_KEY = 'server-public-key',
  REQUEST_SERVER_PUBLIC_KEY = 'request-server-public-key',

  // File Operations
  FILE = 'file',
  FILE_MESSAGE = 'file-message',
  FILE_MESSAGE_CHUNK = 'file-message-chunk',
  FILE_CHUNK_NACK = 'file-chunk-nack',
  FILE_TRANSPORT_ACK = 'file-transport-ack',
  FILE_TRANSFER_CANCEL = 'file-transfer-cancel',

  // Hybrid and Signal Protocol
  // P2P calling
  CALL_SIGNAL = 'call-signal',

  // Post-Quantum
  PQ_ENVELOPE = 'pq-envelope',
  PQ_HANDSHAKE_INIT = 'pq-handshake-init',
  PQ_HANDSHAKE_ACK = 'pq-handshake-ack',
  PQ_HANDSHAKE_CONFIRM = 'pq-handshake-confirm',
  PQ_HANDSHAKE_CONFIRMED = 'pq-handshake-confirmed',
  PQ_HEARTBEAT_PING = 'pq-heartbeat-ping',
  PQ_HEARTBEAT_PONG = 'pq-heartbeat-pong',

  // Server and Connection
  ERROR = 'error',
  SESSION_RESET_REQUEST = 'session-reset-request',

  // Status and Control
  OK = 'ok',
  PING = 'ping',
  PONG = 'pong',

  // Typing Indicators
  TYPING_START = 'typing-start',
  TYPING_STOP = 'typing-stop',

  // Blind Routing
  BLIND_ROUTE = 'blind-route',
  BLIND_ROUTE_ACK = 'blind-route-ack',
  SEALED_ENVELOPE = 'sealed-envelope',
  ACTIVATE_DELIVERY = 'activate-delivery',
  ACTIVATE_DELIVERY_RESPONSE = 'activate-delivery-response',

  // Total Blind Authentication
  AUTH_OT_REGISTER_REQUEST = 'auth-ot-register-request',
  AUTH_OT_REGISTER_RESPONSE = 'auth-ot-register-response',
  AUTH_OT_REGISTER_FINALIZE = 'auth-ot-register-finalize',
  AUTH_OT_REGISTER_READY = 'auth-ot-register-ready',
  AUTH_OT_REGISTER_CONFIRM = 'auth-ot-register-confirm',
  PRIVACY_PASS_REDEMPTION = 'privacy-pass-redemption',
  AUTH_FULL_SUCCESS = 'AUTH_FULL_SUCCESS',

  // OPRF-Based Discovery
  OPRF_DISCOVERY_PUBLIC_KEY = 'oprf-discovery-public-key',
  PUBLISH_DISCOVERY = 'publish-discovery',
  SERVER_ENTRY_REQUEST = 'server-entry-request',
  SERVER_ENTRY_CHALLENGE = 'server-entry-challenge',
  SERVER_ENTRY_TOKEN_ISSUANCE = 'server-entry-token-issuance',
  ACCOUNT_AUTH_TOKEN_REFRESH = 'account-auth-token-refresh',
  ACCOUNT_AUTH_TOKEN_REFRESH_RESPONSE = 'account-auth-token-refresh-response',
  AUTH_OT_REQUEST = 'auth-ot-request',
  AUTH_OT_RESPONSE = 'auth-ot-response',
  AUTH_OT_FINALIZE = 'auth-ot-finalize',
  SECURE_CHUNK = 'secure-chunk',
}
