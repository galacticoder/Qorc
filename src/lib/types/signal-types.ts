export enum SignalType {
  // Account and Authentication
  ACCOUNT_SIGN_IN = 'account-sign-in',
  ACCOUNT_SIGN_UP = 'account-sign-up',
  ACCOUNT_PASSWORD = 'account-password',
  ACCOUNT_META = 'account-meta',
  AUTH_TOKEN_INIT = 'auth-token-init',
  AUTH_TOKEN_ROTATED = 'auth-token-rotated',
  AUTH_RECOVERY = 'auth-recovery',
  IN_ACCOUNT = 'in-account',
  AUTH_ERROR = 'AUTH_ERROR',
  AUTH_SUCCESS = 'AUTH_SUCCESS',
  DEVICE_CHALLENGE_REQUEST = 'device-challenge-request',
  DEVICE_CHALLENGE = 'device-challenge',
  DEVICE_ATTESTATION = 'device-attestation',
  DEVICE_ATTESTATION_ACK = 'device-attestation-ack',
  DEVICE_PROOF_CHALLENGE = 'device-proof-challenge',
  DEVICE_PROOF_RESPONSE = 'device-proof-response',
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
  P2P_ENCRYPTED_MESSAGE = 'p2p-encrypted-message',
  PUBLICKEYS = 'public-keys',
  SERVER_PUBLIC_KEY = 'server-public-key',
  REQUEST_SERVER_PUBLIC_KEY = 'request-server-public-key',
  PASSWORD_HASH_PARAMS = 'password-hash-params',
  PASSWORD_HASH_RESPONSE = 'password-hash-response',
  PASSPHRASE_HASH = 'passphrase-hash',
  PASSPHRASE_SUCCESS = 'passphrase-success',
  KEYS_STORED = 'keys-stored',

  // File Operations
  FILE = 'file',
  FILE_MESSAGE = 'file-message',
  FILE_MESSAGE_CHUNK = 'file-message-chunk',

  // Hybrid and Signal Protocol
  HYBRID_KEYS = 'hybrid-keys',
  HYBRID_KEYS_UPDATE = 'hybrid-keys-update',
  LIBSIGNAL_PUBLISH_BUNDLE = 'libsignal-publish-bundle',
  LIBSIGNAL_REQUEST_BUNDLE = 'libsignal-request-bundle',
  LIBSIGNAL_DELIVER_BUNDLE = 'libsignal-deliver-bundle',
  LIBSIGNAL_PUBLISH_STATUS = 'libsignal-publish-status',
  SIGNAL_PROTOCOL = 'signal-protocol',
  SIGNAL = 'signal',

  // P2P and WebRTC
  CALL_SIGNAL = 'call-signal',
  P2P_FETCH_PEER_CERT = 'p2p-fetch-peer-cert',
  P2P_PEER_CERT = 'p2p-peer-cert',
  OFFER = 'offer',
  ANSWER = 'answer',
  ICE_CANDIDATE = 'ice-candidate',

  // Post-Quantum
  PQ_ENVELOPE = 'pq-envelope',
  PQ_SESSION_INIT = 'pq-session-init',
  PQ_SESSION_RESPONSE = 'pq-session-response',
  PQ_HANDSHAKE_INIT = 'pq-handshake-init',
  PQ_HANDSHAKE_ACK = 'pq-handshake-ack',
  PQ_HEARTBEAT_PING = 'pq-heartbeat-ping',
  PQ_HEARTBEAT_PONG = 'pq-heartbeat-pong',

  // Server and Connection
  SERVER_LOGIN = 'server-login',
  SERVERMESSAGE = 'server-message',
  SERVERLIMIT = 'server-limit',
  ERROR = 'error',
  ERROR_ACKNOWLEDGED = 'error-acknowledged',
  CLIENT_ERROR = 'client-error',
  NAMEEXISTSERROR = 'name-exists-error',
  INVALIDNAMELENGTH = 'invalid-name-length',
  INVALIDNAME = 'invalid-name',
  CONNECTION_RESTORED = 'connection-restored',
  SESSION_ESTABLISHED = 'session-established',
  SESSION_RESET_REQUEST = 'session-reset-request',
  USER_DISCONNECT = 'user-disconnect',

  // Status and Control
  OK = 'ok',
  PING = 'ping',
  PONG = 'pong',
  REGISTER = 'register',
  REGISTER_ACK = 'register-ack',
  DR_SEND = 'dr-send',
  CLIENT_GENERATE_PREKEYS = 'client-generate-prekeys',
  PREKEY_STATUS = 'prekey-status',
  RATE_LIMIT_STATUS = 'rate-limit-status',
  REQUEST_SERVER_PASSWORD_PARAMS = 'REQUEST_PASSWORD_PARAMS',
  SERVER_PASSWORD = 'server-password',

  // Typing Indicators
  TYPING = 'typing',
  TYPING_START = 'typing-start',
  TYPING_STOP = 'typing-stop',
  TYPING_INDICATOR = 'typing-indicator',

  // User Operations
  CHECK_USER_EXISTS = 'check-user-exists',
  USER_EXISTS_RESPONSE = 'user-exists-response',

  // Avatar Operations
  AVATAR_UPLOAD = 'avatar-upload',
  AVATAR_UPLOAD_RESPONSE = 'avatar-upload-response',
  AVATAR_FETCH = 'avatar-fetch',
  AVATAR_FETCH_RESPONSE = 'avatar-fetch-response',
  KEY_CHUNK = 'KEY_CHUNK',
}
