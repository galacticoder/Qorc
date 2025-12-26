export const SignalType = {
  //connection and auth
  SERVER_PUBLIC_KEY: "server-public-key",
  SERVER_LOGIN: "server-login",
  ACCOUNT_SIGN_IN: "account-sign-in",
  ACCOUNT_SIGN_UP: "account-sign-up",
  IN_ACCOUNT: "in-account",
  AUTH_SUCCESS: "AUTH_SUCCESS",
  AUTH_RECOVERY: "auth-recovery",
  TOKEN_VALIDATION: "token-validation",
  TOKEN_VALIDATION_RESPONSE: "token-validation-response",
  DEVICE_CHALLENGE_REQUEST: "device-challenge-request",
  DEVICE_CHALLENGE: "device-challenge",
  DEVICE_ATTESTATION: "device-attestation",
  DEVICE_ATTESTATION_ACK: "device-attestation-ack",
  REGISTER: "register",
  REGISTER_ACK: "register-ack",

  //messaging
  ENCRYPTED_MESSAGE: "encrypted-message",
  FILE_MESSAGE: "file-message",
  FILE_MESSAGE_CHUNK: "file-message-chunk",
  PUBLICKEYS: "public-keys",
  STORE_OFFLINE_MESSAGE: "store-offline-message",
  RETRIEVE_OFFLINE_MESSAGES: "retrieve-offline-messages",
  OFFLINE_MESSAGES_RESPONSE: "offline-messages-response",
  DELETE_MESSAGE: "delete-message",
  EDIT_MESSAGE: "edit-message",
  REACTION_ADD: "reaction-add",
  REACTION_REMOVE: "reaction-remove",

  //receipts and typing
  TYPING_START: "typing-start",
  TYPING_STOP: "typing-stop",
  TYPING_INDICATOR: "typing-indicator",
  DELIVERY_RECEIPT: "delivery-receipt",
  READ_RECEIPT: "read-receipt",

  //errors and status
  ERROR: "error",
  OK: "ok",
  USER_DISCONNECT: "user-disconnect",
  AUTH_ERROR: "AUTH_ERROR",
  NAMEEXISTSERROR: "name-exists-error",
  INVALIDNAME: "invalid-name",
  INVALIDNAMELENGTH: "invalid-name-length",
  SERVERLIMIT: "server-limit",
  SERVERMESSAGE: "server-message",
  ERROR_ACKNOWLEDGED: "error-acknowledged",
  CLIENT_ERROR: "client-error",

  PASSPHRASE_HASH: "passphrase-hash",
  PASSPHRASE_SUCCESS: "passphrase-success",
  PASSWORD_HASH_PARAMS: "password-hash-params",
  PASSWORD_HASH_RESPONSE: "password-hash-response",

  HYBRID_KEYS: "hybrid-keys",
  HYBRID_KEYS_UPDATE: "hybrid-keys-update",
  KEYS_STORED: "keys-stored",

  REQUEST_SERVER_PUBLIC_KEY: "request-server-public-key",

  DR_SEND: "dr-send",
  // libsignal session bootstrap
  LIBSIGNAL_PUBLISH_BUNDLE: "libsignal-publish-bundle",
  LIBSIGNAL_REQUEST_BUNDLE: "libsignal-request-bundle",
  LIBSIGNAL_DELIVER_BUNDLE: "libsignal-deliver-bundle",
  LIBSIGNAL_PUBLISH_STATUS: "libsignal-publish-status",
  SIGNAL_BUNDLE_FAILURE: "signal-bundle-failure",

  // Client-side prekey generation
  CLIENT_GENERATE_PREKEYS: "client-generate-prekeys",
  PREKEY_STATUS: "prekey-status",

  //rate limiting and admin
  RATE_LIMIT_STATUS: "rate-limit-status",

  // User existence validation
  CHECK_USER_EXISTS: "check-user-exists",
  USER_EXISTS_RESPONSE: "user-exists-response",

  // Session management
  PQ_HANDSHAKE_INIT: "pq-handshake-init",
  PQ_HANDSHAKE_ACK: "pq-handshake-ack",
  PQ_SESSION_INIT: "pq-session-init",
  PQ_SESSION_RESPONSE: "pq-session-response",
  PQ_HEARTBEAT_PING: "pq-heartbeat-ping",
  PQ_HEARTBEAT_PONG: "pq-heartbeat-pong",
  PQ_ENVELOPE: "pq-envelope",
  CONNECTION_RESTORED: "connection-restored",
  SESSION_ESTABLISHED: "session-established",
  SESSION_RESET_REQUEST: "session-reset-request",

  // Device proof of possession (Ed25519)
  DEVICE_PROOF_CHALLENGE: "device-proof-challenge",
  DEVICE_PROOF_RESPONSE: "device-proof-response",

  // Blocking system
  BLOCK_LIST_SYNC: "block-list-sync",
  BLOCK_LIST_UPDATE: "block-list-update",
  BLOCK_TOKENS_UPDATE: "block-tokens-update",
  RETRIEVE_BLOCK_LIST: "retrieve-block-list",
  BLOCK_LIST_RESPONSE: "block-list-response",

  // P2P signaling
  P2P_FETCH_PEER_CERT: "p2p-fetch-peer-cert",
  P2P_PEER_CERT: "p2p-peer-cert",
  OFFER: "offer",
  ANSWER: "answer",
  ICE_CANDIDATE: "ice-candidate",

  // Misc
  PING: "ping",
  PONG: "pong",
  AVATAR_UPLOAD: "avatar-upload",
  AVATAR_UPLOAD_RESPONSE: "avatar-upload-response",
  AVATAR_FETCH: "avatar-fetch",
  AVATAR_FETCH_RESPONSE: "avatar-fetch-response",
};

export const SignalMessages = {
  //auth messages
  AUTH_ERROR: "Authentication failed",

  //username validation
  NAMEEXISTSERROR: "Username already exists",
  INVALIDNAME: "Username must only contain letters, numbers, underscores, or hyphens",
  INVALIDNAMELENGTH: "Username must be between 3 and 32 characters",

  //server status
  SERVERLIMIT: "Server has reached maximum capacity",
};