export const SignalType = {
  //connection and auth
  SERVER_PUBLIC_KEY: "server-public-key",
  SERVER_LOGIN: "server-login",
  ACCOUNT_SIGN_IN: "account-sign-in",
  ACCOUNT_SIGN_UP: "account-sign-up",
  IN_ACCOUNT: "in-account",
  AUTH_SUCCESS: "AUTH_SUCCESS",

  //messaging
  ENCRYPTED_MESSAGE: "encrypted-message",
  FILE_MESSAGE: "file-message",
  FILE_MESSAGE_CHUNK: "file-message-chunk",
  PUBLICKEYS: "public-keys",
  SERVER_PASSWORD_ENCRYPTED: "server-password-encrypted",

  //errors and status
  USER_DISCONNECT: "user-disconnect",
  AUTH_ERROR: "AUTH_ERROR",
  NAMEEXISTSERROR: "name-exists-error",
  INVALIDNAME: "invalid-name",
  INVALIDNAMELENGTH: "invalid-name-length",
  SERVERLIMIT: "server-limit",

  PASSPHRASE_HASH: "passphrase-hash",
  PASSPHRASE_HASH_NEW: "passphrase-hash-new",
  PASSPHRASE_SUCCESS: "passphrase-success",

  UPDATE_DB: "update-db",
  HYBRID_KEYS_UPDATE: "hybrid-keys-update",

  
  DR_SEND: "dr-send",
  // libsignal (official) session bootstrap
  LIBSIGNAL_PUBLISH_BUNDLE: "libsignal-publish-bundle",
  LIBSIGNAL_REQUEST_BUNDLE: "libsignal-request-bundle",
  LIBSIGNAL_DELIVER_BUNDLE: "libsignal-deliver-bundle",

  //rate limiting and admin
  RATE_LIMIT_STATUS: "rate-limit-status",
  RATE_LIMIT_RESET: "rate-limit-reset",

  // Note: Typing indicators are now handled as encrypted messages

  // Note: Read receipts and delivery receipts are now handled as encrypted messages
};

export const SignalMessages = {
  //auth messages
  AUTH_ERROR: "Authentication failed",

  //username validation
  NAMEEXISTSERROR: "Username already exists",
  INVALIDNAME: "Username must only contain letters, numbers, underscores, or hyphens",
  INVALIDNAMELENGTH: "Username must be between 3 and 16 characters",

  //server status
  SERVERLIMIT: "Server has reached maximum capacity",
};