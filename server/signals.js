export const SignalType = {
  PUBLICKEYS: "public-keys",
  ENCRYPTED_MESSAGE: "encrypted-message",
  FILE_MESSAGE: "file-message",
  FILE_MESSAGE_CHUNK: "file-message-chunk",
  USER_DISCONNECT: "user-disconnect",
  NAMEEXISTSERROR: "name-exists-error",
  INVALIDNAMELENGTH: "invalid-name-length",
  INVALIDNAME: "invalid-name",
  SERVERLIMIT: "server-limit",
  SERVER_PASSWORD_ENCRYPTED: "server-password-encrypted",
  SERVER_PUBLIC_KEY: "server-public-key",
  LOGIN_INFO: "login-info",
  ACCOUNT_SIGN_IN: "account-sign-in",
  ACCOUNT_SIGN_UP: "account-sign-up",
  IN_ACCOUNT: "in-account",
  AUTH_ERROR: "AUTH_ERROR",
  AUTH_SUCCESS: "AUTH_SUCCESS",
};

export const SignalMessages = {
  NAMEEXISTSERROR: "Username already exists",
  INVALIDNAMELENGTH: "Username must be between 3 and 16 characters",
  INVALIDNAME: "Username must only contain letters, numbers, underscores, or hyphens",
  SERVERLIMIT: "Server has reached the maximum number of users",
  AUTH_ERROR: "Invalid server password",
};