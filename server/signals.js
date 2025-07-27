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
};

export const SignalMessages = {
  NAMEEXISTSERROR: "Username already exists",
  INVALIDNAMELENGTH: "Username must be between 3 and 16 characters",
  INVALIDNAME: "Username must only contain letters, numbers, underscores, or hyphens",
  SERVERLIMIT: "Server has reached the maximum number of users",
};