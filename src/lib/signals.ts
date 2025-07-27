export enum SignalType {
  PUBLICKEYS = "public-keys",
  FILE_MESSAGE = "file-message",
  FILE_MESSAGE_CHUNK = "file-message-chunk",
  ENCRYPTED_MESSAGE = "encrypted-message",
  USER_DISCONNECT = "user-disconnect",
  SERVERLIMIT = "server-limit",
  SERVERMESSAGE = "server-message",
  NAMEEXISTSERROR = "name-exists-error", 
  INVALIDNAMELENGTH = "invalid-name-length",
  INVALIDNAME = "invalid-name",
}