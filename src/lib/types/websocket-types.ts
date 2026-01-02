import { SignalType } from "./signal-types";

export interface WebSocketMessageSchema {
  validate: (message: BaseMessage) => boolean;
}

export interface WebSocketHookOptions {
  schemas?: Record<string, WebSocketMessageSchema>;
  onAudit?: (event: { code: string; type: string }) => void;
}

export interface BaseMessage {
  type: string;
  [key: string]: unknown;
}

export const DEFAULT_ALLOWED_TYPES: Set<string> = new Set([
  SignalType.PQ_ENVELOPE,
  SignalType.PQ_HANDSHAKE_ACK,
  SignalType.PQ_HEARTBEAT_PONG,
  SignalType.CLIENT_ERROR,
  SignalType.DEVICE_CHALLENGE,
  SignalType.DEVICE_ATTESTATION_ACK,
  SignalType.AVATAR_FETCH_RESPONSE,
  SignalType.AVATAR_UPLOAD_RESPONSE,
  SignalType.ENCRYPTED_MESSAGE,
  SignalType.DR_SEND,
  SignalType.SERVERMESSAGE,
  SignalType.SERVERLIMIT,
  SignalType.AUTH_ERROR,
  SignalType.NAMEEXISTSERROR,
  SignalType.INVALIDNAME,
  SignalType.INVALIDNAMELENGTH,
  SignalType.TOKEN_VALIDATION_RESPONSE,
  SignalType.ERROR,
  SignalType.BLOCK_LIST_UPDATE,
  SignalType.BLOCK_LIST_SYNC,
  SignalType.BLOCK_LIST_RESPONSE,
  SignalType.PASSPHRASE_HASH,
  SignalType.PASSPHRASE_SUCCESS,
  SignalType.PASSWORD_HASH_PARAMS,
  SignalType.CONNECTION_RESTORED,
  SignalType.SESSION_ESTABLISHED,
  SignalType.SERVER_PUBLIC_KEY,
  SignalType.IN_ACCOUNT,
  SignalType.AUTH_SUCCESS,
  SignalType.USER_EXISTS_RESPONSE,
  SignalType.P2P_PEER_CERT,
  SignalType.LIBSIGNAL_DELIVER_BUNDLE,
  SignalType.LIBSIGNAL_PUBLISH_STATUS,
  SignalType.SESSION_RESET_REQUEST,
  SignalType.EDIT_MESSAGE,
  SignalType.DELETE_MESSAGE,
  SignalType.USER_DISCONNECT,
  SignalType.FILE_MESSAGE_CHUNK,
  SignalType.OFFLINE_MESSAGES_RESPONSE,
  SignalType.DELIVERY_RECEIPT,
  SignalType.READ_RECEIPT,
]);

export const DEFAULT_ENCRYPTED_TYPES = new Set<string>([
  SignalType.PQ_ENVELOPE,
  SignalType.ENCRYPTED_MESSAGE,
  SignalType.DR_SEND,
]);

export const DEFAULT_SCHEMAS: Record<string, WebSocketMessageSchema> = {
  [SignalType.ENCRYPTED_MESSAGE]: {
    validate: (message) => typeof message.encryptedPayload === 'object' && message.encryptedPayload !== null,
  },
  [SignalType.DR_SEND]: {
    validate: (message) => typeof message.payload === 'object' && message.payload !== null,
  },
  [SignalType.PQ_ENVELOPE]: {
    validate: (message) =>
      typeof (message as any).version === 'string' &&
      (message as any).version === 'pq-ws-1' &&
      typeof (message as any).sessionId === 'string' &&
      typeof (message as any).sessionFingerprint === 'string' &&
      typeof (message as any).messageId === 'string' &&
      typeof (message as any).counter === 'number' &&
      typeof (message as any).timestamp === 'number' &&
      typeof (message as any).nonce === 'string' &&
      typeof (message as any).ciphertext === 'string' &&
      typeof (message as any).tag === 'string' &&
      typeof (message as any).aad === 'string',
  },
};
