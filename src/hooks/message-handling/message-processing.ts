import { SignalType } from '../../lib/types/signal-types';
import { Message } from '../../components/chat/messaging/types';
import { sanitizeMessageId } from '../../lib/sanitizers';
import { nativeMessageContent } from '../../lib/tauri-bindings';
import { setMessagesWithResult } from '../../lib/utils/set-messages-result';
import { blake3 } from '@noble/hashes/blake3.js';
import { PROTOCOL_KEYS } from '../../lib/config/protocol-keys';

const vaultIdEncoder = new TextEncoder();

const deriveInboundVaultId = (
  kind: 'message' | 'reply',
  account: string,
  peer: string,
  messageId: string,
  replyTargetId = '',
): string => {
  const context = vaultIdEncoder.encode(JSON.stringify([
    PROTOCOL_KEYS.INBOUND_VAULT,
    kind,
    account,
    peer,
    messageId,
    replyTargetId,
  ]));
  const digest = blake3(context, { dkLen: 32 });
  try {
    let hex = '';
    for (const byte of digest) hex += byte.toString(16).padStart(2, '0');
    return `${kind === 'message' ? 'text' : 'reply'}-${hex}`;
  } finally {
    context.fill(0);
    digest.fill(0);
  }
};

// Process text message and add to state
export const processTextMessage = async (
  payload: any,
  loginUsername: string,
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  saveMessageToLocalDB: (msg: Message) => Promise<void>,
  isCurrentAccount: () => boolean,
  loadPersistedMessage: (peerUsername: string, messageId: string) => Promise<Message | null>,
  storePersistedMessage: (message: Message) => Promise<{ stored: boolean; existing: Message | null }>,
  receiverObservedTransport: NonNullable<Message['transport']>,
): Promise<{ messageId: string; messageAdded: boolean; duplicate: boolean }> => {
  if (!isCurrentAccount()) {
    console.warn('[MSG-RECV] DROP in processTextMessage: account changed');
    return { messageId: '', messageAdded: false, duplicate: false };
  }
  const messageId = sanitizeMessageId(payload.messageId);
  const nativeContentRef = sanitizeMessageId(payload.nativeContentRef);
  if (!messageId) {
    console.warn('[MSG-RECV] DROP in processTextMessage: invalid messageId');
    return { messageId: '', messageAdded: false, duplicate: false };
  }
  const peerUsername = typeof payload.from === 'string' ? payload.from : '';
  if (!peerUsername || peerUsername === loginUsername) {
    console.warn('[MSG-RECV] DROP in processTextMessage: bad sender (missing, or equals self)', {
      from: peerUsername || null, self: loginUsername,
    });
    return { messageId, messageAdded: false, duplicate: false };
  }
  const messageTimestamp = normalizePeerTimestamp(payload.timestamp);
  
  if (!nativeContentRef || payload.content !== '') {
    console.warn('[MSG-RECV] DROP in processTextMessage: native content reference missing');
    return { messageId, messageAdded: false, duplicate: false };
  }

  const expectedRecipient = loginUsername;
  const localMessageId = deriveInboundVaultId(
    'message',
    loginUsername,
    peerUsername,
    messageId,
  );
  const initial = await setMessagesWithResult<{
    existing: Message | null;
    replyTarget: Message | null;
  }>(setMessages, (prev) => {
    const replyTargetId = sanitizeMessageId(payload?.replyTo?.id);
    return {
      next: prev,
      result: {
        existing: prev.find(message => (
          message.id === localMessageId ||
          (message.wireMessageId === messageId &&
            message.sender === peerUsername &&
            message.recipient === expectedRecipient)
        )) || null,
        replyTarget: replyTargetId
          ? prev.find(message => message.id === replyTargetId || message.wireMessageId === replyTargetId) || null
          : null,
      },
    };
  });
  if (!isCurrentAccount()) return { messageId, messageAdded: false, duplicate: false };

  const finishDuplicate = async (existing: Message, repersist: boolean): Promise<{
    messageId: string;
    messageAdded: boolean;
    duplicate: boolean;
  }> => {
    if (existing.sender !== peerUsername || existing.recipient !== expectedRecipient) {
      return { messageId, messageAdded: false, duplicate: false };
    }
    const existingContentId = sanitizeMessageId(existing.secureContentId) || localMessageId;
    const contentResult = await nativeMessageContent.commitPending(
      loginUsername,
      nativeContentRef,
      messageId,
      existingContentId,
      false,
    );
    if (!isCurrentAccount()) return { messageId, messageAdded: false, duplicate: false };
    if (!contentResult.duplicate) {
      return { messageId, messageAdded: false, duplicate: false };
    }

    if (repersist) {
      await saveMessageToLocalDB({ ...existing, content: '' });
    }
    if (!isCurrentAccount()) return { messageId, messageAdded: false, duplicate: false };
    return { messageId, messageAdded: false, duplicate: true };
  };

  if (initial.existing) return finishDuplicate(initial.existing, true);

  const persistedExisting = await loadPersistedMessage(peerUsername, messageId);
  if (!isCurrentAccount()) return { messageId, messageAdded: false, duplicate: false };
  if (persistedExisting) return finishDuplicate(persistedExisting, false);

  const replyTargetId = sanitizeMessageId(payload?.replyTo?.id);
  let replyTarget = initial.replyTarget;
  if (!replyTarget && replyTargetId) {
    replyTarget = await loadPersistedMessage(peerUsername, replyTargetId);
    if (!isCurrentAccount()) return { messageId, messageAdded: false, duplicate: false };
  }

  let replyToFilled: Message['replyTo'] | undefined;
  const replyBelongsToConversation = !!replyTarget && (
    (replyTarget.sender === peerUsername && replyTarget.recipient === loginUsername) ||
    (replyTarget.sender === loginUsername && replyTarget.recipient === peerUsername)
  );
  if (replyTargetId && replyTarget && replyBelongsToConversation) {
    replyToFilled = {
      id: replyTargetId,
      sender: replyTarget.sender,
      content: '',
      secureContentId: replyTarget.secureContentId,
    };
  }

  const message: Message = {
    id: localMessageId,
    wireMessageId: messageId,
    content: '',
    secureContentId: localMessageId,
    sender: peerUsername,
    recipient: expectedRecipient,
    timestamp: messageTimestamp,
    type: SignalType.TEXT,
    isCurrentUser: false,
    p2p: receiverObservedTransport === 'p2p',
    encrypted: true,
    transport: receiverObservedTransport,
    ...(replyToFilled && { replyTo: replyToFilled }),
  };

  const contentCommit = await nativeMessageContent.commitPending(
    loginUsername,
    nativeContentRef,
    messageId,
    localMessageId,
    false,
  );
  if (!contentCommit.stored && !contentCommit.duplicate) {
    return { messageId, messageAdded: false, duplicate: false };
  }
  if (!isCurrentAccount()) return { messageId, messageAdded: false, duplicate: false };

  const persistence = await storePersistedMessage(message);
  if (!isCurrentAccount()) return { messageId, messageAdded: false, duplicate: false };
  if (!persistence.stored) {
    return persistence.existing
      ? finishDuplicate(persistence.existing, false)
      : { messageId, messageAdded: false, duplicate: false };
  }

  const insertion = await setMessagesWithResult<{ added: boolean; existing: Message | null }>(setMessages, (prev) => {
    if (!isCurrentAccount()) return { next: prev, result: { added: false, existing: null } };
    const existing = prev.find(candidate => (
      candidate.id === localMessageId ||
      (candidate.wireMessageId === messageId &&
        candidate.sender === peerUsername &&
        candidate.recipient === expectedRecipient)
    )) || null;
    return existing
      ? { next: prev, result: { added: false, existing } }
      : { next: [...prev, message], result: { added: true, existing: null } };
  });
  if (!isCurrentAccount()) return { messageId, messageAdded: false, duplicate: false };
  if (!insertion.added) {
    console.log('[MSG-RECV] processTextMessage: not inserted into conversation', {
      from: peerUsername, wireId: messageId.slice(0, 8),
      reason: insertion.existing ? 'already-present (duplicate)' : 'insert rejected',
    });
    return insertion.existing
      ? finishDuplicate(insertion.existing, true)
      : { messageId, messageAdded: false, duplicate: false };
  }
  if (!isCurrentAccount()) return { messageId, messageAdded: false, duplicate: false };

  return { messageId, messageAdded: true, duplicate: false };
};

const MAX_FUTURE_MESSAGE_AGE_MS = 5 * 60 * 1000;
const MAX_PAST_MESSAGE_AGE_MS = 30 * 24 * 60 * 60 * 1000;

export const normalizePeerTimestamp = (value: unknown, now = Date.now()): Date => {
  const parsed = typeof value === 'number'
    ? value
    : typeof value === 'string' && value.trim() !== ''
      ? Number(value)
      : Number.NaN;
  if (!Number.isFinite(parsed)) return new Date(now);
  return new Date(Math.min(now + MAX_FUTURE_MESSAGE_AGE_MS, Math.max(now - MAX_PAST_MESSAGE_AGE_MS, parsed)));
};

// Check if message requires blocking filter
export const checkBlockingFilter = async (
  payload: any,
  loginUsername: string,
  blockingSystem: any
): Promise<boolean> => {
  if (payload.from && payload.from !== loginUsername) {
    return blockingSystem.filterIncomingMessage({
      sender: payload.from,
      content: payload.content || ''
    });
  }
  return true;
};

// Determine message type
export const getMessageType = (payload: any): { isTextMessage: boolean; isCallSignal: boolean } => {
  const isTextMessage = payload.type === SignalType.MESSAGE &&
    payload.content === '' &&
    sanitizeMessageId(payload.nativeContentRef) === payload.nativeContentRef;
  const isCallSignal = payload.type === SignalType.CALL_SIGNAL;

  return { isTextMessage, isCallSignal };
};
