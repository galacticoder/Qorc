import type { Message } from '../../components/chat/messaging/types';
import { MAX_LOCAL_EMOJI_LENGTH } from '../constants';
import {
  hasPrototypePollutionKeys,
  isCanonicalAuthUsername,
  isPlainObject,
  isUnsafeObjectKey,
  sanitizeNonEmptyText,
} from '../sanitizers';

const CONTROL_OPERATION_ID_RE = /^op:([0-9]{13}):([a-f0-9]{32})$/;
const CONTROL_CLOCK_SKEW_MS = 5 * 60 * 1000;
const compareActors = (left: { actor: string }, right: { actor: string }): number => (
  left.actor === right.actor ? 0 : left.actor < right.actor ? -1 : 1
);

export type MessageControlState = {
  editOperationId?: string;
  deleteOperationId?: string;
  reactionOperations?: Array<{ actor: string; operationId: string }>;
};

export type MessageControlOutcome = Readonly<{
  message: Message;
  changed: boolean;
}>;

export function createControlOperationId(now = Date.now()): string {
  if (!Number.isSafeInteger(now) || now <= 0 || now > 9_999_999_999_999) {
    throw new Error('Invalid control operation timestamp');
  }
  return `op:${String(now).padStart(13, '0')}:${crypto.randomUUID().replace(/-/g, '')}`;
}

export function isControlOperationId(value: unknown): value is string {
  return typeof value === 'string' && CONTROL_OPERATION_ID_RE.test(value);
}

export function isPlausibleControlOperationId(value: unknown, now = Date.now()): value is string {
  if (!isControlOperationId(value) || !Number.isSafeInteger(now) || now <= 0) return false;
  const match = CONTROL_OPERATION_ID_RE.exec(value)!;
  const issuedAt = Number(match[1]);
  return Number.isSafeInteger(issuedAt) && issuedAt > 0 && issuedAt <= now + CONTROL_CLOCK_SKEW_MS;
}

export function hasWireMessageId(message: Message, wireMessageId: string): boolean {
  return message.wireMessageId === wireMessageId ||
    (!message.wireMessageId && message.id === wireMessageId);
}

function compareControlOperationIds(left: string, right: string): number {
  return left === right ? 0 : left < right ? -1 : 1;
}

function participants(message: Message): Set<string> {
  const values = [message.sender, message.recipient]
    .filter(isCanonicalAuthUsername);
  return new Set(values);
}

function normalizedControlState(message: Message): MessageControlState {
  const raw = message.controlState;
  if (!isPlainObject(raw) || hasPrototypePollutionKeys(raw)) return {};
  const state: MessageControlState = {};
  if (isControlOperationId(raw.editOperationId)) state.editOperationId = raw.editOperationId;
  if (isControlOperationId(raw.deleteOperationId)) state.deleteOperationId = raw.deleteOperationId;

  const allowedActors = participants(message);
  const byActor = new Map<string, string>();
  if (Array.isArray(raw.reactionOperations)) {
    for (const entry of raw.reactionOperations.slice(0, 2)) {
      if (
        !isPlainObject(entry) ||
        hasPrototypePollutionKeys(entry) ||
        Object.keys(entry).sort().join(',') !== 'actor,operationId' ||
        typeof entry.actor !== 'string' ||
        !allowedActors.has(entry.actor) ||
        !isControlOperationId(entry.operationId)
      ) continue;
      const existing = byActor.get(entry.actor);
      if (!existing || compareControlOperationIds(existing, entry.operationId) < 0) {
        byActor.set(entry.actor, entry.operationId);
      }
    }
  }
  if (byActor.size > 0) {
    state.reactionOperations = Array.from(byActor, ([actor, operationId]) => ({ actor, operationId }))
      .sort(compareActors);
  }
  return state;
}

function withReactionOperation(
  state: MessageControlState,
  actor: string,
  operationId: string,
): MessageControlState {
  const operations = new Map(
    (state.reactionOperations || []).map((entry) => [entry.actor, entry.operationId]),
  );
  operations.set(actor, operationId);
  return {
    ...state,
    reactionOperations: Array.from(operations, ([entryActor, entryOperationId]) => ({
      actor: entryActor,
      operationId: entryOperationId,
    })).sort(compareActors),
  };
}

export function hasValidMessageControlState(message: Message): boolean {
  const raw = message.controlState;
  if (raw === undefined) return true;
  if (!isPlainObject(raw) || hasPrototypePollutionKeys(raw)) return false;
  if (!Object.keys(raw).every((key) => (
    key === 'editOperationId' || key === 'deleteOperationId' || key === 'reactionOperations'
  ))) return false;
  if (raw.editOperationId !== undefined && !isControlOperationId(raw.editOperationId)) return false;
  if (raw.deleteOperationId !== undefined && !isControlOperationId(raw.deleteOperationId)) return false;
  if (raw.reactionOperations === undefined) return true;
  if (!Array.isArray(raw.reactionOperations) || raw.reactionOperations.length > 2) return false;

  const allowedActors = participants(message);
  const seen = new Set<string>();
  for (const entry of raw.reactionOperations) {
    if (
      !isPlainObject(entry) ||
      hasPrototypePollutionKeys(entry) ||
      Object.keys(entry).sort().join(',') !== 'actor,operationId' ||
      typeof entry.actor !== 'string' ||
      !allowedActors.has(entry.actor) ||
      seen.has(entry.actor) ||
      !isControlOperationId(entry.operationId)
    ) return false;
    seen.add(entry.actor);
  }
  return true;
}

function normalizedReactions(message: Message): Record<string, string[]> {
  const allowedActors = participants(message);
  const result: Record<string, string[]> = Object.create(null);
  if (!isPlainObject(message.reactions) || hasPrototypePollutionKeys(message.reactions)) return result;

  for (const [rawEmoji, rawActors] of Object.entries(message.reactions)) {
    const emoji = sanitizeNonEmptyText(rawEmoji, MAX_LOCAL_EMOJI_LENGTH, false);
    if (!emoji || isUnsafeObjectKey(emoji) || !Array.isArray(rawActors)) continue;
    const actors = Array.from(new Set(rawActors.filter((actor): actor is string => (
      typeof actor === 'string' && allowedActors.has(actor)
    ))));
    if (actors.length > 0) result[emoji] = actors;
  }
  return result;
}

export function applyDeleteControl(
  message: Message,
  actor: string,
  operationId: string,
): MessageControlOutcome | null {
  if (message.sender !== actor || !isControlOperationId(operationId)) return null;
  const state = normalizedControlState(message);
  if (
    state.deleteOperationId &&
    compareControlOperationIds(state.deleteOperationId, operationId) >= 0
  ) return { message, changed: false };

  return {
    message: {
      ...message,
      isDeleted: true,
      content: 'This message was deleted',
      controlState: { ...state, deleteOperationId: operationId },
    },
    changed: true,
  };
}

export function applyEditControl(
  message: Message,
  actor: string,
  operationId: string,
): MessageControlOutcome | null {
  if (message.sender !== actor || !isControlOperationId(operationId)) return null;
  const state = normalizedControlState(message);
  // Deletion is irreversible. A delayed edit must never resurrect deleted text.
  if (message.isDeleted || state.deleteOperationId) return { message, changed: false };
  if (
    state.editOperationId &&
    compareControlOperationIds(state.editOperationId, operationId) >= 0
  ) return { message, changed: false };

  return {
    message: {
      ...message,
      isEdited: true,
      controlState: { ...state, editOperationId: operationId },
    },
    changed: true,
  };
}

export function applyReactionControl(
  message: Message,
  actor: string,
  operationId: string,
  emoji: string,
  isAdd: boolean,
): MessageControlOutcome | null {
  const allowedActors = participants(message);
  if (
    !allowedActors.has(actor) ||
    !isControlOperationId(operationId) ||
    !emoji ||
    isUnsafeObjectKey(emoji)
  ) return null;

  const state = normalizedControlState(message);
  const previous = state.reactionOperations?.find((entry) => entry.actor === actor)?.operationId;
  if (previous && compareControlOperationIds(previous, operationId) >= 0) {
    return { message, changed: false };
  }

  const reactions = normalizedReactions(message);
  if (isAdd) {
    for (const key of Object.keys(reactions)) {
      reactions[key] = reactions[key].filter((candidate) => candidate !== actor);
      if (reactions[key].length === 0) delete reactions[key];
    }
    const actors = reactions[emoji] ? [...reactions[emoji]] : [];
    if (!actors.includes(actor)) actors.push(actor);
    reactions[emoji] = actors;
  } else if (reactions[emoji]) {
    reactions[emoji] = reactions[emoji].filter((candidate) => candidate !== actor);
    if (reactions[emoji].length === 0) delete reactions[emoji];
  }

  return {
    message: {
      ...message,
      reactions,
      controlState: withReactionOperation(state, actor, operationId),
    },
    changed: true,
  };
}
