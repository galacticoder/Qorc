/**
 * Active send destination selector policy
 *
 * Blind-route messages are accepted only as opaque sealed envelopes
 */

export const FORBIDDEN_ACTIVE_SEND_SELECTOR_FIELDS = Object.freeze([
  'bucket',
  'bucketId',
  'destination',
  'destinationBucket',
  'destinationBucketId',
  'destinationInbox',
  'destinationInboxId',
  'destinationMailboxLookupId',
  'destinationRouteId',
  'handle',
  'inbox',
  'inboxId',
  'index',
  'lookupId',
  'mailbox',
  'mailboxLookupId',
  'messageId',
  'recipient',
  'recipientHandle',
  'recipientId',
  'recipientInbox',
  'recipientInboxId',
  'recipientRouteId',
  'recipientUsername',
  'route',
  'routeId',
  'shard',
  'shardId',
  'to',
  'username'
]);

const FORBIDDEN_FIELD_SET = new Set(FORBIDDEN_ACTIVE_SEND_SELECTOR_FIELDS);

export function findForbiddenActiveSendSelectors(message) {
  if (!message || typeof message !== 'object') {
    return [];
  }

  return Object.keys(message)
    .filter((key) => FORBIDDEN_FIELD_SET.has(key))
    .sort();
}

export function validateBlindRouteSelectorPolicy(message) {
  const fields = findForbiddenActiveSendSelectors(message);
  if (fields.length > 0) {
    return {
      valid: false,
      error: 'destination_selector_forbidden',
      fields
    };
  }

  return { valid: true, fields: [] };
}
