import { safeJsonParse } from '../../lib/utils/message-handler-utils';
import { MAX_SIGNAL_PAYLOAD_JSON_BYTES } from '../../lib/constants';
import { hasPrototypePollutionKeys, isPlainObject } from '../../lib/sanitizers';

// Parse decrypted plaintext to payload
export const parseDecryptedPayload = (plaintext: string, from?: string): any => {
  const payload = safeJsonParse(plaintext, MAX_SIGNAL_PAYLOAD_JSON_BYTES);

  if (!isPlainObject(payload) || hasPrototypePollutionKeys(payload)) return null;
  if (from && payload.from !== from) return null;
  payload.encrypted = true;
  return payload;
};
