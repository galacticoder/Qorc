/**
 * Outbound spool tag derivation.
 */

import { firstContactProbe } from './detection-key';

export interface OutboundTagContext {
  tag: string;
  probe: string;
}

export async function nextOutboundTag(
  _owner: string,
  peer: string,
  recipientDetectionKey?: string | null
): Promise<OutboundTagContext> {
  const derived = firstContactProbe(recipientDetectionKey);
  if (!derived) {
    throw new Error(`Spool tagging requires the detection key for ${peer}`);
  }
  return { tag: derived.tag, probe: derived.probe };
}
