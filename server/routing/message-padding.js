/**
 * Transport Frame Constants
 */

import crypto from 'crypto';
import { blake3 } from '@noble/hashes/blake3.js';

// Fixed frame size for all messages
const FRAME_SIZE = 262144;
const FRAME_HEADER_SIZE = 64;
const FRAME_MAC_SIZE = 32;
const FRAME_PADDING_HEADER_SIZE = 4;
const DUMMY_FRAME_TYPE = 0x06;

/**
 * Generate random padding
 */
function generatePadding(length) {
  if (length <= 0) return Buffer.alloc(0);
  const seed = crypto.randomBytes(32);
  const padding = blake3(seed, { dkLen: length });
  
  return Buffer.from(padding);
}

/**
 * Create a fixed size frame
 */
export function createFrame(content, options = {}) {
  const {
    frameType = DUMMY_FRAME_TYPE,
    sequenceNumber = 0,
    segmentCount = 1,
    segmentIndex = 0,
    frameSize = FRAME_SIZE
  } = options;
  
  const contentBuffer = Buffer.isBuffer(content) 
    ? content 
    : Buffer.from(JSON.stringify(content));
  
  const maxContent = frameSize - FRAME_HEADER_SIZE - FRAME_MAC_SIZE - FRAME_PADDING_HEADER_SIZE;
  
  if (contentBuffer.length > maxContent) {
    throw new Error(`Content too large for single frame: ${contentBuffer.length} > ${maxContent}`);
  }
  
  // Calculate padding needed
  const paddingLength = maxContent - contentBuffer.length;
  const padding = generatePadding(paddingLength);
  
  // Build header
  const header = Buffer.alloc(FRAME_HEADER_SIZE);
  header.writeUInt8(0x01, 0);
  header.writeUInt8(frameType, 1);
  header.writeUInt32BE(sequenceNumber, 2);
  header.writeUInt16BE(segmentCount, 6);
  header.writeUInt16BE(segmentIndex, 8);
  header.writeUInt32BE(contentBuffer.length, 10);
  header.writeUInt32BE(paddingLength, 14);
  
  crypto.randomBytes(FRAME_HEADER_SIZE - 18).copy(header, 18);
  
  const frameData = Buffer.concat([header, contentBuffer, padding]);
  
  const mac = blake3(frameData);
  
  const frame = Buffer.concat([frameData, Buffer.from(mac)]);
  
  if (frame.length !== frameSize) {
    throw new Error(`Frame size mismatch: ${frame.length} !== ${frameSize}`);
  }
  
  return frame;
}

/**
 * Create dummy traffic frame
 */
export function createDummyFrame(frameSize = FRAME_SIZE) {
  const maxContent = frameSize - FRAME_HEADER_SIZE - FRAME_MAC_SIZE - FRAME_PADDING_HEADER_SIZE;
  const dummyContentSize = crypto.randomInt(100, maxContent);
  const dummyContent = crypto.randomBytes(dummyContentSize);
  
  return createFrame(dummyContent, {
    frameType: DUMMY_FRAME_TYPE,
    sequenceNumber: crypto.randomInt(0, 0xFFFFFFFF),
    frameSize
  });
}

/**
 * Pad a sealed envelope to minimum size
 */
export function padEnvelope(envelope, minSize = 2048) {
  const envelopeJson = JSON.stringify(envelope);
  const currentSize = Buffer.byteLength(envelopeJson, 'utf8');
  
  if (currentSize >= minSize) {
    return envelope;
  }
  
  const paddingNeeded = minSize - currentSize - 20;
  const padding = generatePadding(Math.max(0, paddingNeeded));
  
  return {
    ...envelope,
    _pad: padding.toString('base64')
  };
}

/**
 * Remove padding from envelope
 */
export function unpadEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object') {
    return envelope;
  }
  
  const { _pad, ...rest } = envelope;
  return rest;
}

export const MessagePadding = {
  FRAME_SIZE,
  createDummyFrame,
  padEnvelope,
  unpadEnvelope
};
