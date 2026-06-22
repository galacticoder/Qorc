/**
 * Message Framing and Padding
 */

import { blake3 } from '@noble/hashes/blake3.js';
import { PostQuantumRandom } from '../cryptography/random';
import { PostQuantumUtils } from '../utils/pq-utils';

// Fixed frame size
export const FrameSize = {
  SMALL: 8192,
  XLARGE: 262144
} as const;

// Frame structure
const FRAME_VERSION = 0x01;
const FRAME_HEADER_SIZE = 32;
const FRAME_MAC_SIZE = 32;

// Frame types
export enum FrameType {
  MESSAGE = 0x01,
  CHUNK_START = 0x02,
  CHUNK_CONTINUE = 0x03,
  CHUNK_END = 0x04,
  TYPING = 0x05,
  ACK = 0x06,
  DUMMY = 0x07
}

export interface PaddedFrame {
  data: Uint8Array;
  frameSize: number;
  contentLength: number;
  frameType: FrameType;
}

export interface ParsedFrame {
  valid: boolean;
  content?: Uint8Array;
  frameType?: FrameType;
  sequenceNumber?: number;
  totalChunks?: number;
  chunkIndex?: number;
  error?: string;
}

/**
 * Get maximum content size for a frame
 */
export function getMaxContentSize(frameSize: number = FrameSize.XLARGE): number {
  return frameSize - FRAME_HEADER_SIZE - FRAME_MAC_SIZE;
}

/**
 * Select appropriate frame size for content
 */
export function selectFrameSize(contentLength: number): number {
  if (contentLength <= 8128) {
    return FrameSize.SMALL;
  }
  return FrameSize.XLARGE;
}

/**
 * Generate cryptographically random padding
 */
function generatePadding(length: number): Uint8Array {
  if (length <= 0) return new Uint8Array(0);
  
  const seed = PostQuantumRandom.randomBytes(32);
  return blake3(seed, { dkLen: length });
}

/**
 * Create a padded frame from content
 */
export function createPaddedFrame(
  content: Uint8Array | string,
  options: {
    frameType?: FrameType;
    sequenceNumber?: number;
    totalChunks?: number;
    chunkIndex?: number;
    forceFrameSize?: number;
  } = {}
): PaddedFrame {
  const {
    frameType = FrameType.MESSAGE,
    sequenceNumber = 0,
    totalChunks = 1,
    chunkIndex = 0,
    forceFrameSize
  } = options;
  
  const contentBytes = typeof content === 'string' 
    ? new TextEncoder().encode(content)
    : content;
  
  const frameSize = forceFrameSize || selectFrameSize(contentBytes.length);
  const maxContent = getMaxContentSize(frameSize);
  
  if (contentBytes.length > maxContent) {
    throw new Error(`Content too large for frame: ${contentBytes.length} > ${maxContent}`);
  }
  
  // Calculate padding
  const paddingLength = maxContent - contentBytes.length;
  const padding = generatePadding(paddingLength);
  
  const header = new Uint8Array(FRAME_HEADER_SIZE);
  const headerView = new DataView(header.buffer);
  
  headerView.setUint8(0, FRAME_VERSION);
  headerView.setUint8(1, frameType);
  headerView.setUint32(2, sequenceNumber, false);
  headerView.setUint16(6, totalChunks, false);
  headerView.setUint16(8, chunkIndex, false);
  headerView.setUint32(10, contentBytes.length, false);
  headerView.setUint32(14, paddingLength, false);
  
  const nonce = PostQuantumRandom.randomBytes(FRAME_HEADER_SIZE - 18);
  header.set(nonce, 18);
  
  const frameData = new Uint8Array(frameSize - FRAME_MAC_SIZE);
  frameData.set(header, 0);
  frameData.set(contentBytes, FRAME_HEADER_SIZE);
  frameData.set(padding, FRAME_HEADER_SIZE + contentBytes.length);
  
  const mac = blake3(frameData);
  
  const frame = new Uint8Array(frameSize);
  frame.set(frameData, 0);
  frame.set(mac, frameSize - FRAME_MAC_SIZE);
  
  return {
    data: frame,
    frameSize,
    contentLength: contentBytes.length,
    frameType
  };
}

/**
 * Parse a padded frame and extract content
 */
export function parsePaddedFrame(frameData: Uint8Array): ParsedFrame {
  // Validate frame size
  if (frameData.length !== FrameSize.SMALL && frameData.length !== FrameSize.XLARGE) {
    return { valid: false, error: 'invalid_frame_size' };
  }
  
  // Extract and verify MAC
  const macStart = frameData.length - FRAME_MAC_SIZE;
  const providedMac = frameData.slice(macStart);
  const data = frameData.slice(0, macStart);
  const expectedMac = blake3(data);
  
  let macValid = true;
  for (let i = 0; i < FRAME_MAC_SIZE; i++) {
    if (providedMac[i] !== expectedMac[i]) {
      macValid = false;
    }
  }
  
  if (!macValid) {
    return { valid: false, error: 'mac_verification_failed' };
  }
  
  // Parse header
  const headerView = new DataView(data.buffer, data.byteOffset, FRAME_HEADER_SIZE);
  const version = headerView.getUint8(0);
  const frameType = headerView.getUint8(1) as FrameType;
  const sequenceNumber = headerView.getUint32(2, false);
  const totalChunks = headerView.getUint16(6, false);
  const chunkIndex = headerView.getUint16(8, false);
  const contentLength = headerView.getUint32(10, false);
  
  if (version !== FRAME_VERSION) {
    return { valid: false, error: 'unsupported_version' };
  }
  
  const content = data.slice(FRAME_HEADER_SIZE, FRAME_HEADER_SIZE + contentLength);
  
  return {
    valid: true,
    content,
    frameType,
    sequenceNumber,
    totalChunks,
    chunkIndex
  };
}

/**
 * Chunk large content into multiple frames
 */
export function chunkContent(
  content: Uint8Array | string,
  frameSize: number = FrameSize.XLARGE
): PaddedFrame[] {
  const contentBytes = typeof content === 'string'
    ? new TextEncoder().encode(content)
    : content;
  
  const maxContentPerFrame = frameSize - FRAME_HEADER_SIZE - FRAME_MAC_SIZE;
  const chunks: PaddedFrame[] = [];
  let offset = 0;
  const totalChunks = Math.ceil(contentBytes.length / maxContentPerFrame);
  const sequenceBase = Math.floor(Math.random() * 0xFFFFFFFF);
  
  while (offset < contentBytes.length) {
    const chunkContent = contentBytes.slice(offset, offset + maxContentPerFrame);
    const isFirst = offset === 0;
    const isLast = offset + maxContentPerFrame >= contentBytes.length;
    
    let frameType: FrameType;
    if (isFirst && isLast) {
      frameType = FrameType.MESSAGE;
    } else if (isFirst) {
      frameType = FrameType.CHUNK_START;
    } else if (isLast) {
      frameType = FrameType.CHUNK_END;
    } else {
      frameType = FrameType.CHUNK_CONTINUE;
    }
    
    chunks.push(createPaddedFrame(chunkContent, {
      frameType,
      sequenceNumber: sequenceBase + chunks.length,
      totalChunks,
      chunkIndex: chunks.length,
      forceFrameSize: frameSize
    }));
    
    offset += maxContentPerFrame;
  }
  
  return chunks;
}

/**
 * Reassemble chunked content
 */
export function reassembleChunks(frames: ParsedFrame[]): Uint8Array | null {
  if (frames.length === 0) return null;
  
  // Sort by sequence number
  const sorted = [...frames].sort((a, b) => 
    (a.sequenceNumber || 0) - (b.sequenceNumber || 0)
  );
  
  // Verify all chunks present
  const expectedTotal = sorted[0].totalChunks || 1;
  if (sorted.length !== expectedTotal) {
    return null;
  }
  
  // Combine contents
  const contents = sorted.map(f => f.content).filter(Boolean) as Uint8Array[];
  const totalLength = contents.reduce((sum, c) => sum + c.length, 0);
  const result = new Uint8Array(totalLength);
  
  let offset = 0;
  for (const content of contents) {
    result.set(content, offset);
    offset += content.length;
  }
  
  return result;
}

/**
 * Create a dummy frame
 */
export function createDummyFrame(frameSize: number = FrameSize.XLARGE): PaddedFrame {
  const maxContent = getMaxContentSize(frameSize);
  const contentSize = Math.floor(Math.random() * (maxContent * 0.8)) + 100;
  const dummyContent = PostQuantumRandom.randomBytes(contentSize);
  
  return createPaddedFrame(dummyContent, {
    frameType: FrameType.DUMMY,
    sequenceNumber: Math.floor(Math.random() * 0xFFFFFFFF),
    forceFrameSize: frameSize
  });
}

/**
 * Pad a JSON payload to minimum size before encryption
 */
export function padJsonPayload<T extends object>(
  payload: T,
  minSize: number = FrameSize.XLARGE
): T & { _p?: string } {
  const json = JSON.stringify(payload);
  const currentSize = new TextEncoder().encode(json).length;
  
  if (currentSize >= minSize) {
    return payload;
  }
  
  // Calculate padding needed
  const overhead = ',"_p":""'.length;
  const paddingNeeded = minSize - currentSize - overhead;
  
  if (paddingNeeded <= 0) {
    return payload;
  }
  
  // Generate random padding as base64
  const paddingBytes = PostQuantumRandom.randomBytes(Math.ceil(paddingNeeded * 0.75));
  const paddingStr = PostQuantumUtils.uint8ArrayToBase64(paddingBytes).slice(0, paddingNeeded);
  
  return {
    ...payload,
    _p: paddingStr
  };
}

/**
 * Remove padding from JSON payload after decryption
 */
export function unpadJsonPayload<T extends object>(payload: T & { _p?: string }): T {
  const { _p, ...rest } = payload;
  return rest as T;
}

export const MessageFraming = {
  FrameSize,
  FrameType,
  getMaxContentSize,
  selectFrameSize,
  createPaddedFrame,
  parsePaddedFrame,
  chunkContent,
  reassembleChunks,
  createDummyFrame,
  padJsonPayload,
  unpadJsonPayload
};
