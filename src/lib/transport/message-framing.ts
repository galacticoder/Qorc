/**
 * Message Framing and Padding
 */

export const FrameSize = {
  STANDARD: 131072,
  XLARGE: 262144
} as const;

// Frame structure
const FRAME_VERSION = 0x02;
const MESSAGE_FRAME_HEADER_SIZE = 18;

// Frame types
enum FrameType {
  MESSAGE = 0x01
}

interface PaddedFrame {
  data: Uint8Array;
  frameSize: number;
  contentLength: number;
  frameType: FrameType;
}

interface ParsedFrame {
  valid: boolean;
  content?: Uint8Array;
  frameType?: FrameType;
  error?: string;
}

/**
 * Get maximum content size for a frame
 */
function getMaxContentSize(frameSize: number = FrameSize.STANDARD): number {
  return frameSize - MESSAGE_FRAME_HEADER_SIZE;
}

/**
 * Select appropriate frame size for content
 */
function selectFrameSize(contentLength: number): number {
  if (contentLength <= getMaxContentSize(FrameSize.STANDARD)) {
    return FrameSize.STANDARD;
  }
  return FrameSize.XLARGE;
}

/**
 * Create a padded frame from content
 */
function createPaddedFrame(
  content: Uint8Array | string,
  options: {
    forceFrameSize?: number;
  } = {}
): PaddedFrame {
  const { forceFrameSize } = options;
  const frameType = FrameType.MESSAGE;

  const ownsContentBytes = typeof content === 'string';
  const contentBytes = ownsContentBytes ? new TextEncoder().encode(content) : content;
  try {
    const frameSize = forceFrameSize ?? selectFrameSize(contentBytes.length);
    if (frameSize !== FrameSize.STANDARD && frameSize !== FrameSize.XLARGE) {
      throw new Error('Invalid frame size');
    }
    const maxContent = getMaxContentSize(frameSize);

    if (contentBytes.length > maxContent) {
      throw new Error(`Content too large for frame: ${contentBytes.length} > ${maxContent}`);
    }

    // Calculate padding
    const paddingLength = maxContent - contentBytes.length;
    const frame = new Uint8Array(frameSize);
    const headerView = new DataView(frame.buffer, frame.byteOffset, MESSAGE_FRAME_HEADER_SIZE);

    headerView.setUint8(0, FRAME_VERSION);
    headerView.setUint8(1, frameType);
    headerView.setUint32(2, 0, false);
    headerView.setUint16(6, 1, false);
    headerView.setUint16(8, 0, false);
    headerView.setUint32(10, contentBytes.length, false);
    headerView.setUint32(14, paddingLength, false);

    frame.set(contentBytes, MESSAGE_FRAME_HEADER_SIZE);

    return {
      data: frame,
      frameSize,
      contentLength: contentBytes.length,
      frameType
    };
  } finally {
    if (ownsContentBytes) contentBytes.fill(0);
  }
}

/**
 * Parse a padded frame and extract content
 */
function parsePaddedFrame(frameData: Uint8Array): ParsedFrame {
  if (frameData.length !== FrameSize.STANDARD && frameData.length !== FrameSize.XLARGE) {
    return { valid: false, error: 'invalid_frame_size' };
  }

  // Parse header
  const headerView = new DataView(frameData.buffer, frameData.byteOffset, MESSAGE_FRAME_HEADER_SIZE);
  const version = headerView.getUint8(0);
  const frameType = headerView.getUint8(1) as FrameType;
  const reserved = headerView.getUint32(2, false);
  const totalChunks = headerView.getUint16(6, false);
  const chunkIndex = headerView.getUint16(8, false);
  const contentLength = headerView.getUint32(10, false);
  const paddingLength = headerView.getUint32(14, false);
  
  if (version !== FRAME_VERSION) {
    return { valid: false, error: 'unsupported_version' };
  }
  if (frameType !== FrameType.MESSAGE) {
    return { valid: false, error: 'invalid_frame_type' };
  }
  if (reserved !== 0) {
    return { valid: false, error: 'invalid_reserved_bits' };
  }
  const maxContent = frameData.length - MESSAGE_FRAME_HEADER_SIZE;
  if (contentLength > maxContent || paddingLength > maxContent || contentLength + paddingLength !== maxContent) {
    return { valid: false, error: 'invalid_content_bounds' };
  }
  if (totalChunks < 1 || chunkIndex >= totalChunks) {
    return { valid: false, error: 'invalid_chunk_bounds' };
  }
  if (totalChunks !== 1 || chunkIndex !== 0) {
    return { valid: false, error: 'invalid_message_chunk_fields' };
  }

  const content = frameData.subarray(MESSAGE_FRAME_HEADER_SIZE, MESSAGE_FRAME_HEADER_SIZE + contentLength);
  
  return {
    valid: true,
    content,
    frameType
  };
}

export const MessageFraming = {
  FrameSize,
  FrameType,
  getMaxContentSize,
  selectFrameSize,
  createPaddedFrame,
  parsePaddedFrame
};
