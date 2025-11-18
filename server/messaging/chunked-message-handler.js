/**
 * Chunked Message Handler
 * Implements secure chunked transfer protocol to prevent DoS attacks
 * and handle large messages efficiently
 */

import { timingSafeEqual } from 'crypto';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { sendSecureMessage } from './pq-envelope-handler.js';

// Configuration constants
const CHUNK_SIZE = 64 * 1024; // 64KB chunks for optimal performance
const MAX_CHUNKS_PER_MESSAGE = 16; // Maximum 16 chunks = ~1MB max message 
const CHUNK_TIMEOUT = 30000; // 30 seconds timeout for chunk assembly
const MAX_CONCURRENT_CHUNKED_MESSAGES = 10; // Per connection
const MAX_CHUNK_BYTES = 64 * 1024; // 64KB per chunk
const MAX_TOTAL_CHUNKS = 16; // Maximum total chunks per message
const RESERVED_IDENTIFIERS = new Set(['__proto__', 'prototype', 'constructor']);
const MAX_ACTIVE_CONNECTIONS = 10_000;
const MAX_IDENTIFIER_LENGTH = 128;
const CHUNK_RATE_WINDOW_MS = 5000;
const MAX_CHUNKS_PER_WINDOW = 200;
const BASE64_PADDING_REGEX = /=+$/;

/**
 * Chunked message manager for handling large messages
 */
class ChunkedMessageManager {
  constructor() {
    this.activeChunks = new Map();
    this.verifyChunkSender = null;
    
    this.cleanupInterval = setInterval(() => {
      this.cleanupExpiredChunks();
    }, 60000);
  }

  setSenderVerifier(verifier) {
    if (verifier && typeof verifier !== 'function') {
      throw new Error('Chunk sender verifier must be a function');
    }
    this.verifyChunkSender = verifier;
  }

  /**
   * Process incoming chunk data
   */
  async processChunk(connectionId, chunkData, verifySender) {
    let normalizedConnectionId;
    try {
      normalizedConnectionId = this.normalizeConnectionId(connectionId);
      const senderVerifier = verifySender || this.verifyChunkSender;
      const { messageId, chunkIndex, totalChunks, checksum, chunkBuffer, senderId, signature } = this.parseChunkData(chunkData);

      this.enforceRateLimit(normalizedConnectionId);

      // Initialize chunked message if first chunk
      if (!this.activeChunks.has(normalizedConnectionId)) {
        if (this.activeChunks.size >= MAX_ACTIVE_CONNECTIONS) {
          throw new Error('Too many active chunked connections');
        }
        this.activeChunks.set(normalizedConnectionId, new Map());
      }

      const connectionChunks = this.activeChunks.get(normalizedConnectionId);

      const isFirstChunk = !connectionChunks.has(messageId);
      if (isFirstChunk) {
        if (!senderId || !signature) {
          throw new Error('Missing sender metadata for chunked message');
        }
        if (typeof senderVerifier === 'function') {
          const verified = await senderVerifier({ connectionId: normalizedConnectionId, messageId, senderId, chunkIndex, data: chunkBuffer, signature });
          if (!verified) {
            throw new Error('Sender verification failed for chunk');
          }
        }
      }

      // Check concurrent chunked messages limit
      if (!connectionChunks.has(messageId)) {
        if (connectionChunks.size >= MAX_CONCURRENT_CHUNKED_MESSAGES) {
          throw new Error(`Too many concurrent chunked messages (max: ${MAX_CONCURRENT_CHUNKED_MESSAGES})`);
        }

        connectionChunks.set(messageId, {
          totalChunks,
          chunks: new Map(),
          receivedChunks: 0,
          startTime: Date.now(),
          checksum: checksum,
          senderId,
          signature
        });
      }

      const message = connectionChunks.get(messageId);
      if (message.senderId && senderId && message.senderId !== senderId) {
        throw new Error('Sender mismatch for chunked message');
      }
      if (typeof senderVerifier === 'function' && senderId && signature && message.signature !== signature) {
        const verified = await senderVerifier({ connectionId: normalizedConnectionId, messageId, senderId, chunkIndex, data: chunkBuffer, signature });
        if (!verified) {
          throw new Error('Sender verification failed for chunk');
        }
        message.signature = signature;
      }
      
      // Validate message integrity
      if (message.totalChunks !== totalChunks) {
        throw new Error('Chunk count mismatch');
      }
      
      if (message.checksum !== checksum) {
        throw new Error('Checksum mismatch');
      }

      // Store chunk
      if (!message.chunks.has(chunkIndex)) {
        message.chunks.set(chunkIndex, chunkBuffer);
        message.receivedChunks++;
      } else {
        const existingChunk = message.chunks.get(chunkIndex);
        if (!this.buffersEqual(existingChunk, chunkBuffer)) {
          throw new Error('Conflicting chunk data received');
        }
      }

      // Check if all chunks received
      if (message.receivedChunks === totalChunks) {
        const assembledData = this.assembleMessage(message);
        
        // Verify final checksum
        const finalChecksum = await this.calculateChecksum(assembledData);
        if (!this.constantTimeCompare(finalChecksum, checksum)) {
          throw new Error('Final checksum verification failed');
        }

        // Zero chunk buffers after use
        for (const buffer of message.chunks.values()) {
          if (buffer?.fill) {
            buffer.fill(0);
          }
        }

        // Clean up
        connectionChunks.delete(messageId);
        if (connectionChunks.size === 0) {
          this.activeChunks.delete(normalizedConnectionId);
        }

        return {
          complete: true,
          data: assembledData,
          messageId
        };
      }

      return {
        complete: false,
        progress: message.receivedChunks / totalChunks,
        messageId
      };

    } catch (error) {
      cryptoLogger.error('Chunk processing failed', error, { connectionId, messageId: chunkData?.messageId });
      
      // Clean up failed message
      const cleanupId = normalizedConnectionId || (typeof connectionId === 'string' ? connectionId.trim() : connectionId);
      if (cleanupId && this.activeChunks.has(cleanupId)) {
        const connectionChunks = this.activeChunks.get(cleanupId);
        if (chunkData?.messageId && connectionChunks.has(chunkData.messageId)) {
          connectionChunks.delete(chunkData.messageId);
        }
        // Clean up empty connection
        if (connectionChunks.size === 0) {
          this.activeChunks.delete(cleanupId);
        }
      }
      
      throw error;
    }
  }

  /**
   * Split large message into chunks
   */
  async splitMessage(data, messageId) {
    const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const totalChunks = Math.ceil(dataBuffer.length / CHUNK_SIZE);
    
    if (totalChunks > MAX_CHUNKS_PER_MESSAGE) {
      throw new Error(`Message too large: ${dataBuffer.length} bytes (max: ${MAX_CHUNKS_PER_MESSAGE * CHUNK_SIZE})`);
    }

    const checksum = await this.calculateChecksum(dataBuffer);
    const chunks = [];

    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, dataBuffer.length);
      const chunkData = dataBuffer.slice(start, end);

      chunks.push({
        messageId,
        chunkIndex: i,
        totalChunks,
        data: chunkData.toString('base64'),
        checksum
      });
    }

    return chunks;
  }

  /**
   * Validate chunk data
   */
  parseChunkData(chunkData) {
    if (!chunkData || typeof chunkData !== 'object' || Array.isArray(chunkData)) {
      throw new Error('Invalid chunk data structure');
    }

    const { messageId, chunkIndex, totalChunks, data, checksum } = chunkData;
    const senderId = typeof chunkData.senderId === 'string' ? chunkData.senderId : null;
    const signature = typeof chunkData.signature === 'string' ? chunkData.signature : null;

    if (typeof messageId !== 'string' || messageId.length === 0 || messageId.length > MAX_IDENTIFIER_LENGTH || RESERVED_IDENTIFIERS.has(messageId)) {
      throw new Error('Invalid message identifier');
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(messageId)) {
      throw new Error('Invalid message identifier format');
    }

    if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0) {
      throw new Error('Invalid chunk index');
    }

    if (!Number.isSafeInteger(totalChunks) || totalChunks <= 0 || totalChunks > MAX_TOTAL_CHUNKS) {
      throw new Error('Invalid total chunk count');
    }

    if (chunkIndex >= totalChunks) {
      throw new Error('Chunk index out of bounds');
    }

    if (typeof data !== 'string' || data.length === 0) {
      throw new Error('Missing chunk payload');
    }

    let chunkBuffer;
    try {
      chunkBuffer = Buffer.from(data, 'base64');
      if (chunkBuffer.length === 0 && data.trim().length > 0) {
        const normalized = data.replace(BASE64_PADDING_REGEX, '');
        if (normalized.length > 0) {
          throw new Error('Invalid base64 chunk data');
        }
      }
    } catch (_error) {
      throw new Error('Invalid base64 chunk data');
    }

    if (chunkBuffer.length > MAX_CHUNK_BYTES) {
      throw new Error('Chunk exceeds maximum size');
    }

    if (typeof checksum !== 'string' || checksum.length !== 64 || !/^[0-9a-fA-F]+$/.test(checksum)) {
      throw new Error('Invalid checksum format');
    }

    if (senderId) {
      if (senderId.length === 0 || senderId.length > MAX_IDENTIFIER_LENGTH || RESERVED_IDENTIFIERS.has(senderId)) {
        throw new Error('Invalid sender identifier');
      }
      // Validate sender format (alphanumeric, hyphens, underscores only)
      if (!/^[a-zA-Z0-9_-]+$/.test(senderId)) {
        throw new Error('Invalid sender identifier format');
      }
    }

    if (signature) {
      if (signature.length === 0 || signature.length > 1024) {
        throw new Error('Invalid chunk signature length');
      }
      // Signature should be base64 or hex
      if (!/^[a-zA-Z0-9+/=_-]+$/.test(signature)) {
        throw new Error('Invalid chunk signature format');
      }
    }

    return {
      messageId,
      chunkIndex,
      totalChunks,
      checksum: checksum.toLowerCase(),
      chunkBuffer,
      senderId,
      signature
    };
  }

  /**
   * Assemble message from chunks
   */
  assembleMessage(message) {
    const chunks = [];
    for (let i = 0; i < message.totalChunks; i++) {
      if (!message.chunks.has(i)) {
        throw new Error(`Missing chunk ${i}`);
      }
      chunks.push(message.chunks.get(i));
    }
    
    return Buffer.concat(chunks);
  }

  /**
   * Calculate checksum for data
   */
  async calculateChecksum(data) {
    const hash = await CryptoUtils.Hash.blake3(data);
    return hash.toString('hex');
  }

  /**
   * Clean up expired chunks
   */
  cleanupExpiredChunks() {
    const now = Date.now();
    
    for (const [connectionId, connectionChunks] of this.activeChunks.entries()) {
      for (const [messageId, message] of connectionChunks.entries()) {
        if (now - message.startTime > CHUNK_TIMEOUT) {
          cryptoLogger.warn('Cleaning up expired chunked message', { connectionId, messageId });
          
          if (message.chunks && message.chunks.size > 0) {
            for (const buffer of message.chunks.values()) {
              if (buffer && buffer.fill && Buffer.isBuffer(buffer)) {
                buffer.fill(0);
              }
            }
            message.chunks.clear();
          }
          
          connectionChunks.delete(messageId);
        }
      }
      
      if (connectionChunks.size === 0) {
        this.activeChunks.delete(connectionId);
      }
    }
  }

  /**
   * Get active chunk count for connection
   */
  getActiveChunkCount(connectionId) {
    const connectionChunks = this.activeChunks.get(connectionId);
    return connectionChunks ? connectionChunks.size : 0;
  }

  /**
   * Clean up connection chunks
   */
  cleanupConnection(connectionId) {
    try {
      const normalized = this.normalizeConnectionId(connectionId);
      
      const connectionChunks = this.activeChunks.get(normalized);
      if (connectionChunks && connectionChunks.size > 0) {
        for (const message of connectionChunks.values()) {
          if (message.chunks && message.chunks.size > 0) {
            for (const buffer of message.chunks.values()) {
              if (buffer && buffer.fill && Buffer.isBuffer(buffer)) {
                buffer.fill(0);
              }
            }
            message.chunks.clear();
          }
        }
      }
      
      this.activeChunks.delete(normalized);
    } catch {
      const connectionChunks = this.activeChunks.get(connectionId);
      if (connectionChunks && connectionChunks.size > 0) {
        for (const message of connectionChunks.values()) {
          if (message.chunks && message.chunks.size > 0) {
            for (const buffer of message.chunks.values()) {
              if (buffer && buffer.fill && Buffer.isBuffer(buffer)) {
                buffer.fill(0);
              }
            }
            message.chunks.clear();
          }
        }
      }
      
      this.activeChunks.delete(connectionId);
    }
  }

  /**
   * Destroy manager and cleanup
   */
  destroy() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    
    for (const connectionChunks of this.activeChunks.values()) {
      if (connectionChunks && connectionChunks.size > 0) {
        for (const message of connectionChunks.values()) {
          if (message.chunks && message.chunks.size > 0) {
            for (const buffer of message.chunks.values()) {
              if (buffer && buffer.fill && Buffer.isBuffer(buffer)) {
                buffer.fill(0);
              }
            }
            message.chunks.clear();
          }
        }
      }
    }
    
    this.activeChunks.clear();
  }

  normalizeConnectionId(connectionId) {
    if (typeof connectionId !== 'string') {
      throw new Error('Invalid connection identifier');
    }
    const trimmed = connectionId.trim();
    if (!trimmed || trimmed.length > MAX_IDENTIFIER_LENGTH) {
      throw new Error('Connection identifier out of bounds');
    }
    return trimmed;
  }

  async enforceRateLimit(connectionId) {
    const key = `chunk:ratelimit:${connectionId}`;
    const now = Date.now();
    
    try {
      const { withRedisClient } = await import('../presence/presence.js');
      await withRedisClient(async (client) => {
        const windowStart = now - CHUNK_RATE_WINDOW_MS;
        
        await client.zremrangebyscore(key, 0, windowStart);
        
        const count = await client.zcard(key);
        
        if (count >= MAX_CHUNKS_PER_WINDOW) {
          throw new Error('Chunk rate limit exceeded');
        }
        
        await client.zadd(key, now, `${now}:${Math.random()}`);
        
        await client.expire(key, Math.ceil(CHUNK_RATE_WINDOW_MS / 1000) + 10);
      });
    } catch (error) {
      if (error.message === 'Chunk rate limit exceeded') {
        throw error;
      }
      cryptoLogger.warn('Redis rate limit check failed, allowing chunk', { error: error.message });
    }
  }

  buffersEqual(a, b) {
    if (!a || !b || a.length !== b.length) {
      return false;
    }
    return timingSafeEqual(a, b);
  }

  constantTimeCompare(expectedHex, providedHex) {
    try {
      const expected = Buffer.from(expectedHex, 'hex');
      const provided = Buffer.from(providedHex, 'hex');
      if (expected.length !== provided.length) {
        return false;
      }
      return timingSafeEqual(expected, provided);
    } catch {
      return false;
    }
  }
}

// Global instance
const chunkedMessageManager = new ChunkedMessageManager();

/**
 * Enhanced message size validation with chunked support
 */
export class MessageSizeValidator {
  static MAX_SINGLE_MESSAGE_SIZE = 1024 * 1024; // 1MB for single messages
  static MAX_CHUNKED_MESSAGE_SIZE = 1024 * 1024; // 1MB for chunked messages 
  static CHUNK_SIZE = CHUNK_SIZE;

  /**
   * Check if message needs chunking
   */
  static needsChunking(data) {
    const size = Buffer.isBuffer(data) ? data.length : Buffer.byteLength(data);
    return size > this.MAX_SINGLE_MESSAGE_SIZE;
  }

  /**
   * Validate message size
   */
  static validateSize(data, allowChunked = true) {
    const size = Buffer.isBuffer(data) ? data.length : Buffer.byteLength(data);
    
    if (size <= this.MAX_SINGLE_MESSAGE_SIZE) {
      return { valid: true, needsChunking: false };
    }
    
    if (allowChunked && size <= this.MAX_CHUNKED_MESSAGE_SIZE) {
      return { valid: true, needsChunking: true };
    }
    
    return { 
      valid: false, 
      error: `Message too large: ${size} bytes (max: ${allowChunked ? this.MAX_CHUNKED_MESSAGE_SIZE : this.MAX_SINGLE_MESSAGE_SIZE})` 
    };
  }
}

Object.defineProperty(MessageSizeValidator, 'MAX_SINGLE_MESSAGE_SIZE', {
  writable: false,
  configurable: false
});

Object.defineProperty(MessageSizeValidator, 'MAX_CHUNKED_MESSAGE_SIZE', {
  writable: false,
  configurable: false
});

Object.defineProperty(MessageSizeValidator, 'CHUNK_SIZE', {
  writable: false,
  configurable: false
});

/**
 * Process incoming WebSocket message with chunked support
 */
export async function processWebSocketMessage(connectionId, rawMessage, options = {}) {
  try {
    if (!connectionId || typeof connectionId !== 'string' || connectionId.length === 0 || connectionId.length > MAX_IDENTIFIER_LENGTH) {
      throw new Error('Invalid connection identifier');
    }

    if (typeof rawMessage !== 'string') {
      throw new Error('Invalid message format: expected string');
    }

    const rawSize = Buffer.byteLength(rawMessage);
    if (rawSize > MessageSizeValidator.MAX_CHUNKED_MESSAGE_SIZE) {
      throw new Error(`Message too large: ${rawSize} bytes (max: ${MessageSizeValidator.MAX_CHUNKED_MESSAGE_SIZE})`);
    }

    let message;
    try {
      message = JSON.parse(rawMessage);
    } catch (_error) {
      throw new Error('Invalid message format: JSON parsing failed');
    }

    if (!message || typeof message !== 'object' || Array.isArray(message)) {
      throw new Error('Invalid message structure: expected object');
    }

    if (typeof message.type !== 'string' || message.type.length === 0 || message.type.length > 64) {
      throw new Error('Invalid or missing message type');
    }

    // Check if this is a chunked message
    if (message.type === 'chunked' && message.chunkData) {
      const result = await chunkedMessageManager.processChunk(connectionId, message.chunkData, options.verifySender);
      
      if (result.complete) {
        return {
          type: 'complete',
          data: result.data,
          messageId: result.messageId
        };
      } else {
        return {
          type: 'chunk_progress',
          progress: result.progress,
          messageId: result.messageId
        };
      }
    }

    // Regular message processing
    const sizeValidation = MessageSizeValidator.validateSize(rawMessage, false);
    if (!sizeValidation.valid) {
      throw new Error(sizeValidation.error);
    }

    return {
      type: 'complete',
      data: message,
      messageId: null
    };

  } catch (error) {
    console.error('[CHUNKED] Error processing WebSocket message:', error);
    throw error;
  }
}

/**
 * Send large message with chunked support
 */
export async function sendLargeMessage(ws, data, messageId) {
  const sizeValidation = MessageSizeValidator.validateSize(data, true);
  
  if (!sizeValidation.valid) {
    throw new Error(sizeValidation.error);
  }

  if (sizeValidation.needsChunking) {
    const chunks = await chunkedMessageManager.splitMessage(data, messageId);
    
    for (const chunk of chunks) {
      const chunkMessage = {
        type: 'chunked',
        chunkData: chunk
      };
      
      await sendSecureMessage(ws, chunkMessage);
    }
    
    return {
      chunked: true,
      chunkCount: chunks.length
    };
  } else {
    try {
      const parsed = typeof data === 'string' ? JSON.parse(data) : data;
      await sendSecureMessage(ws, parsed);
    } catch {
      await sendSecureMessage(ws, { type: 'raw', data });
    }
    return {
      chunked: false,
      chunkCount: 1
    };
  }
}

/**
 * Clean up connection chunks
 */
export function cleanupConnection(connectionId) {
  chunkedMessageManager.cleanupConnection(connectionId);
}

/**
 * Get connection chunk status
 */
export function getConnectionChunkStatus(connectionId) {
  return {
    activeChunks: chunkedMessageManager.getActiveChunkCount(connectionId),
    maxConcurrent: MAX_CONCURRENT_CHUNKED_MESSAGES
  };
}

export { chunkedMessageManager };
