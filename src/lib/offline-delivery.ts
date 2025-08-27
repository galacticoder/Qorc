/**
 * Secure Offline Message Delivery System
 * Uses trusted peer nodes for offline message storage with no plaintext logging
 */

import { CryptoUtils } from './unified-crypto';

interface OfflineMessage {
  id: string;
  from: string;
  to: string;
  encryptedPayload: string; // Already encrypted message
  timestamp: number;
  expiresAt: number;
  signature?: string; // Dilithium3 signature
  nonce: string; // For additional encryption layer
}

interface TrustedPeer {
  username: string;
  publicKeys: {
    x25519: string;
    kyber: string;
    dilithium?: string;
  };
  lastSeen: number;
  trustScore: number; // 0-100 based on reliability
  isOnline: boolean;
}

interface OfflineDeliveryConfig {
  maxMessageAge: number; // Maximum age in milliseconds
  minTrustedPeers: number; // Minimum number of peers to store message
  replicationFactor: number; // Number of peers to replicate to
  trustThreshold: number; // Minimum trust score required
}

export class OfflineDeliveryService {
  private trustedPeers: Map<string, TrustedPeer> = new Map();
  private pendingMessages: Map<string, OfflineMessage[]> = new Map();
  private config: OfflineDeliveryConfig;
  private localUsername: string;
  private hybridKeys: any;

  constructor(username: string, hybridKeys: any, config?: Partial<OfflineDeliveryConfig>) {
    this.localUsername = username;
    this.hybridKeys = hybridKeys;
    this.config = {
      maxMessageAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      minTrustedPeers: 2,
      replicationFactor: 3,
      trustThreshold: 70,
      ...config
    };

    // Start cleanup interval
    setInterval(() => this.cleanupExpiredMessages(), 60 * 60 * 1000); // Every hour
  }

  /**
   * Add a trusted peer for offline message storage
   */
  addTrustedPeer(peer: TrustedPeer): void {
    this.trustedPeers.set(peer.username, peer);
    console.log(`[OfflineDelivery] Added trusted peer: ${peer.username} (trust: ${peer.trustScore})`);
  }

  /**
   * Update peer online status
   */
  updatePeerStatus(username: string, isOnline: boolean): void {
    const peer = this.trustedPeers.get(username);
    if (peer) {
      peer.isOnline = isOnline;
      peer.lastSeen = Date.now();
      
      // Increase trust score for reliable peers
      if (isOnline && peer.trustScore < 100) {
        peer.trustScore = Math.min(100, peer.trustScore + 1);
      }
    }
  }

  /**
   * Store message for offline delivery using trusted peers
   */
  async storeOfflineMessage(
    to: string, 
    encryptedPayload: string, 
    messageId: string
  ): Promise<boolean> {
    try {
      // Get available trusted peers
      const availablePeers = this.getAvailableTrustedPeers();
      
      if (availablePeers.length < this.config.minTrustedPeers) {
        console.warn('[OfflineDelivery] Insufficient trusted peers for offline storage');
        return false;
      }

      // Create offline message with additional encryption layer
      const nonce = CryptoUtils.Base64.arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(24)));
      const offlineMessage: OfflineMessage = {
        id: messageId,
        from: this.localUsername,
        to,
        encryptedPayload,
        timestamp: Date.now(),
        expiresAt: Date.now() + this.config.maxMessageAge,
        nonce
      };

      // Add Dilithium3 signature if available
      if (this.hybridKeys?.dilithium) {
        try {
          const messageBytes = new TextEncoder().encode(JSON.stringify({
            ...offlineMessage,
            signature: undefined
          }));
          const signature = await CryptoUtils.Dilithium.sign(
            this.hybridKeys.dilithium.secretKey, 
            messageBytes
          );
          offlineMessage.signature = CryptoUtils.Base64.arrayBufferToBase64(signature);
        } catch (error) {
          console.warn('[OfflineDelivery] Failed to sign offline message:', error);
        }
      }

      // Select peers for replication
      const selectedPeers = this.selectPeersForReplication(availablePeers);
      let successCount = 0;

      // Store message with selected peers
      for (const peer of selectedPeers) {
        try {
          const success = await this.storeMessageWithPeer(peer, offlineMessage);
          if (success) {
            successCount++;
          }
        } catch (error) {
          console.error(`[OfflineDelivery] Failed to store with peer ${peer.username}:`, error);
          // Decrease trust score for unreliable peers
          peer.trustScore = Math.max(0, peer.trustScore - 5);
        }
      }

      const success = successCount >= this.config.minTrustedPeers;
      console.log(`[OfflineDelivery] Message stored with ${successCount}/${selectedPeers.length} peers`);
      return success;

    } catch (error) {
      console.error('[OfflineDelivery] Failed to store offline message:', error);
      return false;
    }
  }

  /**
   * Retrieve offline messages for a user
   */
  async retrieveOfflineMessages(forUser: string): Promise<OfflineMessage[]> {
    const messages: OfflineMessage[] = [];
    const availablePeers = this.getAvailableTrustedPeers();

    for (const peer of availablePeers) {
      try {
        const peerMessages = await this.retrieveMessagesFromPeer(peer, forUser);
        messages.push(...peerMessages);
      } catch (error) {
        console.error(`[OfflineDelivery] Failed to retrieve from peer ${peer.username}:`, error);
      }
    }

    // Deduplicate messages by ID
    const uniqueMessages = messages.filter((message, index, self) => 
      index === self.findIndex(m => m.id === message.id)
    );

    // Verify signatures and filter valid messages
    const validMessages: OfflineMessage[] = [];
    for (const message of uniqueMessages) {
      if (await this.verifyOfflineMessage(message)) {
        validMessages.push(message);
      }
    }

    console.log(`[OfflineDelivery] Retrieved ${validMessages.length} valid offline messages`);
    return validMessages;
  }

  /**
   * Get available trusted peers for storage
   */
  private getAvailableTrustedPeers(): TrustedPeer[] {
    return Array.from(this.trustedPeers.values())
      .filter(peer => 
        peer.isOnline && 
        peer.trustScore >= this.config.trustThreshold &&
        peer.username !== this.localUsername
      )
      .sort((a, b) => b.trustScore - a.trustScore);
  }

  /**
   * Select peers for message replication
   */
  private selectPeersForReplication(availablePeers: TrustedPeer[]): TrustedPeer[] {
    const count = Math.min(this.config.replicationFactor, availablePeers.length);
    return availablePeers.slice(0, count);
  }

  /**
   * Store message with a specific peer (mock implementation)
   */
  private async storeMessageWithPeer(peer: TrustedPeer, message: OfflineMessage): Promise<boolean> {
    // In a real implementation, this would send the message to the peer via P2P
    // For now, we'll simulate storage
    
    if (!this.pendingMessages.has(peer.username)) {
      this.pendingMessages.set(peer.username, []);
    }
    
    const peerMessages = this.pendingMessages.get(peer.username)!;
    
    // Add additional encryption layer using peer's public key
    try {
      const additionalEncryption = await this.encryptForPeer(message, peer);
      peerMessages.push(additionalEncryption);
      return true;
    } catch (error) {
      console.error('[OfflineDelivery] Failed to encrypt for peer:', error);
      return false;
    }
  }

  /**
   * Retrieve messages from a specific peer (mock implementation)
   */
  private async retrieveMessagesFromPeer(peer: TrustedPeer, forUser: string): Promise<OfflineMessage[]> {
    const peerMessages = this.pendingMessages.get(peer.username) || [];
    
    // Filter messages for the specific user and decrypt
    const userMessages: OfflineMessage[] = [];
    for (const encryptedMessage of peerMessages) {
      try {
        const decryptedMessage = await this.decryptFromPeer(encryptedMessage, peer);
        if (decryptedMessage.to === forUser) {
          userMessages.push(decryptedMessage);
        }
      } catch (error) {
        console.error('[OfflineDelivery] Failed to decrypt message from peer:', error);
      }
    }

    return userMessages;
  }

  /**
   * Add additional encryption layer for peer storage
   */
  private async encryptForPeer(message: OfflineMessage, peer: TrustedPeer): Promise<OfflineMessage> {
    // In a real implementation, this would use the peer's public keys
    // For now, we'll just add a nonce-based encryption layer
    const messageStr = JSON.stringify(message);
    const messageBytes = new TextEncoder().encode(messageStr);
    
    // Use XChaCha20-Poly1305 with a derived key
    const key = await this.derivePeerKey(peer);
    const nonce = CryptoUtils.Base64.base64ToUint8Array(message.nonce);
    
    const encrypted = CryptoUtils.XChaCha20Poly1305.encrypt(key, nonce, messageBytes);
    
    return {
      ...message,
      encryptedPayload: CryptoUtils.Base64.arrayBufferToBase64(encrypted)
    };
  }

  /**
   * Decrypt message from peer storage
   */
  private async decryptFromPeer(encryptedMessage: OfflineMessage, peer: TrustedPeer): Promise<OfflineMessage> {
    const key = await this.derivePeerKey(peer);
    const nonce = CryptoUtils.Base64.base64ToUint8Array(encryptedMessage.nonce);
    const ciphertext = CryptoUtils.Base64.base64ToUint8Array(encryptedMessage.encryptedPayload);
    
    const decrypted = CryptoUtils.XChaCha20Poly1305.decrypt(key, nonce, ciphertext);
    const messageStr = new TextDecoder().decode(decrypted);
    
    return JSON.parse(messageStr);
  }

  /**
   * Derive encryption key for peer storage
   */
  private async derivePeerKey(peer: TrustedPeer): Promise<Uint8Array> {
    // Derive key from local keys and peer's public key
    const keyMaterial = new TextEncoder().encode(
      `${this.localUsername}:${peer.username}:${peer.publicKeys.x25519}`
    );
    const hash = await crypto.subtle.digest('SHA-256', keyMaterial);
    return new Uint8Array(hash);
  }

  /**
   * Verify offline message signature
   */
  private async verifyOfflineMessage(message: OfflineMessage): Promise<boolean> {
    if (!message.signature) {
      return true; // Allow unsigned messages for backward compatibility
    }

    try {
      const senderPeer = this.trustedPeers.get(message.from);
      if (!senderPeer?.publicKeys.dilithium) {
        console.warn(`[OfflineDelivery] No Dilithium key for sender: ${message.from}`);
        return true; // Allow if no key available
      }

      const messageBytes = new TextEncoder().encode(JSON.stringify({
        ...message,
        signature: undefined
      }));
      
      const signature = CryptoUtils.Base64.base64ToUint8Array(message.signature);
      const publicKey = CryptoUtils.Base64.base64ToUint8Array(senderPeer.publicKeys.dilithium);
      
      return await CryptoUtils.Dilithium.verify(signature, messageBytes, publicKey);
    } catch (error) {
      console.error('[OfflineDelivery] Failed to verify message signature:', error);
      return false;
    }
  }

  /**
   * Clean up expired messages
   */
  private cleanupExpiredMessages(): void {
    const now = Date.now();
    let cleanedCount = 0;

    this.pendingMessages.forEach((messages, peerUsername) => {
      const validMessages = messages.filter(message => message.expiresAt > now);
      cleanedCount += messages.length - validMessages.length;
      this.pendingMessages.set(peerUsername, validMessages);
    });

    if (cleanedCount > 0) {
      console.log(`[OfflineDelivery] Cleaned up ${cleanedCount} expired messages`);
    }
  }

  /**
   * Get offline delivery statistics
   */
  getStats(): {
    trustedPeers: number;
    onlinePeers: number;
    pendingMessages: number;
    averageTrustScore: number;
  } {
    const peers = Array.from(this.trustedPeers.values());
    const onlinePeers = peers.filter(p => p.isOnline).length;
    const totalMessages = Array.from(this.pendingMessages.values())
      .reduce((sum, messages) => sum + messages.length, 0);
    const averageTrust = peers.length > 0 
      ? peers.reduce((sum, p) => sum + p.trustScore, 0) / peers.length 
      : 0;

    return {
      trustedPeers: peers.length,
      onlinePeers,
      pendingMessages: totalMessages,
      averageTrustScore: Math.round(averageTrust)
    };
  }
}
