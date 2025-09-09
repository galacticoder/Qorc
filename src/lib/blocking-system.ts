// Note: Using native Web Crypto API instead of custom CryptoUtils for maximum compatibility

/**
 * Secure Blocking System - Client-side implementation
 * Maintains end-to-end encryption and privacy while preventing unwanted communication
 */

export interface BlockedUser {
  username: string;
  blockedAt: number;
}

export interface EncryptedBlockList {
  version: number;
  encryptedData: string;
  integrity: string;
  salt: string;
  lastUpdated: number;
}

export interface BlockToken {
  tokenHash: string;
  blockerHash: string;
  blockedHash: string;
  expiresAt?: number;
}

export class BlockingSystem {
  private static instance: BlockingSystem | null = null;
  private cachedBlockList: BlockedUser[] | null = null;
  private lastSyncTime: number = 0;

  static getInstance(): BlockingSystem {
    if (!BlockingSystem.instance) {
      BlockingSystem.instance = new BlockingSystem();
    }
    return BlockingSystem.instance;
  }

  /**
   * Generate cryptographic hash for a username
   * Used for privacy-preserving server-side filtering
   */
  private async generateUserHash(username: string): Promise<string> {
    const encoder = new TextEncoder();
    const usernameBytes = encoder.encode(username);
    const saltBytes = encoder.encode('user_hash_v1');
    
    // Concatenate username and salt
    const combined = new Uint8Array(usernameBytes.length + saltBytes.length);
    combined.set(usernameBytes, 0);
    combined.set(saltBytes, usernameBytes.length);
    
    // Use SubtleCrypto for SHA-512
    const hashBuffer = await crypto.subtle.digest('SHA-512', combined);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Generate block token for server-side filtering
   * Token allows server to filter without knowing actual usernames
   */
  private async generateBlockToken(blockerUsername: string, blockedUsername: string): Promise<BlockToken> {
    const blockerHash = await this.generateUserHash(blockerUsername);
    const blockedHash = await this.generateUserHash(blockedUsername);
    
    const encoder = new TextEncoder();
    const combined = new Uint8Array(
      blockerHash.length / 2 + blockedHash.length / 2 + 'block_token_v1'.length
    );
    
    // Convert hex strings to bytes
    const blockerBytes = new Uint8Array(blockerHash.match(/.{2}/g)!.map(byte => parseInt(byte, 16)));
    const blockedBytes = new Uint8Array(blockedHash.match(/.{2}/g)!.map(byte => parseInt(byte, 16)));
    const saltBytes = encoder.encode('block_token_v1');
    
    combined.set(blockerBytes, 0);
    combined.set(blockedBytes, blockerBytes.length);
    combined.set(saltBytes, blockerBytes.length + blockedBytes.length);
    
    const tokenBuffer = await crypto.subtle.digest('SHA-512', combined);
    const tokenArray = Array.from(new Uint8Array(tokenBuffer));
    const tokenHash = tokenArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 64);
    
    return {
      tokenHash,
      blockerHash,
      blockedHash
    };
  }

  /**
   * Encrypt block list using passphrase-derived key
   */
  private async encryptBlockList(
    blockList: BlockedUser[], 
    passphrase: string
  ): Promise<EncryptedBlockList> {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    
    // Derive encryption key from passphrase using PBKDF2
    const passphraseKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(passphrase),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );
    
    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: 600000, // Strong iteration count
        hash: 'SHA-512'
      },
      passphraseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    
    // Encrypt the block list
    const plaintext = encoder.encode(JSON.stringify(blockList));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      derivedKey,
      plaintext
    );
    
    // Create integrity hash
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);
    
    const integrityHash = await crypto.subtle.digest('SHA-512', combined);
    const integrityArray = Array.from(new Uint8Array(integrityHash));
    const integrity = integrityArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    // Encode encrypted data
    const encryptedDataArray = new Uint8Array(iv.length + ciphertext.byteLength);
    encryptedDataArray.set(iv, 0);
    encryptedDataArray.set(new Uint8Array(ciphertext), iv.length);
    
    return {
      version: 1,
      encryptedData: btoa(String.fromCharCode(...encryptedDataArray)),
      integrity,
      salt: btoa(String.fromCharCode(...salt)),
      lastUpdated: Date.now()
    };
  }

  /**
   * Decrypt block list using passphrase-derived key
   */
  private async decryptBlockList(
    encryptedBlockList: EncryptedBlockList,
    passphrase: string
  ): Promise<BlockedUser[]> {
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    
    // Decode the data
    const encryptedData = Uint8Array.from(atob(encryptedBlockList.encryptedData), c => c.charCodeAt(0));
    const salt = Uint8Array.from(atob(encryptedBlockList.salt), c => c.charCodeAt(0));
    
    // Extract IV and ciphertext
    const iv = encryptedData.slice(0, 12);
    const ciphertext = encryptedData.slice(12);
    
    // Verify integrity
    const integrityHash = await crypto.subtle.digest('SHA-512', encryptedData);
    const integrityArray = Array.from(new Uint8Array(integrityHash));
    const calculatedIntegrity = integrityArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    if (calculatedIntegrity !== encryptedBlockList.integrity) {
      throw new Error('Block list integrity verification failed');
    }
    
    // Derive decryption key
    const passphraseKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(passphrase),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );
    
    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: 600000,
        hash: 'SHA-512'
      },
      passphraseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    
    // Decrypt
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      derivedKey,
      ciphertext
    );
    
    const decryptedText = decoder.decode(plaintext);
    return JSON.parse(decryptedText);
  }

  /**
   * Load block list from local storage
   */
  async loadBlockList(passphrase: string): Promise<BlockedUser[]> {
    try {
      const stored = localStorage.getItem('encrypted_block_list');
      if (!stored) {
        this.cachedBlockList = [];
        return [];
      }
      
      const encryptedBlockList = JSON.parse(stored) as EncryptedBlockList;
      const blockList = await this.decryptBlockList(encryptedBlockList, passphrase);
      
      this.cachedBlockList = blockList;
      return blockList;
    } catch (error) {
      console.error('[BLOCKING] Error loading block list:', error);
      // Re-throw error to allow proper error handling
      throw new Error('Invalid passphrase or corrupted block list');
    }
  }

  /**
   * Save block list to local storage
   */
  async saveBlockList(blockList: BlockedUser[], passphrase: string): Promise<void> {
    try {
      const encrypted = await this.encryptBlockList(blockList, passphrase);
      localStorage.setItem('encrypted_block_list', JSON.stringify(encrypted));
      this.cachedBlockList = blockList;
      
      // Also generate and store block tokens for server-side filtering
      await this.updateBlockTokens(blockList);
    } catch (error) {
      console.error('[BLOCKING] Error saving block list:', error);
      throw error;
    }
  }

  /**
   * Generate and send block tokens to server for filtering
   */
  private async updateBlockTokens(blockList: BlockedUser[]): Promise<void> {
    try {
      const currentUser = localStorage.getItem('last_authenticated_username') || localStorage.getItem('authenticated_username');
      if (!currentUser) return;
      
      const tokens: BlockToken[] = [];
      
      for (const blockedUser of blockList) {
        const token = await this.generateBlockToken(currentUser, blockedUser.username);
        tokens.push(token);
      }
      
      // Send tokens to server via global WebSocket connection
      this.sendToServer({
        type: 'block-tokens-update',
        blockTokens: tokens
      });
      
      console.log(`[BLOCKING] Updated ${tokens.length} block tokens on server`);
    } catch (error) {
      console.error('[BLOCKING] Error updating block tokens:', error);
    }
  }
  
  /**
   * Send message to server via WebSocket
   */
  private sendToServer(message: any): void {
    try {
      // Use the same edgeApi interface as the main WebSocket client
      const edgeApi = (window as any).edgeApi as { wsSend?: (message: string) => void };
      
      if (edgeApi?.wsSend) {
        console.log(`[BLOCKING] Sending block tokens update to server`);
        edgeApi.wsSend(JSON.stringify(message));
      } else {
        console.warn('[BLOCKING] edgeApi.wsSend not available, queuing message for later');
        // Queue message for when connection is available
        this.queuedMessages.push(message);
      }
    } catch (error) {
      console.error('[BLOCKING] Error sending message to server:', error);
      // Queue message on error
      this.queuedMessages.push(message);
    }
  }
  
  private queuedMessages: any[] = [];
  
  /**
   * Process queued messages when WebSocket connection becomes available
   */
  processQueuedMessages(): void {
    if (this.queuedMessages.length === 0) return;
    
    console.log(`[BLOCKING] Processing ${this.queuedMessages.length} queued messages`);
    
    while (this.queuedMessages.length > 0) {
      const message = this.queuedMessages.shift();
      this.sendToServer(message);
    }
  }

  /**
   * Block a user
   */
  async blockUser(username: string, passphrase: string): Promise<void> {
    const blockList = await this.loadBlockList(passphrase);
    
    // Check if user is already blocked
    if (blockList.some(user => user.username === username)) {
      return; // Already blocked
    }
    
    // Add to block list
    blockList.push({
      username,
      blockedAt: Date.now()
    });
    
    await this.saveBlockList(blockList, passphrase);
    console.log(`[BLOCKING] User blocked: ${username}`);
  }

  /**
   * Unblock a user
   */
  async unblockUser(username: string, passphrase: string): Promise<void> {
    const blockList = await this.loadBlockList(passphrase);
    const filteredList = blockList.filter(user => user.username !== username);
    
    if (filteredList.length !== blockList.length) {
      await this.saveBlockList(filteredList, passphrase);
      console.log(`[BLOCKING] User unblocked: ${username}`);
    }
  }

  /**
   * Check if a user is blocked
   */
  async isUserBlocked(username: string, passphrase: string): Promise<boolean> {
    const blockList = await this.loadBlockList(passphrase);
    return blockList.some(user => user.username === username);
  }

  /**
   * Get list of blocked users
   */
  async getBlockedUsers(passphrase: string): Promise<BlockedUser[]> {
    return await this.loadBlockList(passphrase);
  }

  /**
   * Filter incoming messages from blocked users
   */
  async filterIncomingMessage(message: any, passphrase: string): Promise<boolean> {
    if (!message.sender) return true; // Allow messages without sender (system messages)
    
    const isBlocked = await this.isUserBlocked(message.sender, passphrase);
    if (isBlocked) {
      console.log(`[BLOCKING] Filtered incoming message from blocked user: ${message.sender}`);
      return false;
    }
    
    return true;
  }

  /**
   * Check if outgoing message should be allowed
   */
  async canSendMessage(recipientUsername: string, passphrase: string): Promise<boolean> {
    try {
      // Check if we have blocked the recipient
      const isBlocked = await this.isUserBlocked(recipientUsername, passphrase);
      if (isBlocked) {
        console.log(`[BLOCKING] Prevented outgoing message to blocked user: ${recipientUsername}`);
        return false;
      }
      
      // Allow message to proceed (server will handle reverse blocking)
      return true;
    } catch (error) {
      console.error('[BLOCKING] Error checking message permission:', error);
      return true; // Allow by default on error
    }
  }
  
  /**
   * Filter outgoing message before sending to server
   * Returns null if message should be blocked, or the message if allowed
   */
  async filterOutgoingMessage(message: any, passphrase: string): Promise<any | null> {
    try {
      if (!message.recipient && !message.to) {
        return message; // Allow messages without recipient (system messages)
      }
      
      const recipient = message.recipient || message.to;
      const canSend = await this.canSendMessage(recipient, passphrase);
      
      if (!canSend) {
        // Show user feedback that message was blocked
        this.showBlockedMessageNotification(recipient, 'outgoing');
        return null;
      }
      
      return message;
    } catch (error) {
      console.error('[BLOCKING] Error filtering outgoing message:', error);
      return message; // Allow by default on error
    }
  }
  
  /**
   * Show notification when a message is blocked
   */
  private showBlockedMessageNotification(username: string, direction: 'incoming' | 'outgoing'): void {
    const message = direction === 'outgoing' 
      ? `Cannot send message to ${username} - they are blocked`
      : `Blocked message from ${username}`;
    
    // Create a subtle notification
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification('Message Blocked', {
        body: message,
        icon: '/favicon.ico',
        tag: 'blocked-message',
        silent: true
      });
    } else {
      // Fallback to console log
      console.log(`[BLOCKING] ${message}`);
    }
    
    // Dispatch custom event for UI components to handle
    window.dispatchEvent(new CustomEvent('blocked-message', {
      detail: { username, direction, message }
    }));
  }

  /**
   * Sync block list with server
   */
  async syncWithServer(passphrase: string): Promise<void> {
    try {
      console.log('[BLOCKING] Starting block list sync with server');
      
      // Get current local block list
      const localBlockList = await this.loadBlockList(passphrase);
      const encrypted = await this.encryptBlockList(localBlockList, passphrase);
      
      // Send to server for storage
      this.sendToServer({
        type: 'block-list-sync',
        encryptedBlockList: encrypted.encryptedData,
        blockListHash: encrypted.integrity,
        salt: encrypted.salt,
        version: encrypted.version,
        lastUpdated: encrypted.lastUpdated
      });
      
      // Update block tokens
      await this.updateBlockTokens(localBlockList);
      
      console.log('[BLOCKING] Block list sync completed');
    } catch (error) {
      console.error('[BLOCKING] Error syncing with server:', error);
      throw error;
    }
  }
  
  /**
   * Download and restore block list from server
   */
  async downloadFromServer(passphrase: string): Promise<void> {
    try {
      console.log('[BLOCKING] Requesting block list from server');
      
      // Request current block list from server
      this.sendToServer({
        type: 'block-list-update'
      });
      
      // Listen for response (handled elsewhere in the app)
    } catch (error) {
      console.error('[BLOCKING] Error downloading from server:', error);
      throw error;
    }
  }
  
  /**
   * Handle block list data received from server
   */
  async handleServerBlockListData(
    encryptedData: string | null, 
    integrity: string | null, 
    salt: string | null,
    lastUpdated: number | null,
    version: number,
    passphrase: string
  ): Promise<void> {
    try {
      if (!encryptedData || !integrity || !salt) {
        console.log('[BLOCKING] No block list on server or missing data, using local copy');
        return;
      }
      
      // Check if server version is newer
      const localStored = localStorage.getItem('encrypted_block_list');
      if (localStored) {
        const localData = JSON.parse(localStored);
        if (localData.lastUpdated >= (lastUpdated || 0)) {
          console.log('[BLOCKING] Local block list is up to date');
          return;
        }
      }
      
      // Decrypt and apply server block list
      const serverBlockList: EncryptedBlockList = {
        version,
        encryptedData,
        integrity,
        salt: salt,
        lastUpdated: lastUpdated || Date.now()
      };
      
      // This will validate integrity and decrypt
      const blockList = await this.decryptBlockList(serverBlockList, passphrase);
      
      // Save locally
      await this.saveBlockList(blockList, passphrase);
      
      console.log(`[BLOCKING] Downloaded and applied block list from server (${blockList.length} users)`);
    } catch (error) {
      console.error('[BLOCKING] Error handling server block list data:', error);
      throw error;
    }
  }

  /**
   * Clear cached block list
   */
  clearCache(): void {
    this.cachedBlockList = null;
    this.lastSyncTime = 0;
  }
}

export const blockingSystem = BlockingSystem.getInstance();
