import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { withRedisClient } from '../presence/presence.js';
import crypto from 'crypto';
import path from 'path';

export class LBCommandListener {
    constructor(repoRoot, onCommand) {
        this.repoRoot = repoRoot;
        this.onCommand = onCommand;
        this.commandKeypair = null;
        this.commandSubscriber = null;
        this.commandQueue = [];
        this.processingCommand = false;
    }

    // Initialize command encryption using HAProxy stats keypair
    async initEncryption() {
        try {
            const secureCreds = path.join(this.repoRoot, 'server', 'config', 'secure-credentials.js');
            const { unlockKeypair } = await import(`file://${secureCreds}`);

            const username = process.env.HAPROXY_STATS_USERNAME;
            const password = process.env.HAPROXY_STATS_PASSWORD;

            if (!username || !password) {
                throw new Error('HAProxy stats credentials not available in environment');
            }

            this.commandKeypair = await unlockKeypair(username, password);
            cryptoLogger.info('[AUTO-LB] Initialized PQ command encryption using HAProxy stats keypair');
        } catch (error) {
            cryptoLogger.error('[AUTO-LB] Failed to initialize command encryption', error);
            throw error;
        }
    }

    // Decrypt command payload
    async decryptCommand(encryptedData) {
        try {
            const { ml_kem1024 } = await import('@noble/post-quantum/ml-kem.js');
            const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
            const { x25519 } = await import('@noble/curves/ed25519.js');

            const payload = JSON.parse(encryptedData);
            if (payload.version !== 2) {
                throw new Error('Unsupported command payload version');
            }
            const encryptedPackage = payload.encrypted;

            const packageBytes = Buffer.from(JSON.stringify(encryptedPackage));
            const signatureBuffer = Buffer.from(payload.signature, 'base64');

            const isValid = ml_dsa87.verify(
                signatureBuffer,
                packageBytes,
                this.commandKeypair.dilithium.publicKey
            );

            if (!isValid) {
                throw new Error('Command signature verification failed - data may be tampered');
            }

            const kyberCiphertext = Buffer.from(encryptedPackage.kyberCiphertext, 'base64');
            const x25519EphemeralPublic = Buffer.from(encryptedPackage.x25519EphemeralPublic, 'base64');
            const nonce = Buffer.from(encryptedPackage.nonce, 'base64');
            const ciphertext = Buffer.from(encryptedPackage.ciphertext, 'base64');
            const tag = Buffer.from(encryptedPackage.tag, 'base64');
            const kyberSharedSecret = ml_kem1024.decapsulate(kyberCiphertext, this.commandKeypair.kyber.secretKey);
            const x25519SharedSecret = x25519.getSharedSecret(this.commandKeypair.x25519.secretKey, x25519EphemeralPublic);

            const rawSecret = Buffer.concat([
                Buffer.from(kyberSharedSecret),
                Buffer.from(x25519SharedSecret),
            ]);
            const info = new TextEncoder().encode('lb-command-encryption-v2');
            const aeadKey = await CryptoUtils.KDF.quantumHKDF(
                new Uint8Array(rawSecret),
                CryptoUtils.Hash.shake256(rawSecret, 64),
                info,
                32
            );

            const aead = new CryptoUtils.PostQuantumAEAD(aeadKey);
            const aad = new TextEncoder().encode('lb-command-v2');
            let plaintext;
            try {
                plaintext = aead.decrypt(ciphertext, nonce, tag, aad);
            } catch (_error) {
                throw new Error('SECURITY: Command decryption failed - invalid ciphertext');
            }

            return JSON.parse(Buffer.from(plaintext).toString('utf8'));
        } catch (error) {
            cryptoLogger.error('[AUTO-LB] Command decryption failed', error);
            throw new Error('Failed to decrypt command');
        }
    }

    // Process command queue sequentially
    async processQueue() {
        if (this.processingCommand || this.commandQueue.length === 0) {
            return;
        }

        this.processingCommand = true;

        try {
            while (this.commandQueue.length > 0) {
                const cmd = this.commandQueue.shift();

                try {
                    cryptoLogger.info('[AUTO-LB] Processing queued command', { command: cmd.cmd, queueLength: this.commandQueue.length });

                    if (this.onCommand) {
                        await this.onCommand(cmd);
                    }
                } catch (error) {
                    cryptoLogger.error('[AUTO-LB] Failed to execute command', { command: cmd.cmd, error });
                    console.error(`[COMMAND] Error executing ${cmd.cmd}:`, error.message);
                }

                if (this.commandQueue.length > 0) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }
            }
        } finally {
            this.processingCommand = false;
        }
    }

    // Setup Redis command listener
    async setup() {
        try {
            await this.initEncryption();
            await withRedisClient(async (client) => {
                this.commandSubscriber = client.duplicate();

                if (this.commandSubscriber.status !== 'ready' && this.commandSubscriber.status !== 'connecting') {
                    await this.commandSubscriber.connect();
                }

                if (this.commandSubscriber.status === 'connecting') {
                    await new Promise((resolve, reject) => {
                        const timeout = setTimeout(() => reject(new Error('Redis subscriber connection timeout')), 5000);
                        this.commandSubscriber.once('ready', () => { clearTimeout(timeout); resolve(); });
                        this.commandSubscriber.once('error', (err) => { clearTimeout(timeout); reject(err); });
                    });
                }

                await this.commandSubscriber.subscribe('lb:command:encrypted');

                this.commandSubscriber.on('message', async (channel, encryptedMessage) => {
                    if (channel !== 'lb:command:encrypted') {
                        return;
                    }

                    try {
                        if (!encryptedMessage || typeof encryptedMessage !== 'string' || encryptedMessage.trim().length === 0) {
                            cryptoLogger.debug('[AUTO-LB] Received empty or invalid message, ignoring');
                            return;
                        }

                        const cmd = await this.decryptCommand(encryptedMessage);
                        cryptoLogger.info('[AUTO-LB] Received encrypted command from TUI', { command: cmd.cmd });
                        this.commandQueue.push(cmd);

                        this.processQueue().catch((error) => {
                            cryptoLogger.error('[AUTO-LB] Command queue processing error', error);
                        });
                    } catch (error) {
                        if (encryptedMessage && encryptedMessage.trim().length > 0) {
                            cryptoLogger.error('[AUTO-LB] Failed to process encrypted command', error);
                            console.error('[COMMAND] Error processing command:', error.message);
                        }
                    }
                });

                cryptoLogger.info('[AUTO-LB] PQ-encrypted command listener setup complete');
            });
        } catch (error) {
            cryptoLogger.error('[AUTO-LB] Failed to setup command listener', error);
            console.error('[ERROR] Failed to setup command listener:', error.message);
        }
    }

    // Stop and cleanup
    async stop() {
        if (this.commandSubscriber) {
            try {
                await this.commandSubscriber.unsubscribe('lb:command:encrypted');
                await this.commandSubscriber.quit();
                console.log('\t[OK] Closed command listener');
            } catch {
            }
            this.commandSubscriber = null;
        }

        this.commandQueue = [];

        if (this.commandKeypair) {
            if (this.commandKeypair.kyber?.secretKey) {
                crypto.randomFillSync(this.commandKeypair.kyber.secretKey);
                this.commandKeypair.kyber.secretKey.fill(0);
            }
            if (this.commandKeypair.x25519?.secretKey) {
                crypto.randomFillSync(this.commandKeypair.x25519.secretKey);
                this.commandKeypair.x25519.secretKey.fill(0);
            }
            if (this.commandKeypair.dilithium?.secretKey) {
                crypto.randomFillSync(this.commandKeypair.dilithium.secretKey);
                this.commandKeypair.dilithium.secretKey.fill(0);
            }
            this.commandKeypair = null;
        }
    }
}
