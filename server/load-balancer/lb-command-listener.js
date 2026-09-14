import { CryptoUtils } from '../crypto/unified-crypto.js';
import { deriveQuantumAeadKey } from '../crypto/aead-key-derivation.js';
import { withRedisClient } from '../session/redis-client.js';
import path from 'path';
import { UTF8_ENCODER } from '../utils/encoding.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import { REDIS_KEYS } from '../config/redis-keys.js';
import { canonicalBase64Shape } from '../../shared/canonical-base64.js';
import {
  ML_DSA_87_SIGNATURE_BYTES,
  ML_KEM_1024_CIPHERTEXT_BYTES,
  HASH_OUTPUT_BYTES,
  POST_QUANTUM_AEAD_NONCE_BYTES,
  X25519_KEY_BYTES,
} from '../../shared/crypto-sizes.js';
import { hasExactPlainObjectKeys } from '../utils/validation.js';
import { wipeByteArrays } from '../utils/wipe.js';
import { UUID_V4_RE } from '../../shared/patterns.js';

const COMMAND_WIRE_MAX_CHARS = 32 * 1024;
const COMMAND_CIPHERTEXT_MAX_BYTES = 1024;
const COMMAND_MAX_CLOCK_SKEW_MS = 30_000;
const COMMAND_REPLAY_TTL_MS = 60_000;
const COMMAND_QUEUE_MAX = 16;
const COMMAND_VERIFY_MAX_INFLIGHT = 2;
const COMMAND_ALGORITHM = 'ML-KEM-1024 + X25519 + PostQuantumAEAD + ML-DSA-87';

function wipeCommandKeypair(keypair) {
    for (const family of Object.values(keypair || {})) {
        wipeByteArrays([family?.publicKey, family?.secretKey]);
    }
}

export class LBCommandListener {
    constructor(repoRoot, onCommand) {
        this.repoRoot = repoRoot;
        this.onCommand = onCommand;
        this.commandKeypair = null;
        this.commandSubscriber = null;
        this.commandQueue = [];
        this.processingCommand = false;
        this.commandVerificationsInflight = 0;
        this.commandQueueReservations = 0;
        this.commandGeneration = 0;
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

            const previousKeypair = this.commandKeypair;
            this.commandKeypair = await unlockKeypair(username, password);
            wipeCommandKeypair(previousKeypair);
            console.log('[AUTO-LB] Initialized PQ command encryption using HAProxy stats keypair');
        } catch (error) {
            console.error('[AUTO-LB] Failed to initialize command encryption', error);
            throw error;
        }
    }

    // Decrypt command payload
    async decryptCommand(encryptedData) {
        const temporaryBytes = [];
        try {
            const { ml_kem1024 } = await import('@noble/post-quantum/ml-kem.js');
            const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
            const { x25519 } = await import('@noble/curves/ed25519.js');

            const payload = JSON.parse(encryptedData);
            if (
                !hasExactPlainObjectKeys(payload, ['algorithm', 'encrypted', 'signature', 'version']) ||
                payload.version !== 2 ||
                payload.algorithm !== COMMAND_ALGORITHM ||
                !hasExactPlainObjectKeys(payload.encrypted, [
                    'ciphertext', 'kyberCiphertext', 'nonce', 'tag', 'x25519EphemeralPublic'
                ]) ||
                !canonicalBase64Shape(payload.signature, { exactBytes: ML_DSA_87_SIGNATURE_BYTES }) ||
                !canonicalBase64Shape(payload.encrypted.kyberCiphertext, { exactBytes: ML_KEM_1024_CIPHERTEXT_BYTES }) ||
                !canonicalBase64Shape(payload.encrypted.x25519EphemeralPublic, { exactBytes: X25519_KEY_BYTES }) ||
                !canonicalBase64Shape(payload.encrypted.nonce, { exactBytes: POST_QUANTUM_AEAD_NONCE_BYTES }) ||
                !canonicalBase64Shape(payload.encrypted.tag, { exactBytes: HASH_OUTPUT_BYTES }) ||
                !canonicalBase64Shape(payload.encrypted.ciphertext, { maxBytes: COMMAND_CIPHERTEXT_MAX_BYTES })
            ) {
                throw new Error('Unsupported command payload version');
            }
            const encryptedPackage = payload.encrypted;

            const packageBytes = Buffer.from(JSON.stringify(encryptedPackage));
            const signatureBuffer = Buffer.from(payload.signature, 'base64');
            temporaryBytes.push(packageBytes, signatureBuffer);

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
            temporaryBytes.push(
                kyberCiphertext,
                x25519EphemeralPublic,
                nonce,
                ciphertext,
                tag
            );
            const kyberSharedSecret = ml_kem1024.decapsulate(kyberCiphertext, this.commandKeypair.kyber.secretKey);
            const x25519SharedSecret = x25519.getSharedSecret(this.commandKeypair.x25519.secretKey, x25519EphemeralPublic);
            temporaryBytes.push(kyberSharedSecret, x25519SharedSecret);

            const rawSecret = Buffer.concat([
                Buffer.from(kyberSharedSecret),
                Buffer.from(x25519SharedSecret),
            ]);
            const aeadKey = await deriveQuantumAeadKey(rawSecret, PROTOCOL_KEYS.LB_COMMAND_ENCRYPTION);
            temporaryBytes.push(rawSecret, aeadKey);

            const aead = new CryptoUtils.PostQuantumAEAD(aeadKey);
            const aad = UTF8_ENCODER.encode(PROTOCOL_KEYS.LB_COMMAND_AAD);
            let plaintext;
            try {
                plaintext = aead.decrypt(ciphertext, nonce, tag, aad);
                temporaryBytes.push(plaintext);
            } catch (_error) {
                throw new Error('SECURITY: Command decryption failed');
            }

            const command = JSON.parse(Buffer.from(plaintext).toString('utf8'));
            if (
                !hasExactPlainObjectKeys(command, ['cmd', 'commandId', 'issuedAt']) ||
                command.cmd !== 'reload' ||
                !UUID_V4_RE.test(command.commandId) ||
                !Number.isSafeInteger(command.issuedAt) ||
                Math.abs(Date.now() - command.issuedAt) > COMMAND_MAX_CLOCK_SKEW_MS
            ) throw new Error('Invalid or expired load-balancer command');
            return command;
        } catch (error) {
            console.error('[AUTO-LB] Command decryption failed', error);
            throw new Error('Failed to decrypt command');
        } finally {
            wipeByteArrays(temporaryBytes);
        }
    }

    async claimCommand(commandId) {
        return await withRedisClient(async (client) => {
            const result = await client.set(
                `${REDIS_KEYS.LB_COMMAND_REPLAY_PREFIX}${commandId}`,
                '1',
                'PX',
                COMMAND_REPLAY_TTL_MS,
                'NX'
            );
            return result === 'OK';
        });
    }

    async acceptEncryptedCommand(encryptedMessage, generation = this.commandGeneration) {
        if (
            !encryptedMessage ||
            typeof encryptedMessage !== 'string' ||
            encryptedMessage.trim().length === 0 ||
            encryptedMessage.length > COMMAND_WIRE_MAX_CHARS ||
            generation !== this.commandGeneration ||
            this.commandVerificationsInflight >= COMMAND_VERIFY_MAX_INFLIGHT ||
            this.commandQueue.length + this.commandQueueReservations >= COMMAND_QUEUE_MAX
        ) {
            return false;
        }

        this.commandVerificationsInflight += 1;
        this.commandQueueReservations += 1;
        try {
            const cmd = await this.decryptCommand(encryptedMessage);
            if (generation !== this.commandGeneration) return false;

            if (!await this.claimCommand(cmd.commandId)) return false;
            if (generation !== this.commandGeneration) return false;

            console.log('[AUTO-LB] Received encrypted command from TUI', { command: cmd.cmd });
            this.commandQueue.push(cmd);
            this.processQueue().catch((error) => {
                console.error('[AUTO-LB] Command queue processing error', error);
            });
            return true;
        } finally {
            this.commandVerificationsInflight = Math.max(0, this.commandVerificationsInflight - 1);
            this.commandQueueReservations = Math.max(0, this.commandQueueReservations - 1);
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
                    console.log('[AUTO-LB] Processing queued command', { command: cmd.cmd, queueLength: this.commandQueue.length });

                    if (this.onCommand) {
                        await this.onCommand(cmd);
                    }
                } catch (error) {
                    console.error('[AUTO-LB] Failed to execute command', { command: cmd.cmd, error });
                    console.error(`[COMMAND] Error executing ${cmd.cmd}:`, error.message);
                }

                if (this.commandQueue.length > 0) {
                    await new Promise((resolve) => setTimeout(resolve, 100));
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

                await this.commandSubscriber.subscribe(REDIS_KEYS.LB_ENCRYPTED_COMMAND_CHANNEL);
                const generation = this.commandGeneration;

                this.commandSubscriber.on('message', async (channel, encryptedMessage) => {
                    if (channel !== REDIS_KEYS.LB_ENCRYPTED_COMMAND_CHANNEL) {
                        return;
                    }

                    try {
                        await this.acceptEncryptedCommand(encryptedMessage, generation);
                    } catch (error) {
                        if (encryptedMessage && encryptedMessage.trim().length > 0) {
                            console.error('[AUTO-LB] Failed to process encrypted command', error);
                            console.error('[COMMAND] Error processing command:', error.message);
                        }
                    }
                });

                console.log('[AUTO-LB] PQ-encrypted command listener setup complete');
            });
        } catch (error) {
            console.error('[AUTO-LB] Failed to setup command listener', error);
            console.error('[ERROR] Failed to setup command listener:', error.message);
            throw error;
        }
    }

    // Stop and cleanup
    async stop() {
        this.commandGeneration += 1;
        if (this.commandSubscriber) {
            try {
                await this.commandSubscriber.unsubscribe(REDIS_KEYS.LB_ENCRYPTED_COMMAND_CHANNEL);
                await this.commandSubscriber.quit();
                console.log('\t[OK] Closed command listener');
            } catch {
            }
            this.commandSubscriber = null;
        }

        this.commandQueue = [];
        this.commandQueueReservations = 0;

        wipeCommandKeypair(this.commandKeypair);
        this.commandKeypair = null;
    }
}
