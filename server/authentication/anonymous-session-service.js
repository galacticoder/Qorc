/**
 * Anonymous Session Service
 * 
 * Provides anonymous session tokens that cant be linked back to user identities
 */

import crypto from 'crypto';
import { blake3 } from '@noble/hashes/blake3.js';
import { shake256 } from '@noble/hashes/sha3.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { withRedisClient } from '../session/redis-client.js';

// Configuration for session tokens
const SESSION_CONFIG = {
    // Token entropy
    TOKEN_ENTROPY_BYTES: 32,
    SESSION_NONCE_BYTES: 24,

    // 1 week auto expiry
    SESSION_TTL_SECONDS: 7 * 24 * 60 * 60,
    GRACE_PERIOD_SECONDS: 5 * 60,

    // Per token rate limiting
    REQUESTS_PER_MINUTE: 60,
    REQUESTS_PER_HOUR: 1000,

    // Key derivation
    MAC_KEY_DOMAIN: 'anonymous-session-mac-v1',
    ENCRYPTION_KEY_DOMAIN: 'anonymous-session-enc-v1',
};

class AnonymousSessionService {
    constructor() {
        this.macKey = null;
        this.encryptionKey = null;
        this.initialized = false;
        this.initPromise = null;
    }

    /**
     * Initialize service with server derived keys
     */
    async initialize() {
        if (this.initialized) return;
        if (this.initPromise) return await this.initPromise;

        this.initPromise = this._doInitialize();
        try {
            await this.initPromise;
        } finally {
            this.initPromise = null;
        }
    }

    async _doInitialize() {
        if (this.initialized) return;

        const serverSecret = this._getServerSecret();

        // Derive MAC key
        const macSalt = blake3(Buffer.from('session-mac-salt-v1'));
        this.macKey = hkdf(
            blake3,
            serverSecret,
            macSalt,
            Buffer.from(SESSION_CONFIG.MAC_KEY_DOMAIN),
            32
        );

        // Derive encryption key for encrypted session data
        const encSalt = blake3(Buffer.from('session-enc-salt-v1'));
        this.encryptionKey = hkdf(
            blake3,
            serverSecret,
            encSalt,
            Buffer.from(SESSION_CONFIG.ENCRYPTION_KEY_DOMAIN),
            32
        );

        this.initialized = true;
        console.log('[ANON-SESSION] Anonymous session service initialized');
    }

    /**
     * Get server secret from environment
     */
    _getServerSecret() {
        const secret = process.env.KEY_ENCRYPTION_SECRET;
        if (!secret || secret.length < 32) {
            throw new Error('KEY_ENCRYPTION_SECRET must be at least 32 characters');
        }
        return Buffer.from(secret);
    }

    /**
     * Create a new anonymous session token
     */
    async createSession() {
        if (!this.initialized) await this.initialize();

        const version = Buffer.alloc(1);
        version[0] = 0x01;

        // Generate random nonce
        const nonce = await this._generateSecureNonce();
        console.log(`[ANON-SESSION] Nonce size: ${nonce.length} bytes`);

        const now = Math.floor(Date.now() / 1000);
        const timestamp = Buffer.alloc(8);
        timestamp.writeBigUInt64BE(BigInt(now), 0);

        const expiresAt = now + SESSION_CONFIG.SESSION_TTL_SECONDS;
        const data = Buffer.concat([version, nonce, timestamp]);

        // Create BLAKE3 keyed MAC
        const mac = blake3(data, { key: this.macKey });
        console.log(`[ANON-SESSION] MAC size: ${mac.length} bytes, data size: ${data.length} bytes`);

        const tokenBytes = Buffer.concat([data, mac]);
        const token = this._base64UrlEncode(tokenBytes);
        console.log(`[ANON-SESSION] Created token: ${tokenBytes.length} bytes -> ${token.length} chars`);

        // Session ID is hash of the nonce for rate limiting lookups
        const sessionId = blake3(nonce).slice(0, 16).toString('hex');

        // Initialize rate limit counters for this session
        await this._initSessionQuota(sessionId, expiresAt);

        return {
            token,
            expiresAt,
            sessionId,
            tokenType: 'Anonymous'
        };
    }

    /**
     * Verify an anonymous session token
     */
    async verifySession(token) {
        if (!this.initialized) await this.initialize();

        try {
            const tokenBytes = this._base64UrlDecode(token);

            if (tokenBytes.length !== 65) {
                return { valid: false, error: 'Invalid token format' };
            }

            const version = tokenBytes[0];
            const nonce = tokenBytes.slice(1, 25);
            const timestamp = tokenBytes.slice(25, 33);
            const providedMac = tokenBytes.slice(33, 65);

            // Always compute MAC to avoid timing side channels
            const data = tokenBytes.subarray(0, 33);
            const expectedMac = blake3(data, { key: this.macKey });
            const macValid = this._constantTimeEqual(providedMac, expectedMac);

            // Compute all checks before returning
            const versionValid = version === 0x01;
            const issuedAt = Number(timestamp.readBigUInt64BE(0));
            const expiresAt = issuedAt + SESSION_CONFIG.SESSION_TTL_SECONDS;
            const now = Math.floor(Date.now() / 1000);
            const notExpired = now <= expiresAt + SESSION_CONFIG.GRACE_PERIOD_SECONDS;

            if (!macValid || !versionValid) {
                return { valid: false, error: 'Invalid token' };
            }

            if (!notExpired) {
                return { valid: false, error: 'Token expired' };
            }

            // Session ID for rate limiting
            const sessionId = blake3(nonce).slice(0, 16).toString('hex');

            // Check rate limit
            const quotaResult = await this._checkSessionQuota(sessionId);
            if (!quotaResult.allowed) {
                return { valid: false, error: 'Rate limit exceeded', retryAfter: quotaResult.retryAfter };
            }

            return {
                valid: true,
                sessionId,
                issuedAt,
                expiresAt,
                remainingSeconds: expiresAt - now
            };
        } catch (error) {
            console.error('[ANON-SESSION] Token verification error:', error.message);
            return { valid: false, error: 'Token verification failed' };
        }
    }

    /**
     * Revoke a session by its token
     */
    async revokeSession(token) {
        if (!this.initialized) await this.initialize();

        try {
            const tokenBytes = this._base64UrlDecode(token);
            if (tokenBytes.length !== 65) return false;

            const nonce = tokenBytes.slice(1, 25);
            const sessionId = blake3(nonce).slice(0, 16).toString('hex');

            // Add to blacklist
            await this._blacklistSession(sessionId);

            return true;
        } catch {
            return false;
        }
    }

    /**
     * Create session with encrypted capability data
     */
    async createSessionWithCapabilities(capabilities = { scopes: ['chat:read', 'chat:write'] }) {
        const session = await this.createSession();

        // Encrypt capabilities with XChaCha20-Poly1305
        const capData = JSON.stringify(capabilities);
        const nonce = crypto.randomBytes(24);
        const cipher = xchacha20poly1305(this.encryptionKey, nonce);
        const encrypted = cipher.encrypt(Buffer.from(capData));

        // Store encrypted capabilities by session ID
        const stored = Buffer.concat([nonce, encrypted]);
        await this._storeSessionData(session.sessionId, stored, session.expiresAt);

        return session;
    }

    /**
     * Get capabilities for a verified session
     */
    async getSessionCapabilities(sessionId) {
        const stored = await this._getSessionData(sessionId);
        if (!stored) {
            return { scopes: ['chat:read', 'chat:write'] };
        }

        try {
            const nonce = stored.slice(0, 24);
            const encrypted = stored.slice(24);
            const cipher = xchacha20poly1305(this.encryptionKey, nonce);
            const decrypted = cipher.decrypt(encrypted);
            return JSON.parse(Buffer.from(decrypted).toString());
        } catch {
            return { scopes: ['chat:read', 'chat:write'] };
        }
    }

    /**
     * Generate nonce
     */
    async _generateSecureNonce() {
        const random = crypto.randomBytes(SESSION_CONFIG.SESSION_NONCE_BYTES);
        const timestamp = Buffer.alloc(8);
        timestamp.writeBigUInt64BE(BigInt(Date.now()), 0);
        const processEntropy = Buffer.from(process.pid.toString() + process.hrtime.bigint().toString());

        // Mix entropy sources with SHAKE256
        const mixed = shake256(
            Buffer.concat([random, timestamp, processEntropy]),
            SESSION_CONFIG.SESSION_NONCE_BYTES
        );

        return Buffer.from(mixed).slice(0, SESSION_CONFIG.SESSION_NONCE_BYTES);
    }

    /**
     * Time buffer comparison
     */
    _constantTimeEqual(a, b) {
        if (a.length !== b.length) return false;
        return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    }

    /**
     * Base64url encode
     */
    _base64UrlEncode(buffer) {
        return Buffer.from(buffer)
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }

    /**
     * Base64url decode
     */
    _base64UrlDecode(str) {
        str = str.replace(/-/g, '+').replace(/_/g, '/');
        while (str.length % 4) str += '=';
        return Buffer.from(str, 'base64');
    }

    async _initSessionQuota(sessionId, expiresAt) {
        const ttl = expiresAt - Math.floor(Date.now() / 1000);
        if (ttl <= 0) return;

        try {
            await withRedisClient(async (redis) => {
                const key = `session:quota:${sessionId}`;
                await redis.set(key, JSON.stringify({
                    minuteCount: 0,
                    minuteReset: Math.floor(Date.now() / 1000) + 60,
                    hourCount: 0,
                    hourReset: Math.floor(Date.now() / 1000) + 3600
                }), 'EX', ttl);
            });
        } catch (error) {
            console.warn('[ANON-SESSION] Failed to init quota:', error.message);
        }
    }

    async _checkSessionQuota(sessionId) {
        try {
            return await withRedisClient(async (redis) => {
                const key = `session:quota:${sessionId}`;
                const blacklistKey = `session:blacklist:${sessionId}`;

                // Check blacklist
                const isBlacklisted = await redis.exists(blacklistKey);
                if (isBlacklisted) {
                    return { allowed: false, retryAfter: null };
                }

                const data = await redis.get(key);
                if (!data) {
                    return { allowed: true };
                }

                const raw = JSON.parse(data);
                const now = Math.floor(Date.now() / 1000);

                // Extract only expected numeric fields
                const quota = {
                    minuteCount: typeof raw.minuteCount === 'number' ? raw.minuteCount : 0,
                    minuteReset: typeof raw.minuteReset === 'number' ? raw.minuteReset : now + 60,
                    hourCount: typeof raw.hourCount === 'number' ? raw.hourCount : 0,
                    hourReset: typeof raw.hourReset === 'number' ? raw.hourReset : now + 3600,
                };

                // Reset counters if windows expired
                if (now >= quota.minuteReset) {
                    quota.minuteCount = 0;
                    quota.minuteReset = now + 60;
                }
                if (now >= quota.hourReset) {
                    quota.hourCount = 0;
                    quota.hourReset = now + 3600;
                }

                // Check limits
                if (quota.minuteCount >= SESSION_CONFIG.REQUESTS_PER_MINUTE) {
                    return { allowed: false, retryAfter: quota.minuteReset - now };
                }
                if (quota.hourCount >= SESSION_CONFIG.REQUESTS_PER_HOUR) {
                    return { allowed: false, retryAfter: quota.hourReset - now };
                }

                // Increment counters
                quota.minuteCount++;
                quota.hourCount++;

                await redis.set(key, JSON.stringify(quota), 'KEEPTTL');

                return { allowed: true };
            });
        } catch (error) {
            console.warn('[ANON-SESSION] Quota check failed:', error.message);
            return { allowed: true };
        }
    }

    async _blacklistSession(sessionId) {
        try {
            await withRedisClient(async (redis) => {
                const key = `session:blacklist:${sessionId}`;
                // Blacklist for 30 days
                await redis.set(key, '1', 'EX', 30 * 24 * 60 * 60);
            });
        } catch (error) {
            console.warn('[ANON-SESSION] Failed to blacklist session:', error.message);
        }
    }

    async _storeSessionData(sessionId, data, expiresAt) {
        const ttl = expiresAt - Math.floor(Date.now() / 1000);
        if (ttl <= 0) return;

        try {
            await withRedisClient(async (redis) => {
                const key = `session:data:${sessionId}`;
                await redis.set(key, data.toString('base64'), 'EX', ttl);
            });
        } catch (error) {
            console.warn('[ANON-SESSION] Failed to store session data:', error.message);
        }
    }

    async _getSessionData(sessionId) {
        try {
            return await withRedisClient(async (redis) => {
                const key = `session:data:${sessionId}`;
                const data = await redis.get(key);
                if (!data) return null;
                return Buffer.from(data, 'base64');
            });
        } catch {
            return null;
        }
    }
}

const anonymousSessionService = new AnonymousSessionService();
export { AnonymousSessionService, anonymousSessionService };
