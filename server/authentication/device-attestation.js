import { CryptoUtils } from '../crypto/unified-crypto.js';
const { blake3 } = CryptoUtils.Hash;

let ml_dsa87 = null;

async function loadMlDsa() {
    if (!ml_dsa87) {
        const mod = await import('@noble/post-quantum/ml-dsa.js');
        ml_dsa87 = mod.ml_dsa87;
    }
}

class DeviceAttestationService {
    constructor(db, config) {
        this.db = db;
        this.maxAccounts = config?.maxAccounts || 2;
        this.challengeExpiry = 300000;
        this.challenges = new Map();
    }

    async initialize() {
        await loadMlDsa();

        await this.db.query(`
      CREATE TABLE IF NOT EXISTS device_attestations (
        id BIGSERIAL PRIMARY KEY,
        device_public_key_hash BYTEA NOT NULL UNIQUE,
        accounts_created INTEGER NOT NULL DEFAULT 0,
        first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT device_public_key_hash_check CHECK (length(device_public_key_hash) = 32)
      );
    `);

        await this.db.query(`
      CREATE INDEX IF NOT EXISTS idx_device_attestations_hash 
      ON device_attestations(device_public_key_hash);
    `);

        await this.db.query(`
      CREATE TABLE IF NOT EXISTS device_challenges (
        nonce TEXT PRIMARY KEY,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL,
        used BOOLEAN NOT NULL DEFAULT false
      );
    `);

        await this.db.query(`
      CREATE INDEX IF NOT EXISTS idx_device_challenges_expires 
      ON device_challenges(expires_at) WHERE NOT used;
    `);

        setInterval(() => this.cleanupExpiredChallenges(), 60000);
    }

    generateChallenge() {
        const nonce = CryptoUtils.Random.generateRandomBytes(32).toString('base64');
        const expiresAt = Date.now() + this.challengeExpiry;

        this.challenges.set(nonce, {
            createdAt: Date.now(),
            expiresAt,
            used: false
        });

        return {
            nonce,
            expiresAt
        };
    }

    verifySignature({ devicePublicKey, signature, challenge }) {
        if (typeof devicePublicKey !== 'string' || typeof signature !== 'string' || typeof challenge !== 'string') {
            throw new Error('Invalid attestation format');
        }

        const challengeData = this.challenges.get(challenge);
        if (!challengeData || Date.now() > challengeData.expiresAt) {
            throw new Error('Invalid or expired challenge');
        }

        const publicKeyBytes = Buffer.from(devicePublicKey, 'base64');
        const signatureBytes = Buffer.from(signature, 'base64');
        const messageBytes = Buffer.from(challenge, 'utf8');

        if (publicKeyBytes.length !== 2592) {
            throw new Error('Invalid ML-DSA-87 public key length');
        }

        const isValid = ml_dsa87.verify(signatureBytes, messageBytes, publicKeyBytes);
        if (!isValid) {
            throw new Error('Invalid signature');
        }

        return true;
    }

    async verifyAttestation({ devicePublicKey, signature, challenge }) {
        if (typeof devicePublicKey !== 'string' || typeof signature !== 'string' || typeof challenge !== 'string') {
            throw new Error('Invalid attestation format');
        }

        const challengeData = this.challenges.get(challenge);
        if (!challengeData || challengeData.used || Date.now() > challengeData.expiresAt) {
            throw new Error('Invalid or expired challenge');
        }

        challengeData.used = true;

        const publicKeyBytes = Buffer.from(devicePublicKey, 'base64');
        const signatureBytes = Buffer.from(signature, 'base64');
        const messageBytes = Buffer.from(challenge, 'utf8');

        if (publicKeyBytes.length !== 2592) {
            throw new Error('Invalid ML-DSA-87 public key length');
        }

        const isValid = ml_dsa87.verify(signatureBytes, messageBytes, publicKeyBytes);
        if (!isValid) {
            throw new Error('Invalid signature');
        }

        const keyHash = Buffer.from(blake3(publicKeyBytes));

        const result = await this.db.query(
            'SELECT accounts_created FROM device_attestations WHERE device_public_key_hash = $1',
            [keyHash]
        );

        let accountsCreated = 0;
        if (result.rows.length > 0) {
            accountsCreated = result.rows[0].accounts_created;
        }

        if (accountsCreated >= this.maxAccounts) {
            return {
                allowed: false,
                reason: 'Device account limit reached',
                limit: this.maxAccounts,
                current: accountsCreated
            };
        }

        if (result.rows.length === 0) {
            await this.db.query(
                `INSERT INTO device_attestations (device_public_key_hash, accounts_created) 
         VALUES ($1, 1)`,
                [keyHash]
            );
        } else {
            await this.db.query(
                `UPDATE device_attestations 
         SET accounts_created = accounts_created + 1, last_used_at = NOW() 
         WHERE device_public_key_hash = $1`,
                [keyHash]
            );
        }

        return {
            allowed: true,
            newCount: accountsCreated + 1
        };
    }

    async cleanupExpiredChallenges() {
        const now = Date.now();
        for (const [nonce, data] of this.challenges.entries()) {
            if (now > data.expiresAt) {
                this.challenges.delete(nonce);
            }
        }

        await this.db.query(
            'DELETE FROM device_challenges WHERE expires_at < NOW() - INTERVAL \'1 hour\''
        );
    }
}

export { DeviceAttestationService };
