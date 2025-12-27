// Device credentials handler
const { ipcMain } = require('electron');
const { init: initSecureStorage, setItem, getItem } = require('./secure-storage.cjs');
const crypto = require('crypto');

let ml_dsa87 = null;
let blake3 = null;

async function loadNoble() {
    if (!ml_dsa87) {
        const mldsa = await import('@noble/post-quantum/ml-dsa.js');
        const b3 = await import('@noble/hashes/blake3.js');
        ml_dsa87 = mldsa.ml_dsa87;
        blake3 = b3.blake3;
    }
}

// Storage key for device keys
const DEVICE_KEYPAIR_KEY = 'device_mldsa87_keypair';

let cachedKeyPair = null;

// Get existing device key pair or create new one
async function getOrGenerateDeviceKeyPair() {
    if (cachedKeyPair) {
        return cachedKeyPair;
    }

    await loadNoble();

    try {
        const stored = await getItem(DEVICE_KEYPAIR_KEY);
        if (stored) {
            const parsed = JSON.parse(stored);
            const publicKey = Buffer.from(parsed.publicKey, 'base64');
            const secretKey = Buffer.from(parsed.secretKey, 'base64');

            if (publicKey.length === 2592 && secretKey.length === 4896) {
                cachedKeyPair = { publicKey, secretKey };
                return cachedKeyPair;
            }
        }
    } catch (_err) { }

    const seed = crypto.randomBytes(32);
    const kp = await ml_dsa87.keygen(seed);

    const publicKey = Buffer.from(kp.publicKey);
    const secretKey = Buffer.from(kp.secretKey);

    await setItem(DEVICE_KEYPAIR_KEY, JSON.stringify({
        publicKey: publicKey.toString('base64'),
        secretKey: secretKey.toString('base64'),
        generated: Date.now()
    }));

    cachedKeyPair = { publicKey, secretKey };
    return cachedKeyPair;
}

// Create hash of public key
async function hashPublicKey(publicKey) {
    await loadNoble();
    return Buffer.from(blake3(publicKey));
}

// Register IPC handlers for device credentials
function initDeviceCredentials({ logger, installPath }) {
    initSecureStorage({ logger, installPath }).catch(err => {
        logger?.error('Failed to initialize secure storage for device credentials:', err);
    });

    ipcMain.handle('device:getCredentials', async () => {
        try {
            const kp = await getOrGenerateDeviceKeyPair();
            const keyHash = await hashPublicKey(kp.publicKey);

            return {
                publicKey: kp.publicKey.toString('base64'),
                keyHash: keyHash.toString('base64')
            };
        } catch (err) {
            throw new Error(`Failed to get device credentials: ${err.message}`);
        }
    });

    ipcMain.handle('device:signChallenge', async (event, challenge) => {
        try {
            if (typeof challenge !== 'string' || challenge.length === 0) {
                throw new Error('Invalid challenge');
            }

            const kp = await getOrGenerateDeviceKeyPair();
            const message = Buffer.from(challenge, 'utf8');
            const signature = ml_dsa87.sign(message, kp.secretKey);

            return Buffer.from(signature).toString('base64');
        } catch (err) {
            throw new Error(`Failed to sign challenge: ${err.message}`);
        }
    });
}

module.exports = { initDeviceCredentials };
