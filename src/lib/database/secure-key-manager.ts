import { CryptoUtils } from '../utils/crypto-utils';
import * as argon2 from "argon2-wasm";
import { blake3 as nobleBlake3 } from '@noble/hashes/blake3.js';
import { PostQuantumUtils } from '../utils/pq-utils';
import { SQLiteKV } from './sqlite-kv';
import { PostQuantumAEAD } from '../cryptography/aead';
import { EncryptedKeyData, DecryptedKeys } from '../types/database-types';

const getCrypto = () => {
	if (typeof globalThis !== 'undefined' && globalThis.crypto) {
		return globalThis.crypto;
	}
	try {
		return require('crypto').webcrypto;
	} catch {
		throw new Error('SecureKeyManager requires WebCrypto support');
	}
};

export class SecureKeyManager {
	private masterKey: CryptoKey | null = null;
	private username: string;
	private initializationPromise: Promise<void> | null = null;

	constructor(username: string) {
		this.username = username;
		this.masterKey = null;
	}

	// Get master AES-GCM key
	getMasterKey(): CryptoKey | null {
		return this.masterKey;
	}

	// Initialize the key manager with master key
	async initializeWithMasterKey(masterKeyRaw: Uint8Array): Promise<void> {
		if (!masterKeyRaw || !(masterKeyRaw instanceof Uint8Array) || masterKeyRaw.length !== 32) {
			throw new Error('Master key must be 32 raw bytes');
		}

		const masterKey = await (getCrypto().subtle.importKey(
			'raw',
			masterKeyRaw,
			{ name: 'AES-GCM' },
			true,
			['encrypt', 'decrypt']
		));
		this.masterKey = masterKey;

		let meta = await this.getKeyMetadata();
		if (!meta || !meta.salt || !meta.argon2Params) {
			try {
				const saltBytes = getCrypto().getRandomValues(new Uint8Array(32));
				const argon2Params = {
					version: 0x13,
					algorithm: 'argon2id',
					memoryCost: 524288,
					timeCost: 6,
					parallelism: 4,
				};
				await this.storeKeyMetadata({
					salt: CryptoUtils.Base64.arrayBufferToBase64(saltBytes),
					iv: CryptoUtils.Base64.arrayBufferToBase64(getCrypto().getRandomValues(new Uint8Array(16))),
					argon2Params,
				});
				meta = await this.getKeyMetadata();
			} catch {
				this.masterKey = null;
				throw new Error('Failed to create key metadata for token-based unlock');
			}
		}
	}

	// Get Argon2 hash for the current passphrase
	async getEncodedPassphraseHash(passphrase: string): Promise<string | null> {
		if (!this.masterKey) {
			return null;
		}

		try {
			const metadata = await this.getKeyMetadata();
			if (!metadata || !metadata.salt || !metadata.argon2Params) {
				console.error('[secure-key-manager] No key metadata available for passphrase hashing');
				return null;
			}

			const saltBytes = CryptoUtils.Base64.base64ToUint8Array(metadata.salt);

			const hashResult = await argon2.hash({
				pass: passphrase,
				salt: saltBytes,
				time: metadata.argon2Params.timeCost,
				mem: metadata.argon2Params.memoryCost,
				parallelism: metadata.argon2Params.parallelism,
				type: metadata.argon2Params.algorithm === 'argon2id' ? 2 : (metadata.argon2Params.algorithm === 'argon2i' ? 1 : 0),
				version: metadata.argon2Params.version,
				hashLen: 32
			});

			return hashResult.encoded;
		} catch (_error) {
			console.error('[secure-key-manager] Failed to encode passphrase hash', { error: (_error as Error).message });
			return null;
		}
	}

	// Internal storage helpers
	private async kv() { return SQLiteKV.forUser(this.username); }

	private async storeKeyMetadata(metadata: any): Promise<void> {
		await (await this.kv()).setJsonKey('metadata', metadata);
	}

	async getKeyMetadata(): Promise<any | null> {
		return (await this.kv()).getJsonKey('metadata');
	}

	private async storeEncryptedKeys(payload: EncryptedKeyData): Promise<void> {
		await (await this.kv()).setJsonKey('keys', payload);
	}

	private async getEncryptedKeys(): Promise<EncryptedKeyData | null> {
		return (await this.kv()).getJsonKey<EncryptedKeyData>('keys');
	}

	// Initialize key manager
	async initialize(passphrase: string, salt?: string, argon2Params?: { version: number; algorithm: string; memoryCost: number; timeCost: number; parallelism: number }): Promise<void> {
		if (this.masterKey) {
			return;
		}

		if (this.initializationPromise) {
			return this.initializationPromise;
		}

		this.initializationPromise = this.doInitialize(passphrase, salt, argon2Params);

		try {
			await this.initializationPromise;
		} finally {
			this.initializationPromise = null;
		}
	}

	// Do initialization
	private async doInitialize(passphrase: string, salt?: string, argon2Params?: { version: number; algorithm: string; memoryCost: number; timeCost: number; parallelism: number }): Promise<void> {
		if (this.masterKey) {
			return;
		}

		this.masterKey = null;

		let keySalt: Uint8Array;
		let keyIv: Uint8Array;
		let storedArgon2Params: { version: number; algorithm: string; memoryCost: number; timeCost: number; parallelism: number };

		// Load any previously stored metadata to recover salt and Argon2 parameters
		let existingMetadata: any = null;
		try {
			existingMetadata = await this.getKeyMetadata();
		} catch (_error) {
			throw new Error('Failed to load key metadata: ' + (_error as Error).message);
		}

		// Use stored salt if available otherwise use provided salt or generate new one
		if (salt) {
			keySalt = CryptoUtils.Base64.base64ToUint8Array(salt);
			keyIv = getCrypto().getRandomValues(new Uint8Array(16));
		} else if (existingMetadata?.salt) {
			keySalt = CryptoUtils.Base64.base64ToUint8Array(existingMetadata.salt);
			keyIv = getCrypto().getRandomValues(new Uint8Array(16));
		} else {
			keySalt = getCrypto().getRandomValues(new Uint8Array(32));
			keyIv = getCrypto().getRandomValues(new Uint8Array(16));
		}

		if (argon2Params) {
			storedArgon2Params = argon2Params;
		} else if (existingMetadata?.argon2Params) {
			storedArgon2Params = existingMetadata.argon2Params;
		} else {
			storedArgon2Params = {
				version: 0x13,
				algorithm: 'argon2id',
				memoryCost: 524288,
				timeCost: 6,
				parallelism: 4
			};
		}

		const startTime = performance.now();

		const argon2Result = await argon2.hash({
			pass: passphrase,
			salt: keySalt,
			time: storedArgon2Params.timeCost,
			mem: storedArgon2Params.memoryCost,
			parallelism: storedArgon2Params.parallelism,
			type: 2,
			version: storedArgon2Params.version,
			hashLen: 32
		});

		const elapsedTime = performance.now() - startTime;
		const minTime = 200;
		if (elapsedTime < minTime) {
			await new Promise(resolve => setTimeout(resolve, minTime - elapsedTime));
		}

		if (!argon2Result || !argon2Result.hash || argon2Result.hash.length !== 32) {
			throw new Error('CRITICAL: Invalid Argon2 key derivation result');
		}

		const masterKey = await getCrypto().subtle.importKey(
			'raw',
			argon2Result.hash,
			{ name: 'AES-GCM' },
			true,
			['encrypt', 'decrypt']
		);

		this.masterKey = masterKey;

		if (!existingMetadata || !existingMetadata.salt) {
			await this.storeKeyMetadata({
				salt: CryptoUtils.Base64.arrayBufferToBase64(keySalt),
				iv: CryptoUtils.Base64.arrayBufferToBase64(keyIv),
				argon2Params: storedArgon2Params
			});

			const storedMetadata = await this.getKeyMetadata();
			if (!storedMetadata) {
				throw new Error('Failed to verify stored key metadata');
			}
		}
	}

	// Store encrypted keys
	async storeKeys(keys: DecryptedKeys): Promise<void> {
		if (!this.masterKey) {
			throw new Error('Key manager not initialized');
		}

		const metadata = await this.getKeyMetadata();
		if (!metadata || !metadata.salt || !metadata.argon2Params) {
			throw new Error('Key metadata not found or incomplete');
		}

		// Export master key to raw bytes
		let key: Uint8Array;
		try {
			const masterKeyBytes = await getCrypto().subtle.exportKey('raw', this.masterKey);
			key = new Uint8Array(masterKeyBytes);
		} catch {
			throw new Error('Failed to export master key for post-quantum encryption.');
		}

		// Encrypt secret keys
		const kyberSecretBytes = new TextEncoder().encode(JSON.stringify(Array.from(keys.kyber.secretKey)));
		const dilithiumSecretBytes = new TextEncoder().encode(JSON.stringify(Array.from(keys.dilithium.secretKey)));
		const x25519SecretBytes = new TextEncoder().encode(JSON.stringify(Array.from(keys.x25519.private)));

		const payload = {
			kyber: CryptoUtils.Base64.arrayBufferToBase64(kyberSecretBytes),
			dilithium: CryptoUtils.Base64.arrayBufferToBase64(dilithiumSecretBytes),
			x25519: CryptoUtils.Base64.arrayBufferToBase64(x25519SecretBytes)
		};

		const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
		const pqNonce = getCrypto().getRandomValues(new Uint8Array(36));
		const pqAad = new TextEncoder().encode(`secure-key-manager-pq-${this.username}`);
		const pqEncResult = PostQuantumAEAD.encrypt(payloadBytes, key, pqAad, pqNonce);

		const fullCiphertext = new Uint8Array(pqEncResult.ciphertext.length + pqEncResult.tag.length);
		fullCiphertext.set(pqEncResult.ciphertext, 0);
		fullCiphertext.set(pqEncResult.tag, pqEncResult.ciphertext.length);

		const macInput = new Uint8Array(fullCiphertext.length + pqAad.length);
		macInput.set(fullCiphertext, 0);
		macInput.set(pqAad, fullCiphertext.length);
		const mac = nobleBlake3(macInput, { key });

		const encryptedData: EncryptedKeyData = {
			bundleCiphertext: CryptoUtils.Base64.arrayBufferToBase64(pqEncResult.ciphertext),
			bundleNonce: CryptoUtils.Base64.arrayBufferToBase64(pqNonce),
			bundleTag: CryptoUtils.Base64.arrayBufferToBase64(pqEncResult.tag),
			bundleAad: CryptoUtils.Base64.arrayBufferToBase64(pqAad),
			bundleMac: CryptoUtils.Base64.arrayBufferToBase64(mac),
			kyberPublicBase64: keys.kyber.publicKeyBase64,
			dilithiumPublicBase64: keys.dilithium.publicKeyBase64,
			x25519PublicBase64: keys.x25519.publicKeyBase64,
			salt: metadata.salt,
			version: 4,
			argon2Params: metadata.argon2Params,
			createdAt: Date.now(),
			expiresAt: Date.now() + 365 * 24 * 60 * 60 * 1000,
			sequence: Math.floor(Date.now() / 1000),
			payloadSize: payloadBytes.byteLength
		};

		await this.storeEncryptedKeys(encryptedData);
		key.fill(0);
	}

	// Get decrypted keys from encrypted storage
	async getKeys(): Promise<DecryptedKeys | null> {
		if (!this.masterKey) {
			throw new Error('Key manager not initialized');
		}

		let encryptedData: EncryptedKeyData | null = null;

		try {
			encryptedData = await this.getEncryptedKeys();
		} catch (_error) {
			throw new Error(`Failed to retrieve encrypted keys: ${_error instanceof Error ? _error.message : String(_error)}`);
		}

		if (!encryptedData) {
			return null;
		}

		// Export master key to raw bytes
		let key: Uint8Array;
		try {
			const masterKeyBytes = await getCrypto().subtle.exportKey('raw', this.masterKey);
			key = new Uint8Array(masterKeyBytes);
		} catch {
			throw new Error('Failed to export master key for post-quantum decryption.');
		}

		const ciphertext = CryptoUtils.Base64.base64ToUint8Array(encryptedData.bundleCiphertext);
		const nonce = CryptoUtils.Base64.base64ToUint8Array(encryptedData.bundleNonce);
		const tag = CryptoUtils.Base64.base64ToUint8Array(encryptedData.bundleTag);
		const storedAad = CryptoUtils.Base64.base64ToUint8Array(encryptedData.bundleAad);
		const storedMac = CryptoUtils.Base64.base64ToUint8Array(encryptedData.bundleMac);

		if (nonce.length !== 36) {
			throw new Error(`Invalid payload nonce length: ${nonce.length}.`);
		}

		if (tag.length !== 32) {
			throw new Error(`Invalid payload tag length: ${tag.length}.`);
		}

		const fullCiphertext = new Uint8Array(ciphertext.length + tag.length);
		fullCiphertext.set(ciphertext, 0);
		fullCiphertext.set(tag, ciphertext.length);

		const macInput = new Uint8Array(fullCiphertext.length + storedAad.length);
		macInput.set(fullCiphertext, 0);
		macInput.set(storedAad, fullCiphertext.length);
		const expectedMac = nobleBlake3(macInput, { key });

		if (!PostQuantumUtils.timingSafeEqual(expectedMac, storedMac)) {
			throw new Error('Payload integrity verification failed');
		}

		const decryptedPayload = PostQuantumAEAD.decrypt(ciphertext, nonce, tag, key, storedAad);
		const parsed = JSON.parse(new TextDecoder().decode(decryptedPayload));
		if (!parsed?.kyber || !parsed?.dilithium || !parsed?.x25519) {
			throw new Error('Decrypted payload missing required key material');
		}

		const decodeKey = (base64: string, expectedLength: number): Uint8Array => {
			const jsonBytes = CryptoUtils.Base64.base64ToUint8Array(base64);
			const jsonString = new TextDecoder().decode(jsonBytes);
			const array = JSON.parse(jsonString);
			const bytes = new Uint8Array(array);

			if (bytes.length !== expectedLength) {
				throw new Error(`Invalid key length (${bytes.length}), expected ${expectedLength}`);
			}
			return bytes;
		};

		const kyberSecret = decodeKey(parsed.kyber, 3168);
		const dilithiumSecret = decodeKey(parsed.dilithium, 4896);
		const x25519Secret = decodeKey(parsed.x25519, 32);

		key.fill(0);
		return {
			kyber: {
				publicKeyBase64: encryptedData.kyberPublicBase64,
				secretKey: kyberSecret
			},
			dilithium: {
				publicKeyBase64: encryptedData.dilithiumPublicBase64,
				secretKey: dilithiumSecret
			},
			x25519: {
				publicKeyBase64: encryptedData.x25519PublicBase64,
				private: x25519Secret
			}
		};
	}

	// Get public keys from encrypted data
	async getPublicKeys(): Promise<{ kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64: string } | null> {
		const encryptedData = await this.getEncryptedKeys();
		if (!encryptedData) {
			return null;
		}

		if (!encryptedData.dilithiumPublicBase64) {
			throw new Error('Dilithium public key missing from stored key bundle');
		}

		if (!encryptedData.x25519PublicBase64) {
			throw new Error('X25519 public key missing from stored key bundle');
		}

		return {
			kyberPublicBase64: encryptedData.kyberPublicBase64,
			dilithiumPublicBase64: encryptedData.dilithiumPublicBase64,
			x25519PublicBase64: encryptedData.x25519PublicBase64,
		};
	}

	// Clear master key
	clearKeys(): void {
		this.masterKey = null;
	}

	// Check if keys exist
	async hasKeys(): Promise<boolean> {
		try {
			const encryptedData = await this.getEncryptedKeys();
			return encryptedData !== null;
		} catch {
			return false;
		}
	}
	
	// Delete database
	async deleteDatabase(): Promise<void> {
		this.masterKey = null;
		await (await this.kv()).clearSecureKeys();
	}
}