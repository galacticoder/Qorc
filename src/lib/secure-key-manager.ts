import { CryptoUtils } from './unified-crypto';
import * as argon2 from "argon2-wasm";

interface EncryptedKeyData {
	encryptedX25519Private: string;
	encryptedKyberSecret: string;
	encryptedDilithiumSecret?: string; // New field for Dilithium3 secret key
	x25519Nonce: string; // Nonce for XChaCha20-Poly1305
	kyberNonce: string; // Nonce for XChaCha20-Poly1305
	dilithiumNonce?: string; // Nonce for Dilithium3 secret key
	x25519PublicBase64: string;
	kyberPublicBase64: string;
	dilithiumPublicBase64?: string; // New field for Dilithium3 public key
	salt: string;
	iv: string; // Keep for backward compatibility
	argon2Params?: {
		version: number;
		algorithm: string;
		memoryCost: number;
		timeCost: number;
		parallelism: number;
	};
}

interface DecryptedKeys {
	x25519: {
		private: Uint8Array;
		publicKeyBase64: string;
	};
	kyber: {
		publicKeyBase64: string;
		secretKey: Uint8Array;
	};
	dilithium?: { // New optional field for Dilithium3 keys
		publicKeyBase64: string;
		secretKey: Uint8Array;
	};
}

export class SecureKeyManager {
	private dbName: string;
	private storeName = 'encryptedKeys';
	private masterKey: CryptoKey | null = null;
	private username: string;
	// In-memory fallback when IndexedDB is unavailable in dev
	private memoryMode: boolean = false;
	private memory: Record<string, any> = {};

	constructor(username: string) {
		this.username = username;
		this.dbName = `SecureKeyDB_${username}`;
	}

	async initialize(passphrase: string, salt?: string, argon2Params?: { version: number; algorithm: string; memoryCost: number; timeCost: number; parallelism: number }): Promise<void> {
		if (this.masterKey) {
			return;
		}

		let keySalt: Uint8Array;
		let keyIv: Uint8Array;
		let storedArgon2Params: { version: number; algorithm: string; memoryCost: number; timeCost: number; parallelism: number };

		if (salt) {
			keySalt = CryptoUtils.Base64.base64ToUint8Array(salt);
			keyIv = crypto.getRandomValues(new Uint8Array(12));
		} else {
			keySalt = crypto.getRandomValues(new Uint8Array(16));
			keyIv = crypto.getRandomValues(new Uint8Array(12));
		}

		// check if we have existing metadata to determine key derivation method
		let existingMetadata: any = null;
		try {
			existingMetadata = await this.getKeyMetadata();
		} catch {
			this.memoryMode = true;
			existingMetadata = this.memory['metadata'] || null;
		}
		const useArgon2 = !existingMetadata || existingMetadata.argon2Params;

		if (useArgon2) {
			if (argon2Params) {
				storedArgon2Params = argon2Params;
			} else if (existingMetadata?.argon2Params) {
				storedArgon2Params = existingMetadata.argon2Params;
			} else {
				storedArgon2Params = {
					version: 0x13,
					algorithm: 'argon2id',
					memoryCost: 131072,
					timeCost: 3,
					parallelism: 1
				};
			}

			// SECURITY: Derive master key using argon2id with timing attack protection
			const startTime = performance.now();
			const argon2Result = await argon2.hash({
				pass: passphrase,
				salt: keySalt,
				time: storedArgon2Params.timeCost,
				mem: storedArgon2Params.memoryCost,
				parallelism: storedArgon2Params.parallelism,
				type: 2, // argon2id
				version: storedArgon2Params.version,
				hashLen: 32
			});

			// SECURITY: Add constant-time delay to prevent timing attacks
			const elapsedTime = performance.now() - startTime;
			const minTime = 100; // Minimum 100ms for key derivation
			if (elapsedTime < minTime) {
				await new Promise(resolve => setTimeout(resolve, minTime - elapsedTime));
			}

			// SECURITY: Validate Argon2 result
			if (!argon2Result || !argon2Result.hash || argon2Result.hash.length !== 32) {
				throw new Error('CRITICAL: Invalid Argon2 key derivation result');
			}

			// import the derived hash as a crypto key
			const masterKey = await crypto.subtle.importKey(
				'raw',
				argon2Result.hash,
				{ name: 'AES-GCM' },
				true, // Make extractable for ChaCha20 encryption
				['encrypt', 'decrypt']
			);

			this.masterKey = masterKey;
		} else {
			// fallback to pbkdf2 for backward compatibility with existing users
			const masterKey = await crypto.subtle.importKey(
				'raw',
				new TextEncoder().encode(passphrase),
				{ name: 'PBKDF2' },
				false,
				['deriveKey']
			);

			const derivedKey = await crypto.subtle.deriveKey(
				{
					name: 'PBKDF2',
					salt: keySalt,
					iterations: 100000,
					hash: 'SHA-256'
				},
				masterKey,
				{ name: 'AES-GCM', length: 256 },
				false, // Keep non-extractable for legacy security
				['encrypt', 'decrypt']
			);

			this.masterKey = derivedKey;
		}

		if (!salt) {
			await this.storeKeyMetadata({
				salt: CryptoUtils.Base64.arrayBufferToBase64(keySalt),
				iv: CryptoUtils.Base64.arrayBufferToBase64(keyIv),
				argon2Params: useArgon2 ? storedArgon2Params : undefined
			});

			let storedMetadata: any = null;
			try {
				storedMetadata = await this.getKeyMetadata();
			} catch {
				storedMetadata = this.memory['metadata'] || null;
			}
			if (!storedMetadata) {
				throw new Error('Failed to store key metadata');
			}
		}
	}

	async storeKeys(keys: DecryptedKeys): Promise<void> {
		if (!this.masterKey) {
			throw new Error('Key manager not initialized');
		}

		const metadata = await this.getKeyMetadata();
		if (!metadata) {
			throw new Error('Key metadata not found');
		}

		const iv = CryptoUtils.Base64.base64ToUint8Array(metadata.iv);

		// Export master key to raw bytes for ChaCha20
		let key: Uint8Array;
		try {
			const masterKeyBytes = await crypto.subtle.exportKey('raw', this.masterKey);
			key = new Uint8Array(masterKeyBytes);
		} catch (error) {
			// Legacy PBKDF2 keys are not extractable - user needs to re-register with Argon2
			throw new Error('Legacy key format detected. Please clear your data and re-register for enhanced security.');
		}

		const x25519PrivateBytes = new TextEncoder().encode(JSON.stringify(Array.from(keys.x25519.private)));
		const { nonce: x25519Nonce, ciphertext: encryptedX25519Private } = CryptoUtils.XChaCha20Poly1305.encryptWithNonce(key, x25519PrivateBytes);

		const kyberSecretBytes = new TextEncoder().encode(JSON.stringify(Array.from(keys.kyber.secretKey)));
		const { nonce: kyberNonce, ciphertext: encryptedKyberSecret } = CryptoUtils.XChaCha20Poly1305.encryptWithNonce(key, kyberSecretBytes);

		// Handle optional Dilithium3 keys
		let encryptedDilithiumSecret: string | undefined;
		let dilithiumNonce: string | undefined;
		let dilithiumPublicBase64: string | undefined;

		if (keys.dilithium) {
			const dilithiumSecretBytes = new TextEncoder().encode(JSON.stringify(Array.from(keys.dilithium.secretKey)));
			const { nonce: dilithiumNonceBytes, ciphertext: encryptedDilithiumSecretBytes } = CryptoUtils.XChaCha20Poly1305.encryptWithNonce(key, dilithiumSecretBytes);
			encryptedDilithiumSecret = CryptoUtils.Base64.arrayBufferToBase64(encryptedDilithiumSecretBytes);
			dilithiumNonce = CryptoUtils.Base64.arrayBufferToBase64(dilithiumNonceBytes);
			dilithiumPublicBase64 = keys.dilithium.publicKeyBase64;
		}

		const encryptedData: EncryptedKeyData = {
			encryptedX25519Private: CryptoUtils.Base64.arrayBufferToBase64(encryptedX25519Private),
			encryptedKyberSecret: CryptoUtils.Base64.arrayBufferToBase64(encryptedKyberSecret),
			encryptedDilithiumSecret,
			x25519Nonce: CryptoUtils.Base64.arrayBufferToBase64(x25519Nonce),
			kyberNonce: CryptoUtils.Base64.arrayBufferToBase64(kyberNonce),
			dilithiumNonce,
			x25519PublicBase64: keys.x25519.publicKeyBase64,
			kyberPublicBase64: keys.kyber.publicKeyBase64,
			dilithiumPublicBase64,
			salt: metadata.salt,
			iv: metadata.iv, // Keep for backward compatibility
			argon2Params: metadata.argon2Params
		};

		await this.storeEncryptedKeys(encryptedData);
	}

	async getKeys(): Promise<DecryptedKeys | null> {
		if (!this.masterKey) {
			throw new Error('Key manager not initialized');
		}

		const encryptedData = await this.getEncryptedKeys();
		if (!encryptedData) {
			return null;
		}

		// Export master key to raw bytes for ChaCha20
		let key: Uint8Array;
		try {
			const masterKeyBytes = await crypto.subtle.exportKey('raw', this.masterKey);
			key = new Uint8Array(masterKeyBytes);
		} catch (error) {
			// Legacy PBKDF2 keys are not extractable - user needs to re-register with Argon2
			throw new Error('Legacy key format detected. Please clear your data and re-register for enhanced security.');
		}

		const encryptedX25519Private = CryptoUtils.Base64.base64ToUint8Array(encryptedData.encryptedX25519Private);

		let x25519Private: Uint8Array;
		try {
			let decryptedX25519Private: Uint8Array;

			// Try XChaCha20-Poly1305 first (new format)
			if (encryptedData.x25519Nonce) {
				const x25519Nonce = CryptoUtils.Base64.base64ToUint8Array(encryptedData.x25519Nonce);
				decryptedX25519Private = CryptoUtils.XChaCha20Poly1305.decryptWithNonce(key, x25519Nonce, encryptedX25519Private);
			} else {
				// Fallback to AES-GCM (legacy format)
				const iv = CryptoUtils.Base64.base64ToUint8Array(encryptedData.iv);
				const decryptedBuffer = await crypto.subtle.decrypt(
					{ name: 'AES-GCM', iv },
					this.masterKey,
					encryptedX25519Private
				);
				decryptedX25519Private = new Uint8Array(decryptedBuffer);
			}

			const decryptedText = new TextDecoder().decode(decryptedX25519Private);
			const parsedArray = JSON.parse(decryptedText);

			if (!Array.isArray(parsedArray) || parsedArray.length !== 32) {
				throw new Error(`Invalid X25519 private key length: ${parsedArray?.length}, expected 32`);
			}

			x25519Private = new Uint8Array(parsedArray);
		} catch (error) {
			console.error('X25519 decryption failed:', error);
			throw error;
		}

		const encryptedKyberSecret = CryptoUtils.Base64.base64ToUint8Array(encryptedData.encryptedKyberSecret);

		let kyberSecret: Uint8Array;
		try {
			let decryptedKyberSecret: Uint8Array;

			// Try XChaCha20-Poly1305 first (new format)
			if (encryptedData.kyberNonce) {
				const kyberNonce = CryptoUtils.Base64.base64ToUint8Array(encryptedData.kyberNonce);
				decryptedKyberSecret = CryptoUtils.XChaCha20Poly1305.decryptWithNonce(key, kyberNonce, encryptedKyberSecret);
			} else {
				// Fallback to AES-GCM (legacy format)
				const iv = CryptoUtils.Base64.base64ToUint8Array(encryptedData.iv);
				const decryptedBuffer = await crypto.subtle.decrypt(
					{ name: 'AES-GCM', iv },
					this.masterKey,
					encryptedKyberSecret
				);
				decryptedKyberSecret = new Uint8Array(decryptedBuffer);
			}

			const decryptedText = new TextDecoder().decode(decryptedKyberSecret);
			const parsedArray = JSON.parse(decryptedText);

			if (!Array.isArray(parsedArray) || parsedArray.length !== 2400) {
				throw new Error(`Invalid Kyber secret key length: ${parsedArray?.length}, expected 2400`);
			}

			kyberSecret = new Uint8Array(parsedArray);
		} catch (error) {
			console.error('Kyber decryption failed:', error);
			throw error;
		}

		// Handle optional Dilithium3 keys
		let dilithiumKeys: { publicKeyBase64: string; secretKey: Uint8Array } | undefined;

		if (encryptedData.encryptedDilithiumSecret && encryptedData.dilithiumPublicBase64) {
			try {
				const encryptedDilithiumSecret = CryptoUtils.Base64.base64ToUint8Array(encryptedData.encryptedDilithiumSecret);
				let decryptedDilithiumSecret: Uint8Array;

				// Try XChaCha20-Poly1305 first (new format)
				if (encryptedData.dilithiumNonce) {
					const dilithiumNonce = CryptoUtils.Base64.base64ToUint8Array(encryptedData.dilithiumNonce);
					decryptedDilithiumSecret = CryptoUtils.XChaCha20Poly1305.decryptWithNonce(key, dilithiumNonce, encryptedDilithiumSecret);
				} else {
					// Fallback to AES-GCM (legacy format)
					const iv = CryptoUtils.Base64.base64ToUint8Array(encryptedData.iv);
					const decryptedBuffer = await crypto.subtle.decrypt(
						{ name: 'AES-GCM', iv },
						this.masterKey,
						encryptedDilithiumSecret
					);
					decryptedDilithiumSecret = new Uint8Array(decryptedBuffer);
				}

				const decryptedText = new TextDecoder().decode(decryptedDilithiumSecret);
				const parsedArray = JSON.parse(decryptedText);

				if (!Array.isArray(parsedArray)) {
					throw new Error('Invalid Dilithium secret key format');
				}

				dilithiumKeys = {
					publicKeyBase64: encryptedData.dilithiumPublicBase64,
					secretKey: new Uint8Array(parsedArray)
				};
			} catch (error) {
				console.error('Dilithium decryption failed:', error);
				// Don't throw - Dilithium keys are optional for backward compatibility
			}
		}

		const result: DecryptedKeys = {
			x25519: {
				private: x25519Private,
				publicKeyBase64: encryptedData.x25519PublicBase64
			},
			kyber: {
				publicKeyBase64: encryptedData.kyberPublicBase64,
				secretKey: kyberSecret
			}
		};

		if (dilithiumKeys) {
			result.dilithium = dilithiumKeys;
		}

		return result;
	}

	async getPublicKeys(): Promise<{ x25519PublicBase64: string; kyberPublicBase64: string; dilithiumPublicBase64?: string } | null> {
		const encryptedData = await this.getEncryptedKeys();
		if (!encryptedData) {
			return null;
		}

		const result: { x25519PublicBase64: string; kyberPublicBase64: string; dilithiumPublicBase64?: string } = {
			x25519PublicBase64: encryptedData.x25519PublicBase64,
			kyberPublicBase64: encryptedData.kyberPublicBase64
		};

		if (encryptedData.dilithiumPublicBase64) {
			result.dilithiumPublicBase64 = encryptedData.dilithiumPublicBase64;
		}

		return result;
	}

	clearKeys(): void {
		this.masterKey = null;
	}

	async hasKeys(): Promise<boolean> {
		const encryptedData = await this.getEncryptedKeys();
		return encryptedData !== null;
	}

	async migrateToArgon2(passphrase: string): Promise<boolean> {
		// check if migration is needed
		const metadata = await this.getKeyMetadata();
		if (!metadata || metadata.argon2Params) {
			return false; // already using argon2 or no keys exist
		}

		// decrypt existing keys using pbkdf2
		const existingKeys = await this.getKeys();
		if (!existingKeys) {
			return false;
		}

		// re-encrypt with argon2id
		await this.storeKeys(existingKeys);
		return true;
	}

	async deleteKeys(): Promise<void> {
		const db = await this.openDB();
		return new Promise((resolve, reject) => {
			const tx = db.transaction(this.storeName, 'readwrite');
			const store = tx.objectStore(this.storeName);

			const deleteMetadata = store.delete('metadata');
			const deleteKeys = store.delete('keys');

			deleteMetadata.onsuccess = () => {
				deleteKeys.onsuccess = () => {
					tx.oncomplete = () => resolve();
					tx.onerror = () => reject(tx.error);
				};
				deleteKeys.onerror = () => reject(deleteKeys.error);
			};
			deleteMetadata.onerror = () => reject(deleteMetadata.error);
		});
	}

	async deleteDatabase(): Promise<void> {
		return new Promise((resolve, reject) => {
			const request = indexedDB.deleteDatabase(this.dbName);

			request.onsuccess = () => {
				resolve();
			};

			request.onerror = () => {
				reject(request.error);
			};
		});
	}

	private async openDB(): Promise<IDBDatabase> {
		return new Promise((resolve, reject) => {
			const request = indexedDB.open(this.dbName, 1);

			request.onerror = () => reject(request.error);
			request.onsuccess = () => resolve(request.result);

			request.onupgradeneeded = (event) => {
				const db = (event.target as IDBOpenDBRequest).result;
				if (!db.objectStoreNames.contains(this.storeName)) {
					db.createObjectStore(this.storeName, { keyPath: 'username' });
				}
			};
		});
	}

	private async storeKeyMetadata(metadata: { salt: string; iv: string; argon2Params?: { version: number; algorithm: string; memoryCost: number; timeCost: number; parallelism: number } }): Promise<void> {
		try {
			const db = await this.openDB();
			return new Promise((resolve, reject) => {
				const tx = db.transaction(this.storeName, 'readwrite');
				const store = tx.objectStore(this.storeName);
				const request = store.put({ username: 'metadata', type: 'metadata', ...metadata });
				request.onsuccess = () => { tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); };
				request.onerror = () => reject(request.error);
			});
		} catch {
			this.memoryMode = true;
			this.memory['metadata'] = metadata;
		}
	}

	async getKeyMetadata(): Promise<{ salt: string; iv: string; argon2Params?: { version: number; algorithm: string; memoryCost: number; timeCost: number; parallelism: number } } | null> {
		try {
			const db = await this.openDB();
			return new Promise((resolve, reject) => {
				const tx = db.transaction(this.storeName, 'readonly');
				const store = tx.objectStore(this.storeName);
				const request = store.get('metadata');
				request.onsuccess = () => {
					const result = request.result;
					if (result && result.type === 'metadata') {
						resolve({ salt: result.salt, iv: result.iv, argon2Params: result.argon2Params });
					} else {
						resolve(null);
					}
				};
				request.onerror = () => reject(request.error);
			});
		} catch {
			this.memoryMode = true;
			return this.memory['metadata'] || null;
		}
	}

	private async storeEncryptedKeys(encryptedData: EncryptedKeyData): Promise<void> {
		try {
			const db = await this.openDB();
			return new Promise((resolve, reject) => {
				const tx = db.transaction(this.storeName, 'readwrite');
				const store = tx.objectStore(this.storeName);
				const request = store.put({ username: 'keys', type: 'keys', ...encryptedData });
				request.onsuccess = () => { tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); };
				request.onerror = () => reject(request.error);
			});
		} catch {
			this.memoryMode = true;
			this.memory['keys'] = encryptedData;
		}
	}

	private async getEncryptedKeys(): Promise<EncryptedKeyData | null> {
		try {
			const db = await this.openDB();
			return new Promise((resolve, reject) => {
				const tx = db.transaction(this.storeName, 'readonly');
				const store = tx.objectStore(this.storeName);
				const request = store.get('keys');
				request.onsuccess = () => {
					const result = request.result;
					if (result && result.type === 'keys') {
						resolve({
							encryptedX25519Private: result.encryptedX25519Private,
							encryptedKyberSecret: result.encryptedKyberSecret,
							x25519PublicBase64: result.x25519PublicBase64,
							kyberPublicBase64: result.kyberPublicBase64,
							salt: result.salt,
							iv: result.iv
						});
					} else {
						resolve(null);
					}
				};
				request.onerror = () => reject(request.error);
			});
		} catch {
			this.memoryMode = true;
			return this.memory['keys'] || null;
		}
	}






}
