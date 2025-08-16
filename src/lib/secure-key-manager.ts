import { CryptoUtils } from './unified-crypto';

interface EncryptedKeyData {
	encryptedX25519Private: string;
	encryptedKyberSecret: string;
	x25519PublicBase64: string;
	kyberPublicBase64: string;
	salt: string;
	iv: string;
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
}

export class SecureKeyManager {
	private dbName: string;
	private storeName = 'encryptedKeys';
	private masterKey: CryptoKey | null = null;
	private username: string;

	constructor(username: string) {
		this.username = username;
		this.dbName = `SecureKeyDB_${username}`;
	}

	async initialize(passphrase: string, salt?: string): Promise<void> {
		if (this.masterKey) {
			return;
		}

		let keySalt: Uint8Array;
		let keyIv: Uint8Array;

		if (salt) {
			keySalt = CryptoUtils.Base64.base64ToUint8Array(salt);
			keyIv = crypto.getRandomValues(new Uint8Array(12));
		} else {
			keySalt = crypto.getRandomValues(new Uint8Array(16));
			keyIv = crypto.getRandomValues(new Uint8Array(12));
		}

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
			false,
			['encrypt', 'decrypt']
		);

		this.masterKey = derivedKey;

		if (!salt) {
			await this.storeKeyMetadata({
				salt: CryptoUtils.Base64.arrayBufferToBase64(keySalt),
				iv: CryptoUtils.Base64.arrayBufferToBase64(keyIv)
			});

			const storedMetadata = await this.getKeyMetadata();
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

		const x25519PrivateBytes = new TextEncoder().encode(JSON.stringify(Array.from(keys.x25519.private)));

		const encryptedX25519Private = await crypto.subtle.encrypt(
			{ name: 'AES-GCM', iv },
			this.masterKey,
			x25519PrivateBytes
		);

		const kyberSecretBytes = new TextEncoder().encode(JSON.stringify(Array.from(keys.kyber.secretKey)));

		const encryptedKyberSecret = await crypto.subtle.encrypt(
			{ name: 'AES-GCM', iv },
			this.masterKey,
			kyberSecretBytes
		);

		const encryptedData: EncryptedKeyData = {
			encryptedX25519Private: CryptoUtils.Base64.arrayBufferToBase64(encryptedX25519Private),
			encryptedKyberSecret: CryptoUtils.Base64.arrayBufferToBase64(encryptedKyberSecret),
			x25519PublicBase64: keys.x25519.publicKeyBase64,
			kyberPublicBase64: keys.kyber.publicKeyBase64,
			salt: metadata.salt,
			iv: metadata.iv
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

		const iv = CryptoUtils.Base64.base64ToUint8Array(encryptedData.iv);

		const encryptedX25519Private = CryptoUtils.Base64.base64ToUint8Array(encryptedData.encryptedX25519Private);

		let x25519Private: Uint8Array;
		try {
			const decryptedX25519Private = await crypto.subtle.decrypt(
				{ name: 'AES-GCM', iv },
				this.masterKey,
				encryptedX25519Private
			);
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
			const decryptedKyberSecret = await crypto.subtle.decrypt(
				{ name: 'AES-GCM', iv },
				this.masterKey,
				encryptedKyberSecret
			);
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

		return {
			x25519: {
				private: x25519Private,
				publicKeyBase64: encryptedData.x25519PublicBase64
			},
			kyber: {
				publicKeyBase64: encryptedData.kyberPublicBase64,
				secretKey: kyberSecret
			}
		};
	}

	async getPublicKeys(): Promise<{ x25519PublicBase64: string; kyberPublicBase64: string } | null> {
		const encryptedData = await this.getEncryptedKeys();
		if (!encryptedData) {
			return null;
		}

		return {
			x25519PublicBase64: encryptedData.x25519PublicBase64,
			kyberPublicBase64: encryptedData.kyberPublicBase64
		};
	}

	clearKeys(): void {
		this.masterKey = null;
	}

	async hasKeys(): Promise<boolean> {
		const encryptedData = await this.getEncryptedKeys();
		return encryptedData !== null;
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

	private async storeKeyMetadata(metadata: { salt: string; iv: string }): Promise<void> {
		const db = await this.openDB();
		return new Promise((resolve, reject) => {
			const tx = db.transaction(this.storeName, 'readwrite');
			const store = tx.objectStore(this.storeName);

			const request = store.put({
				username: 'metadata',
				type: 'metadata',
				...metadata
			});

			request.onsuccess = () => {
				tx.oncomplete = () => resolve();
				tx.onerror = () => reject(tx.error);
			};

			request.onerror = () => reject(request.error);
		});
	}

	async getKeyMetadata(): Promise<{ salt: string; iv: string } | null> {
		const db = await this.openDB();
		return new Promise((resolve, reject) => {
			const tx = db.transaction(this.storeName, 'readonly');
			const store = tx.objectStore(this.storeName);

			const request = store.get('metadata');

			request.onsuccess = () => {
				const result = request.result;

				if (result && result.type === 'metadata') {
					resolve({
						salt: result.salt,
						iv: result.iv
					});
				} else {
					resolve(null);
				}
			};

			request.onerror = () => reject(request.error);
		});
	}

	private async storeEncryptedKeys(encryptedData: EncryptedKeyData): Promise<void> {
		const db = await this.openDB();
		return new Promise((resolve, reject) => {
			const tx = db.transaction(this.storeName, 'readwrite');
			const store = tx.objectStore(this.storeName);

			const request = store.put({
				username: 'keys',
				type: 'keys',
				...encryptedData
			});

			request.onsuccess = () => {
				tx.oncomplete = () => resolve();
				tx.onerror = () => reject(tx.error);
			};

			request.onerror = () => reject(request.error);
		});
	}

	private async getEncryptedKeys(): Promise<EncryptedKeyData | null> {
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
	}
}
