export interface IdentityKeyPair {
	// long term signing identity (ed25519 + dilithium)
	ed25519Public: Uint8Array;
	ed25519Private: Uint8Array;
	dilithiumPublic: Uint8Array;
	dilithiumPrivate: Uint8Array;

	// long term dh identity (x25519)
	x25519Public: Uint8Array;
	x25519Private: Uint8Array;
}

export interface SignedPreKey {
	id: string; // unique id for rotation
	publicKey: Uint8Array; // x25519 public
	ed25519Signature: Uint8Array; // ed25519 signature over identity and signed prekey
	dilithiumSignature?: Uint8Array; // dilithium signature over identity and signed prekey
	privateKey?: Uint8Array; // stored locally only
}

export interface OneTimePreKey {
	id: string;
	publicKey: Uint8Array; // x25519 public
	privateKey?: Uint8Array; // stored locally only
}

export interface PreKeyBundle {
	username: string;
	identityEd25519Public: Uint8Array;
	identityDilithiumPublic?: Uint8Array;
	identityX25519Public: Uint8Array;
	signedPreKey: SignedPreKey;
	oneTimePreKey?: OneTimePreKey | null; // dispensed one time prekey
	ratchetPublic: Uint8Array; // receivers initial ratchet public key
}

export interface X3DHInitEnvelope {
	ephX25519PublicBase64: string;
	usedSignedPreKeyId: string;
	usedOneTimePreKeyId?: string;
}

export interface X3DHInitResponse {
	to: string;
	from: string;
	// receivers current dh ratchet public key for starting double ratchet
	receiverRatchetPublic: Uint8Array; // x25519
}

export interface RatchetHeader {
	dhPub: Uint8Array; // current sending ratchet public key
	pn: number; // number of messages in previous sending chain
	n: number; // message number in current sending chain
}

export interface RatchetMessage {
	header: RatchetHeader;
	ciphertext: string; // base64 encoded aes gcm ciphertext
	blake3Mac?: string; // base64 encoded BLAKE3 MAC for additional integrity
}

export interface SessionState {
	// root key for kdf chain
	rootKey: Uint8Array;

	// our current dh ratchet key pair
	currentDhPrivate: Uint8Array;
	currentDhPublic: Uint8Array;

	// their current dh ratchet public key
	remoteDhPublic: Uint8Array;

	// sending and receiving chain keys and counters
	sendChainKey: Uint8Array;
	recvChainKey: Uint8Array;
	sendMessageNumber: number;
	recvMessageNumber: number;
	previousSendMessageCount: number;

	// skipped message keys map dhpubbase64:n to messagekey
	skippedMessageKeys: Map<string, Uint8Array>;

	// x3dh metadata for receiver bootstrap
	usedSignedPreKeyId?: string;
	usedOneTimePreKeyId?: string;
}


