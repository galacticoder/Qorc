import { CryptoUtils } from "../unified-crypto";
import type { IdentityKeyPair, OneTimePreKey, PreKeyBundle, SignedPreKey } from "./types";

export class X3DH {
	static async generateIdentityKeyPair(): Promise<IdentityKeyPair> {
		// ed25519 + dilithium for signing, x25519 for dh
		const noble = await import("@noble/curves/ed25519");
		const ed = noble.ed25519;
		const x = noble.x25519 || (await import("@noble/curves")).x25519;

		const edSk = ed.utils.randomPrivateKey();
		const edPk = ed.getPublicKey(edSk);

		const dilithiumKP = await CryptoUtils.Dilithium.generateKeyPair();

		const xSk = x.utils.randomPrivateKey();
		const xPk = x.getPublicKey(xSk);

		return {
			ed25519Private: edSk,
			ed25519Public: edPk,
			dilithiumPrivate: dilithiumKP.secretKey,
			dilithiumPublic: dilithiumKP.publicKey,
			x25519Private: xSk,
			x25519Public: xPk,
		};
	}

	static async generateSignedPreKey(identityEd25519Private: Uint8Array, identityDilithiumPrivate: Uint8Array): Promise<SignedPreKey> {
		const noble = await import("@noble/curves/ed25519");
		const ed = noble.ed25519;
		const x = noble.x25519 || (await import("@noble/curves")).x25519;

		const spkSk = x.utils.randomPrivateKey();
		const spkPk = x.getPublicKey(spkSk);
		const id = crypto.randomUUID();

		// Generate hybrid signatures (Ed25519 + Dilithium)
		const ed25519Signature = await ed.sign(spkPk, identityEd25519Private);
		const dilithiumSignature = await CryptoUtils.Dilithium.sign(spkPk, identityDilithiumPrivate);

		return {
			id,
			publicKey: spkPk,
			ed25519Signature: ed25519Signature,
			dilithiumSignature: dilithiumSignature,
			privateKey: spkSk,
		};
	}

	static async generateOneTimePreKeys(count: number): Promise<OneTimePreKey[]> {
		const noble = await import("@noble/curves/ed25519");
		const x = noble.x25519 || (await import("@noble/curves")).x25519;
		const keys: OneTimePreKey[] = [];
		for (let i = 0; i < count; i++) {
			const sk = x.utils.randomPrivateKey();
			const pk = x.getPublicKey(sk);
			keys.push({ id: crypto.randomUUID(), publicKey: pk, privateKey: sk });
		}
		return keys;
	}

	static async generateEphemeralX25519KeyPair(): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
		const noble = await import("@noble/curves/ed25519");
		const x = noble.x25519 || (await import("@noble/curves")).x25519;
		const sk = x.utils.randomPrivateKey();
		const pk = x.getPublicKey(sk);
		return { privateKey: sk, publicKey: pk };
	}

	static async deriveReceiverSecret(
		receiverIdentityXSk: Uint8Array,
		signedPreKeySk: Uint8Array,
		senderEphXPub: Uint8Array,
		oneTimePreKeySk?: Uint8Array
	): Promise<Uint8Array> {
		const x = await (await import("@noble/curves/ed25519")).x25519 || (await import("@noble/curves")).x25519;
		// match sender side combination dh2 dh3 optional dh4
		const DH2 = x.getSharedSecret(receiverIdentityXSk, senderEphXPub);
		const DH3 = x.getSharedSecret(signedPreKeySk, senderEphXPub);
		const DH4 = oneTimePreKeySk ? x.getSharedSecret(oneTimePreKeySk, senderEphXPub) : new Uint8Array();

		const ikm = new Uint8Array(DH2.length + DH3.length + DH4.length);
		let offset = 0;
		for (const part of [DH2, DH3, DH4]) {
			ikm.set(part, offset);
			offset += part.length;
		}

		// use a fixed zero salt so both sides derive the same root key
		const salt = new Uint8Array(32);
		const rootKey = await CryptoUtils.KDF.hkdfDerive(ikm, salt, new TextEncoder().encode("x3dh-root"), 32);
		return rootKey;
	}

	static async verifyPreKeyBundle(bundle: PreKeyBundle): Promise<boolean> {
		const noble = await import("@noble/curves/ed25519");
		const ed = noble.ed25519;
		
		// verify Ed25519 signature
		const ed25519Valid = ed.verify(bundle.signedPreKey.ed25519Signature, bundle.signedPreKey.publicKey, bundle.identityEd25519Public);
		
		// verify Dilithium signature if present
		let dilithiumValid = true;
		if (bundle.signedPreKey.dilithiumSignature && bundle.identityDilithiumPublic) {
			dilithiumValid = await CryptoUtils.Dilithium.verify(
				bundle.signedPreKey.dilithiumSignature, 
				bundle.signedPreKey.publicKey, 
				bundle.identityDilithiumPublic
			);
		}
		
		// both signatures must be valid
		return ed25519Valid && dilithiumValid;
	}

	// derive the x3dh shared secret for sender a using recipient b prekey bundle
	static async deriveSenderSecret(
		senderIdentityXSk: Uint8Array,
		ephXSk: Uint8Array,
		recipientBundle: PreKeyBundle,
		usedOneTimePreKey?: OneTimePreKey
	): Promise<Uint8Array> {
		const x = await (await import("@noble/curves/ed25519")).x25519 || (await import("@noble/curves")).x25519;

		// use dh2 dh3 optional dh4
		const DH2 = x.getSharedSecret(ephXSk, recipientBundle.identityX25519Public);
		const DH3 = x.getSharedSecret(ephXSk, recipientBundle.signedPreKey.publicKey);
		const DH4 = usedOneTimePreKey ? x.getSharedSecret(ephXSk, usedOneTimePreKey.publicKey) : new Uint8Array();

		const ikm = new Uint8Array(DH2.length + DH3.length + DH4.length);
		let offset = 0;
		for (const part of [DH2, DH3, DH4]) {
			ikm.set(part, offset);
			offset += part.length;
		}

		// use hkdf with fixed zero salt to match receiver side
		const salt = new Uint8Array(32);
		const rootKey = await CryptoUtils.KDF.hkdfDerive(ikm, salt, new TextEncoder().encode("x3dh-root"), 32);
		return rootKey;
	}
}


