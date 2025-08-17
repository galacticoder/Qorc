import { CryptoUtils } from "../unified-crypto";
import type { RatchetMessage, SessionState } from "./types";

export class DoubleRatchet {
	static async kdfRoot(rootKey: Uint8Array, dhOutput: Uint8Array): Promise<{ rootKey: Uint8Array; chainKey: Uint8Array }> {
		const input = new Uint8Array(rootKey.length + dhOutput.length);
		input.set(rootKey, 0);
		input.set(dhOutput, rootKey.length);
		const okm = await CryptoUtils.KDF.hkdfDerive(input, new Uint8Array(32), new TextEncoder().encode("root-kdf"), 64);
		return { rootKey: okm.slice(0, 32), chainKey: okm.slice(32, 64) };
	}

	static async kdfChain(chainKey: Uint8Array): Promise<{ nextChainKey: Uint8Array; messageKey: Uint8Array }> {
		const okm = await CryptoUtils.KDF.hkdfDerive(chainKey, new Uint8Array(32), new TextEncoder().encode("chain-kdf"), 64);
		return { nextChainKey: okm.slice(0, 32), messageKey: okm.slice(32, 64) };
	}

	static async ratchetStep(state: SessionState, remoteDhPublic: Uint8Array): Promise<SessionState> {
		const x = await (await import("@noble/curves/ed25519")).x25519 || (await import("@noble/curves")).x25519;
		state.previousSendMessageCount = state.sendMessageNumber;
		state.sendMessageNumber = 0;
		state.recvMessageNumber = 0;
		state.remoteDhPublic = remoteDhPublic;

		const dhOut = x.getSharedSecret(state.currentDhPrivate, remoteDhPublic);
		const { rootKey, chainKey } = await this.kdfRoot(state.rootKey, dhOut);
		state.rootKey = rootKey;
		state.recvChainKey = chainKey;

		// advance our sending ratchet key
		const ourNewSk = x.utils.randomPrivateKey();
		const ourNewPk = x.getPublicKey(ourNewSk);
		state.currentDhPrivate = ourNewSk;
		state.currentDhPublic = ourNewPk;

		const dhOut2 = x.getSharedSecret(ourNewSk, remoteDhPublic);
		const { chainKey: sendChain } = await this.kdfRoot(state.rootKey, dhOut2);
		state.sendChainKey = sendChain;
		return state;
	}

	static async encrypt(state: SessionState, plaintext: string): Promise<RatchetMessage> {
		// if this is the very first send on this session derive the initial send chain from root plus dh current remote
		if (state.sendMessageNumber === 0 && state.previousSendMessageCount === 0 && state.sendChainKey.every((b) => b === 0)) {
			const x = await (await import("@noble/curves/ed25519")).x25519 || (await import("@noble/curves")).x25519;
			const dhOut = x.getSharedSecret(state.currentDhPrivate, state.remoteDhPublic);
			const { rootKey, chainKey } = await this.kdfRoot(state.rootKey, dhOut);
			state.rootKey = rootKey;
			state.sendChainKey = chainKey;
			try {
				console.debug('[DR] Initial send chain derived', {
					dhOutLen: dhOut.length,
					rootKeyLen: rootKey.length,
					chainKeyLen: chainKey.length,
					currentDhPublicPrefix: CryptoUtils.Base64.arrayBufferToBase64(state.currentDhPublic).slice(0, 24) + '...',
					remoteDhPublicPrefix: CryptoUtils.Base64.arrayBufferToBase64(state.remoteDhPublic).slice(0, 24) + '...',
				});
			} catch { }
		}
		const { nextChainKey, messageKey } = await this.kdfChain(state.sendChainKey);
		state.sendChainKey = nextChainKey;
		const header = { dhPub: state.currentDhPublic, pn: state.previousSendMessageCount, n: state.sendMessageNumber++ };
		const aesKey = await CryptoUtils.Keys.importRawAesKey(messageKey);
		const { iv, authTag, encrypted } = await CryptoUtils.AES.encryptWithAesGcmRaw(plaintext, aesKey);
		const ciphertext = CryptoUtils.AES.serializeEncryptedData(iv, authTag, encrypted);
		try {
			console.debug('[DR] encrypt', {
				pn: header.pn,
				n: header.n,
				ciphertextLen: ciphertext.length,
			});
		} catch { }
		return { header, ciphertext };
	}

	static async tryDecryptWithSkipped(state: SessionState, headerKey: string, ciphertext: string): Promise<string | null> {
		const mk = state.skippedMessageKeys.get(headerKey);
		if (!mk) return null;
		state.skippedMessageKeys.delete(headerKey);
		const aesKey = await CryptoUtils.Keys.importRawAesKey(mk);
		const des = CryptoUtils.AES.deserializeEncryptedData(ciphertext);
		return await CryptoUtils.AES.decryptWithAesGcmRaw(des.iv, des.authTag, des.encrypted, aesKey);
	}

	static async decrypt(state: SessionState, message: RatchetMessage): Promise<string> {
		const x = await (await import("@noble/curves/ed25519")).x25519 || (await import("@noble/curves")).x25519;
		const headerKey = `${CryptoUtils.Base64.arrayBufferToBase64(message.header.dhPub)}:${message.header.n}`;
		try { console.debug('[DR] decrypt begin', { pn: message.header.pn, n: message.header.n, ctLen: (message.ciphertext || '').length }); } catch { }
		const trySkipped = await this.tryDecryptWithSkipped(state, headerKey, message.ciphertext);
		if (trySkipped !== null) return trySkipped;

		const sameRemote = (() => {
			const a = state.remoteDhPublic;
			const b = message.header.dhPub;
			if (a.length !== b.length) return false;
			for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
			return true;
		})();
		try { console.debug('[DR] sameRemote', sameRemote); } catch { }
		if (!sameRemote) {
			// new ratchet step
			const dhOut = x.getSharedSecret(state.currentDhPrivate, message.header.dhPub);
			const { rootKey, chainKey } = await this.kdfRoot(state.rootKey, dhOut);
			state.rootKey = rootKey;
			state.recvChainKey = chainKey;
			state.remoteDhPublic = message.header.dhPub;
			state.recvMessageNumber = 0;
			try {
				console.debug('[DR] ratchet step performed', {
					dhOutLen: dhOut.length,
					rootKeyLen: rootKey.length,
					chainKeyLen: chainKey.length,
					currentDhPublicPrefix: CryptoUtils.Base64.arrayBufferToBase64(state.currentDhPublic).slice(0, 24) + '...',
					messageDhPublicPrefix: CryptoUtils.Base64.arrayBufferToBase64(message.header.dhPub).slice(0, 24) + '...',
				});
			} catch { }
		}

		// if this is the very first receive on this session and the receive chain key is all zeros
		// derive the initial receive chain from root plus dh current remote this mirrors the senders
		// initial send chain derivation and is required when the receiver bootstraps a session from x3dh
		// and the incoming header dhpub already matches state remotedhpublic
		if (sameRemote && state.recvMessageNumber === 0 && state.recvChainKey.every((b) => b === 0)) {
			const dhOut = x.getSharedSecret(state.currentDhPrivate, message.header.dhPub);
			const { rootKey, chainKey } = await this.kdfRoot(state.rootKey, dhOut);
			state.rootKey = rootKey;
			state.recvChainKey = chainKey;
			try {
				console.debug('[DR] Initial receive chain derived', {
					dhOutLen: dhOut.length,
					rootKeyLen: rootKey.length,
					chainKeyLen: chainKey.length,
					currentDhPublicPrefix: CryptoUtils.Base64.arrayBufferToBase64(state.currentDhPublic).slice(0, 24) + '...',
					remoteDhPublicPrefix: CryptoUtils.Base64.arrayBufferToBase64(state.remoteDhPublic).slice(0, 24) + '...',
				});
			} catch { }
		}

		while (state.recvMessageNumber < message.header.n) {
			const { nextChainKey, messageKey } = await this.kdfChain(state.recvChainKey);
			state.recvChainKey = nextChainKey;
			const key = `${CryptoUtils.Base64.arrayBufferToBase64(state.remoteDhPublic)}:${state.recvMessageNumber}`;
			state.skippedMessageKeys.set(key, messageKey);
			state.recvMessageNumber++;
		}

		const { nextChainKey, messageKey } = await this.kdfChain(state.recvChainKey);
		state.recvChainKey = nextChainKey;
		state.recvMessageNumber++;
		try {
			console.debug('[DR] Message key derived', {
				messageKeyLen: messageKey.length,
				nextChainKeyLen: nextChainKey.length,
			});
		} catch { }
		const aesKey = await CryptoUtils.Keys.importRawAesKey(messageKey);
		const des = CryptoUtils.AES.deserializeEncryptedData(message.ciphertext);
		try {
			console.debug('[DR] aes params', { ivLen: des.iv.length, tagLen: des.authTag.length, encLen: des.encrypted.length });
		} catch { }
		const out = await CryptoUtils.AES.decryptWithAesGcmRaw(des.iv, des.authTag, des.encrypted, aesKey);
		try { console.debug('[DR] decrypt ok, length', (out || '').length); } catch { }
		return out;
	}
}


