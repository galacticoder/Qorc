import { CryptoUtils } from "../unified-crypto";
import type { SessionState } from "./types";

type EncodedSession = {
	rootKey: string;
	currentDhPrivate: string;
	currentDhPublic: string;
	remoteDhPublic: string;
	sendChainKey: string;
	recvChainKey: string;
	sendMessageNumber: number;
	recvMessageNumber: number;
	previousSendMessageCount: number;
	skippedMessageKeys: Record<string, string>;
	usedSignedPreKeyId?: string;
	usedOneTimePreKeyId?: string;
};

function u8(b64: string): Uint8Array { return CryptoUtils.Base64.base64ToUint8Array(b64); }
function b64(u: Uint8Array): string { return CryptoUtils.Base64.arrayBufferToBase64(u); }

export class PersistentSessionStore {
	private static username: string | null = null;
	private static aesKey: CryptoKey | null = null;
	private static cache: Record<string, SessionState> = {};

	static setUserContext(username: string, aesKey: CryptoKey | null) {
		if (!username || !aesKey) return;
		this.username = username;
		this.aesKey = aesKey;
	}

	static clearAll(): void {
		if (this.username) {
			try { localStorage.removeItem(`securechat_sessions_${this.username}`); } catch { }
		}
		this.cache = {};
	}

	static async load(): Promise<void> {
		if (!this.username || !this.aesKey) return;
		const raw = localStorage.getItem(`securechat_sessions_${this.username}`);
		if (!raw) { this.cache = {}; return; }
		try {
			const des = JSON.parse(raw) as { data: string };
			const { iv, authTag, encrypted } = CryptoUtils.Decrypt.deserializeEncryptedDataFromUint8Array(CryptoUtils.Base64.base64ToUint8Array(des.data));
			const json = await CryptoUtils.Decrypt.decryptWithAESRaw(iv, authTag, encrypted, this.aesKey);
			const parsed = JSON.parse(json) as Record<string, EncodedSession>;
			this.cache = {};
			for (const [peer, s] of Object.entries(parsed)) {
				const skipped = new Map<string, Uint8Array>();
				for (const [k, v] of Object.entries(s.skippedMessageKeys)) skipped.set(k, u8(v));
				this.cache[peer] = {
					rootKey: u8(s.rootKey),
					currentDhPrivate: u8(s.currentDhPrivate),
					currentDhPublic: u8(s.currentDhPublic),
					remoteDhPublic: u8(s.remoteDhPublic),
					sendChainKey: u8(s.sendChainKey),
					recvChainKey: u8(s.recvChainKey),
					sendMessageNumber: s.sendMessageNumber,
					recvMessageNumber: s.recvMessageNumber,
					previousSendMessageCount: s.previousSendMessageCount,
					skippedMessageKeys: skipped,
					...(s.usedSignedPreKeyId ? { usedSignedPreKeyId: s.usedSignedPreKeyId } : {}),
					...(s.usedOneTimePreKeyId ? { usedOneTimePreKeyId: s.usedOneTimePreKeyId } : {}),
				};
			}
		} catch {
			this.cache = {};
		}
	}

	private static async persist(): Promise<void> {
		if (!this.username || !this.aesKey) return;
		const out: Record<string, EncodedSession> = {};
		for (const [peer, s] of Object.entries(this.cache)) {
			const skipped: Record<string, string> = {};
			s.skippedMessageKeys.forEach((v, k) => { skipped[k] = b64(v); });
			out[peer] = {
				rootKey: b64(s.rootKey),
				currentDhPrivate: b64(s.currentDhPrivate),
				currentDhPublic: b64(s.currentDhPublic),
				remoteDhPublic: b64(s.remoteDhPublic),
				sendChainKey: b64(s.sendChainKey),
				recvChainKey: b64(s.recvChainKey),
				sendMessageNumber: s.sendMessageNumber,
				recvMessageNumber: s.recvMessageNumber,
				previousSendMessageCount: s.previousSendMessageCount,
				skippedMessageKeys: skipped,
				...(s.usedSignedPreKeyId ? { usedSignedPreKeyId: s.usedSignedPreKeyId } : {}),
				...(s.usedOneTimePreKeyId ? { usedOneTimePreKeyId: s.usedOneTimePreKeyId } : {}),
			};
		}
		const json = JSON.stringify(out);
		const { iv, authTag, encrypted } = await CryptoUtils.AES.encryptWithAesGcmRaw(json, this.aesKey);
		const serialized = CryptoUtils.Encrypt.serializeEncryptedData(iv, authTag, encrypted);
		localStorage.setItem(`securechat_sessions_${this.username}`, JSON.stringify({ data: serialized }));
	}

	static get(peer: string): SessionState | null { return this.cache[peer] || null; }
	static async set(peer: string, state: SessionState): Promise<void> { this.cache[peer] = state; await this.persist(); }
	static async remove(peer: string): Promise<void> { delete this.cache[peer]; await this.persist(); }
}


