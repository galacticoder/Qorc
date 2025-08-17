export type ServerHybridKeys = {
	x25519PublicBase64: string;
	kyberPublicBase64: string;
};

export class PinnedServer {
	private static storageKey = 'securechat_server_pin_v1';

	static get(): ServerHybridKeys | null {
		try {
			const raw = localStorage.getItem(this.storageKey);
			if (!raw) return null;
			const obj = JSON.parse(raw);
			if (typeof obj?.x25519PublicBase64 === 'string' && typeof obj?.kyberPublicBase64 === 'string') {
				return { x25519PublicBase64: obj.x25519PublicBase64, kyberPublicBase64: obj.kyberPublicBase64 };
			}
			return null;
		} catch {
			return null;
		}
	}

	static set(keys: ServerHybridKeys): void {
		try {
			localStorage.setItem(this.storageKey, JSON.stringify(keys));
		} catch { }
	}

	static clear(): void {
		try { localStorage.removeItem(this.storageKey); } catch { }
	}
}


