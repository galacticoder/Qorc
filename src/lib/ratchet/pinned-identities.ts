export class PinnedIdentities {
	private static storageKey(currentUser: string): string {
		return `securechat_pins_${currentUser}`;
	}

	static get(currentUser: string, peer: string): string | null {
		try {
			const raw = localStorage.getItem(this.storageKey(currentUser));
			if (!raw) return null;
			const map = JSON.parse(raw) as Record<string, string>;
			return typeof map[peer] === 'string' ? map[peer] : null;
		} catch {
			return null;
		}
	}

	static set(currentUser: string, peer: string, identityEd25519PublicBase64: string): void {
		try {
			const key = this.storageKey(currentUser);
			const raw = localStorage.getItem(key);
			const map = raw ? (JSON.parse(raw) as Record<string, string>) : {};
			map[peer] = identityEd25519PublicBase64;
			localStorage.setItem(key, JSON.stringify(map));
		} catch {
			// ignore storage errors
		}
	}
}
