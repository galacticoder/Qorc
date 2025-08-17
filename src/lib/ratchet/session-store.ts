import type { SessionState } from "./types";
import { PersistentSessionStore } from "./persistent-session-store";

export class SessionStore {
	private static inMemory = new Map<string, SessionState>();
	private static currentUser: string | null = null;

	static sessionKey(currentUser: string, peer: string): string {
		return `${currentUser}::${peer}`;
	}

	static get(currentUser: string, peer: string): SessionState | null {
		const key = this.sessionKey(currentUser, peer);
		const existing = this.inMemory.get(key);
		if (existing) return existing;

		const cached = PersistentSessionStore.get(peer);
		if (cached) {
			this.inMemory.set(key, cached);
			return cached;
		}
		return null;
	}

	static set(currentUser: string, peer: string, state: SessionState): void {
		const key = this.sessionKey(currentUser, peer);
		this.inMemory.set(key, state);
		PersistentSessionStore.set(peer, state).catch(() => { });
	}

	static clear(currentUser: string, peer: string): void {
		this.inMemory.delete(this.sessionKey(currentUser, peer));
		PersistentSessionStore.remove(peer).catch(() => { });
	}

	static async initUserContext(currentUser: string, aesKey: CryptoKey | null) {
		this.currentUser = currentUser;
		PersistentSessionStore.setUserContext(currentUser, aesKey);
		await PersistentSessionStore.load();
	}

	static clearAllForCurrentUser(): void {
		if (!this.currentUser) return;
		// clear in memory entries for this user
		for (const key of Array.from(this.inMemory.keys())) {
			if (key.startsWith(`${this.currentUser}::`)) this.inMemory.delete(key);
		}
		// clear persisted store
		PersistentSessionStore.clearAll();
	}
}


