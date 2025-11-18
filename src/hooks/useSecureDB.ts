import { useRef, useEffect, useCallback, useState } from "react";
import { SecureDB } from "@/lib/secureDB";
import { Message } from "@/components/chat/types";
import { User } from "@/components/chat/UserList";
import { CryptoUtils } from "@/lib/unified-crypto";
import { SignalType } from "@/lib/signal-types";
import { encryptedStorage, syncEncryptedStorage } from "@/lib/encrypted-storage";
import { prewarmUsernameCache } from "@/hooks/useUnifiedUsernameDisplay";
import { blockingSystem } from "@/lib/blocking-system";
 

import websocketClient from "@/lib/websocket";

const MAX_PENDING_MESSAGES = 500;
const MAX_PENDING_MAPPINGS = 1000;
const MAX_DB_MESSAGES = 5000;
const RATE_LIMIT_WINDOW_MS = 10_000;
const RATE_LIMIT_MAX_EVENTS = 200;

const sanitizeUsername = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 128) return null;
  return trimmed;
};

const sanitizeMappingPayload = (value: unknown): { hashed: string; original: string } | null => {
  if (!value || typeof value !== 'object') return null;
  const hashed = sanitizeUsername((value as any).hashed);
  const original = sanitizeUsername((value as any).original);
  if (!hashed || !original) return null;
  return { hashed, original };
};

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== 'object' || value === null) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

const hasPrototypePollutionKeys = (obj: Record<string, unknown>): boolean => {
  return ['__proto__', 'prototype', 'constructor'].some(key => Object.prototype.hasOwnProperty.call(obj, key));
};

const validateEventDetail = (detail: unknown): boolean => {
  if (!isPlainObject(detail)) return false;
  if (hasPrototypePollutionKeys(detail)) return false;
  return true;
};

interface UseSecureDBProps {
	Authentication: any;
	setMessages: React.Dispatch<React.SetStateAction<Message[]>>;
}

export const useSecureDB = ({ Authentication, setMessages }: UseSecureDBProps) => {
	const secureDBRef = useRef<SecureDB | null>(null);
	const [dbInitialized, setDbInitialized] = useState(false);
	const [users, setUsers] = useState<User[]>([]);

	const pendingMessagesRef = useRef<Message[]>([]);
	const pendingMappingsRef = useRef<Array<{ hashed: string; original: string }>>([]);
	const debouncedSaveRef = useRef<ReturnType<typeof setTimeout> | null>(null);
	const pendingSavesRef = useRef<Set<string>>(new Set());
	const messageMapRef = useRef<Map<string, Message>>(new Map());
	const inflightDbOpRef = useRef<Promise<void>>(Promise.resolve());
	const eventRateLimitRef = useRef<{ windowStart: number; count: number }>({ windowStart: Date.now(), count: 0 });

	useEffect(() => {

		if (!Authentication?.isLoggedIn || dbInitialized || secureDBRef.current) {
			return;
		}

		// Initialize when username and AES key are available; passphrase fields are optional
		if (!Authentication.loginUsernameRef.current || !Authentication.aesKeyRef?.current) {
			return;
		}

		const initializeDB = async () => {
			try {
				const key = Authentication.aesKeyRef.current;
				if (
					!key ||
					typeof key !== 'object' ||
					!('type' in key) ||
					!('extractable' in key) ||
					!('algorithm' in key) ||
					!('usages' in key)
				) {
					console.error("[useSecureDB] Invalid CryptoKey");
					Authentication.setLoginError?.("Invalid stored key, cannot initialize secure storage");
					secureDBRef.current = null;
					Authentication.logout(secureDBRef).catch(console.error);
					return;
				}

secureDBRef.current = new SecureDB(Authentication.loginUsernameRef.current);
await secureDBRef.current.initializeWithKey(Authentication.aesKeyRef.current);
try { blockingSystem.setSecureDB(secureDBRef.current); } catch {}

			// Initialize block list after SecureDB is set
			try {
				const passphrase = Authentication.passphrasePlaintextRef?.current;
				const kyberSecret: Uint8Array | null = Authentication.hybridKeysRef?.current?.kyber?.secretKey || null;
				if (passphrase) {
					// Load the block list from local storage to restore blocked users
					await blockingSystem.getBlockedUsers(passphrase);
				} else if (kyberSecret) {
					await blockingSystem.getBlockedUsers({ kyberSecret });
				}
			} catch (_err) {
				console.error('[useSecureDB] Failed to load block list:', _err);
				// If decryption failed due to key mismatch, clear only block list data and proceed
				try {
					const msg = (_err as Error)?.message || String(_err);
					if (/decrypt|BLAKE3|passphrase|corrupt/i.test(msg)) {
						await Promise.all([
							secureDBRef.current!.clearStore('blockListData'),
							secureDBRef.current!.clearStore('blockListMeta')
						]);
						// Retry block list load once
						const passphrase = Authentication.passphrasePlaintextRef?.current;
						if (passphrase) {
							await blockingSystem.getBlockedUsers(passphrase).catch(() => {});
						}
					}
				} catch {}
			}
			
			if (Authentication.loginUsernameRef.current) {
				try {
					await secureDBRef.current.store('auth_metadata', 'current_user', Authentication.loginUsernameRef.current);
				} catch (_err) {
					console.error('[useSecureDB] Failed to store authenticated user:', _err);
				}
			}

			// Ensure our own username mapping exists (token-login case): map hashed -> original if present in SecureDB
			try {
				const currentHashed = Authentication.loginUsernameRef.current || '';
				if (currentHashed) {
					const existingOriginal = await secureDBRef.current.retrieve('auth_metadata', 'original_username');
					if (typeof existingOriginal === 'string' && existingOriginal) {
						try { await secureDBRef.current.storeUsernameMapping(currentHashed, existingOriginal); } catch {}
						try { window.dispatchEvent(new CustomEvent('username-mapping-updated', { detail: { username: currentHashed, original: existingOriginal } })); } catch {}
					}
				}
			} catch (_err) {
			}
			
			if (Authentication.originalUsernameRef?.current && Authentication.loginUsernameRef.current) {
				try {
					await secureDBRef.current.storeUsernameMapping(
						Authentication.loginUsernameRef.current,
						Authentication.originalUsernameRef.current
					);
					await secureDBRef.current.store('auth_metadata', 'original_username', Authentication.originalUsernameRef.current);
				} catch (_err) {
					console.error('[useSecureDB] Failed to pre-store username mapping:', _err);
				}
			}
			
			try {
				await encryptedStorage.initialize(secureDBRef.current);
				await syncEncryptedStorage.initialize();
			} catch (_err) {
				console.error('[useSecureDB] Failed to initialize encrypted storage:', _err);
				// If storage contains data from a previous key, clear only encrypted_storage entries and re-init
				try {
					const msg = (_err as Error)?.message || String(_err);
					if (/decrypt|BLAKE3|passphrase|corrupt/i.test(msg)) {
						await secureDBRef.current!.clearStore('encrypted_storage');
						await encryptedStorage.initialize(secureDBRef.current);
						await syncEncryptedStorage.initialize();
					}
				} catch {}
			}
			
			setDbInitialized(true);
				Authentication.passphraseRef.current = "";
			} catch (_err) {
				console.error("[useSecureDB] Failed to initialize SecureDB", _err);
				Authentication.setLoginError?.("Failed to initialize secure storage");
			}
		};

	initializeDB();
	}, [
		Authentication?.isLoggedIn,
		Authentication?.username,
		dbInitialized
	]);

	useEffect(() => {
		if (!Authentication?.isLoggedIn || !dbInitialized || !secureDBRef.current) return;

		const loadData = () => {
			if (!secureDBRef.current) return;

			// Pre-warm username cache from SecureDB to avoid hashed flicker on login
			(async () => {
				try {
					const mappings = await secureDBRef.current!.getAllUsernameMappings();
					if (Array.isArray(mappings) && mappings.length > 0) {
						prewarmUsernameCache(mappings);
					}
				} catch (_err) {
				}
			})();
			
			const currentUser = Authentication?.loginUsernameRef?.current;
			
			secureDBRef.current.loadRecentMessagesByConversation(50, currentUser)
				.then(savedMessages => {
					if (!savedMessages || savedMessages.length === 0) return;
					
					const processedMessages = savedMessages.map((msg: any) => ({
						...msg,
						timestamp: new Date(msg.timestamp),
						isCurrentUser:
							msg.sender === currentUser,
						receipt: msg.receipt ? {
							...msg.receipt,
							deliveredAt: msg.receipt.deliveredAt ? new Date(msg.receipt.deliveredAt) : undefined,
							readAt: msg.receipt.readAt ? new Date(msg.receipt.readAt) : undefined,
						} : undefined,
					}));

					const sortedMessages = processedMessages.sort((a, b) => 
						new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
					);

					setMessages(prevMessages => {
						const existingIds = new Set(prevMessages.map(msg => msg.id));
						const newMessages = sortedMessages.filter(msg => !existingIds.has(msg.id));
						const merged = [...prevMessages, ...newMessages];
						merged.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
						return merged;
					});
					
					// Count unique conversations
					const uniquePeers = new Set<string>();
					savedMessages.forEach(msg => {
						const peer = msg.sender === currentUser ? msg.recipient : msg.sender;
						uniquePeers.add(peer);
					});
					
				})
				.catch(err => {
				console.error('[useSecureDB] Failed to load messages', err);
				});

			// Load users asynchronously without blocking
			secureDBRef.current.loadUsers()
				.then(savedUsers => {
					if (savedUsers && savedUsers.length > 0) {
						setUsers(savedUsers);
					}
				})
				.catch(err => {
				console.error('[useSecureDB] Failed to load users', err);
				});
		};

		loadData();

		// Listen for incoming username mappings attached to encrypted messages
		const mappingListener = (e: any) => {
			try {
				// Rate limiting
				const now = Date.now();
				const bucket = eventRateLimitRef.current;
				if (now - bucket.windowStart > RATE_LIMIT_WINDOW_MS) {
					bucket.windowStart = now;
					bucket.count = 0;
				}
				bucket.count += 1;
				if (bucket.count > RATE_LIMIT_MAX_EVENTS) {
					return;
				}

				// Strict validation
				if (!validateEventDetail(e.detail)) {
					return;
				}
				const sanitized = sanitizeMappingPayload(e.detail);
				if (!sanitized) return;
				secureDBRef.current!.storeUsernameMapping(sanitized.hashed, sanitized.original)
					.then(() => {
						try { window.dispatchEvent(new CustomEvent('username-mapping-updated', { detail: { username: sanitized.hashed } })); } catch {}
					})
					.catch((err) => console.error('[useSecureDB] Failed to store username mapping', err));
			} catch {}
		};
		window.addEventListener('username-mapping-received', mappingListener as EventListener);
		return () => window.removeEventListener('username-mapping-received', mappingListener as EventListener);
	}, [Authentication?.isLoggedIn, dbInitialized]);

	useEffect(() => {
		if (dbInitialized) return;
		const preInitListener = (e: any) => {
			try {
				if (!validateEventDetail(e.detail)) return;
				const sanitized = sanitizeMappingPayload(e.detail);
				if (!sanitized) return;
				if (pendingMappingsRef.current.length >= MAX_PENDING_MAPPINGS) {
					return;
				}
				pendingMappingsRef.current.push(sanitized);
			} catch {}
		};
		window.addEventListener('username-mapping-received', preInitListener as EventListener);
		return () => window.removeEventListener('username-mapping-received', preInitListener as EventListener);
	}, [dbInitialized]);

	useEffect(() => {
		if (!dbInitialized || !secureDBRef.current || pendingMappingsRef.current.length === 0) return;
		const toFlush = [...pendingMappingsRef.current];
		pendingMappingsRef.current = [];
		(async () => {
			for (const m of toFlush) {
				try {
					await secureDBRef.current!.storeUsernameMapping(m.hashed, m.original);
					try { window.dispatchEvent(new CustomEvent('username-mapping-updated', { detail: { username: m.hashed } })); } catch {}
				} catch (_err) {
					console.error('[useSecureDB] Failed to flush mapping:', _err);
				}
			}
			try { window.dispatchEvent(new CustomEvent('username-mapping-updated', { detail: { username: '__all__' } })); } catch {}
		})();
	}, [dbInitialized]);

	useEffect(() => {
		if (!Authentication?.isLoggedIn || !dbInitialized || !secureDBRef.current) return;
		try { window.dispatchEvent(new CustomEvent('username-mapping-updated', { detail: { username: '__all__' } })); } catch {}
	}, [Authentication?.isLoggedIn, dbInitialized]);

	useEffect(() => {
		if (!dbInitialized || !secureDBRef.current || pendingMessagesRef.current.length === 0) return;

		const flushPending = async () => {
			try {
				const currentMessages = (await secureDBRef.current!.loadMessages()) || [];
				const mergedMap = new Map<string, Message>();
				[...currentMessages, ...pendingMessagesRef.current].forEach((msg: Message) => {
					mergedMap.set(msg.id!, msg);
				});
				const limited = Array.from(mergedMap.values()).slice(-MAX_DB_MESSAGES);
				await inflightDbOpRef.current;
				inflightDbOpRef.current = secureDBRef.current!.saveMessages(limited).catch((err) => {
					console.error('[useSecureDB] Failed to flush pending messages', err);
					pendingMessagesRef.current.push(...limited);
				});
				await inflightDbOpRef.current;
				pendingMessagesRef.current = [];
				} catch (_err) {
					console.error('[useSecureDB] Failed to flush pending messages', _err);
				}
		};

		flushPending();
	}, [dbInitialized]);

	useEffect(() => {
		if (!Authentication?.isLoggedIn || !dbInitialized || !secureDBRef.current || users.length === 0) return;

		secureDBRef.current.saveUsers(users).catch((err) => console.error("[useSecureDB] saveUsers error:", err));
	}, [users, Authentication?.isLoggedIn, dbInitialized]);

	const saveMessageToLocalDB = useCallback(
		async (message: Message, activeConversationPeer?: string) => {
			if (!message.id) {
				console.error("[useSecureDB] No message id provided");
				return;
			}

			setMessages((prev) => {
				const idx = prev.findIndex((m) => m.id === message.id);
				if (idx !== -1) {
					const updated = [...prev];
					updated[idx] = message;
					messageMapRef.current.set(message.id, message);
					return updated;
				} else {
					messageMapRef.current.set(message.id, message);
					return [...prev, message];
				}
			});

			const saveToPending = () => {
				const idx = pendingMessagesRef.current.findIndex((m) => m.id === message.id);
				if (idx !== -1) {
					pendingMessagesRef.current[idx] = message;
				} else {
					pendingMessagesRef.current.push(message);
					if (pendingMessagesRef.current.length > MAX_PENDING_MESSAGES) {
						pendingMessagesRef.current = pendingMessagesRef.current.slice(-MAX_PENDING_MESSAGES);
					}
				}
			};

			if (!dbInitialized || !secureDBRef.current) {
				return saveToPending();
			}

			if (pendingSavesRef.current.has(message.id)) {
				return;
			}

			pendingSavesRef.current.add(message.id);

			if (debouncedSaveRef.current) {
				clearTimeout(debouncedSaveRef.current);
			}

			debouncedSaveRef.current = setTimeout(async () => {
				try {
					await new Promise(resolve => setTimeout(resolve, 0));

					const msgs = (await secureDBRef.current!.loadMessages().catch(() => [])) || [];

					const idx = msgs.findIndex((m: Message) => m.id === message.id);

					if (idx !== -1) {
						msgs[idx] = message;
					} else {
						msgs.push(message);
					}

					// Let saveMessages handle per-conversation limits (500/1000)
					await secureDBRef.current!.saveMessages(msgs, activeConversationPeer).catch(saveToPending);
					pendingSavesRef.current.delete(message.id);
				} catch (_err) {
					console.error("[useSecureDB] DB save failed", _err);
					pendingSavesRef.current.delete(message.id);
					saveToPending();
				}
			}, 100);
		},
		[dbInitialized, setMessages]
	);

	const loadMoreConversationMessages = useCallback(
		async (peerUsername: string, currentOffset: number, limit: number = 50) => {
			if (!secureDBRef.current || !Authentication?.loginUsernameRef?.current) {
				console.error("[useSecureDB] Cannot load more messages: DB or username not available");
				return [];
			}

			try {
				const moreMessages = await secureDBRef.current.loadConversationMessages(
					peerUsername,
					Authentication.loginUsernameRef.current,
					limit,
					currentOffset
				);

				if (moreMessages.length === 0) return [];

				const processedMessages = moreMessages.map((msg: any) => ({
					...msg,
					timestamp: new Date(msg.timestamp),
					isCurrentUser:
						msg.sender ===
						(Authentication?.loginUsernameRef?.current ?? Authentication?.username),
					receipt: msg.receipt ? {
						...msg.receipt,
						deliveredAt: msg.receipt.deliveredAt ? new Date(msg.receipt.deliveredAt) : undefined,
						readAt: msg.receipt.readAt ? new Date(msg.receipt.readAt) : undefined,
					} : undefined,
				}));

				// Ensure chronological order (oldest -> newest)
				processedMessages.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

				setMessages(prevMessages => {
					const existingIds = new Set(prevMessages.map(msg => msg.id));
					const newMessages = processedMessages.filter(msg => !existingIds.has(msg.id));
					const merged = [...prevMessages, ...newMessages];
					merged.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
					return merged;
				});

				return processedMessages;
			} catch (_err) {
				console.error("[useSecureDB] Failed to load more messages", _err);
				return [];
			}
		},
		[Authentication?.loginUsernameRef?.current, secureDBRef, setMessages]
	);

	return { users, setUsers, dbInitialized, secureDBRef, saveMessageToLocalDB, loadMoreConversationMessages };
};

export class ServerDatabase {
	static async sendDataToServerDb(args: {
		content: string;
		messageId: string;
		serverHybridKeys: { x25519PublicBase64: string; kyberPublicBase64: string; dilithiumPublicBase64: string },
		fromUsername: string;
		toUsername?: string;
		timestamp: number;
		typeInside: string;
		aesKey: CryptoKey | null;
		replyTo?: { id: string; sender: string; content?: string } | null;
	}) {
		try {
			if (!args.aesKey) throw new Error("AES key is required to encrypt data");

			let replyContent = "";
			const { iv, authTag, encrypted } = await CryptoUtils.Encrypt.encryptBinaryWithAES(
				new TextEncoder().encode(args.content),
				args.aesKey
			);
			const serializedCiphertext = CryptoUtils.Encrypt.serializeEncryptedData(iv, authTag, encrypted);

			if (args.replyTo) {
				const replyContentCiphertext = await CryptoUtils.Encrypt.encryptBinaryWithAES(
					new TextEncoder().encode(args.replyTo.content ?? args.content),
					args.aesKey
				);
				replyContent = CryptoUtils.Encrypt.serializeEncryptedData(
					replyContentCiphertext.iv,
					replyContentCiphertext.authTag,
					replyContentCiphertext.encrypted
				);
			}

        return;
      } catch (err) {
        console.error("[useSecureDB] Failed to prepare encrypted server update", err);
      }
    }
}

export default useSecureDB;
