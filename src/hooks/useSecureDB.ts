import React, { useRef, useEffect, useCallback, useState } from "react";
import { SecureDB } from "@/lib/secureDB";
import { Message } from "@/components/chat/messaging/types";
import { User } from "@/components/chat/messaging/UserList";
import { encryptedStorage, syncEncryptedStorage } from "@/lib/encrypted-storage";
import { prewarmUsernameCache } from "@/hooks/useUnifiedUsernameDisplay";
import { blockingSystem } from "@/lib/blocking-system";
import { EventType } from "@/lib/event-types";

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
	const pendingSaveMessagesRef = useRef<Map<string, Message>>(new Map());
	const messageMapRef = useRef<Map<string, Message>>(new Map());
	const inflightDbOpRef = useRef<Promise<void>>(Promise.resolve());
	const eventRateLimitRef = useRef<{ windowStart: number; count: number }>({ windowStart: Date.now(), count: 0 });
	const keysEventRateLimitRef = useRef<{ windowStart: number; count: number }>({ windowStart: Date.now(), count: 0 });

	useEffect(() => {
		if (!Authentication?.isLoggedIn) {
			setDbInitialized(false);
			secureDBRef.current = null;
		}
	}, [Authentication?.isLoggedIn]);

	useEffect(() => {

		if (!Authentication?.isLoggedIn || dbInitialized || secureDBRef.current) {
			return;
		}

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
				try { blockingSystem.setSecureDB(secureDBRef.current); } catch { }

				try {
					const passphrase = Authentication.passphrasePlaintextRef?.current;
					const kyberSecret: Uint8Array | null = Authentication.hybridKeysRef?.current?.kyber?.secretKey || null;
					if (passphrase) {
						await blockingSystem.getBlockedUsers(passphrase);
					} else if (kyberSecret) {
						await blockingSystem.getBlockedUsers({ kyberSecret });
					}
				} catch (_err) {
					console.error('[useSecureDB] Failed to load block list:', _err);
					try {
						const msg = (_err as Error)?.message || String(_err);
						if (/decrypt|BLAKE3|passphrase|corrupt/i.test(msg)) {
							await Promise.all([
								secureDBRef.current!.clearStore('blockListData'),
								secureDBRef.current!.clearStore('blockListMeta')
							]);
							const passphrase = Authentication.passphrasePlaintextRef?.current;
							if (passphrase) {
								await blockingSystem.getBlockedUsers(passphrase).catch(() => { });
							}
						}
					} catch { }
				}

				if (Authentication.loginUsernameRef.current) {
					try {
						await secureDBRef.current.store('auth_metadata', 'current_user', Authentication.loginUsernameRef.current);
					} catch (_err) {
						console.error('[useSecureDB] Failed to store authenticated user:', _err);
					}
				}

				try {
					const currentHashed = Authentication.loginUsernameRef.current || '';
					if (currentHashed) {
						const existingOriginal = await secureDBRef.current.retrieve('auth_metadata', 'original_username');
						if (typeof existingOriginal === 'string' && existingOriginal) {
							try { await secureDBRef.current.storeUsernameMapping(currentHashed, existingOriginal); } catch { }
							try { window.dispatchEvent(new CustomEvent(EventType.USERNAME_MAPPING_UPDATED, { detail: { username: currentHashed, original: existingOriginal } })); } catch { }
						}
					}
				} catch { }

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
					try {
						const msg = (_err as Error)?.message || String(_err);
						if (/decrypt|BLAKE3|passphrase|corrupt/i.test(msg)) {
							await secureDBRef.current!.clearStore('encrypted_storage');
							await encryptedStorage.initialize(secureDBRef.current);
							await syncEncryptedStorage.initialize();
						}
					} catch { }
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

			(async () => {
				try {
					const mappings = await secureDBRef.current!.getAllUsernameMappings();
					if (Array.isArray(mappings) && mappings.length > 0) {
						prewarmUsernameCache(mappings);
					}
				} catch { }
			})();

			const currentUser = Authentication?.loginUsernameRef?.current;
			if (!currentUser) return;

			secureDBRef.current.loadRecentMessagesByConversation(50, currentUser)
				.then(savedMessages => {
					if (savedMessages && savedMessages.length > 0) {
						const processedMessages = savedMessages.map((msg: any) => ({
							...msg,
							timestamp: new Date(msg.timestamp),
							isCurrentUser: msg.sender === currentUser,
							receipt: msg.receipt ? {
								...msg.receipt,
								deliveredAt: msg.receipt.deliveredAt ? new Date(msg.receipt.deliveredAt) : undefined,
								readAt: msg.receipt.readAt ? new Date(msg.receipt.readAt) : undefined,
							} : undefined,
						}));

						setMessages(prevMessages => {
							const existingMap = new Map(prevMessages.map(msg => [msg.id, msg]));
							const merged: Message[] = [];

							for (const dbMsg of processedMessages) {
								const existing = existingMap.get(dbMsg.id);
								if (existing) {
									const mergedReceipt = {
										delivered: existing.receipt?.delivered || dbMsg.receipt?.delivered || false,
										read: existing.receipt?.read || dbMsg.receipt?.read || false,
										deliveredAt: existing.receipt?.deliveredAt || dbMsg.receipt?.deliveredAt,
										readAt: existing.receipt?.readAt || dbMsg.receipt?.readAt,
									};
									existingMap.set(dbMsg.id, { ...existing, receipt: mergedReceipt });
								} else {
									existingMap.set(dbMsg.id, dbMsg);
								}
							}

							merged.push(...existingMap.values());
							merged.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
							return merged;
						});
					}

					// Background Full Load
					setTimeout(() => {
						if (!secureDBRef.current) return;
						secureDBRef.current.loadMessages()
							.then(allMessages => {
								if (!allMessages || allMessages.length === 0) return;

								const processedAll = allMessages.map((msg: any) => ({
									...msg,
									timestamp: new Date(msg.timestamp),
									isCurrentUser: msg.sender === currentUser,
									receipt: msg.receipt ? {
										...msg.receipt,
										deliveredAt: msg.receipt.deliveredAt ? new Date(msg.receipt.deliveredAt) : undefined,
										readAt: msg.receipt.readAt ? new Date(msg.receipt.readAt) : undefined,
									} : undefined,
								}));

								setMessages(prevMessages => {
									const existingMap = new Map(prevMessages.map(msg => [msg.id, msg]));
									let hasChanges = false;

									for (const dbMsg of processedAll) {
										const existing = existingMap.get(dbMsg.id);
										if (existing) {
											const mergedReceipt = {
												delivered: existing.receipt?.delivered || dbMsg.receipt?.delivered || false,
												read: existing.receipt?.read || dbMsg.receipt?.read || false,
												deliveredAt: existing.receipt?.deliveredAt || dbMsg.receipt?.deliveredAt,
												readAt: existing.receipt?.readAt || dbMsg.receipt?.readAt,
											};
											const receiptChanged =
												mergedReceipt.delivered !== (existing.receipt?.delivered || false) ||
												mergedReceipt.read !== (existing.receipt?.read || false);
											if (receiptChanged) {
												existingMap.set(dbMsg.id, { ...existing, receipt: mergedReceipt });
												hasChanges = true;
											}
										} else {
											existingMap.set(dbMsg.id, dbMsg);
											hasChanges = true;
										}
									}

									if (!hasChanges) return prevMessages;

									const merged = Array.from(existingMap.values());
									merged.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
									return merged;
								});
							})
							.catch(err => console.error('[useSecureDB] Background history load failed', err));
					}, 500);
				})
				.catch(err => {
					console.error('[useSecureDB] Failed to load messages', err);
				});

			secureDBRef.current.loadUsers()
				.then(savedUsers => {
					if (savedUsers && savedUsers.length > 0) {
						// Convert StoredUser[] to User[] by adding required UI fields
						const usersWithDefaults: User[] = savedUsers.map((su: any) => ({
							id: su.id || '',
							username: su.username || '',
							isOnline: su.isOnline ?? false,
							isTyping: su.isTyping,
							hybridPublicKeys: su.hybridPublicKeys,
						}));
						setUsers(usersWithDefaults);
					}
				})
				.catch(err => {
					console.error('[useSecureDB] Failed to load users', err);
				});
		};

		loadData();

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

				if (!validateEventDetail(e.detail)) {
					return;
				}
				const sanitized = sanitizeMappingPayload(e.detail);
				if (!sanitized) return;
				secureDBRef.current!.storeUsernameMapping(sanitized.hashed, sanitized.original)
					.then(() => {
						try { window.dispatchEvent(new CustomEvent(EventType.USERNAME_MAPPING_UPDATED, { detail: { username: sanitized.hashed } })); } catch { }
					})
					.catch((err) => console.error('[useSecureDB] Failed to store username mapping', err));
			} catch { }
		};

		const keysListener = (e: Event) => {
			try {
				const now = Date.now();
				const bucket = keysEventRateLimitRef.current;
				if (now - bucket.windowStart > RATE_LIMIT_WINDOW_MS) {
					bucket.windowStart = now;
					bucket.count = 0;
				}
				bucket.count += 1;
				if (bucket.count > RATE_LIMIT_MAX_EVENTS) {
					return;
				}

				const detail = (e as CustomEvent).detail;
				if (!validateEventDetail(detail)) return;

				const username = sanitizeUsername((detail as any).username);
				if (!username) return;

				const hybridKeys = (detail as any).hybridKeys;
				if (!isPlainObject(hybridKeys) || hasPrototypePollutionKeys(hybridKeys)) return;
				if (typeof (hybridKeys as any).kyberPublicBase64 !== 'string' || typeof (hybridKeys as any).dilithiumPublicBase64 !== 'string') {
					return;
				}

				setUsers(prev => {
					const idx = prev.findIndex(u => u.username === username);
					if (idx !== -1) {
						const updatedUser = { ...prev[idx], hybridPublicKeys: hybridKeys as User['hybridPublicKeys'] };
						if (JSON.stringify(prev[idx].hybridPublicKeys) === JSON.stringify(hybridKeys)) {
							return prev;
						}
						const newUsers = [...prev];
						newUsers[idx] = updatedUser;
						return newUsers;
					} else {
						return prev;
					}
				});
			} catch { }
		};

		window.addEventListener(EventType.USERNAME_MAPPING_RECEIVED, mappingListener as EventListener);
		window.addEventListener(EventType.USER_KEYS_AVAILABLE, keysListener as EventListener);
		return () => {
			window.removeEventListener(EventType.USERNAME_MAPPING_RECEIVED, mappingListener as EventListener);
			window.removeEventListener(EventType.USER_KEYS_AVAILABLE, keysListener as EventListener);
		};
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
			} catch { }
		};
		window.addEventListener(EventType.USERNAME_MAPPING_RECEIVED, preInitListener as EventListener);
		return () => window.removeEventListener(EventType.USERNAME_MAPPING_RECEIVED, preInitListener as EventListener);
	}, [dbInitialized]);

	useEffect(() => {
		if (!dbInitialized || !secureDBRef.current || pendingMappingsRef.current.length === 0) return;
		const toFlush = [...pendingMappingsRef.current];
		pendingMappingsRef.current = [];
		(async () => {
			for (const m of toFlush) {
				try {
					await secureDBRef.current!.storeUsernameMapping(m.hashed, m.original);
					try { window.dispatchEvent(new CustomEvent(EventType.USERNAME_MAPPING_UPDATED, { detail: { username: m.hashed } })); } catch { }
				} catch (_err) {
					console.error('[useSecureDB] Failed to flush mapping:', _err);
				}
			}
			try { window.dispatchEvent(new CustomEvent(EventType.USERNAME_MAPPING_UPDATED, { detail: { username: '__all__' } })); } catch { }
		})();
	}, [dbInitialized]);

	useEffect(() => {
		if (!Authentication?.isLoggedIn || !dbInitialized || !secureDBRef.current) return;
		try { window.dispatchEvent(new CustomEvent(EventType.USERNAME_MAPPING_UPDATED, { detail: { username: '__all__' } })); } catch { }
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
				// Convert Message[] to StoredMessage[] (Date -> number for timestamp)
				const storedMessages = limited.map(m => ({
					...m,
					timestamp: m.timestamp instanceof Date ? m.timestamp.getTime() : m.timestamp,
				}));
				await inflightDbOpRef.current;
				inflightDbOpRef.current = secureDBRef.current!.saveMessages(storedMessages as any).catch((err) => {
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

		const storedUsers = users.map(u => ({ ...u } as any));
		secureDBRef.current.saveUsers(storedUsers).catch((err) => console.error("[useSecureDB] saveUsers error:", err));
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
				pendingSaveMessagesRef.current.set(message.id, message);
				return;
			}

			pendingSavesRef.current.add(message.id);
			pendingSaveMessagesRef.current.set(message.id, message);

			if (debouncedSaveRef.current) {
				clearTimeout(debouncedSaveRef.current);
			}

			debouncedSaveRef.current = setTimeout(async () => {
				try {
					await new Promise(resolve => setTimeout(resolve, 0));

					const msgs = (await secureDBRef.current!.loadMessages().catch(() => [])) || [];

					for (const [msgId, pendingMsg] of pendingSaveMessagesRef.current.entries()) {
						const idx = msgs.findIndex((m: Message) => m.id === msgId);
						if (idx !== -1) {
							msgs[idx] = pendingMsg;
						} else {
							msgs.push(pendingMsg);
						}
					}

					await secureDBRef.current!.saveMessages(msgs, activeConversationPeer).catch(saveToPending);
					pendingSavesRef.current.clear();
					pendingSaveMessagesRef.current.clear();
				} catch (_err) {
					console.error("[useSecureDB] DB save failed", _err);
					pendingSavesRef.current.clear();
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

	const flushPendingSaves = useCallback(async () => {
		if (!secureDBRef.current) return;

		if (debouncedSaveRef.current) {
			clearTimeout(debouncedSaveRef.current);
			debouncedSaveRef.current = null;
		}

		if (pendingSaveMessagesRef.current.size > 0 || pendingMessagesRef.current.length > 0) {
			try {
				const msgs = (await secureDBRef.current.loadMessages().catch(() => [])) || [];
				let hasChanges = false;

				for (const [msgId, pendingMsg] of pendingSaveMessagesRef.current.entries()) {
					const idx = msgs.findIndex((m: Message) => m.id === msgId);
					if (idx !== -1) {
						msgs[idx] = pendingMsg;
					} else {
						msgs.push(pendingMsg);
					}
					hasChanges = true;
				}

				for (const pendingMsg of pendingMessagesRef.current) {
					const idx = msgs.findIndex((m: Message) => m.id === pendingMsg.id);
					if (idx !== -1) {
						msgs[idx] = pendingMsg;
					} else {
						msgs.push(pendingMsg);
					}
					hasChanges = true;
				}

				if (hasChanges) {
					await secureDBRef.current.saveMessages(msgs);
				}

				pendingSavesRef.current.clear();
				pendingSaveMessagesRef.current.clear();
				pendingMessagesRef.current = [];
			} catch (err) {
				console.error('[useSecureDB] Failed to flush pending saves:', err);
			}
		}
	}, []);

	return { users, setUsers, dbInitialized, secureDBRef, saveMessageToLocalDB, loadMoreConversationMessages, flushPendingSaves };
};

export default useSecureDB;
