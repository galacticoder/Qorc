import { useRef, useEffect, useCallback, useState } from "react";
import { SecureDB } from "@/lib/secureDB";
import { Message } from "@/components/chat/types";
import { User } from "@/components/chat/UserList";
import { CryptoUtils } from "@/lib/unified-crypto";
import { SignalType } from "@/lib/signals";

import websocketClient from "@/lib/websocket";

interface UseSecureDBProps {
	Authentication: any;
	setMessages: React.Dispatch<React.SetStateAction<Message[]>>;
}

export const useSecureDB = ({ Authentication, setMessages }: UseSecureDBProps) => {
	const secureDBRef = useRef<SecureDB | null>(null);
	const [dbInitialized, setDbInitialized] = useState(false);
	const [users, setUsers] = useState<User[]>([]);
	const pendingMessagesRef = useRef<Message[]>([]);

	// Debounced save optimization
	const debouncedSaveRef = useRef<NodeJS.Timeout | null>(null);
	const pendingSavesRef = useRef<Set<string>>(new Set());

	useEffect(() => {
		if (!Authentication?.isLoggedIn || dbInitialized || secureDBRef.current) return;

		if (!Authentication.loginUsernameRef.current || !Authentication.passphraseRef.current || !Authentication.passphrasePlaintextRef.current) {
			console.error("[useSecureDB] Cannot initialize DB: missing username, passphrase, or hash");
			return;
		}

		const initializeDB = async () => {
			try {
				console.debug('[useSecureDB] Initializing SecureDB with auth context', {
					username: Authentication.loginUsernameRef.current,
					hasPassphraseHash: !!Authentication.passphraseRef.current,
					hasPassphrasePlaintext: !!Authentication.passphrasePlaintextRef.current,
					hasAesKey: !!Authentication.aesKeyRef.current,
				});
				const parsedStoredHash = CryptoUtils.Hash.parseArgon2Hash(Authentication.passphraseRef.current)

				const { aesKey: newKey, encodedHash } = await CryptoUtils.Keys.deriveAESKeyFromPassphrase(Authentication.passphrasePlaintextRef.current, {
					saltBase64: parsedStoredHash.salt,
					time: parsedStoredHash.timeCost,
					memoryCost: parsedStoredHash.memoryCost,
					parallelism: parsedStoredHash.parallelism,
					algorithm: parsedStoredHash.algorithm,
					version: parsedStoredHash.version,
				});

				const exportedStoredKey = await CryptoUtils.Keys.exportAESKey(Authentication.aesKeyRef.current);
				const exportedNewCheckKey = await CryptoUtils.Keys.exportAESKey(newKey)

				const keysMatch =
					exportedStoredKey.byteLength === exportedNewCheckKey.byteLength &&
					new Uint8Array(exportedStoredKey).every((b, i) => b === new Uint8Array(exportedNewCheckKey)[i]);

				if (!keysMatch) {
					console.error("[useSecureDB] Stored key is not the correct key for this account — aborting initialization");
					Authentication.setLoginError?.("Stored key is not the correct key for this account, cannot initialize secure storage");
					secureDBRef.current = null;
					Authentication.logout(secureDBRef).catch(console.error);
					return;
				}

				if (encodedHash !== Authentication.passphraseRef.current) {
					console.error("[useSecureDB] Passphrase does not match stored hash — aborting initialization");
					Authentication.setLoginError?.("Incorrect passphrase, cannot initialize secure storage");
					secureDBRef.current = null;
					Authentication.logout(secureDBRef).catch(console.error);
					return;
				}

				secureDBRef.current = new SecureDB(Authentication.loginUsernameRef.current);
				await secureDBRef.current.initializeWithKey(Authentication.aesKeyRef.current);
				setDbInitialized(true);

				console.debug('[useSecureDB] SecureDB initialized and session context set');

				Authentication.passphraseRef.current = "";
			} catch (err) {
				console.error("[useSecureDB] Failed to initialize SecureDB", err);
				Authentication.setLoginError?.("Failed to initialize secure storage");
			}
		};

		initializeDB();
	}, [
		Authentication?.isLoggedIn,
		Authentication?.username,
		Authentication?.loginUsernameRef?.current,
		Authentication?.passphraseRef?.current,
		Authentication?.passphrasePlaintextRef?.current
	]);

	useEffect(() => {
		if (!Authentication?.isLoggedIn || !dbInitialized || !secureDBRef.current) return;

		const loadData = async () => {
			try {
				if (!secureDBRef.current) return;

				const savedMessages = (await secureDBRef.current.loadMessages().catch(() => [])) || [];
				const savedUsers = (await secureDBRef.current.loadUsers().catch(() => [])) || [];
				console.debug('[useSecureDB] Loaded persisted data', { savedMessages: savedMessages.length, savedUsers: savedUsers.length });

				const processedMessages = savedMessages.map((msg: any) => ({
					...msg,
					timestamp: new Date(msg.timestamp),
					isCurrentUser:
						msg.sender ===
						(Authentication?.loginUsernameRef?.current ?? Authentication?.username),
					// Ensure receipt information is properly restored
					receipt: msg.receipt ? {
						...msg.receipt,
						deliveredAt: msg.receipt.deliveredAt ? new Date(msg.receipt.deliveredAt) : undefined,
						readAt: msg.receipt.readAt ? new Date(msg.receipt.readAt) : undefined,
					} : undefined,
				}));

				// Merge with existing messages instead of replacing them
				setMessages(prevMessages => {
					console.debug('[useSecureDB] Merging loaded messages with existing messages', {
						loadedCount: processedMessages.length,
						existingCount: prevMessages.length
					});
					
					if (processedMessages.length === 0) {
						// No stored messages, keep existing ones (including any received during login)
						return prevMessages;
					}
					
					// Create a map of existing message IDs for deduplication
					const existingIds = new Set(prevMessages.map(msg => msg.id));
					
					// Add loaded messages that don't already exist
					const newMessages = processedMessages.filter(msg => !existingIds.has(msg.id));
					
					const merged = [...prevMessages, ...newMessages];
					console.debug('[useSecureDB] Message merge complete', {
						finalCount: merged.length,
						addedFromDB: newMessages.length,
						keptExisting: prevMessages.length
					});
					
					return merged;
				});

				if (savedUsers.length) setUsers(savedUsers);
			} catch (err) {
				console.error("[useSecureDB] Failed to load secure data", err);
				Authentication.setLoginError?.("Failed to load secure data");
			}
		};

		loadData();
	}, [Authentication?.isLoggedIn, dbInitialized]);

	useEffect(() => {
		if (!dbInitialized || !secureDBRef.current || pendingMessagesRef.current.length === 0) return;

		const flushPending = async () => {
			try {
				const currentMessages = (await secureDBRef.current!.loadMessages()) || [];
				await secureDBRef.current!.saveMessages([...currentMessages, ...pendingMessagesRef.current]);
				console.debug('[useSecureDB] Flushed pending messages', { count: pendingMessagesRef.current.length });
				pendingMessagesRef.current = [];
			} catch (err) {
				console.error("[useSecureDB] Failed to flush pending messages", err);
			}
		};

		flushPending();
	}, [dbInitialized]);

	useEffect(() => {
		if (!Authentication?.isLoggedIn || !dbInitialized || !secureDBRef.current || users.length === 0) return;

		secureDBRef.current.saveUsers(users).catch((err) => console.error("[useSecureDB] saveUsers error:", err));
	}, [users, Authentication?.isLoggedIn, dbInitialized]);

	const saveMessageToLocalDB = useCallback(
		async (message: Message) => {
			if (!message.id) {
				console.error("[useSecureDB] No message id provided");
				return;
			}

			setMessages((prev) => {
				const idx = prev.findIndex((m) => m.id === message.id);
				if (idx !== -1) {
					const updated = [...prev];
					updated[idx] = message;
					return updated;
				} else {
					return [...prev, message];
				}
			});

			const saveToPending = () => {
				// Prevent memory leak by limiting pending messages
				const maxPending = 100;
				const idx = pendingMessagesRef.current.findIndex((m) => m.id === message.id);
				if (idx !== -1) {
					pendingMessagesRef.current[idx] = message;
				} else {
					pendingMessagesRef.current.push(message);
					// Trim to prevent memory leak
					if (pendingMessagesRef.current.length > maxPending) {
						pendingMessagesRef.current = pendingMessagesRef.current.slice(-maxPending);
					}
				}
			};

			if (!dbInitialized || !secureDBRef.current) return saveToPending();

			// Debounce saves to prevent excessive database operations
			if (pendingSavesRef.current.has(message.id)) {
				return; // Already pending save for this message
			}

			pendingSavesRef.current.add(message.id);

			// Clear existing debounce timer
			if (debouncedSaveRef.current) {
				clearTimeout(debouncedSaveRef.current);
			}

			// SECURITY: Debounce with event loop protection to prevent starvation
			debouncedSaveRef.current = setTimeout(async () => {
				try {
					// SECURITY: Yield to event loop to prevent blocking
					await new Promise(resolve => setTimeout(resolve, 0));

					const msgs = (await secureDBRef.current!.loadMessages().catch(() => [])) || [];

					// SECURITY: Limit processing time to prevent event loop starvation
					const startTime = performance.now();
					const maxProcessingTime = 50; // 50ms max processing time

					const idx = msgs.findIndex((m: Message) => {
						// Check if we've exceeded processing time
						if (performance.now() - startTime > maxProcessingTime) {
							console.warn('[useSecureDB] Processing time limit reached, deferring save');
							// Reschedule for later
							setTimeout(() => {
								debouncedSaveRef.current = setTimeout(async () => {
									// Retry the operation
									try {
										await secureDBRef.current!.saveMessages([message]);
										pendingSavesRef.current.delete(message.id);
									} catch (retryErr) {
										saveToPending();
									}
								}, 10);
							}, 10);
							return false; // Stop processing
						}
						return m.id === message.id;
					});

					if (idx !== -1) {
						msgs[idx] = message;
					} else {
						msgs.push(message);
					}

					// Limit total messages to prevent memory issues
					const maxMessages = 1000;
					const limitedMsgs = msgs.length > maxMessages ? msgs.slice(-maxMessages) : msgs;

					await secureDBRef.current!.saveMessages(limitedMsgs).catch(saveToPending);
					pendingSavesRef.current.delete(message.id);
				} catch (err) {
					console.error("[useSecureDB] DB save failed, saving to pending", err);
					pendingSavesRef.current.delete(message.id);
					saveToPending();
				}
			}, 100); // 100ms debounce
		},
		[dbInitialized, setMessages]
	);

	return { users, setUsers, dbInitialized, secureDBRef, saveMessageToLocalDB };
};

export class ServerDatabase {
	static async sendDataToServerDb(args: {
		content: string;
		messageId: string;
		serverHybridKeys: { x25519PublicBase64: string; kyberPublicBase64: string };
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

			const serverPayloadDBUpdate = await CryptoUtils.Encrypt.encryptAndFormatPayload({
				id: args.messageId,
				recipientHybridKeys: args.serverHybridKeys,
				from: args.fromUsername,
				to: args.toUsername ?? "",
				type: SignalType.UPDATE_DB,
				content: serializedCiphertext,
				timestamp: args.timestamp,
				typeInside: args.typeInside,
				...(args.replyTo && {
					replyTo: {
						id: args.replyTo.id,
						sender: args.replyTo.sender,
						content: replyContent,
					},
				}),
			});

			websocketClient.send(JSON.stringify(serverPayloadDBUpdate));
		} catch (err) {
			console.error("[useSecureDB] Failed to send encrypted server update", err);
		}
	}
}

export default useSecureDB;