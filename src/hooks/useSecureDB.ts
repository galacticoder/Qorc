import { useRef, useEffect, useCallback, useState } from "react";
import { SecureDB } from "@/lib/secureDB";
import { Message } from "@/components/chat/types";
import { User } from "@/components/chat/UserList";
import { CryptoUtils } from "@/lib/unified-crypto";
import { SignalType } from "@/lib/signals";
import websocketClient from "@/lib/websocket";
import { SessionStore } from "@/lib/ratchet/session-store";

interface UseSecureDBProps {
	Authentication: any;
	messages: Message[];
	setMessages: React.Dispatch<React.SetStateAction<Message[]>>;
}

export const useSecureDB = ({ Authentication, messages, setMessages }: UseSecureDBProps) => {
	const secureDBRef = useRef<SecureDB | null>(null);
	const [dbInitialized, setDbInitialized] = useState(false);
	const [users, setUsers] = useState<User[]>([]);
	const pendingMessagesRef = useRef<Message[]>([]);

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
				await SessionStore.initUserContext(Authentication.loginUsernameRef.current, Authentication.aesKeyRef.current);
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

				setMessages(processedMessages);

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
				const idx = pendingMessagesRef.current.findIndex((m) => m.id === message.id);
				if (idx !== -1) {
					pendingMessagesRef.current[idx] = message;
				} else {
					pendingMessagesRef.current.push(message);
				}
			};

			if (!dbInitialized || !secureDBRef.current) return saveToPending();

			try {
				const msgs = (await secureDBRef.current.loadMessages().catch(() => [])) || [];
				const idx = msgs.findIndex((m: Message) => m.id === message.id);
				if (idx !== -1) {
					msgs[idx] = message;
				} else {
					msgs.push(message);
				}
				await secureDBRef.current.saveMessages(msgs).catch(saveToPending);
			} catch (err) {
				console.error("[useSecureDB] DB save failed, saving to pending", err);
				saveToPending();
			}
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