import { useRef, useEffect, useCallback, useState } from "react";
import { SecureDB } from "@/lib/secureDB";
import { Message } from "@/components/chat/types";
import { User } from "@/components/chat/UserList";
import { CryptoUtils } from "@/lib/unified-crypto";
import { SignalType } from "@/lib/signals";
import websocketClient from "@/lib/websocket";

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

	useEffect(() => { //init db
		if (!Authentication?.isLoggedIn || dbInitialized || secureDBRef.current) return;

		if (!Authentication.loginUsernameRef.current || !Authentication.passphraseRef.current || !Authentication.passphrasePlaintextRef.current) {
			console.error("[useSecureDB] Cannot initialize DB: missing username, passphrase, or hash");
			return;
		}

		const initializeDB = async () => {
			try {
				//check if key and hashed passphrase are correct and exit if not
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

				if (!keysMatch) { //if keys dont match
					console.error("[useSecureDB] Stored key is not the correct key for this account — aborting initialization");
					Authentication.setLoginError?.("Stored key is not the correct key for this account, cannot initialize secure storage");
					secureDBRef.current = null;
					Authentication.logout(secureDBRef);
					return;
				}

				console.log("[useSecureDB] Passphrase derived aes key verified");

				if (encodedHash !== Authentication.passphraseRef.current) { //if passphrase hashes dont match
					console.error("[useSecureDB] Passphrase does not match stored hash — aborting initialization");
					Authentication.setLoginError?.("Incorrect passphrase, cannot initialize secure storage");
					secureDBRef.current = null;
					Authentication.logout(secureDBRef);
					return;
				}

				console.log("[useSecureDB] Passphrase hash verified");

				secureDBRef.current = new SecureDB(Authentication.loginUsernameRef.current);
				await secureDBRef.current.initializeWithKey(Authentication.aesKeyRef.current);
				setDbInitialized(true);

				Authentication.passphrasePlaintextRef.current = "";
				Authentication.passphraseRef.current = "";
				console.log("[useSecureDB] SecureDB initialized successfully");
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


	useEffect(() => { //load saved messages and users
		if (!Authentication?.isLoggedIn || !dbInitialized || !secureDBRef.current) return;

		const loadData = async () => {
			try {
				if (!secureDBRef.current) return;

				const savedMessages = (await secureDBRef.current.loadMessages().catch(() => [])) || [];
				const savedUsers = (await secureDBRef.current.loadUsers().catch(() => [])) || [];

				setMessages(
					savedMessages.map((msg: any) => ({
						...msg,
						timestamp: new Date(msg.timestamp),
						isCurrentUser:
							msg.sender ===
							(Authentication?.loginUsernameRef?.current ?? Authentication?.username),
					}))
				);

				if (savedUsers.length) setUsers(savedUsers);
			} catch (err) {
				console.error("[useSecureDB] Failed to load secure data", err);
				Authentication.setLoginError?.("Failed to load secure data");
			}
		};


		loadData();
	}, [Authentication?.isLoggedIn, dbInitialized]);

	useEffect(() => { //flush messages pending
		if (!dbInitialized || !secureDBRef.current || pendingMessagesRef.current.length === 0) return;

		const flushPending = async () => {
			try {
				const currentMessages = (await secureDBRef.current!.loadMessages()) || [];
				await secureDBRef.current!.saveMessages([...currentMessages, ...pendingMessagesRef.current]);
				pendingMessagesRef.current = [];
			} catch (err) {
				console.error("[useSecureDB] Failed to flush pending messages", err);
			}
		};

		flushPending();
	}, [dbInitialized]);

	useEffect(() => { //save users when they change
		if (!Authentication?.isLoggedIn || !dbInitialized || !secureDBRef.current || users.length === 0) return;

		secureDBRef.current.saveUsers(users).catch((err) => console.error("[useSecureDB] saveUsers error:", err));
	}, [users, Authentication?.isLoggedIn, dbInitialized]);

	const saveMessageToLocalDB = useCallback(
		async (message: Message) => {
			if (!message.id) {
				console.error("[useSecureDB] No message id provided");
				return;
			}

			const log = (where: string, action: "Added" | "Replaced") =>
				console.log(`[useSecureDB] ${action} in ${where}: ${message.id}`);

			setMessages((prev) => {
				const idx = prev.findIndex((m) => m.id === message.id);
				if (idx !== -1) {
					log("state", "Replaced");
					const updated = [...prev];
					updated[idx] = message;
					return updated;
				} else {
					log("state", "Added");
					return [...prev, message];
				}
			});

			const shouldPersist =
				!message.isSystemMessage ||
				message.content.includes("joined") ||
				message.content.includes("left");
			if (!shouldPersist) return;

			const saveToPending = () => {
				const idx = pendingMessagesRef.current.findIndex((m) => m.id === message.id);
				if (idx !== -1) {
					log("pending", "Replaced");
					pendingMessagesRef.current[idx] = message;
				} else {
					log("pending", "Added");
					pendingMessagesRef.current.push(message);
				}
			};

			if (!dbInitialized || !secureDBRef.current) return saveToPending();

			try {
				const msgs = (await secureDBRef.current.loadMessages().catch(() => [])) || [];
				const idx = msgs.findIndex((m: Message) => m.id === message.id);
				if (idx !== -1) {
					log("db", "Replaced");
					msgs[idx] = message;
				} else {
					log("db", "Added");
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
		serverPemKey: string;
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
			const ciphertext = await CryptoUtils.Encrypt.encryptWithAES(args.content, args.aesKey);
			const serializedCiphertext = CryptoUtils.Encrypt.serializeEncryptedData(
				ciphertext.iv,
				ciphertext.authTag,
				ciphertext.encrypted
			);

			if (args.replyTo) {
				const replyContentCiphertext = await CryptoUtils.Encrypt.encryptWithAES(
					args.replyTo.content ?? args.content,
					args.aesKey
				);
				replyContent = CryptoUtils.Encrypt.serializeEncryptedData(
					replyContentCiphertext.iv,
					replyContentCiphertext.authTag,
					replyContentCiphertext.encrypted
				);
			}

			console.log("[useSecureDB] Server db update serialized ciphertext:", serializedCiphertext);

			const serverPayloadDBUpdate = await CryptoUtils.Encrypt.encryptAndFormatPayload({
				id: args.messageId,
				recipientPEM: args.serverPemKey,
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

			console.log("[useSecureDB] DB update payload to server sent: ", serverPayloadDBUpdate);
			websocketClient.send(JSON.stringify(serverPayloadDBUpdate));
		} catch (err) {
			console.error("[useSecureDB] Failed to send encrypted server update", err);
		}
	}
}

export default useSecureDB;