import { useRef, useEffect, useCallback, useState } from "react";
import { SecureDB } from "@/lib/secureDB";
import { Message } from "@/components/chat/types";
import { User } from "@/components/chat/UserList";

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

  useEffect(() => { //init db using aes key derived from passphrase
	if (!Authentication?.isLoggedIn) return;

	const username = Authentication?.username ?? Authentication?.loginUsernameRef?.current;
	const key = Authentication?.aesKeyRef?.current;

	if (!username || !key) {
		console.error("[useSecureDB] Cannot initialize DB: missing username or AES key");
		return;
	}

	const initializeDB = async () => {
		try {
		secureDBRef.current = new SecureDB(username);
		await secureDBRef.current.initializeWithKey(key);
		setDbInitialized(true);
		console.log("[useSecureDB] SecureDB initialized");
		} catch (err) {
		console.error("[useSecureDB] Failed to initialize SecureDB", err);
		Authentication.setLoginError?.("Failed to initialize secure storage");
		}
	};

	initializeDB();
	}, [Authentication?.isLoggedIn, Authentication?.username, Authentication?.loginUsernameRef?.current, Authentication?.aesKeyRef?.current]);

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

  const saveMessageToLocalDB = useCallback( //save to db
	async (message: Message) => {
		setMessages((prev) => [...prev, message]);

		const shouldPersist =
		!message.isSystemMessage || message.content.includes("joined") || message.content.includes("left");

		if (!shouldPersist) return;

		if (!dbInitialized || !secureDBRef.current) {
		pendingMessagesRef.current.push(message);
		return;
		}

		try {
		const currentMessages = (await secureDBRef.current.loadMessages().catch(() => [])) || [];
		await secureDBRef.current.saveMessages([...currentMessages, message]).catch((err) => {
			console.error("[useSecureDB] saveMessages failed", err);
			pendingMessagesRef.current.push(message);
		});
		console.log("[useSecureDB] Saved message to db")
		} catch (err) {
		console.error("[useSecureDB] Failed to persist message:", err);
		pendingMessagesRef.current.push(message);
		}
	},
	[dbInitialized, setMessages]
	);


  return { users, setUsers, dbInitialized, secureDBRef, handleNewMessage: saveMessageToLocalDB };
};

export default useSecureDB;
