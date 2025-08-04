import { useState, useRef, useCallback } from "react";
import { v4 as uuidv4 } from 'uuid';
import { useLocalStorage } from "./use-local-storage";
import { Message } from "@/components/chat/ChatMessage";
import { SignalType } from "@/lib/signals";
import websocketClient from "@/lib/websocket";
import { CryptoUtils }from "@/lib/unified-crypto";

export const useAuth = () => {
  //states
  const [username, setUsername] = useState("");
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [isGeneratingKeys, setIsGeneratingKeys] = useState(false);
  const [loginError, setLoginError] = useState("");
  const [accountAuthenticated, setAccountAuthenticated] = useState(false);
  
  // keys
  const [privateKeyPEM, setPrivateKeyPEM] = useLocalStorage<string>("private_key", "");
  const [publicKeyPEM, setPublicKeyPEM] = useLocalStorage<string>("public_key", "");
  const privateKeyRef = useRef<CryptoKey | null>(null);
  const publicKeyRef = useRef<CryptoKey | null>(null);
  const [serverPublicKeyPEM, setServerPublicKeyPEM] = useState<string | null>(null);
  const loginUsernameRef = useRef("");
  const serverPublicKeyRef = useRef<CryptoKey | null>(null);
  const passwordRef = useRef<string>("");

  const initializeKeys = useCallback(async () => {
    if (!privateKeyPEM || !publicKeyPEM) {
      setIsGeneratingKeys(true);
      try {
        const keyPair = await CryptoUtils.Keys.generateRSAKeyPair();
        const publicKeyString = await CryptoUtils.Keys.exportPublicKeyToPEM(keyPair.publicKey);
        const privateKeyString = await CryptoUtils.Keys.exportPrivateKeyToPEM(keyPair.privateKey);
        
        setPublicKeyPEM(publicKeyString);
        setPrivateKeyPEM(privateKeyString);
        
        publicKeyRef.current = keyPair.publicKey;
        privateKeyRef.current = keyPair.privateKey;
      } catch (error) {
        console.error("Error generating keys: ", error);
      } finally {
        setIsGeneratingKeys(false);
      }
    } else {
      try {
        const publicKey = await CryptoUtils.Keys.importPublicKeyFromPEM(publicKeyPEM);
        const privateKey = await CryptoUtils.Keys.importPrivateKeyFromPEM(privateKeyPEM);
        
        publicKeyRef.current = publicKey;
        privateKeyRef.current = privateKey;
      } catch (error) {
        console.error("Error importing existing keys: ", error);
        setPublicKeyPEM("");
        setPrivateKeyPEM("");
      }
    }
  }, [privateKeyPEM, publicKeyPEM, setPublicKeyPEM, setPrivateKeyPEM]);

  const handleAccountSubmit = async (
    mode: "login" | "register",
    username: string,
    password: string
  ) => {
    setLoginError("");
    loginUsernameRef.current = username;
    setUsername(username);
    passwordRef.current = password; 

    try {
      if (!serverPublicKeyPEM) throw new Error("Server public key not available");
      if (!websocketClient.isConnectedToServer()) await websocketClient.connect();

      const encryptedPasswordPayload = await CryptoUtils.Encrypt.encryptAndFormatPayload({
        recipientPEM: serverPublicKeyPEM,
        content: password
      });

      const encryptedUserPayload = await CryptoUtils.Encrypt.encryptAndFormatPayload({
        recipientPEM: serverPublicKeyPEM,
        usernameSent: username,
        publicKey: publicKeyPEM
      });

      const payload = {
        type: mode === "register" ? SignalType.ACCOUNT_SIGN_UP : SignalType.ACCOUNT_SIGN_IN,
        userData: encryptedUserPayload,
        passwordData: encryptedPasswordPayload
      };

      websocketClient.send(JSON.stringify(payload));
    } catch (error) {
      console.error("Account submission failed:", error);
      setLoginError(`Submission error: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  };

  //server password submitting
  const handleServerPasswordSubmit = async (password: string) => {
     setLoginError("");
    if (!publicKeyRef.current || !privateKeyRef.current) {
      setLoginError("Encryption keys not ready");
      return;
    }

    try {
      if (!websocketClient.isConnectedToServer()) {
        try {
          await websocketClient.connect();
        } catch (error) {
          setLoginError("Failed to connect to server");
          return;
        }
      }

      const exportPem = await CryptoUtils.Keys.exportPublicKeyToPEM(serverPublicKeyRef.current);
      const passwordPayload = await CryptoUtils.Encrypt.encryptAndFormatPayload({
        recipientPEM: exportPem,
        type: SignalType.SERVER_PASSWORD_ENCRYPTED,
        content: password
      });
      
      const userPayload = await CryptoUtils.Encrypt.encryptAndFormatPayload({
        recipientPEM: exportPem,
        publicKey: publicKeyPEM
      });

      const loginInfo = {
        type: SignalType.LOGIN_INFO,
        userData: userPayload,
        passwordData: passwordPayload
      };

      console.log("Sending combined login info: ", loginInfo);
      websocketClient.send(JSON.stringify(loginInfo));
      
      loginUsernameRef.current = username;
    } catch (error) {
      console.error("Login failed: ", error);
    }
  };

  const getWelcomeMessages = (username: string): Message[] => {
    return [
      {
        id: uuidv4(),
        content: `Welcome to SecureChat, ${username}! Your messages are secured with this encryption:
          • RSA-4096 for key exchange
          • AES-256-GCM for message encryption
          • SHA-512 for integrity verification`,
        sender: "System",
        timestamp: new Date(),
        isCurrentUser: false,
        isSystemMessage: true
      },
      {
        id: uuidv4(),
        content: "Connected to secure WebSocket server with end-to-end encryption.",
        sender: "System",
        timestamp: new Date(),
        isCurrentUser: false,
        isSystemMessage: true
      }
    ];
  };

  const handleAuthSuccess = (username: string, onSuccess?: (messages: Message[]) => void) => {
    setUsername(username);
    setIsLoggedIn(true);
    setLoginError("");
    
    const welcomeMessages = getWelcomeMessages(username);
    onSuccess?.(welcomeMessages);
  };
  
  return {
    username,
    serverPublicKeyPEM,
    setServerPublicKeyPEM,
    isLoggedIn,
    setIsLoggedIn,
    isGeneratingKeys,
    loginError,
    accountAuthenticated,
    privateKeyRef,
    publicKeyRef,
    loginUsernameRef,
    initializeKeys,
    handleAccountSubmit,
    handleServerPasswordSubmit,
    handleAuthSuccess,
    getWelcomeMessages,
    setAccountAuthenticated,
    serverPublicKeyRef,
    passwordRef,
    setLoginError
  };
};