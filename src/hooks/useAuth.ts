import { useState, useRef, useCallback, MutableRefObject } from "react";
import { useLocalStorage } from "./use-local-storage";
import { Message } from "@/components/chat/types";
import { SignalType } from "@/lib/signals";
import websocketClient from "@/lib/websocket";
import { CryptoUtils } from "@/lib/unified-crypto";
import { SecureDB } from "@/lib/secureDB";


export const useAuth = () => {
  //states
  const [username, setUsername] = useState("");
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [isGeneratingKeys, setIsGeneratingKeys] = useState(false);
  const [loginError, setLoginError] = useState("");
  const [accountAuthenticated, setAccountAuthenticated] = useState(false);
  const passphraseRef = useRef<string>("");
  const passphrasePlaintextRef = useRef<string>("");
  const aesKeyRef = useRef<CryptoKey | null>(null);

  // keys
  const [privateKeyPEM, setPrivateKeyPEM] = useLocalStorage<string>("private_key", "");
  const [publicKeyPEM, setPublicKeyPEM] = useLocalStorage<string>("public_key", "");
  const privateKeyRef = useRef<CryptoKey | null>(null);
  const publicKeyRef = useRef<CryptoKey | null>(null);
  const [serverPublicKeyPEM, setServerPublicKeyPEM] = useState<string | null>(null);
  const loginUsernameRef = useRef("");
  const serverPublicKeyRef = useRef<CryptoKey | null>(null);
  const passwordRef = useRef<string>("");
  const [passphraseHashParams, setPassphraseHashParams] = useState(null);
  const [showPassphrasePrompt, setShowPassphrasePrompt] = useState(false);

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
    password: string,
    passphrase?: string
  ) => {
    setLoginError("");
    loginUsernameRef.current = username;
    setUsername(username);
    passwordRef.current = password;
    passphraseRef.current = passphrase || "";

    try {
      if (!serverPublicKeyPEM) throw new Error("Server public key not available");
      if (!websocketClient.isConnectedToServer()) await websocketClient.connect();

      await initializeKeys();

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

      console.log("Sent account info")

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
        type: SignalType.SERVER_LOGIN,
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

  const handlePassphraseSubmit = async (passphrase: string, mode: "login" | "register") => {
    passphrasePlaintextRef.current = passphrase;
    if (mode === "login") {
      if (!passphraseHashParams) {
        setLoginError("Missing passphrase hashing parameters from server.");
        return;
      }
      try {
        console.log("Hashing passphrase for login...");
        const passphraseHash = await CryptoUtils.Hash.hashDataUsingInfo(passphrase, passphraseHashParams);
        passphraseRef.current = passphraseHash;

        websocketClient.send(JSON.stringify({
          type: SignalType.PASSPHRASE_HASH,
          passphraseHash: passphraseHash,
        }));

        console.log("Sent hashed passphrase to server for login");
      } catch (error) {
        console.error("Passphrase hashing failed:", error);
        setLoginError("Failed to hash passphrase.");
      }
    } else if (mode === "register") {
      try {
        console.log("Generating new hashing passphrase for registration...");

        const passphraseHash = await CryptoUtils.Hash.hashData(passphrase);
        passphraseRef.current = passphraseHash;

        websocketClient.send(JSON.stringify({
          type: SignalType.PASSPHRASE_HASH_NEW,
          passphraseHash: passphraseHash,
        }));

        console.log("Sent hashed passphrase to server for registration");
      } catch (error) {
        console.error("Passphrase hashing failed:", error);
        setLoginError("Failed to hash passphrase.");
      }
    }
  };

  const handleAuthSuccess = (username: string) => {
    if (!accountAuthenticated) return;

    console.log("Auth success")
    setUsername(username);
    setIsLoggedIn(true);
    setLoginError("");
  };

  const logout = (secureDBRef?: MutableRefObject<SecureDB | null>, setLoginErrorMessage: string = "") => {
    if (secureDBRef?.current) secureDBRef.current = null;

    passwordRef.current = "";
    passphraseRef.current = "";
    passphrasePlaintextRef.current = "";

    aesKeyRef.current = null;

    setIsLoggedIn(false);
    setLoginError(setLoginErrorMessage);
    setAccountAuthenticated(false);

    console.log("Logged out successfully");
  };

  const useLogout = (Database: any) => {
    return useCallback(() => {
      if (Database.secureDBRef?.current) Database.secureDBRef.current = null; //clear db ref

      //clear again just in case values didnt clear before (it will always be cleared this is just in case)
      passwordRef.current = "";
      passphraseRef.current = "";
      passphrasePlaintextRef.current = "";

      aesKeyRef.current = null; //clear key

      setIsLoggedIn(false);
      setLoginError("");
      setAccountAuthenticated(false);

      console.log("Logged out successfully");
    }, [Database]);
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
    handlePassphraseSubmit,
    handleServerPasswordSubmit,
    handleAuthSuccess,
    setAccountAuthenticated,
    serverPublicKeyRef,
    passwordRef,
    setLoginError,
    passphraseHashParams,
    setPassphraseHashParams,
    passphrasePlaintextRef,
    passphraseRef,
    aesKeyRef,
    setShowPassphrasePrompt,
    showPassphrasePrompt,
    logout,
    useLogout
  };
};