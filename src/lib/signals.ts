import { v4 as uuidv4 } from 'uuid';
import { CryptoUtils } from '@/lib/unified-crypto';
import { useAuth } from '@/hooks/useAuth';
import { Message } from '@/components/chat/types';
import { SecureDB } from '@/lib/secureDB';

export enum SignalType {
  PUBLICKEYS = "public-keys",
  FILE_MESSAGE = "file-message",
  FILE_MESSAGE_CHUNK = "file-message-chunk",
  ENCRYPTED_MESSAGE = "encrypted-message",
  USER_DISCONNECT = "user-disconnect",
  SERVERLIMIT = "server-limit",
  SERVERMESSAGE = "server-message",
  NAMEEXISTSERROR = "name-exists-error",
  INVALIDNAMELENGTH = "invalid-name-length",
  INVALIDNAME = "invalid-name",
  SERVER_PASSWORD_ENCRYPTED = "server-password-encrypted",
  SERVER_PUBLIC_KEY = "server-public-key",
  SERVER_LOGIN = "server-login",
  ACCOUNT_SIGN_IN = "account-sign-in",
  ACCOUNT_SIGN_UP = "account-sign-up",
  IN_ACCOUNT = "in-account",
  DELETE_MESSAGE = "delete-message",
  EDIT_MESSAGE = "edit-message",
  AUTH_ERROR = "AUTH_ERROR",
  AUTH_SUCCESS = "AUTH_SUCCESS",
  PASSPHRASE_HASH = "passphrase-hash",
  PASSPHRASE_HASH_NEW = "passphrase-hash-new",
  PASSPHRASE_SUCCESS = "passphrase-success",
  UPDATE_DB = "update-db",
}

interface SignalHandlers {
  Authentication: ReturnType<typeof useAuth>;
  Database: any;
  handleFileMessageChunk: (data: any, meta: any) => Promise<void>;
  handleEncryptedMessagePayload: (message: any) => Promise<void>;
}

export async function handleSignalMessages(
  data: any,
  handlers: SignalHandlers
) {

  const { Authentication, Database, handleFileMessageChunk, handleEncryptedMessagePayload } = handlers;
  const { type, message } = data;

  const {
    setUsers
  } = Database

  const {
    setServerPublicKeyPEM,
    serverPublicKeyRef,
    handleAuthSuccess,
    loginUsernameRef,
    aesKeyRef,
    setAccountAuthenticated,
    setIsLoggedIn,
    setLoginError,
    setPassphraseHashParams,
    passphrasePlaintextRef,
    passphraseRef,
    setShowPassphrasePrompt,
    passwordRef,
  } = Authentication;

  try {
    switch (type) {
      case SignalType.PUBLICKEYS:
        const keyData = JSON.parse(message) as Record<string, string>;
        setUsers(Object.entries(keyData).map(([username, publicKey]) => ({
          id: uuidv4(),
          username,
          isTyping: false,
          isOnline: true,
          publicKey
        })));
        break;

      case SignalType.SERVER_PUBLIC_KEY:
        const pem = (data as any).publicKey;
        setServerPublicKeyPEM(pem);
        serverPublicKeyRef.current = await CryptoUtils.Keys.importPublicKeyFromPEM(pem);

        console.log("Server public key received: ", pem);
        break;

      case SignalType.AUTH_SUCCESS:
        handleAuthSuccess(loginUsernameRef.current);
        break;

      case SignalType.PASSPHRASE_HASH:
        if (data && typeof data === "object") {
          const {
            version,
            algorithm,
            salt,
            memoryCost,
            timeCost,
            parallelism,
            message: serverMessage
          } = data || {};

          if (
            version !== undefined &&
            algorithm !== undefined &&
            salt !== undefined &&
            memoryCost !== undefined &&
            timeCost !== undefined &&
            parallelism !== undefined &&
            serverMessage !== undefined
          ) {
            setPassphraseHashParams({
              version,
              algorithm,
              salt,
              memoryCost,
              timeCost,
              parallelism,
              message: serverMessage
            });
            console.log("Received Passphrase hash info: ", data);
          }
        }
        setShowPassphrasePrompt(true);
        break;

      case SignalType.PASSPHRASE_SUCCESS:
        const parsedStoredHash = CryptoUtils.Hash.parseArgon2Hash(passphraseRef.current)
        const { aesKey: derivedKey } = await CryptoUtils.Keys.deriveAESKeyFromPassphrase(passphrasePlaintextRef.current, {
          saltBase64: parsedStoredHash.salt,
          time: parsedStoredHash.timeCost,
          memoryCost: parsedStoredHash.memoryCost,
          parallelism: parsedStoredHash.parallelism,
          algorithm: parsedStoredHash.algorithm,
          version: parsedStoredHash.version,
        });

        aesKeyRef.current = derivedKey;
        console.log("AES key derived and stored for encrypting messages for server db");
        setShowPassphrasePrompt(false);
        break;

      case SignalType.ENCRYPTED_MESSAGE:
      case SignalType.USER_DISCONNECT:
      case SignalType.EDIT_MESSAGE:
      case SignalType.DELETE_MESSAGE:
        if (handlers['handleEncryptedMessagePayload'])
          await (handlers as any).handleEncryptedMessagePayload(data);
        break;

      case SignalType.IN_ACCOUNT:
        setAccountAuthenticated(true);
        passwordRef.current = "";
        break;

      case SignalType.FILE_MESSAGE_CHUNK:
        await handleFileMessageChunk(data, { from: data.from });
        break;

      case SignalType.NAMEEXISTSERROR:
      case SignalType.INVALIDNAMELENGTH:
      case SignalType.INVALIDNAME:
      case SignalType.AUTH_ERROR:
      case SignalType.SERVERLIMIT:
        setIsLoggedIn(false);
        setLoginError(`Login error: ${message}`);
        break;

      default:
        console.warn("Unhandled signal type: ", type);
    }
  } catch (error) {
    console.error("Error handling server message:", error);
    setLoginError("Error processing server message");
  }
}
