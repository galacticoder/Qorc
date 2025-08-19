import { v4 as uuidv4 } from 'uuid';
import { CryptoUtils } from '@/lib/unified-crypto';
import { useAuth } from '@/hooks/useAuth';
import { PinnedServer } from '@/lib/ratchet/pinned-server';
import { Message } from '@/components/chat/types';
import { SecureDB } from '@/lib/secureDB';

export enum SignalType {
  PUBLICKEYS = "public-keys",
  FILE_MESSAGE = "file-message",
  FILE_MESSAGE_CHUNK = "file-message-chunk",
  ENCRYPTED_MESSAGE = "encrypted-message",
  USER_DISCONNECT = "user-disconnect",
  SERVERLIMIT = "server-limit",
  ERROR = "ERROR",
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
  HYBRID_KEYS = "hybrid-keys",
  HYBRID_KEYS_UPDATE = "hybrid-keys-update",
  // ratchet and x3dh stuff
  X3DH_PUBLISH_BUNDLE = "x3dh-publish-bundle",
  X3DH_REQUEST_BUNDLE = "x3dh-request-bundle",
  X3DH_DELIVER_BUNDLE = "x3dh-deliver-bundle",
  DR_SEND = "dr-send",
  TYPING_START = "typing-start",
  TYPING_STOP = "typing-stop",
  // Receipt signals
  MESSAGE_DELIVERED = "message-delivered",
  MESSAGE_READ = "message-read",
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
  } = Database;

  const {
    setServerHybridPublic,
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
      case SignalType.PUBLICKEYS: {
        const usersData = JSON.parse(message) as Record<string, {
          x25519PublicBase64: string;
          kyberPublicBase64: string
        }>;

        setUsers(Object.entries(usersData).map(([username, keys]) => ({
          id: uuidv4(),
          username,
          isTyping: false,
          isOnline: true,
          hybridPublicKeys: keys
        })));
        break;
      }

      case SignalType.SERVER_PUBLIC_KEY: {
        const hybridKeys = data.hybridKeys as {
          x25519PublicBase64: string;
          kyberPublicBase64: string;
        };

        console.log("Received server hybrid keys: ", {
          x25519PublicBase64: hybridKeys?.x25519PublicBase64?.substring(0, 20) + "...",
          kyberPublicBase64: hybridKeys?.kyberPublicBase64?.substring(0, 20) + "...",
          fullX25519: hybridKeys?.x25519PublicBase64,
          fullKyber: hybridKeys?.kyberPublicBase64
        });

        if (hybridKeys?.x25519PublicBase64 && hybridKeys?.kyberPublicBase64) {
          // enforce tofu pinning for server hybrid keys
          const pinned = PinnedServer.get();
          if (!pinned) {
            PinnedServer.set({ x25519PublicBase64: hybridKeys.x25519PublicBase64, kyberPublicBase64: hybridKeys.kyberPublicBase64 });
            setServerHybridPublic(hybridKeys);
            console.log("Server hybrid keys stored (pinned)");
          } else if (
            pinned.x25519PublicBase64 !== hybridKeys.x25519PublicBase64 ||
            pinned.kyberPublicBase64 !== hybridKeys.kyberPublicBase64
          ) {
            console.error('[Signals] Server hybrid keys changed! Prompting user to trust new server keys.');
            // surface trust prompt via authentication hook state
            handlers.Authentication.setServerTrustRequest?.({
              newKeys: { x25519PublicBase64: hybridKeys.x25519PublicBase64, kyberPublicBase64: hybridKeys.kyberPublicBase64 },
              pinned,
            });
            break;
          } else {
            setServerHybridPublic(hybridKeys);
          }
          try {
            console.debug('[Signals] Server hybrid keys set', {
              x25519Len: (hybridKeys?.x25519PublicBase64 || '').length,
              kyberLen: (hybridKeys?.kyberPublicBase64 || '').length,
            });
          } catch { }
        } else {
          console.error("Invalid server hybrid keys format");
        }
        break;
      }

      case SignalType.HYBRID_KEYS: {
        const { username, hybridKeys } = data as {
          username: string;
          hybridKeys: {
            x25519PublicBase64: string;
            kyberPublicBase64: string;
          }
        };

        if (username && hybridKeys) {
          setUsers(prevUsers => prevUsers.map(user =>
            user.username === username
              ? { ...user, hybridPublicKeys: hybridKeys }
              : user
          ));
        }
        break;
      }

      case SignalType.AUTH_SUCCESS: {
        handleAuthSuccess(loginUsernameRef.current);
        break;
      }

      case SignalType.PASSPHRASE_HASH: {
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
        }
        setShowPassphrasePrompt(true);
        break;
      }

      case SignalType.PASSPHRASE_SUCCESS: {
        const parsedStoredHash = CryptoUtils.Hash.parseArgon2Hash(passphraseRef.current);
        const { aesKey: derivedKey } = await CryptoUtils.Keys.deriveAESKeyFromPassphrase(
          passphrasePlaintextRef.current,
          {
            saltBase64: parsedStoredHash.salt,
            time: parsedStoredHash.timeCost,
            memoryCost: parsedStoredHash.memoryCost,
            parallelism: parsedStoredHash.parallelism,
            algorithm: parsedStoredHash.algorithm,
            version: parsedStoredHash.version,
          }
        );

        aesKeyRef.current = derivedKey;
        setShowPassphrasePrompt(false);
        break;
      }

      case SignalType.MESSAGE_DELIVERED: {
        // Handle message delivery receipt
        const { messageId, from } = data || {};
        if (messageId && from) {
          // Dispatch delivery receipt event
          const event = new CustomEvent('message-delivered', {
            detail: { messageId, from }
          });
          window.dispatchEvent(event);
        }
        break;
      }

      case SignalType.ENCRYPTED_MESSAGE:
      case SignalType.DR_SEND:
      case SignalType.USER_DISCONNECT:
      case SignalType.EDIT_MESSAGE:
      case SignalType.DELETE_MESSAGE: {
        if (handlers['handleEncryptedMessagePayload']) {
          try {
            console.debug('[Signals] Dispatching to encrypted handler', { type, keys: Object.keys(data || {}) });
          } catch { }
          await (handlers as any).handleEncryptedMessagePayload(data);
        }
        break;
      }
      case SignalType.X3DH_DELIVER_BUNDLE: {
        // session setup is handled in encrypted handler and ratchet initiator
        break;
      }

      case SignalType.IN_ACCOUNT: {
        setAccountAuthenticated(true);
        passwordRef.current = "";
        break;
      }

      case SignalType.FILE_MESSAGE_CHUNK: {
        await handleFileMessageChunk(data, { from: data.from });
        break;
      }

      case SignalType.NAMEEXISTSERROR:
      case SignalType.INVALIDNAMELENGTH:
      case SignalType.INVALIDNAME:
      case SignalType.AUTH_ERROR:
      case SignalType.SERVERLIMIT: {
        setIsLoggedIn(false);
        setLoginError(`Login error: ${message}`);
        break;
      }

      default:
        console.warn("Unhandled signal type: ", type);
    }
  } catch (error) {
    console.error("Error handling server message:", error);
    setLoginError("Error processing server message");
  }
}