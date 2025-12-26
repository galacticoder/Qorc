import { v4 as uuidv4 } from 'uuid';
import { CryptoUtils } from './unified-crypto';
import websocketClient from './websocket';
import { sanitizeHybridKeys } from './validators';
import { SecureAuditLogger } from './secure-error-handler';
import { clusterKeyManager } from './cluster-key-manager';
import { SignalType } from './signal-types';
import { profilePictureSystem } from './profile-picture-system';

const __userExistsDebounce = new Map<string, number>();

class SecureTokenStorage {
  private static readonly KEY_BASE = 'tok';

  private static keyForInstance(): string {
    try {
      const id = (window as any).electronAPI?.instanceId;
      const suffix = typeof id === 'string' || typeof id === 'number' ? String(id) : '1';
      return `${this.KEY_BASE}:${suffix}`;
    } catch {
      return `${this.KEY_BASE}:1`;
    }
  }

  static async store(tokens: { accessToken: string; refreshToken: string }): Promise<boolean> {
    try {
      const access = typeof tokens.accessToken === 'string' ? tokens.accessToken.trim() : '';
      const refresh = typeof tokens.refreshToken === 'string' ? tokens.refreshToken.trim() : '';
      if (!access || !refresh) return false;
      if (
        !/^[A-Za-z0-9_.~-]+\.[A-Za-z0-9_.~-]+\.[A-Za-z0-9_.~-]*$/.test(access) ||
        !/^[A-Za-z0-9_.~-]+\.[A-Za-z0-9_.~-]+\.[A-Za-z0-9_.~-]*$/.test(refresh)
      ) {
        return false;
      }
      const api = (window as any).electronAPI;
      if (!api?.secureStore?.set) return false;
      await api.secureStore.init?.();
      const ok = await api.secureStore.set(
        this.keyForInstance(),
        JSON.stringify({ a: access, r: refresh, t: Date.now() })
      );
      return !!ok;
    } catch (_error) {
      SecureAuditLogger.error('tokens', 'storage', 'store-failed', { error: (_error as Error).message });
      return false;
    }
  }

  static async retrieve(): Promise<{ accessToken: string; refreshToken: string } | null> {
    try {
      const api = (window as any).electronAPI;
      if (!api?.secureStore?.get) return null;
      await api.secureStore.init?.();
      const raw = await api.secureStore.get(this.keyForInstance());
      if (!raw || typeof raw !== 'string') return null;
      const parsed = JSON.parse(raw);
      const access = typeof parsed?.a === 'string' ? parsed.a.trim() : '';
      const refresh = typeof parsed?.r === 'string' ? parsed.r.trim() : '';
      if (!access || !refresh) return null;
      return { accessToken: access, refreshToken: refresh };
    } catch (_error) {
      SecureAuditLogger.error('tokens', 'retrieval', 'retrieve-failed', { error: (_error as Error).message });
      return null;
    }
  }

  static clear(): void {
    try {
      (window as any).electronAPI?.secureStore?.remove?.(this.keyForInstance());
    } catch { }
  }

  static clearEncryptionKey(): void {
  }
}

export async function persistAuthTokens(tokens: {
  accessToken: string;
  refreshToken: string;
}): Promise<boolean> {
  return await SecureTokenStorage.store(tokens);
}

export async function retrieveAuthTokens(): Promise<{ accessToken: string; refreshToken: string } | null> {
  return await SecureTokenStorage.retrieve();
}

export function clearAuthTokens(): void {
  SecureTokenStorage.clear();
}

export function clearTokenEncryptionKey(): void {
  SecureTokenStorage.clearEncryptionKey();
}

interface SignalHandlers {
  Authentication: any;
  Database: any;
  handleFileMessageChunk: (data: any, meta: any) => Promise<void>;
  handleEncryptedMessagePayload: (message: any) => Promise<void>;
}

export async function handleSignalMessages(data: any, handlers: SignalHandlers) {
  const { Authentication, Database, handleFileMessageChunk, handleEncryptedMessagePayload } = handlers;
  const { type, message } = data ?? {};

  const { setUsers } = Database ?? {};
  const {
    setServerHybridPublic,
    serverHybridPublic,
    handleAuthSuccess,
    loginUsernameRef,
    aesKeyRef,
    setAccountAuthenticated,
    setIsLoggedIn,
    setLoginError,
    setPassphraseHashParams,
    passphrasePlaintextRef: _passphrasePlaintextRef,
    passphraseRef: _passphraseRef,
    setShowPassphrasePrompt,
    passwordRef,
    setIsSubmittingAuth,
    setAuthStatus,
    setTokenValidationInProgress,
    setServerTrustRequest: _setServerTrustRequest,
    keyManagerRef: _keyManagerRef
  } = Authentication ?? {};

  if (!type) {
    SecureAuditLogger.warn('signals', 'message', 'missing-type', {});
    return;
  }

  if (type === 'pq-heartbeat-pong' || type === 'pq-heartbeat-ping') {
    return;
  }

  try {
    switch (type) {
      case 'pq-handshake-ack': {
        break;
      }
      case SignalType.PUBLICKEYS: {
        if (!Array.isArray(Object.keys(data?.message ?? {}))) {
          SecureAuditLogger.warn('signals', 'publickeys', 'invalid-payload', {});
          return;
        }
        const usersData = JSON.parse(message) as Record<string, { x25519PublicBase64: string; kyberPublicBase64: string }>;
        if (!setUsers) {
          SecureAuditLogger.warn('signals', 'publickeys', 'setusers-unavailable', {});
          return;
        }
        setUsers(
          Object.entries(usersData)
            .filter(([username]) => typeof username === 'string' && username.length > 0 && username.length <= 64)
            .map(([username, keys]) => {
              const sanitized = sanitizeHybridKeys(keys);
              return {
                id: uuidv4(),
                username,
                isTyping: false,
                isOnline: true,
                hybridPublicKeys: sanitized
              };
            })
        );

        // Trigger events to process queued messages for each user
        Object.entries(usersData).forEach(([username, hybridKeys]) => {
          const sanitized = sanitizeHybridKeys(hybridKeys);
          window.dispatchEvent(new CustomEvent('user-keys-available', {
            detail: { username, hybridKeys: sanitized }
          }));
        });

        break;
      }

      case SignalType.SERVER_PUBLIC_KEY: {
        const rawKeys = data?.hybridKeys;
        const serverId = data?.serverId;

        if (!rawKeys) {
          console.error('[SIGNALS] SERVER_PUBLIC_KEY missing hybridKeys!');
          SecureAuditLogger.warn('signals', 'server-key', 'missing-keys', {});
          return;
        }

        // Sanitize server keys before pinning
        const hybridKeys = sanitizeHybridKeys(rawKeys);
        if (!hybridKeys || !hybridKeys.kyberPublicBase64) {
          SecureAuditLogger.warn('signals', 'server-key', 'invalid-key-material', {});
          return;
        }

        try {
          websocketClient.setServerKeyMaterial(hybridKeys as any, serverId);

          if (serverId) {
            clusterKeyManager.updateServerKeys(serverId, hybridKeys as any);
          }

          try { const { encryptedStorage } = await import('./encrypted-storage'); await encryptedStorage.setItem('securechat_server_pin_v2', JSON.stringify(hybridKeys)); } catch { }
        } catch (_err) {
          SecureAuditLogger.error('signals', 'server-key', 'persist-failed', { error: (_err as Error).message });
        }

        if (setServerHybridPublic) {
          setServerHybridPublic(hybridKeys);
        }
        break;
      }

      case SignalType.HYBRID_KEYS: {
        if (!setUsers) break;
        const { username, hybridKeys } = data ?? {};
        if (typeof username !== 'string' || !hybridKeys) {
          SecureAuditLogger.warn('signals', 'hybrid-keys', 'invalid-payload', {});
          return;
        }
        const sanitized = sanitizeHybridKeys(hybridKeys);
        setUsers((prev: any[]) =>
          prev.map((user: any) =>
            user.username === username
              ? { ...user, hybridPublicKeys: sanitized }
              : user
          )
        );

        // Trigger event to process queued messages for this user
        window.dispatchEvent(new CustomEvent('user-keys-available', {
          detail: { username, hybridKeys: sanitized }
        }));

        break;
      }

      case SignalType.PQ_SESSION_INIT: {
        if (!data?.serverKeys || typeof data.serverKeys !== 'object') {
          SecureAuditLogger.warn('signals', 'pq-session', 'missing-server-keys', {});
          return;
        }
        try { const { encryptedStorage } = await import('./encrypted-storage'); await encryptedStorage.setItem('securechat_server_pin_v2', JSON.stringify(data.serverKeys)); } catch { }
        (websocketClient as any).initiateSessionKeyExchange?.(data.serverKeys);
        break;
      }

      case SignalType.PQ_SESSION_RESPONSE: {
        if (!data?.kemCiphertext || !data?.sessionId) {
          SecureAuditLogger.warn('signals', 'pq-session', 'invalid-response', {});
          return;
        }
        (websocketClient as any).handleSessionKeyExchangeResponse?.(data);
        break;
      }

      case SignalType.AUTH_SUCCESS: {
        const usernameFromServer = typeof data?.username === 'string' ? data.username.trim() : '';
        let recoveredUser = usernameFromServer;

        if (!recoveredUser) {
          let fallback = loginUsernameRef?.current as string | undefined;
          if (!fallback) {
            try {
              const { syncEncryptedStorage } = await import('./encrypted-storage');
              fallback = syncEncryptedStorage.getItem('last_authenticated_username') || '';
            } catch {
              fallback = '';
            }
          }

          if (typeof fallback === 'string') {
            recoveredUser = fallback.trim();
          }
        }

        if (recoveredUser && /^[a-zA-Z0-9._-]{3,100}$/.test(recoveredUser)) {
          loginUsernameRef && (loginUsernameRef.current = recoveredUser);
          try { (await import('./encrypted-storage')).syncEncryptedStorage.setItem('last_authenticated_username', recoveredUser); } catch { }
        } else {
          SecureAuditLogger.warn('signals', 'auth-success', 'invalid-username', {});
          recoveredUser = '';
        }

        if (data?.tokens?.accessToken && data?.tokens?.refreshToken) {
          clearTokenEncryptionKey();
          await persistAuthTokens({
            accessToken: String(data.tokens.accessToken),
            refreshToken: String(data.tokens.refreshToken)
          }).catch((error) => SecureAuditLogger.error('signals', 'auth-success', 'persist-tokens-failed', { error: error.message }));
          setAccountAuthenticated?.(true);
          setIsSubmittingAuth?.(false);
          try { window.dispatchEvent(new CustomEvent('secure-chat:auth-success')); } catch { }
        }

        if (data?.recovered && recoveredUser) {
          let vaultKeyUnwrapSuccess = false;
          try {
            let vaultKey: CryptoKey | null = null;
            const { loadVaultKeyRaw, ensureVaultKeyCryptoKey } = await import('./vault-key');
            const raw = await loadVaultKeyRaw(recoveredUser);
            if (raw && raw.length === 32) {
              const { AES } = await import('./unified-crypto');
              vaultKey = await AES.importAesKey(raw);
            } else {
              vaultKey = await ensureVaultKeyCryptoKey(recoveredUser);
            }

            if (vaultKey) {
              const { loadWrappedMasterKey } = await import('./vault-key');
              const masterKeyBytes = await loadWrappedMasterKey(recoveredUser, vaultKey);

              if (masterKeyBytes && masterKeyBytes.length === 32) {
                const { AES } = await import('./unified-crypto');
                const masterKey = await AES.importAesKey(masterKeyBytes);
                if (aesKeyRef) {
                  aesKeyRef.current = masterKey;
                }

                if (!Authentication?.keyManagerRef?.current) {
                  const mod = await import('./secure-key-manager');
                  const SKM = (mod as any).SecureKeyManager || (mod as any).default;
                  Authentication.keyManagerRef.current = new SKM(recoveredUser);
                }
                try { await Authentication.keyManagerRef.current!.initializeWithMasterKey(masterKeyBytes); } catch { }
                try { masterKeyBytes.fill(0); } catch { }

                try {
                  if (Authentication?.keyManagerRef?.current && serverHybridPublic) {
                    const maybeKeys = await Authentication.keyManagerRef.current.getKeys().catch(() => null);
                    if (!maybeKeys) {
                      const pair = await CryptoUtils.Hybrid.generateHybridKeyPair();
                      await Authentication.keyManagerRef.current.storeKeys(pair);
                    }
                    const publicKeys = await Authentication.keyManagerRef.current.getPublicKeys();
                    if (publicKeys) {
                      const keysToSend = {
                        kyberPublicBase64: publicKeys.kyberPublicBase64 || '',
                        dilithiumPublicBase64: publicKeys.dilithiumPublicBase64 || '',
                        x25519PublicBase64: publicKeys.x25519PublicBase64 || ''
                      };
                      const payload = JSON.stringify(keysToSend);
                      try {
                        const keys = await Authentication.getKeysOnDemand?.();
                        const encryptedHybridKeys = await CryptoUtils.Hybrid.encryptForServer(
                          payload,
                          serverHybridPublic,
                          {
                            senderDilithiumSecretKey: keys?.dilithium?.secretKey,
                            senderDilithiumPublicKey: keys?.dilithium?.publicKey,
                            metadata: { context: 'hybrid-keys-update' }
                          }
                        );
                        websocketClient.send(JSON.stringify({ type: SignalType.HYBRID_KEYS_UPDATE, userData: encryptedHybridKeys }));
                      } catch { }
                    }
                  }
                } catch { }

                try {
                  if ((window as any).edgeApi?.setSignalStorageKey) {
                    const label = new TextEncoder().encode('signal-storage-key-v1');
                    let derived: Uint8Array | null = null;
                    const keys = await Authentication.getKeysOnDemand?.();
                    const kyberSecret: Uint8Array | undefined = keys?.kyber?.secretKey || Authentication?.hybridKeysRef?.current?.kyber?.secretKey;
                    if (kyberSecret && kyberSecret instanceof Uint8Array && kyberSecret.length > 0) {
                      derived = await (CryptoUtils as any).Hash.generateBlake3Mac(label, kyberSecret);
                    }
                    if (derived) {
                      const keyB64 = (CryptoUtils as any).Base64.arrayBufferToBase64(derived);
                      await (window as any).edgeApi.setSignalStorageKey({ keyBase64: keyB64 });
                      try { if ((derived as any)?.fill) (derived as any).fill(0); } catch { }
                    }
                  }
                } catch { }

                setAccountAuthenticated?.(true);
                setIsLoggedIn?.(true);
                setShowPassphrasePrompt?.(false);
                Authentication?.setUsername?.(recoveredUser);
                Authentication?.setMaxStepReached?.('server');
                Authentication?.setRecoveryActive?.(false);
                try { window.dispatchEvent(new CustomEvent('secure-chat:auth-success')); } catch { }
                vaultKeyUnwrapSuccess = true;
              }
            }
          } catch { }

          if (vaultKeyUnwrapSuccess) {
            break;
          }
        }

        handleAuthSuccess?.(recoveredUser || usernameFromServer || '', Boolean(data?.recovered));
        try { Authentication?.setTokenValidationInProgress?.(false); } catch { }
        try { setAuthStatus?.(''); } catch { }
        break;
      }

      case SignalType.TOKEN_VALIDATION_RESPONSE: {
        if (!data || typeof data !== 'object') {
          SecureAuditLogger.warn('signals', 'token-validation', 'invalid-data', {});
          return;
        }

        try { SecureAuditLogger.info('auth', 'token-validate', 'response', { valid: !!(data as any).valid, error: (data as any)?.error || null }); } catch { }

        if (data.valid) {
          if (typeof data.username === 'string' && data.username) {
            if (loginUsernameRef) loginUsernameRef.current = data.username;
            try { (await import('./encrypted-storage')).syncEncryptedStorage.setItem('last_authenticated_username', data.username); } catch { }
            Authentication?.setUsername?.(data.username);
          }
          try { setLoginError?.(''); } catch { }

          let vaultKey: CryptoKey | null = null;
          try {
            const { loadVaultKeyRaw, ensureVaultKeyCryptoKey } = await import('./vault-key');
            let raw = await loadVaultKeyRaw(loginUsernameRef?.current || data.username || '');
            if (raw && raw.length === 32) {
              const { AES } = await import('./unified-crypto');
              vaultKey = await AES.importAesKey(raw);
            } else if (loginUsernameRef?.current) {
              vaultKey = await ensureVaultKeyCryptoKey(loginUsernameRef.current);
            }
          } catch { }

          let masterKeyBytes: Uint8Array | null = null;
          if (vaultKey && loginUsernameRef?.current) {
            try {
              const { loadWrappedMasterKey } = await import('./vault-key');
              masterKeyBytes = await loadWrappedMasterKey(loginUsernameRef.current, vaultKey);
            } catch { }
          }

          if (masterKeyBytes && masterKeyBytes.length === 32) {
            try {
              const { AES } = await import('./unified-crypto');
              const masterKey = await AES.importAesKey(masterKeyBytes);
              if (aesKeyRef) {
                aesKeyRef.current = masterKey;
              }

              if (!Authentication?.keyManagerRef?.current) {
                const mod = await import('./secure-key-manager');
                const SKM = (mod as any).SecureKeyManager || (mod as any).default;
                Authentication.keyManagerRef.current = new SKM(loginUsernameRef!.current);
              }
              try { await Authentication.keyManagerRef.current!.initializeWithMasterKey(masterKeyBytes); } catch { }

              try {
                const existingKeys = await Authentication.keyManagerRef.current!.getKeys().catch(() => null);
                if (!existingKeys) {
                  const { CryptoUtils } = await import('./unified-crypto');
                  const pair = await CryptoUtils.Hybrid.generateHybridKeyPair();
                  await Authentication.keyManagerRef.current!.storeKeys(pair);
                }
              } catch { }
            } finally {
              try { masterKeyBytes.fill(0); } catch { }
            }
          } else {
            try { setShowPassphrasePrompt?.(true); setAuthStatus?.('Passphrase required to unlock local keys'); } catch { }
          }

          try {
            if (Authentication?.keyManagerRef?.current && serverHybridPublic) {
              try {
                const maybeKeys = await Authentication.keyManagerRef.current.getKeys().catch(() => null);
                if (!maybeKeys) {
                  const { CryptoUtils } = await import('./unified-crypto');
                  const pair = await CryptoUtils.Hybrid.generateHybridKeyPair();
                  await Authentication.keyManagerRef.current.storeKeys(pair);
                }
              } catch { }
              
              try { await Authentication.getKeysOnDemand?.(); } catch { }
              const publicKeys = await Authentication.keyManagerRef.current.getPublicKeys();
              if (publicKeys) {
                const keysToSend = {
                  kyberPublicBase64: publicKeys.kyberPublicBase64 || '',
                  dilithiumPublicBase64: publicKeys.dilithiumPublicBase64 || '',
                  x25519PublicBase64: publicKeys.x25519PublicBase64 || ''
                };
                const payload = JSON.stringify(keysToSend);
                try {
                  const keys = await Authentication.getKeysOnDemand?.();
                  const encryptedHybridKeys = await CryptoUtils.Hybrid.encryptForServer(
                    payload,
                    serverHybridPublic,
                    {
                      senderDilithiumSecretKey: keys?.dilithium?.secretKey,
                      senderDilithiumPublicKey: keys?.dilithium?.publicKey,
                      metadata: { context: 'hybrid-keys-update' }
                    }
                  );
                  websocketClient.send(JSON.stringify({ type: SignalType.HYBRID_KEYS_UPDATE, userData: encryptedHybridKeys }));
                } catch { }
              }
            }
          } catch { }

          // Configure Signal storage key
          try {
            if (loginUsernameRef?.current && (window as any).edgeApi?.setSignalStorageKey) {
              const label = new TextEncoder().encode('signal-storage-key-v1');
              let derived: Uint8Array | null = null;
              try {
                const keys = await Authentication.getKeysOnDemand?.();
                const kyberSecret: Uint8Array | undefined = keys?.kyber?.secretKey || Authentication?.hybridKeysRef?.current?.kyber?.secretKey;
                if (kyberSecret && kyberSecret instanceof Uint8Array && kyberSecret.length > 0) {
                  derived = await (CryptoUtils as any).Hash.generateBlake3Mac(label, kyberSecret);
                } else if (_passphrasePlaintextRef?.current) {
                  const salt = new TextEncoder().encode('signal-storage-key-v1');
                  derived = await (CryptoUtils as any).KDF.argon2id(_passphrasePlaintextRef.current, {
                    salt,
                    time: 3,
                    memoryCost: 1 << 17,
                    parallelism: 2,
                    hashLen: 32
                  });
                }
                if (derived) {
                  const keyB64 = (CryptoUtils as any).Base64.arrayBufferToBase64(derived);
                  try { await (window as any).edgeApi.setSignalStorageKey({ keyBase64: keyB64 }); } catch { }
                  try {
                    const existing = await (window as any).edgeApi.getPreKeyBundle?.({ username: loginUsernameRef.current });
                    if (!existing || !existing.identityKeyBase64) {
                      try { await (window as any).edgeApi.generateIdentity?.({ username: loginUsernameRef.current }); } catch { }
                      try { await (window as any).edgeApi.generatePreKeys?.({ username: loginUsernameRef.current, startId: 1, count: 100 }); } catch { }
                    }
                    try { await (window as any).edgeApi.trustPeerIdentity?.({ selfUsername: loginUsernameRef.current, peerUsername: loginUsernameRef.current, deviceId: 1 }); } catch { }
                    try {
                      const bundle = await (window as any).edgeApi.getPreKeyBundle?.({ username: loginUsernameRef.current });
                      if (bundle && !bundle.error) {
                        await websocketClient.sendSecureControlMessage({ type: SignalType.LIBSIGNAL_PUBLISH_BUNDLE, bundle });
                      }
                    } catch { }
                  } catch { }
                  try { if ((derived as any)?.fill) (derived as any).fill(0); } catch { }
                }
              } catch { }
            }
          } catch { }

          setAccountAuthenticated?.(true);
          try { window.dispatchEvent(new CustomEvent('secure-chat:auth-success')); } catch { }
          setIsLoggedIn?.(true);
          Authentication?.setMaxStepReached?.('passphrase');
          try { Authentication?.setTokenValidationInProgress?.(false); } catch { }

          if (data.tokens?.accessToken && data.tokens.refreshToken) {
            clearTokenEncryptionKey();
            const ok = await persistAuthTokens({
              accessToken: data.tokens.accessToken,
              refreshToken: data.tokens.refreshToken
            }).catch(() => false);
            try {
              const api: any = (window as any).electronAPI;
              const inst = api?.instanceId ? String(api.instanceId) : '1';
              const verify = api?.secureStore?.get ? await api.secureStore.get(`tok:${inst}`) : null;
              SecureAuditLogger.info('auth', 'tokens', 'persist-verify', { ok: !!ok, hasValue: typeof verify === 'string', instanceId: inst });
            } catch { }
          }
        } else {
          if (Authentication?.accountAuthenticated || Authentication?.isLoggedIn) {
            try { SecureAuditLogger.info('auth', 'token-validate', 'ignored-stale-failure', {}); } catch { }
            break;
          }

          // Try device-proof refresh via HTTP
          try {
            setTokenValidationInProgress?.(true);
            setAuthStatus?.('Refreshing session...');
            const tokens = await retrieveAuthTokens();
            const rt = tokens?.refreshToken;
            try { SecureAuditLogger.info('auth', 'refresh', 'start', { hasRefreshToken: !!rt }); } catch { }
            if (rt && (window as any).edgeApi?.refreshTokens) {
              try { SecureAuditLogger.info('auth', 'refresh', 'challenge', {}); } catch { }
              const res = await (window as any).edgeApi.refreshTokens({ refreshToken: rt });
              try { SecureAuditLogger.info('auth', 'refresh', 'result', { success: !!res?.success, status: res?.status || null, hasTokens: !!(res?.tokens?.accessToken && res?.tokens?.refreshToken) }); } catch { }
              if (res?.success && res.tokens?.accessToken && res.tokens?.refreshToken) {
                await persistAuthTokens({ accessToken: res.tokens.accessToken, refreshToken: res.tokens.refreshToken });
                try { await websocketClient.attemptTokenValidationOnce?.('refresh'); } catch { }
                setAuthStatus?.('');
                setTokenValidationInProgress?.(false);
                break;
              }
            } else {
              try { SecureAuditLogger.warn('auth', 'refresh', 'edge-api-missing', { hasEdgeApi: !!(window as any).edgeApi, hasMethod: !!(window as any).edgeApi?.refreshTokens }); } catch { }
            }
          } catch (e) {
            SecureAuditLogger.error('auth', 'refresh', 'failed', { error: (e as Error)?.message || String(e) });
          } finally {
            try { setAuthStatus?.(''); setTokenValidationInProgress?.(false); } catch { }
          }

          await clearAuthTokens();
          clearTokenEncryptionKey();
          setAccountAuthenticated?.(false);
          Authentication?.setMaxStepReached?.('login');
          setShowPassphrasePrompt?.(false);
          try { Authentication?.setTokenValidationInProgress?.(false); } catch { }
          if (data.error) {
            setLoginError?.(`Token validation failed: ${data.message}`);
          }
        }
        break;
      }

      case SignalType.IN_ACCOUNT: {
        setAccountAuthenticated?.(true);
        setShowPassphrasePrompt?.(false);
        setAuthStatus?.('Account authentication successful. Enter server password.');
        setLoginError?.('');
        if (passwordRef) passwordRef.current = '';

        const userCandidate = typeof data?.username === 'string' ? data.username.trim() : loginUsernameRef?.current;
        if (userCandidate) {
          if (loginUsernameRef) loginUsernameRef.current = userCandidate;
          try { (await import('./encrypted-storage')).syncEncryptedStorage.setItem('last_authenticated_username', userCandidate as string); } catch { }
        }

        if (data?.tokens?.accessToken && data.tokens.refreshToken) {
          clearTokenEncryptionKey();
          const ok = await persistAuthTokens({
            accessToken: data.tokens.accessToken,
            refreshToken: data.tokens.refreshToken
          }).catch(() => false);
          try {
            const api: any = (window as any).electronAPI;
            const inst = api?.instanceId ? String(api.instanceId) : '1';
            const verify = api?.secureStore?.get ? await api.secureStore.get(`tok:${inst}`) : null;
            SecureAuditLogger.info('auth', 'tokens', 'persist-verify', { ok: !!ok, hasValue: typeof verify === 'string', instanceId: inst });
          } catch { }
        }

        setIsSubmittingAuth?.(false);
        break;
      }

      case SignalType.PASSPHRASE_HASH: {
        const requiredFields = ['version', 'algorithm', 'salt', 'memoryCost', 'timeCost', 'parallelism'];
        const hasAllFields = requiredFields.every((field) => field in (data ?? {}));
        if (hasAllFields) {
          setPassphraseHashParams?.({
            version: data.version,
            algorithm: data.algorithm,
            salt: data.salt,
            memoryCost: data.memoryCost,
            timeCost: data.timeCost,
            parallelism: data.parallelism,
            message: data.message ?? ''
          });

          if (data.recovered && !Authentication?.isRegistrationMode && !Authentication?.accountAuthenticated) {
            Authentication?.setRecoveryActive?.(true);
          }
        } else {
          try {
            const missing = requiredFields.filter((field) => !(field in (data ?? {})));
            console.error('[Signals] PASSPHRASE_HASH missing required fields from server payload', {
              receivedKeys: Object.keys(data || {}),
              missing,
              raw: data
            });
          } catch { }
          setPassphraseHashParams?.(null);
        }

        setShowPassphrasePrompt?.(true);
        setAuthStatus?.('Please enter your passphrase to continue...');
        setLoginError?.('');
        setIsSubmittingAuth?.(false);
        break;
      }

      case SignalType.PASSWORD_HASH_PARAMS: {
        try {
          const event = new CustomEvent('password-hash-params', {
            detail: {
              salt: data.salt,
              timeCost: data.timeCost,
              memoryCost: data.memoryCost,
              parallelism: data.parallelism,
              algorithm: data.algorithm,
              version: data.version
            }
          });
          window.dispatchEvent(event);
        } catch (_error) {
          SecureAuditLogger.error('signals', 'password-params', 'dispatch-failed', { error: (_error as Error).message });
          try {
            setIsSubmittingAuth?.(false);
            setAuthStatus?.('');
            Authentication?.setMaxStepReached?.('login');
            setAccountAuthenticated?.(false);
            setIsLoggedIn?.(false);
            setShowPassphrasePrompt?.(false);
          } catch { }
        }
        break;
      }

      case SignalType.PASSPHRASE_SUCCESS: {
        try {
          // Passphrase verified by server save a wrapped copy of the master key.
          const user = loginUsernameRef?.current || '';
          if (user && aesKeyRef?.current) {
            try {
              const { ensureVaultKeyCryptoKey, saveWrappedMasterKey } = await import('./vault-key');
              const vaultKey = await ensureVaultKeyCryptoKey(user);
              const raw = new Uint8Array(await (globalThis as any).crypto?.subtle?.exportKey('raw', aesKeyRef.current as CryptoKey));
              await saveWrappedMasterKey(user, raw, vaultKey);
              raw.fill(0);
            } catch { }
          }
        } catch (_error) {
          SecureAuditLogger.error('signals', 'password-hash', 'derive-key-failed', { error: (_error as Error).message });
        }

        setShowPassphrasePrompt?.(false);
        Authentication?.setRecoveryActive?.(false);
        setAccountAuthenticated?.(true);
        break;
      }

      case SignalType.ENCRYPTED_MESSAGE:
      case SignalType.DR_SEND:
      case SignalType.USER_DISCONNECT:
      case SignalType.EDIT_MESSAGE:
      case SignalType.DELETE_MESSAGE: {
        if (!handleEncryptedMessagePayload) {
          SecureAuditLogger.warn('signals', 'encrypted-message', 'no-handler', {});
          return;
        }
        await handleEncryptedMessagePayload(data);
        break;
      }

      case SignalType.LIBSIGNAL_DELIVER_BUNDLE: {
        try {
          const currentUser = loginUsernameRef?.current;
          const targetUser = data?.username;

          if (!data?.success || data?.error || !data?.bundle) {
            SecureAuditLogger.warn('signals', 'libsignal', 'bundle-request-failed', { hasError: !!data?.error });
            window.dispatchEvent(new CustomEvent('libsignal-bundle-failed', {
              detail: { peer: targetUser, error: data?.error || 'Bundle not available' }
            }));
            return;
          }

          if (!currentUser || !targetUser) {
            SecureAuditLogger.warn('signals', 'libsignal', 'missing-fields', {});
            return;
          }

          // Check if session already exists before processing bundle
          await new Promise(resolve => setTimeout(resolve, 0));
          const sessionCheck = await (window as any).edgeApi?.hasSession?.({
            selfUsername: currentUser,
            peerUsername: targetUser,
            deviceId: 1
          });
          await new Promise(resolve => setTimeout(resolve, 0));

          if (sessionCheck?.hasSession) {
            break;
          }

          // Only process bundle if we do not already have a session with this peer
          await new Promise(resolve => setTimeout(resolve, 0));
          const result = await (window as any).edgeApi?.processPreKeyBundle?.({ selfUsername: currentUser, peerUsername: targetUser, bundle: data.bundle });
          await new Promise(resolve => setTimeout(resolve, 0));

          if (!result?.success) {
            throw new Error(result?.error || 'Failed to process pre-key bundle');
          }


          await new Promise(resolve => setTimeout(resolve, 0));
          const confirm = await (window as any).edgeApi?.hasSession?.({ selfUsername: currentUser, peerUsername: targetUser, deviceId: 1 });
          await new Promise(resolve => setTimeout(resolve, 0));
          if (confirm?.hasSession) {
            try { await (window as any).edgeApi?.trustPeerIdentity?.({ selfUsername: currentUser, peerUsername: targetUser, deviceId: 1 }); } catch { }
            window.dispatchEvent(new CustomEvent('libsignal-session-ready', { detail: { peer: targetUser } }));
            await websocketClient.sendSecureControlMessage({
              type: SignalType.SESSION_ESTABLISHED,
              from: currentUser,
              username: targetUser,
              timestamp: Date.now()
            });
          } else {
            throw new Error('Session not present after bundle processing');
          }
        } catch (_error) {
          SecureAuditLogger.error('signals', 'libsignal', 'bundle-processing-failed', { error: (_error as Error).message });
          const targetUser = data?.username;
          if (targetUser) {
            window.dispatchEvent(new CustomEvent('libsignal-bundle-failed', {
              detail: { peer: targetUser, error: String(_error) }
            }));
          }
        }
        break;
      }

      case SignalType.FILE_MESSAGE_CHUNK: {
        if (!handleFileMessageChunk) {
          SecureAuditLogger.warn('signals', 'file-chunk', 'no-handler', {});
          return;
        }
        await handleFileMessageChunk(data, { from: data?.from, to: data?.to });
        break;
      }

      case SignalType.USER_EXISTS_RESPONSE: {
        try {
          const uname = typeof (data as any)?.username === 'string' ? (data as any).username : '';
          if (uname) {
            const now = Date.now();
            const last = __userExistsDebounce.get(uname) || 0;
            if (now - last < 2000) {
              break;
            }
            __userExistsDebounce.set(uname, now);
          }
          setTimeout(() => {
            try { window.dispatchEvent(new CustomEvent('user-exists-response', { detail: data })); } catch { }
          }, 0);
        } catch (_error) {
          SecureAuditLogger.error('signals', 'user-exists', 'dispatch-failed', { error: (_error as Error).message });
        }
        try {
          if (data?.exists && data?.username && data?.hybridPublicKeys) {
            const sanitized = sanitizeHybridKeys(data.hybridPublicKeys);
            if (sanitized) {
              setTimeout(() => {
                try {
                  window.dispatchEvent(new CustomEvent('user-keys-available', {
                    detail: { username: data.username, hybridKeys: sanitized }
                  }));
                } catch { }
              }, 0);
            }
            
            if (handlers?.Database?.setUsers) {
              setTimeout(() => {
                try {
                  handlers.Database.setUsers((prev: any[]) => {
                    const found = prev.find((u) => u.username === data.username);
                    if (!found) {
                      return [
                        ...prev,
                        {
                          id: crypto.randomUUID?.() || String(Date.now()),
                          username: data.username,
                          isOnline: true,
                          hybridPublicKeys: sanitized || data.hybridPublicKeys
                        }
                      ];
                    }
                    if (!found.hybridPublicKeys && data.hybridPublicKeys) {
                      return prev.map((u) => (u.username === data.username ? { ...u, hybridPublicKeys: sanitized || data.hybridPublicKeys, isOnline: true } : u));
                    }
                    return prev;
                  });
                } catch { }
              }, 0);
            }
          }
        } catch { }
        break;
      }

      case SignalType.OFFLINE_MESSAGES_RESPONSE: {
        try {
          window.dispatchEvent(new CustomEvent('offline-messages-response', { detail: data }));
        } catch (_error) {
          SecureAuditLogger.error('signals', 'offline-messages', 'dispatch-failed', { error: (_error as Error).message });
        }
        break;
      }

      case SignalType.BLOCK_TOKENS_UPDATE: {
        window.dispatchEvent(new CustomEvent('block-tokens-updated', { detail: data }));
        break;
      }

      case SignalType.BLOCK_LIST_SYNC: {
        window.dispatchEvent(new CustomEvent('block-list-synced', { detail: data }));
        break;
      }

      case SignalType.BLOCK_LIST_UPDATE: {
        window.dispatchEvent(new CustomEvent('block-list-update', { detail: data }));
        break;
      }

      case SignalType.BLOCK_LIST_RESPONSE: {
        try {
          window.dispatchEvent(new CustomEvent('block-list-response', { detail: data }));
        } catch (_error) {
          SecureAuditLogger.error('signals', 'block-list-response', 'dispatch-failed', { error: (_error as Error).message });
        }
        break;
      }

      case SignalType.CLIENT_GENERATE_PREKEYS: {
        window.dispatchEvent(new CustomEvent('generate-prekeys-request', { detail: data }));
        break;
      }

      case SignalType.PREKEY_STATUS: {
        try {
          window.dispatchEvent(new CustomEvent('libsignal-publish-status', { detail: data }));
        } catch (_error) {
          SecureAuditLogger.error('signals', 'prekey-status', 'dispatch-failed', { error: (_error as Error).message });
        }
        break;
      }

      case 'libsignal-publish-status': {
        try {
          window.dispatchEvent(new CustomEvent('libsignal-publish-status', { detail: data }));
        } catch (_error) {
          SecureAuditLogger.error('signals', 'libsignal-publish', 'dispatch-failed', { error: (_error as Error).message });
        }
        break;
      }

      case SignalType.RATE_LIMIT_STATUS: {
        break;
      }

      case SignalType.CONNECTION_RESTORED: {
        if (data?.hasAuthenticated) {
          setIsLoggedIn?.(true);
          setAccountAuthenticated?.(true);
        }
        break;
      }

      case SignalType.NAMEEXISTSERROR:
      case SignalType.INVALIDNAMELENGTH:
      case SignalType.INVALIDNAME:
      case SignalType.SERVERLIMIT: {
        if (setLoginError) {
          setLoginError(`Login error: ${message ?? type}`);
        }
        try { setAuthStatus?.(''); } catch { }
        try { setIsSubmittingAuth?.(false); } catch { }
        break;
      }

      case SignalType.AUTH_ERROR: {
        const attemptsRemaining = typeof data?.attemptsRemaining === 'number' ? data.attemptsRemaining : undefined;
        const locked = Boolean(data?.locked);
        const cooldownSeconds = typeof data?.cooldownSeconds === 'number' ? data.cooldownSeconds : undefined;
        const category = typeof data?.category === 'string' ? data.category : undefined;

        let errorMessage = message ?? 'Authentication failed';

        if (locked && cooldownSeconds) {
          errorMessage = `Too many attempts. Try again in ${cooldownSeconds}s.`;
          try {
            websocketClient.setGlobalRateLimit?.(cooldownSeconds);
          } catch { }

          try {
            setAccountAuthenticated?.(false);
            setIsLoggedIn?.(false);
            setShowPassphrasePrompt?.(false);
            Authentication?.setMaxStepReached?.('login');
          } catch { }
        } else if (typeof attemptsRemaining === 'number' && !locked) {
          errorMessage += ` (${attemptsRemaining} attempt${attemptsRemaining === 1 ? '' : 's'} remaining)`;
        }

        setLoginError?.(errorMessage);
        try { setAuthStatus?.(''); } catch { }
        try { setIsSubmittingAuth?.(false); } catch { }
        try { window.dispatchEvent(new CustomEvent('auth-error', { detail: { category, code: (data as any)?.code } })); } catch { }

        if (category === 'passphrase' && !locked) {
          setAccountAuthenticated?.(false);
          setIsLoggedIn?.(false);
          setShowPassphrasePrompt?.(false);
          Authentication?.setMaxStepReached?.('login');
        }
        break;
      }

      case SignalType.SESSION_RESET_REQUEST: {
        const peerUsername = data?.from || data?.username;
        const deviceId = data?.deviceId || 1;

        if (!peerUsername || !loginUsernameRef?.current) {
          SecureAuditLogger.warn('signals', 'session-reset', 'missing-peer', {});
          break;
        }

        try {
          await (window as any).edgeApi?.deleteSession?.({
            selfUsername: loginUsernameRef.current,
            peerUsername: peerUsername,
            deviceId: deviceId
          });

          window.dispatchEvent(new CustomEvent('session-reset-received', {
            detail: { peerUsername, reason: data?.reason || 'peer-request' }
          }));

        } catch (_err) {
          SecureAuditLogger.error('signals', 'session-reset', 'delete-failed', {
            error: _err instanceof Error ? _err.message : String(_err),
            peer: peerUsername
          });
        }
        break;
      }

      case SignalType.SESSION_ESTABLISHED: {
        const peerUsername = data?.from || data?.username;

        if (!peerUsername) {
          SecureAuditLogger.warn('signals', 'session-established', 'missing-peer', {});
          break;
        }

        window.dispatchEvent(new CustomEvent('session-established-received', {
          detail: { fromPeer: peerUsername }
        }));

        break;
      }

      case SignalType.ERROR: {
        const errorMsg = message || '';

        try { setIsSubmittingAuth?.(false); } catch { }

        if ((data as any)?.code === 'OFFLINE_LONGTERM_REQUIRED') {
          try {
            window.dispatchEvent(new CustomEvent('offline-longterm-required', { detail: data }));
          } catch { }
          break;
        }

        if (errorMsg.includes('Unknown PQ session') || errorMsg.includes('PQ session')) {
          SecureAuditLogger.warn('signals', 'session-error', 'unknown-session', {
            message: errorMsg,
            action: 'rehandshaking'
          });

          try {
            websocketClient.resetSessionKeys();
            await websocketClient.performHandshake(false);
            void websocketClient.flushPendingQueue();
          } catch (_error) {
            SecureAuditLogger.error('signals', 'session-error', 'rehandshake-failed', {
              error: _error instanceof Error ? _error.message : String(_error)
            });
          }
        } else {
          SecureAuditLogger.warn('signals', 'server-error', 'received', {
            message: errorMsg
          });
        }
        break;
      }

      case 'avatar-fetch-response': {
        try {
          if (data && typeof data.target === 'string') {
            profilePictureSystem.handleServerAvatarResponse({
              target: data.target,
              envelope: data.envelope,
              found: !!data.found
            }).catch(() => { });
          }
        } catch (error) {
          SecureAuditLogger.error('signals', 'avatar-fetch', 'handler-failed', {
            error: error instanceof Error ? error.message : 'unknown'
          });
        }
        break;
      }

      default: {
        SecureAuditLogger.warn('signals', 'unhandled', 'unknown-signal-type', {
          type: type,
          hasMessage: !!message,
          messagePreview: message ? String(message).substring(0, 100) : ''
        });
        break;
      }
    }
  } catch (_error) {
    SecureAuditLogger.error('signals', 'handler', 'signal-processing-error', { error: (_error as Error).message });
    setLoginError?.('Error processing server message');
  }
}

