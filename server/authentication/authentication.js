import crypto from 'node:crypto';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { SignalType } from '../signals.js';
import { UserDatabase } from '../database/database.js';
import { anonymousSessionService } from './anonymous-session-service.js';
import { OPAQUEServer, OPAQUEHelpers } from '../crypto/opaque-service.js';
import { PrivacyPassServer, PrivacyPassHelpers, NullifierStore } from './privacy-pass-server.js';
import { ZKDeviceProofVerifier, DeviceCommitmentHelpers } from './zk-verifier.js';
import { BlindSignatureIssuer } from '../security/blind-signatures.js';
import { sendSecureMessage, sendSecureMessageChunked } from '../messaging/pq-envelope-handler.js';
import { ServerGatekeeper } from './gatekeeper.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import * as ServerConfig from '../config/config.js';

async function rejectConnection(ws, type, reason, code = 1008) {
  cryptoLogger.warn('[AUTH] Rejecting connection', { type });
  await sendSecureMessage(ws, { type, message: reason });
  ws.close(code, reason);
  return;
}

async function sendAuthError(ws, { message, code = 'AUTH_FAILED', category = 'general', attemptsRemaining = undefined, locked = false, cooldownSeconds = undefined, logout = false }) {
  const payload = {
    type: SignalType.AUTH_ERROR,
    message,
    code, 
    category,
    locked,
  };
  if (attemptsRemaining !== undefined) payload.attemptsRemaining = attemptsRemaining;
  if (cooldownSeconds !== undefined) payload.cooldownSeconds = cooldownSeconds;
  if (logout) payload.logout = true;
  try { await sendSecureMessage(ws, payload); } catch (e) {
    cryptoLogger.error('[AUTH] Failed to send soft auth error', { error: e?.message });
  }
  return { handled: true };
}

function requiresServerEntry(ws) {
  return Boolean(ServerConfig.getServerPasswordHash()) && !ws?._hasServerAuth;
}

function serverEntryResponseFields(ws) {
  const serverEntryRequired = requiresServerEntry(ws);
  return {
    serverEntryRequired,
    serverEntryGranted: !serverEntryRequired
  };
}

// Immutable state manager
export class SecureStateManager {
  static states = new WeakMap();
  static setState(ws, updates) {
    const current = this.states.get(ws) || {};
    const newState = Object.freeze({
      ...current,
      ...updates,
      lastModified: Date.now(),
      stateVersion: (current.stateVersion || 0) + 1
    });
    this.states.set(ws, newState);
    return newState;
  }
  static getState(ws) {
    return this.states.get(ws) || {};
  }
}

export class AccountAuthHandler {
  constructor(serverHybridKeyPair, db) {
    this.serverHybridKeyPair = serverHybridKeyPair;
    this.db = db;
    this.nullifierStore = new NullifierStore(db);
    this.opaqueServer = OPAQUEServer;
    this.ppServer = PrivacyPassServer;
    this.zkVerifier = new ZKDeviceProofVerifier(db);
    this.gatekeeper = new ServerGatekeeper(db);
  }

  /**
   * OT Registration
   * Server assigns a random shard without knowing who the user is
   */
  async handleOTRegisterRequest(ws, data) {
    try {
      const { blindedElement, clientPublicKey } = OPAQUEHelpers.parseRegistrationRequest(data);
      cryptoLogger.info('[AUTH] OT registration request received', {
        hasBlindedElement: !!blindedElement,
        hasClientPublicKey: !!clientPublicKey,
        hasPqSession: !!ws._pqSessionId
      });

      // OPRF evaluation
      const registrationResponse = await this.opaqueServer.createRegistrationResponse(blindedElement, clientPublicKey);

      const allocatedSlot = await UserDatabase.allocatePrivateAuthSlot();
      const shardId = allocatedSlot.shard_id;
      const slotIndex = allocatedSlot.credential_index;
      const shardSize = OPAQUEServer.getShardSize();

      // Store registration state
      ws.clientState = SecureStateManager.setState(ws, {
        pendingRegistration: true,
        serverPrivateKey: registrationResponse.serverPrivateKey,
        registrationSalt: registrationResponse.serverNonce,
        assignedShardId: shardId,
        assignedSlotIndex: slotIndex,
        assignedShardSize: shardSize
      });

      await sendSecureMessage(ws, {
        type: SignalType.AUTH_OT_REGISTER_RESPONSE,
        ...OPAQUEHelpers.formatResponse({
          evaluatedElement: registrationResponse.evaluatedElement,
          serverPublicKey: registrationResponse.serverPublicKey,
          serverNonce: registrationResponse.serverNonce
        }),
        shardId,
        slotIndex,
        shardSize
      });

      cryptoLogger.info('[AUTH] OT registration response sent', {
        shardId,
        slotIndex,
        shardSize
      });
      return { pending: true };
    } catch (error) {
      cryptoLogger.error('[AUTH] OT registration request error', { error: error?.message });
      return sendAuthError(ws, {
        message: "Registration request failed",
        code: 'REGISTRATION_REQUEST_FAILED'
      });
    }
  }

  /**
   * OT Registration finalization
   */
  async handleOTRegisterFinalize(ws, data) {
    const { serverPrivateKey, registrationSalt, assignedShardId, assignedSlotIndex, assignedShardSize, blindedTokens } = SecureStateManager.getState(ws);

    if (!serverPrivateKey || assignedShardId === undefined) {
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Registration state lost");
    }

    try {
      const { credentialId, envelope, maskedResponse } = data;
      cryptoLogger.info('[AUTH] OT registration finalize received', {
        hasCredentialId: !!credentialId,
        hasEnvelope: !!envelope,
        blindedTokenBatchCount: Array.isArray(data.blindedTokens) ? data.blindedTokens.length : 0,
        hasPqSession: !!ws._pqSessionId
      });

      if (!credentialId || !envelope) {
        return sendAuthError(ws, { message: "Missing credential data", code: 'INVALID_REQUEST' });
      }

      const credentialLookupId = UserDatabase.credentialLookupId(credentialId);

      const record = this.opaqueServer.createRegistrationRecord(
        credentialLookupId,
        Buffer.from(envelope, 'base64'),
        serverPrivateKey,
        Buffer.from(maskedResponse, 'base64'),
        registrationSalt
      );

      const userRecord = {
        credentialId: credentialLookupId,
        opaqueRecord: JSON.stringify(record),
        shard_id: assignedShardId,
        credential_index: assignedSlotIndex
      };

      const shardResult = await UserDatabase.saveUserRecord(userRecord);

      cryptoLogger.info('[AUTH] OT registration complete');

      // Issue session token
      const { anonymousSessionService } = await import('./anonymous-session-service.js');
      const anonymousSession = await anonymousSessionService.createSessionWithCapabilities();
      cryptoLogger.info('[AUTH] Created session token for registration', { hasToken: !!anonymousSession.token });

      const responsePayload = {
        type: SignalType.AUTH_FULL_SUCCESS,
        ...serverEntryResponseFields(ws),
        shardId: shardResult.shard_id,
        credentialIndex: shardResult.credential_index,
        shardSize: assignedShardSize || OPAQUEServer.getShardSize(),
        anonymousSession: {
          token: anonymousSession.token,
          expiresAt: anonymousSession.expiresAt,
          tokenType: 'Anonymous'
        }
      };

      // Issue blind routing credentials if blinded token was provided
      if (data.blindedToken && !requiresServerEntry(ws)) {
        try {
          const { generateCapabilityToken, storeCapabilityToken } = await import('../routing/capability-tokens.js');

          const cap = generateCapabilityToken();
          try {
            await storeCapabilityToken(cap.token, [], {
              ttl: Math.max(1, Math.floor((cap.expiresAt - Date.now()) / 1000))
            });
          } catch (e) {
            cryptoLogger.warn('[AUTH] Failed to store capability token for registration', { error: e?.message });
          }

          const signed = await BlindSignatureIssuer.signBlindedMessage(data.blindedToken);
          const serverBlindPublicKey = await BlindSignatureIssuer.getPublicKey();
          responsePayload.blindRouting = {
            capabilityToken: cap.token,
            expiresAt: cap.expiresAt,
            signedBlindedToken: signed.signature,
            blindSignatureKid: signed.kid,
            serverBlindPublicKey
          };
          cryptoLogger.info('[AUTH] Issued blind routing credentials for registration');
        } catch (e) {
          cryptoLogger.error('[AUTH] Failed to issue blind routing for registration', { error: e?.message });
        }
      } else if (data.blindedToken) {
        cryptoLogger.info('[AUTH] Deferring blind routing credentials until server entry is granted');
      }

      const requestedTokenBatch = Array.isArray(data.blindedTokens) ? data.blindedTokens : blindedTokens;

      // Issue initial Privacy Pass tokens if blinded tokens were provided
      if (requestedTokenBatch && requestedTokenBatch.length > 0) {
        const tokenBatch = await this.ppServer.issueTokenBatch(
          requestedTokenBatch.map(t => Buffer.from(t, 'base64')),
          Buffer.from('INITIAL_REGISTRATION_PROOF_AUTH_V1')
        );

        await sendSecureMessage(ws, {
          ...responsePayload,
          message: "Account created and tokens issued",
          anonymousTokenBatch: PrivacyPassHelpers.formatResponse(tokenBatch)
        });
      } else {
        await sendSecureMessage(ws, {
          ...responsePayload,
          message: "Account created successfully"
        });
      }

      ws.clientState = SecureStateManager.setState(ws, {
        pendingRegistration: false,
        hasAuthenticated: true
      });

      return { success: true };
    } catch (error) {
      cryptoLogger.error('[AUTH] OT registration finalization error', { error: error?.message });
      return sendAuthError(ws, {
        message: "Failed to finalize account creation: " + error.message,
        code: 'REGISTRATION_FINALIZATION_FAILED'
      });
    }
  }

  /**
   * OT Sign In
   */
  async handleOTSignIn(ws, data) {
    try {
      const { shardId, clientPubKeys, blindedElement, anonymousTokenData } = data;
      if (!Number.isInteger(shardId) || shardId < 0 || !Array.isArray(clientPubKeys) || clientPubKeys.length !== OPAQUEServer.getShardSize()) {
        return sendAuthError(ws, { message: 'Invalid private auth request', code: 'INVALID_PRIVATE_AUTH_REQUEST' });
      }
      
      // Verify Anonymous Token
      let redemptionResult = null;
      if (anonymousTokenData) {
        const parsedRequest = PrivacyPassHelpers.parseRedemptionRequest(anonymousTokenData);
        redemptionResult = await this.ppServer.redeemToken(
          parsedRequest.token,
          parsedRequest.nullifier,
          parsedRequest.mac,
          parsedRequest.tokenSecret,
          'account-auth'
        );
      }

      // Load the shard from DB
      const shardRecords = await UserDatabase.getShardRecords(shardId);

      // Perform OPRF evaluation
      const evaluated = OPAQUEServer.createLoginResponseLocal(
        Buffer.from(blindedElement, 'base64')
      );

      // Encrypt the entire shard for OT
      const otRecords = await OPAQUEServer.encryptShardForOT(shardRecords, clientPubKeys);

      // Generate a server nonce for this attempt and bind it to this connection
      const serverNonce = crypto.randomBytes(32);
      ws._loginServerNonce = serverNonce.toString('base64');
      ws._loginServerNonceAt = Date.now();

      // Send back to client
      await sendSecureMessageChunked(ws, {
        type: SignalType.AUTH_OT_RESPONSE,
        otRecords,
        serverNonce: serverNonce.toString('base64'),
        evaluatedElement: Buffer.from(evaluated).toString('base64'),
        redemptionResult: redemptionResult ? PrivacyPassHelpers.formatResponse(redemptionResult) : null
      });

    } catch (error) {
      cryptoLogger.error('[AUTH] OT login failed', { error: error?.message });
      return sendAuthError(ws, { message: 'Login request failed', code: 'LOGIN_REQUEST_FAILED' });
    }
  }

  /**
   * OT Sign In finalization
   */
  async handleSignInFinalize(ws, data) {
    try {
      const { authProof, shardId } = data;

      const stashedNonce = ws._loginServerNonce;
      ws._loginServerNonce = null;
      ws._loginServerNonceAt = null;

      if (!authProof || !stashedNonce || !Number.isInteger(shardId) || shardId < 0) {
        return sendAuthError(ws, { message: 'Invalid login finalization request', code: 'INVALID_FINALIZE_REQUEST' });
      }

      const shardRecords = await UserDatabase.getShardRecords(shardId);
      if (!Array.isArray(shardRecords) || shardRecords.length === 0) {
        return sendAuthError(ws, { message: 'Authentication failed', code: 'AUTH_FAILED' });
      }

      const loginResult = await OPAQUEServer.finishLoginAcrossShard(
        shardRecords,
        Buffer.from(authProof, 'base64'),
        Buffer.from(stashedNonce, 'base64')
      );

      if (loginResult.success) {
        // Success then use anonymous session tokens
        const anonymousSession = await anonymousSessionService.createSessionWithCapabilities();

        const uniformResponse = OPAQUEServer.generateUniformResponse({
          success: true,
          sessionKey: loginResult.sessionKey,
          anonymousSessionToken: anonymousSession.token,
          sessionExpiresAt: anonymousSession.expiresAt
        }, loginResult.sessionKey);

        // Issue blind routing credentials if blinded token was provided
        let blindRouting = null;
        if (data.blindedToken && !requiresServerEntry(ws)) {
          try {
            const { generateCapabilityToken, storeCapabilityToken } = await import('../routing/capability-tokens.js');

            const cap = generateCapabilityToken();
            try {
              await storeCapabilityToken(cap.token, [], {
                ttl: Math.max(1, Math.floor((cap.expiresAt - Date.now()) / 1000))
              });
            } catch (e) {
              cryptoLogger.warn('[AUTH] Failed to store capability token for login', { error: e?.message });
            }

            const signed = await BlindSignatureIssuer.signBlindedMessage(data.blindedToken);
            const serverBlindPublicKey = await BlindSignatureIssuer.getPublicKey();
            blindRouting = {
              capabilityToken: cap.token,
              expiresAt: cap.expiresAt,
              signedBlindedToken: signed.signature,
              blindSignatureKid: signed.kid,
              serverBlindPublicKey
            };
            cryptoLogger.info('[AUTH] Issued blind routing credentials for login');
          } catch (e) {
            cryptoLogger.error('[AUTH] Failed to issue blind routing for login', { error: e?.message });
          }
        } else if (data.blindedToken) {
          cryptoLogger.info('[AUTH] Deferring blind routing credentials until server entry is granted');
        }

        await sendSecureMessage(ws, {
          type: SignalType.AUTH_FULL_SUCCESS,
          ...serverEntryResponseFields(ws),
          maskedResult: Buffer.from(uniformResponse).toString('base64'),
          anonymousSession: {
            token: anonymousSession.token,
            expiresAt: anonymousSession.expiresAt,
            tokenType: 'Anonymous'
          },
          blindRouting
        });

        ws.clientState = SecureStateManager.setState(ws, {
          hasAuthenticated: true
        });

        cryptoLogger.info('[AUTH] Successful blind login');
        return { success: true };
      } else {
        const uniformResponse = OPAQUEServer.generateUniformResponse({ success: false }, randomBytes(32));
        await sendSecureMessage(ws, {
          type: SignalType.AUTH_FULL_SUCCESS,
          maskedResult: Buffer.from(uniformResponse).toString('base64')
        });
      }
    } catch (error) {
      cryptoLogger.error('[AUTH] Login finalization failed', { error: error?.message });
      return sendAuthError(ws, { message: 'Login finalization failed', code: 'LOGIN_FINALIZATION_FAILED' });
    }
  }

  /**
   * Blind signature request
   */
  async handleBlindSignatureRequest(ws, blindedToken) {
    const state = SecureStateManager.getState(ws);
    if (!state.hasPassedAccountLogin) {
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication required");
    }

    try {
      const signed = await BlindSignatureIssuer.signBlindedMessage(blindedToken);
      const serverBlindPublicKey = await BlindSignatureIssuer.getPublicKey();

      await sendSecureMessage(ws, {
        type: SignalType.BLIND_SIGNATURE_RESPONSE,
        signedBlindedToken: signed.signature,
        blindSignatureKid: signed.kid,
        serverBlindPublicKey
      });
    } catch (e) {
      cryptoLogger.error('[AUTH] Blind signature failed', { error: e?.message });
    }
  }

  /**
   * Process device proof response
   */
  async processDeviceProofResponse(ws, msgString) {
    try {
      const data = JSON.parse(msgString);
      const proofPayload = typeof data.proof === 'string' ? JSON.parse(data.proof) : data.proof;
      const verifyResult = await this.zkVerifier.verifyProof(data.challengeId, proofPayload);

      if (!verifyResult.valid) {
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid proof");
      }

      if (data.blindedTokens) {
        const tokenBatch = await this.ppServer.issueTokenBatch(
          data.blindedTokens.map(t => Buffer.from(t, 'base64')),
          Buffer.from(verifyResult.proofId)
        );

        await sendSecureMessage(ws, {
          type: SignalType.PRIVACY_PASS_ISSUANCE,
          ...PrivacyPassHelpers.formatResponse(tokenBatch)
        });
      }

      return { success: true };
    } catch (e) {
      cryptoLogger.error('[AUTH] ZK proof error', { error: e?.message });
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Verification failed");
    }
  }

  /**
   * Handle ZK challenge request
   */
  async handleZKChallengeRequest(ws) {
    try {
      const challengeData = await this.zkVerifier.generateChallenge();
      await sendSecureMessage(ws, {
        type: SignalType.ZK_REFRESH_CHALLENGE,
        ...DeviceCommitmentHelpers.formatChallengeResponse(challengeData)
      });
    } catch (e) {
      cryptoLogger.error('[AUTH] ZK challenge error', { error: e?.message });
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Failed to generate challenge");
    }
  }

  /**
   * Register ring public key for ZK proofs
   */
  async handleZKDeviceRegisterRequest(ws, data) {
    const state = SecureStateManager.getState(ws);
    if (!state.hasPassedAccountLogin && !state.hasAuthenticated) {
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication required");
    }

    try {
      const { ringPublicKey } = DeviceCommitmentHelpers.parseRegistrationRequest(data || {});
      const commitmentHash = await this.zkVerifier.registerDeviceCommitment(ringPublicKey);
      await sendSecureMessage(ws, {
        type: SignalType.ZK_DEVICE_REGISTER_RESPONSE,
        success: true,
        commitmentHash
      });
    } catch (e) {
      cryptoLogger.error('[AUTH] ZK device registration failed', { error: e?.message });
      await sendSecureMessage(ws, {
        type: SignalType.ZK_DEVICE_REGISTER_RESPONSE,
        success: false,
        error: 'registration_failed'
      });
    }
  }

  /**
   * Process authentication request
   */
  async processAuthRequest(ws, str) {
    if (!str || typeof str !== 'string') {
      cryptoLogger.warn('[AUTH] Invalid authentication request format');
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid request format");
    }

    if (str.length > 1048576) {
      cryptoLogger.warn('[AUTH] Authentication request too large');
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Request too large");
    }

    try {
      const parsed = JSON.parse(str);
      const {
        type,
        blindedElement,
        blindedToken,
        blindedTokens,
        proofOfKnowledge
      } = parsed;

      if (!parsed || typeof parsed !== 'object') {
        cryptoLogger.warn('[AUTH] Invalid authentication data structure');
        return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid request structure");
      }

      // Verify request signature only if a client public key is already known for this connection
      if (ws.clientPublicKey) {
        const signatureHeader = ws.headers?.['x-request-signature'];
        if (!signatureHeader) {
          return rejectConnection(ws, SignalType.AUTH_ERROR, "Missing request signature");
        }
        if (!(await this.verifyRequestSignature(str, signatureHeader, ws))) {
          return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid request signature");
        }
      }

      // Extract credentialId from request
      let credentialId = parsed.credentialId || null;

      // Validate credentialId format
      if (credentialId) {
        if (typeof credentialId !== 'string' || credentialId.length < 32 || !/^[a-f0-9]+$/i.test(credentialId)) {
          cryptoLogger.warn('[AUTH] Invalid credentialId format');
          return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid credential ID format");
        }
      }

      // Route to OT-based handlers
      switch (type) {
        case SignalType.AUTH_OT_REGISTER_REQUEST:
          cryptoLogger.info('[AUTH] Handling OT registration request');
          return this.handleOTRegisterRequest(ws, parsed);
        case SignalType.AUTH_OT_REGISTER_FINALIZE:
          cryptoLogger.info('[AUTH] Handling OT registration finalize');
          return this.handleOTRegisterFinalize(ws, parsed);
        case SignalType.BLIND_SIGNATURE_REQUEST:
          cryptoLogger.info('[AUTH] Handling blind signature request');
          return this.handleBlindSignatureRequest(ws, blindedToken);
        case SignalType.ZK_REFRESH_CHALLENGE:
          cryptoLogger.info('[AUTH] Handling ZK refresh challenge');
          return this.handleZKChallengeRequest(ws);
        case SignalType.ZK_DEVICE_REGISTER:
          cryptoLogger.info('[AUTH] Handling ZK device register');
          return this.handleZKDeviceRegisterRequest(ws, parsed);
        case SignalType.ZK_PROOF_RESPONSE:
          cryptoLogger.info('[AUTH] Handling ZK proof response');
          return this.processDeviceProofResponse(ws, str);
        case SignalType.AUTH_OT_REQUEST:
          cryptoLogger.info('[AUTH] Handling blind OT sign in');
          return this.handleOTSignIn(ws, parsed);
        case SignalType.AUTH_OT_FINALIZE:
          cryptoLogger.info('[AUTH] Handling blind OT login finalize');
          return this.handleSignInFinalize(ws, parsed);
        case SignalType.SERVER_ENTRY_REQUEST:
          cryptoLogger.info('[AUTH] Handling server entry request');
          return this.gatekeeper.handleEntryRequest(ws, blindedElement);
        case SignalType.SERVER_ENTRY_TOKEN_ISSUANCE:
          cryptoLogger.info('[AUTH] Handling server entry token issuance');
          return this.gatekeeper.handleTokenIssuance(ws, blindedTokens, proofOfKnowledge);
        default:
          cryptoLogger.warn('[AUTH] Invalid auth type', { type });
          return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid auth type");
      }
    } catch (error) {
      cryptoLogger.error('[AUTH] Auth processing error', { error: error?.message });
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Authentication failed");
    }
  }

  /**
   * Verify request signature
   */
  async verifyRequestSignature(data, signature, ws) {
    const clientKeyBase64 = ws.clientPublicKey;
    if (!clientKeyBase64) return false;
    try {
      const publicKey = new Uint8Array(Buffer.from(clientKeyBase64, 'base64'));
      const msg = Buffer.from(String(data), 'utf8');
      const sig = Buffer.from(signature, 'base64');
      return ml_dsa87.verify(sig, msg, publicKey);
    } catch {
      return false;
    }
  }
}

/**
 * Server Authentication Handler
 *  will implement soon.
 * Manages admin-level and server-specific authentication tasks.
 */
export class ServerAuthHandler {
  constructor(serverHybridKeyPair, db, serverConfig) {
    this.serverHybridKeyPair = serverHybridKeyPair;
    this.db = db;
    this.serverConfig = serverConfig;
    this.gatekeeper = new ServerGatekeeper(db);
  }

  /**
   * Handle server-level operations if any
   * Currently delegates to Gatekeeper for anonymous entry
   */
  async handleServerOperation() {
    cryptoLogger.info('[SERVER-AUTH] Processing server-level operation');
    // TODO: implementation for admin/server tasks
  }
}
