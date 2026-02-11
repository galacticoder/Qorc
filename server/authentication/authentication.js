import crypto from 'node:crypto';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { SignalType } from '../signals.js';
import { UserDatabase } from '../database/database.js';
import { anonymousSessionService } from './anonymous-session-service.js';
import { OPAQUEServer, OPAQUEHelpers } from '../crypto/opaque-service.js';
import { PrivacyPassServer, PrivacyPassHelpers, NullifierStore } from './privacy-pass-server.js';
import { ZKDeviceProofVerifier, DeviceCommitmentHelpers } from './zk-verifier.js';
import { BlindSignatureIssuer } from '../security/blind-signatures.js';
import { sendSecureMessage } from '../messaging/pq-envelope-handler.js';
import { ServerGatekeeper } from './gatekeeper.js';

async function rejectConnection(ws, type, reason, code = 1008) {
  console.log(`[AUTH] Rejecting connection: ${type} - ${reason}`);
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
    console.error('[AUTH] Failed to send soft auth error:', e?.message || e);
  }
  return { handled: true };
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

function anonId(username) {
  if (!username) return '[unknown]';
  return `${username.slice(0, 3)}...${username.slice(-3)}`;
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

      // OPRF evaluation
      const registrationResponse = await this.opaqueServer.createRegistrationResponse(blindedElement, clientPublicKey);

      const pool = await (await import('../database/database.js')).getPgPool();
      const { rows } = await pool.query('SELECT COUNT(*) FROM users');
      const count = parseInt(rows[0].count, 10);
      const shardId = Math.floor(count / 100);
      const slotIndex = count % 100;

      // Store registration state
      ws.clientState = SecureStateManager.setState(ws, {
        pendingRegistration: true,
        serverPrivateKey: registrationResponse.serverPrivateKey,
        registrationSalt: registrationResponse.serverNonce,
        assignedShardId: shardId,
        assignedSlotIndex: slotIndex,
        blindedTokens: data.blindedTokens
      });

      await sendSecureMessage(ws, {
        type: SignalType.AUTH_OT_REGISTER_RESPONSE,
        ...OPAQUEHelpers.formatResponse({
          evaluatedElement: registrationResponse.evaluatedElement,
          serverPublicKey: registrationResponse.serverPublicKey,
          serverNonce: registrationResponse.serverNonce
        }),
        shardId,
        slotIndex
      });

      console.log(`[AUTH] OT Registration slot assigned`);
      return { pending: true };
    } catch (error) {
      console.error('[AUTH] OT Registration request error:', error.message);
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
    const { serverPrivateKey, registrationSalt, assignedShardId, assignedSlotIndex, blindedTokens } = SecureStateManager.getState(ws);

    if (!serverPrivateKey || assignedShardId === undefined) {
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Registration state lost");
    }

    try {
      const { credentialId, envelope, maskedResponse } = data;

      if (!credentialId || !envelope) {
        return sendAuthError(ws, { message: "Missing credential data", code: 'INVALID_REQUEST' });
      }

      // Create OPAQUE record using password derived credentialId
      const record = this.opaqueServer.createRegistrationRecord(
        Buffer.from(credentialId, 'base64'),
        Buffer.from(envelope, 'base64'),
        serverPrivateKey,
        Buffer.from(maskedResponse, 'base64'),
        registrationSalt
      );

      // Store record using credentialId as the lookup key
      const userRecord = {
        credentialId: credentialId,
        opaqueRecord: JSON.stringify(record),
        shard_id: assignedShardId,
        credential_index: assignedSlotIndex
      };

      const shardResult = await UserDatabase.saveUserRecord(userRecord);

      console.log(`[AUTH] OT Registration complete: Shard ${shardResult.shard_id}, Index ${shardResult.credential_index}`);

      // Issue session token
      const { anonymousSessionService } = await import('./anonymous-session-service.js');
      const anonymousSession = await anonymousSessionService.createSessionWithCapabilities();
      console.log(`[AUTH] Created session token for registration: ${anonymousSession.token?.length} chars`);

      const responsePayload = {
        type: SignalType.AUTH_FULL_SUCCESS,
        shardId: shardResult.shard_id,
        credentialIndex: shardResult.credential_index,
        anonymousSession: {
          token: anonymousSession.token,
          expiresAt: anonymousSession.expiresAt,
          tokenType: 'Anonymous'
        }
      };

      // Issue blind routing credentials if blinded token was provided
      if (data.blindedToken) {
        try {
          const { generateCapabilityToken, storeCapabilityToken } = await import('../routing/capability-tokens.js');

          const cap = generateCapabilityToken();
          try {
            await storeCapabilityToken(cap.token, [], {
              ttl: Math.max(1, Math.floor((cap.expiresAt - Date.now()) / 1000))
            });
          } catch (e) {
            console.warn('[AUTH] Failed to store capability token for registration', { error: e?.message });
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
          console.log('[AUTH] Issued blind routing credentials for registration');
        } catch (e) {
          console.error('[AUTH] Failed to issue blind routing for registration:', e.message);
        }
      }

      // Issue initial Privacy Pass tokens if blinded tokens were provided
      if (blindedTokens && blindedTokens.length > 0) {
        const tokenBatch = await this.ppServer.issueTokenBatch(
          blindedTokens.map(t => Buffer.from(t, 'base64')),
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
        hasAuthenticated: true,
        credentialId: credentialId
      });

      return { success: true, credentialId };
    } catch (error) {
      console.error('[AUTH] OT Registration finalization error:', error.message);
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
      
      // Verify Anonymous Token
      let redemptionResult = null;
      if (anonymousTokenData) {
        const parsedRequest = PrivacyPassHelpers.parseRedemptionRequest(anonymousTokenData);
        redemptionResult = await this.ppServer.redeemToken(parsedRequest.token, parsedRequest.nullifier, parsedRequest.mac);
      }

      // Load the shard from DB
      const shardRecords = await UserDatabase.getShardRecords(shardId);

      // Perform OPRF evaluation
      const evaluated = OPAQUEServer.createLoginResponseLocal(
        Buffer.from(blindedElement, 'base64')
      );

      // Encrypt the entire shard for OT
      const otRecords = await OPAQUEServer.encryptShardForOT(shardRecords, clientPubKeys);

      // Generate a server nonce for this attempt
      const serverNonce = crypto.randomBytes(32);

      // Send back to client
      await sendSecureMessage(ws, {
        type: SignalType.AUTH_OT_RESPONSE,
        otRecords,
        serverNonce: serverNonce.toString('base64'),
        evaluatedElement: Buffer.from(evaluated).toString('base64'),
        redemptionResult: redemptionResult ? PrivacyPassHelpers.formatResponse(redemptionResult) : null
      });

    } catch (error) {
      console.error('[AUTH] OT Login failed:', error);
      ws.send(JSON.stringify({ type: 'AUTH_ERROR', error: 'internal_error' }));
    }
  }

  /**
   * OT Sign In finalization
   */
  async handleSignInFinalize(ws, data) {
    try {
      const { authProof, serverNonce, credentialId } = data;

      if (!credentialId || !authProof || !serverNonce) {
        return ws.send(JSON.stringify({ type: 'AUTH_ERROR', error: 'invalid_finalize_request' }));
      }

      const recordBase = await UserDatabase.loadUser(credentialId);
      if (!recordBase) return ws.send(JSON.stringify({ type: 'AUTH_ERROR', error: 'auth_failed' }));

      // Parse record if was stored as JSON string
      const record = typeof recordBase.opaqueRecord === 'string' ? JSON.parse(recordBase.opaqueRecord) : recordBase.opaqueRecord;

      const loginResult = await OPAQUEServer.finishLogin(
        Buffer.from(authProof, 'base64'),
        record,
        Buffer.from(serverNonce, 'base64')
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
        if (data.blindedToken) {
          try {
            const { generateCapabilityToken, storeCapabilityToken } = await import('../routing/capability-tokens.js');

            const cap = generateCapabilityToken();
            try {
              await storeCapabilityToken(cap.token, [], {
                ttl: Math.max(1, Math.floor((cap.expiresAt - Date.now()) / 1000))
              });
            } catch (e) {
              console.warn('[AUTH] Failed to store capability token for login', { error: e?.message });
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
            console.log('[AUTH] Issued blind routing credentials for login');
          } catch (e) {
            console.error('[AUTH] Failed to issue blind routing for login:', e.message);
          }
        }

        await sendSecureMessage(ws, {
          type: SignalType.AUTH_FULL_SUCCESS,
          maskedResult: Buffer.from(uniformResponse).toString('base64'),
          anonymousSession: {
            token: anonymousSession.token,
            expiresAt: anonymousSession.expiresAt,
            tokenType: 'Anonymous'
          },
          blindRouting
        });

        ws.clientState = SecureStateManager.setState(ws, {
          hasAuthenticated: true,
          sessionId: anonymousSession.sessionId,
          credentialId: recordBase.credentialId
        });
        ws._primaryInboxId = recordBase.credentialId;

        console.log(`[AUTH] Successful blind login for credentialId: ${credentialId.slice(0, 8)}...`);
        return { success: true, credentialId: recordBase.credentialId };
      } else {
        const uniformResponse = OPAQUEServer.generateUniformResponse({ success: false }, randomBytes(32));
        await sendSecureMessage(ws, {
          type: SignalType.AUTH_FULL_SUCCESS,
          maskedResult: Buffer.from(uniformResponse).toString('base64')
        });
      }
    } catch (error) {
      console.error('[AUTH] Login finalization failed:', error);
      ws.send(JSON.stringify({ type: 'AUTH_ERROR', error: 'internal_error' }));
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
      console.error('[AUTH] Blind signature failed:', e.message);
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
      console.error('[AUTH] ZK Proof error:', e);
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
      console.error('[AUTH] ZK Challenge error:', e);
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
      console.error('[AUTH] ZK device registration failed:', e.message);
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
      console.error('[AUTH] Invalid authentication request format');
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid request format");
    }

    if (str.length > 1048576) {
      console.error('[AUTH] Authentication request too large');
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
        console.error('[AUTH] Invalid authentication data structure');
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
          console.error(`[AUTH] Invalid credentialId format`);
          return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid credential ID format");
        }
      }

      // Route to OT-based handlers
      switch (type) {
        case SignalType.AUTH_OT_REGISTER_REQUEST:
          console.log(`[AUTH] Handling OT registration request`);
          return this.handleOTRegisterRequest(ws, parsed);
        case SignalType.AUTH_OT_REGISTER_FINALIZE:
          console.log(`[AUTH] Handling OT registration finalize`);
          return this.handleOTRegisterFinalize(ws, parsed);
        case SignalType.BLIND_SIGNATURE_REQUEST:
          console.log(`[AUTH] Handling blind signature request`);
          return this.handleBlindSignatureRequest(ws, blindedToken);
        case SignalType.ZK_REFRESH_CHALLENGE:
          console.log(`[AUTH] Handling ZK refresh challenge`);
          return this.handleZKChallengeRequest(ws);
        case SignalType.ZK_DEVICE_REGISTER:
          console.log(`[AUTH] Handling ZK device register`);
          return this.handleZKDeviceRegisterRequest(ws, parsed);
        case SignalType.ZK_PROOF_RESPONSE:
          console.log(`[AUTH] Handling ZK proof response`);
          return this.processDeviceProofResponse(ws, str);
        case SignalType.AUTH_OT_REQUEST:
          console.log(`[AUTH] Handling blind OT sign in`);
          return this.handleOTSignIn(ws, parsed);
        case SignalType.AUTH_OT_FINALIZE:
          console.log(`[AUTH] Handling blind OT login finalize`);
          return this.handleSignInFinalize(ws, parsed);
        case SignalType.SERVER_ENTRY_REQUEST:
          console.log(`[AUTH] Handling server entry request`);
          return this.gatekeeper.handleEntryRequest(ws, blindedElement);
        case SignalType.SERVER_ENTRY_TOKEN_ISSUANCE:
          console.log(`[AUTH] Handling server entry token issuance`);
          return this.gatekeeper.handleTokenIssuance(ws, blindedTokens, proofOfKnowledge);
        default:
          console.error(`[AUTH] Invalid auth type: ${type}`);
          return rejectConnection(ws, SignalType.AUTH_ERROR, "Invalid auth type");
      }
    } catch (error) {
      console.error('[AUTH] Auth processing error:', error);
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
    console.log('[SERVER-AUTH] Processing server-level operation');
    // TODO: implementation for admin/server tasks
  }
}
