import crypto from 'node:crypto';
import { SignalType } from '../signals.js';
import { UserDatabase } from '../database/database.js';
import { OPAQUEServer, OPAQUEHelpers } from '../crypto/opaque-service.js';
import { PrivacyPassServer, PrivacyPassHelpers } from './privacy-pass-server.js';
import {
  consumeVerifiedAuthChannelBinding,
  sendSecureMessage,
  sendSecureAuthResponse,
} from '../messaging/pq-envelope-handler.js';
import { ServerGatekeeper } from './gatekeeper.js';
import { applyAdaptiveAuthDelay, recordAuthFailure, getAuthVerificationDifficulty, getAuthPreflightDifficulty, recordAuthPreflightCompletion, createPowChallenge, verifyPowSolution, throttleExpensiveAuthRequest, acquireExpensiveAuthVerificationSlot } from '../security/auth-throttle.js';
import { isAuthPreflightLive, verifyAuthPreflightProof } from './auth-preflight.js';
import {
  decodeCanonicalBase64,
  decodeCanonicalBase64List
} from '../utils/encoding.js';
import { hasExactPlainObjectKeys, requireUuidV4 } from '../utils/validation.js';
import {
  wipeByteArrays,
  wipeBytes,
  wipeIssuedTokenBatch
} from '../utils/wipe.js';
import {
  AUTH_SERVER_BUSY,
  AUTH_SERVICE_BUSY_MESSAGE,
  AUTH_SERVICE_UNAVAILABLE_MESSAGE,
  INVALID_REQUEST,
  INVALID_TOKEN_BATCH_MESSAGE,
  POW_REQUIRED,
  PROOF_OF_WORK_REQUIRED_MESSAGE,
  REGISTRATION_ATTEMPT_MISMATCH,
  REGISTRATION_RECEIPT_EXPIRED
} from '../config/error-codes.js';
import {
  ML_DSA_87_PUBLIC_KEY_BYTES,
  ML_DSA_87_SIGNATURE_BYTES,
  ML_KEM_1024_PUBLIC_KEY_BYTES
} from '../../shared/crypto-sizes.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import {
  AUTH_CHANNEL_BINDING_BYTES,
  HASH_OUTPUT_BYTES,
  OPAQUE_ELEMENT_BYTES,
  OPAQUE_ENVELOPE_BYTES,
  OPAQUE_NONCE_BYTES,
  PRIVACY_PASS_BLINDED_TOKEN_BYTES,
  SHA_256_ALGORITHM
} from '../utils/crypto-consts.js';

import * as ServerConfig from '../config/config.js';

async function rejectConnection(ws, type, reason, code = 1008, authRequestId = undefined) {
  console.warn('[AUTH] Rejecting connection', { type });
  await sendSecureMessage(ws, { type, message: reason, authRequestId });
  ws.close(code, reason);
  return;
}

async function sendAuthError(ws, { message, code = 'AUTH_FAILED', category = 'general', attemptsRemaining = undefined, locked = false, cooldownSeconds = undefined, logout = false, authRequestId = undefined }) {
  const payload = {
    type: SignalType.AUTH_ERROR,
    message,
    code, 
    category,
    locked,
  };
  if (authRequestId !== undefined) payload.authRequestId = authRequestId;
  if (attemptsRemaining !== undefined) payload.attemptsRemaining = attemptsRemaining;
  if (cooldownSeconds !== undefined) payload.cooldownSeconds = cooldownSeconds;
  if (logout) payload.logout = true;
  try { await sendSecureMessage(ws, payload); } catch (e) {
    console.error('[AUTH] Failed to send soft auth error', { error: e?.message });
  }
  return { handled: true };
}

function requiresServerEntry(ws) {
  return ServerConfig.isServerPasswordGateReady() && !ws?._hasServerAuth;
}

function serverEntryResponseFields(ws) {
  const serverEntryRequired = requiresServerEntry(ws);
  return {
    serverEntryRequired,
    serverEntryGranted: !serverEntryRequired
  };
}

const REGISTRATION_FINALIZE_TTL_MS = 2 * 60_000;
const REGISTRATION_CONFIRM_TTL_MS = 2 * 60_000;
const LOGIN_FINALIZE_TTL_MS = 2 * 60_000;

function authRequestCommitment(kind, data) {
  const hash = crypto.createHash(SHA_256_ALGORITHM);
  hash.update(`${PROTOCOL_KEYS.AUTH_PREFLIGHT}:${kind}\0`);
  hash.update(String(data?.blindedElement ?? ''));
  hash.update('\0');
  if (Array.isArray(data?.clientPubKeys)) {
    for (const publicKey of data.clientPubKeys) {
      hash.update('\0');
      hash.update(String(publicKey ?? ''));
    }
  }
  return hash.digest('base64url');
}

async function requireAuthPreflight(ws, data, kind, responseType, suppliedCommitment = null) {
  const authRequestId = requireUuidV4(data?.authRequestId, 'authentication request identifier');
  const commitment = suppliedCommitment || authRequestCommitment(kind, data);
  const pending = ws._authPreflight;
  const now = Date.now();
  const pendingIsLive = isAuthPreflightLive(pending, now);
  if (
    pendingIsLive &&
    (pending?.kind !== kind || pending?.authRequestId !== authRequestId)
  ) {
    await sendAuthError(ws, {
      message: 'Another authentication request is in progress',
      code: 'AUTH_IN_PROGRESS',
      authRequestId
    });
    return false;
  }

  ws._authPreflight = null;

  if (verifyAuthPreflightProof(pending, {
    kind,
    authRequestId,
    commitment,
    solution: data?.preflightPowSolution
  }, now)) {
    return true;
  }

  const challenge = createPowChallenge(await getAuthPreflightDifficulty());
  ws._authPreflight = {
    kind,
    authRequestId,
    commitment,
    seed: challenge.seed,
    difficulty: challenge.difficulty,
    createdAt: Date.now()
  };
  await sendSecureMessage(ws, {
    type: responseType,
    authRequestId,
    preflightRequired: true,
    powChallenge: challenge
  });
  return false;
}

function decodeMlKemPublicKeys(keys, expectedCount) {
  if (!Array.isArray(keys) || keys.length !== expectedCount) {
    throw new Error('Invalid ML-KEM public-key set');
  }
  return decodeCanonicalBase64List(keys, ML_KEM_1024_PUBLIC_KEY_BYTES, 2200);
}

function privateAuthRequestCommitment(blindedElement, publicKeys) {
  const hash = crypto.createHash(SHA_256_ALGORITHM);
  hash.update(PROTOCOL_KEYS.PRIVATE_AUTH_REQUEST);
  hash.update(blindedElement);
  for (const publicKey of publicKeys) hash.update(publicKey);
  return hash.digest();
}

// Connection-private immutable authentication state.
export class SecureStateManager {
  static states = new WeakMap();
  static setState(ws, updates) {
    const current = this.states.get(ws) || {};
    const newState = Object.freeze({
      ...current,
      ...updates
    });
    this.states.set(ws, newState);
  }
  static getState(ws) {
    return this.states.get(ws) || {};
  }
  static clearState(ws) {
    const state = this.states.get(ws);
    wipeBytes(state?.registrationSalt);
    this.states.delete(ws);
  }
}

export class AccountAuthHandler {
  constructor() {
    this.opaqueServer = OPAQUEServer;
    this.ppServer = PrivacyPassServer;
    this.gatekeeper = new ServerGatekeeper();
  }

  clearConnectionState(ws) {
    SecureStateManager.clearState(ws);
    ServerGatekeeper.clearConnectionState(ws);
    ws._authPreflight = null;
    ws._loginServerNonce = null;
    ws._loginServerNonceAt = null;
    ws._loginAuthRequestId = null;
    wipeBytes(ws._loginAuthChannelBinding);
    ws._loginAuthChannelBinding = null;
    ws._loginPowSeed = null;
    ws._loginPowDifficulty = 0;
    ws._loginRequestInProgress = false;
    delete ws._connectionPrivacyMode;
  }

  /**
   * OT Registration
   */
  async handleOTRegisterRequest(ws, data) {
    let authRequestId;
    let blindedElement = null;
    let registrationResponse = null;
    let pendingRegistrationStored = false;
    try {
      authRequestId = requireUuidV4(data?.authRequestId, 'authentication request identifier');
      const requestKeys = Object.hasOwn(data, 'preflightPowSolution')
        ? ['authRequestId', 'blindedElement', 'preflightPowSolution', 'type']
        : ['authRequestId', 'blindedElement', 'type'];
      if (!hasExactPlainObjectKeys(data, requestKeys)) {
        ws._authPreflight = null;
        return sendAuthError(ws, {
          message: 'Invalid registration request',
          code: INVALID_REQUEST,
          authRequestId
        });
      }
      const registrationState = SecureStateManager.getState(ws);
      if (
        registrationState.hasAuthenticated ||
        ws._authenticated ||
        ws._hasAuthenticated ||
        registrationState.pendingRegistration ||
        registrationState.registrationFinalizeInProgress ||
        registrationState.registrationReadyRecordId ||
        registrationState.registrationConfirmInProgress ||
        ws._loginRequestInProgress ||
        ws._loginServerNonce
      ) {
        return sendAuthError(ws, {
          message: 'Registration already in progress',
          code: 'AUTH_IN_PROGRESS',
          authRequestId
        });
      }

      if (!await requireAuthPreflight(
        ws,
        data,
        'registration',
        SignalType.AUTH_OT_REGISTER_RESPONSE
      )) {
        return { pending: true, preflight: true };
      }
      await recordAuthPreflightCompletion();

      ({ blindedElement } = OPAQUEHelpers.parseRegistrationRequest(data));
      console.log('[AUTH] OT registration request received', {
        hasBlindedElement: !!blindedElement,
        hasPqSession: !!ws._pqSessionId
      });

      // OPRF evaluation
      registrationResponse = await this.opaqueServer.createRegistrationResponse(blindedElement);

      SecureStateManager.setState(ws, {
        pendingRegistration: true,
        registrationSalt: new Uint8Array(registrationResponse.serverNonce),
        registrationStartedAt: Date.now(),
        registrationAuthRequestId: authRequestId
      });
      pendingRegistrationStored = true;

      const delivered = await sendSecureMessage(ws, {
        type: SignalType.AUTH_OT_REGISTER_RESPONSE,
        authRequestId,
        ...OPAQUEHelpers.formatResponse({
          evaluatedElement: registrationResponse.evaluatedElement,
          serverNonce: registrationResponse.serverNonce
        })
      });
      if (delivered === false) throw new Error('Registration response was not delivered');

      console.log('[AUTH] OT registration response sent');
      return { pending: true };
    } catch (error) {
      if (pendingRegistrationStored) {
        const state = SecureStateManager.getState(ws);
        if (state.registrationAuthRequestId === authRequestId) {
          wipeBytes(state.registrationSalt);
          SecureStateManager.setState(ws, {
            pendingRegistration: false,
            registrationSalt: null,
            registrationStartedAt: null,
            registrationAuthRequestId: null
          });
        }
      }
      console.error('[AUTH] OT registration request error', { error: error?.message });
      return sendAuthError(ws, {
        message: "Registration request failed",
        code: 'REGISTRATION_REQUEST_FAILED',
        authRequestId
      });
    } finally {
      wipeBytes(blindedElement);
      wipeBytes(registrationResponse?.evaluatedElement);
      wipeBytes(registrationResponse?.serverNonce);
    }
  }

  /**
   * OT Registration finalization
   */
  async handleOTRegisterFinalize(ws, data) {
    let authRequestId;
    try {
      authRequestId = requireUuidV4(data?.authRequestId, 'authentication request identifier');
    } catch {
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Registration state lost");
    }
    const registrationState = SecureStateManager.getState(ws);
    const {
      pendingRegistration,
      registrationFinalizeInProgress,
      registrationSalt,
      registrationStartedAt,
      registrationAuthRequestId
    } = registrationState;

    if (
      !pendingRegistration ||
      registrationFinalizeInProgress ||
      !registrationSalt ||
      registrationAuthRequestId !== authRequestId
    ) {
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Registration state lost", 1008, authRequestId);
    }
    const registrationAgeMs = Date.now() - Number(registrationStartedAt);
    if (
      !Number.isSafeInteger(registrationStartedAt) ||
      !Number.isSafeInteger(registrationAgeMs) ||
      registrationAgeMs < 0 ||
      registrationAgeMs > REGISTRATION_FINALIZE_TTL_MS
    ) {
      wipeBytes(registrationSalt);
      SecureStateManager.setState(ws, {
        pendingRegistration: false,
        registrationFinalizeInProgress: false,
        registrationSalt: null,
        registrationStartedAt: null,
        registrationAuthRequestId: null
      });
      return rejectConnection(ws, SignalType.AUTH_ERROR, "Registration state expired", 1008, authRequestId);
    }

    SecureStateManager.setState(ws, {
      pendingRegistration: false,
      registrationFinalizeInProgress: true,
      registrationSalt: null,
      registrationStartedAt: null,
      registrationAuthRequestId: null
    });

    let envelopeBytes = null;
    let authPublicKeyBytes = null;
    let registrationAttemptBytes = null;
    try {
      const { envelope, authPublicKey, registrationAttemptId } = data;
      console.log('[AUTH] OT registration finalize received', {
        hasEnvelope: !!envelope,
        hasAuthPublicKey: !!authPublicKey,
        hasPqSession: !!ws._pqSessionId
      });

      if (
        !hasExactPlainObjectKeys(data, [
          'authPublicKey',
          'authRequestId',
          'envelope',
          'registrationAttemptId',
          'type'
        ]) ||
        !envelope ||
        !authPublicKey
      ) {
        return sendAuthError(ws, { message: "Missing credential data", code: INVALID_REQUEST, authRequestId });
      }

      try {
        envelopeBytes = decodeCanonicalBase64(envelope, OPAQUE_ENVELOPE_BYTES);
        authPublicKeyBytes = decodeCanonicalBase64(authPublicKey, ML_DSA_87_PUBLIC_KEY_BYTES, 3600);
        registrationAttemptBytes = decodeCanonicalBase64(registrationAttemptId, HASH_OUTPUT_BYTES, 64);
      } catch {
        return sendAuthError(ws, { message: "Invalid credential data", code: INVALID_REQUEST, authRequestId });
      }

      const record = this.opaqueServer.createRegistrationRecord(
        envelopeBytes,
        authPublicKeyBytes,
        registrationSalt
      );

      const opaqueRecord = JSON.stringify(record);
      if (Buffer.byteLength(opaqueRecord, 'utf8') > OPAQUEServer.getRegistrationRecordMaxBytes()) {
        return sendAuthError(ws, {
          message: "Credential payload too large",
          code: 'CREDENTIAL_TOO_LARGE',
          authRequestId
        });
      }

      const userRecord = {
        recordId: UserDatabase.createRecordId(registrationAttemptId),
        opaqueRecord
      };
      const slotResult = await UserDatabase.stageUserRecord(userRecord);

      SecureStateManager.setState(ws, {
        registrationFinalizeInProgress: false,
        registrationReadyRecordId: slotResult.recovery_only ? null : userRecord.recordId,
        registrationReadyAt: slotResult.recovery_only ? null : Date.now(),
        registrationReadyAuthRequestId: slotResult.recovery_only ? null : authRequestId
      });

      const delivered = await sendSecureMessage(ws, {
        type: SignalType.AUTH_OT_REGISTER_READY,
        authRequestId,
        staged: slotResult.recovery_only !== true,
        registrationAlreadyCommitted: slotResult.recovery_only === true,
        credentialIndex: slotResult.credential_index,
        anonymitySetSize: OPAQUEServer.getAnonymitySetSize()
      });
      if (delivered === false) throw new Error('Registration ready response was not delivered');

      console.log('[AUTH] OT registration staged');
      return { pending: true };
    } catch (error) {
      SecureStateManager.setState(ws, {
        registrationFinalizeInProgress: false,
        registrationReadyRecordId: null,
        registrationReadyAt: null,
        registrationReadyAuthRequestId: null
      });
      console.error('[AUTH] OT registration finalization error', {
        category: 'internal'
      });
      return sendAuthError(ws, {
        message: error?.code === REGISTRATION_RECEIPT_EXPIRED
          ? 'Registration retry expired. Start registration again.'
          : error?.code === REGISTRATION_ATTEMPT_MISMATCH
            ? 'Registration retry state changed. Start registration again.'
            : 'Failed to stage account creation',
        code: error?.code === REGISTRATION_RECEIPT_EXPIRED
          ? REGISTRATION_RECEIPT_EXPIRED
          : error?.code === REGISTRATION_ATTEMPT_MISMATCH
            ? REGISTRATION_ATTEMPT_MISMATCH
            : 'REGISTRATION_FINALIZATION_FAILED',
        authRequestId
      });
    } finally {
      wipeBytes(envelopeBytes);
      wipeBytes(authPublicKeyBytes);
      wipeBytes(registrationAttemptBytes);
      wipeBytes(registrationSalt);
      if (SecureStateManager.getState(ws).registrationFinalizeInProgress) {
        SecureStateManager.setState(ws, {
          registrationFinalizeInProgress: false
        });
      }
    }
  }

  /**
   * Promote staged registration
   */
  async handleOTRegisterConfirm(ws, data) {
    let authRequestId;
    let registrationAttemptBytes = null;
    let blindedTokenBytes = [];
    let issuedTokenBatch = null;
    let releaseVerificationSlot = null;
    let issuanceEpoch = null;
    try {
      authRequestId = requireUuidV4(data?.authRequestId, 'authentication request identifier');
      registrationAttemptBytes = decodeCanonicalBase64(data?.registrationAttemptId, HASH_OUTPUT_BYTES, 64);
    } catch {
      return rejectConnection(ws, SignalType.AUTH_ERROR, 'Invalid registration confirmation');
    }

    const recordId = UserDatabase.createRecordId(data.registrationAttemptId);
    const state = SecureStateManager.getState(ws);
    const readyAgeMs = Date.now() - Number(state.registrationReadyAt);
    if (
      state.registrationConfirmInProgress ||
      state.registrationReadyRecordId !== recordId ||
      state.registrationReadyAuthRequestId !== authRequestId ||
      ws._loginRequestInProgress ||
      ws._loginServerNonce ||
      !Number.isSafeInteger(readyAgeMs) ||
      readyAgeMs < 0 ||
      readyAgeMs > REGISTRATION_CONFIRM_TTL_MS
    ) {
      wipeBytes(registrationAttemptBytes);
      return rejectConnection(ws, SignalType.AUTH_ERROR, 'Registration confirmation state lost', 1008, authRequestId);
    }

    SecureStateManager.setState(ws, {
      registrationReadyRecordId: null,
      registrationReadyAt: null,
      registrationReadyAuthRequestId: null,
      registrationConfirmInProgress: true
    });

    try {
      if (
        !hasExactPlainObjectKeys(data, [
          'authRequestId',
          'blindedTokens',
          'registrationAttemptId',
          'tokenEpoch',
          'type'
        ]) ||
        !Array.isArray(data?.blindedTokens) ||
        data.blindedTokens.length !== 250
      ) {
        throw new Error(INVALID_TOKEN_BATCH_MESSAGE);
      }
      blindedTokenBytes = decodeCanonicalBase64List(
        data.blindedTokens,
        PRIVACY_PASS_BLINDED_TOKEN_BYTES,
        64
      );
      issuanceEpoch = this.ppServer.validateIssuanceEpoch(data.tokenEpoch);
      releaseVerificationSlot = await acquireExpensiveAuthVerificationSlot(ws._connectionAbortSignal);

      const slotResult = await UserDatabase.confirmStagedUserRecord(recordId);
      if (slotResult.already_committed === true) {
        const error = new Error('Registration was already committed');
        error.code = 'REGISTRATION_ALREADY_COMMITTED';
        throw error;
      }

      issuedTokenBatch = await this.ppServer.issueAccountAuthTokenBatch(
        blindedTokenBytes,
        issuanceEpoch,
        ws._connectionAbortSignal
      );
      releaseVerificationSlot?.();
      releaseVerificationSlot = null;

      const formattedTokenBatch = PrivacyPassHelpers.formatResponse(issuedTokenBatch);
      const delivered = await sendSecureMessage(ws, {
        type: SignalType.AUTH_FULL_SUCCESS,
        authRequestId,
        authenticated: true,
        registrationConfirmed: true,
        ...serverEntryResponseFields(ws),
        credentialIndex: slotResult.credential_index,
        anonymitySetSize: OPAQUEServer.getAnonymitySetSize(),
        anonymousTokenBatch: formattedTokenBatch
      });
      if (delivered === false) throw new Error('Registration success was not delivered');

      SecureStateManager.setState(ws, {
        registrationConfirmInProgress: false,
        hasAuthenticated: true
      });
      console.log('[AUTH] OT registration confirmed', {
        replayedReceipt: slotResult.already_committed === true
      });
      return { success: true };
    } catch (error) {
      SecureStateManager.setState(ws, {
        registrationConfirmInProgress: false
      });
      console.error('[AUTH] OT registration confirmation error', {
        category: 'internal'
      });
      return sendAuthError(ws, {
        message: error?.code === REGISTRATION_RECEIPT_EXPIRED
          ? 'Registration retry expired. Start registration again.'
          : error?.code === 'REGISTRATION_ALREADY_COMMITTED'
            ? 'Account creation was already committed. Sign in to continue.'
          : 'Failed to confirm account creation',
        code: error?.code === REGISTRATION_RECEIPT_EXPIRED
          ? REGISTRATION_RECEIPT_EXPIRED
          : error?.code === 'REGISTRATION_ALREADY_COMMITTED'
            ? 'REGISTRATION_ALREADY_COMMITTED'
          : 'REGISTRATION_CONFIRMATION_FAILED',
        authRequestId
      });
    } finally {
      releaseVerificationSlot?.();
      wipeIssuedTokenBatch(issuedTokenBatch);
      wipeByteArrays(blindedTokenBytes);
      wipeBytes(registrationAttemptBytes);
      if (SecureStateManager.getState(ws).registrationConfirmInProgress) {
        SecureStateManager.setState(ws, {
          registrationConfirmInProgress: false
        });
      }
    }
  }

  /**
   * OT Sign In
   */
  async handleOTSignIn(ws, data) {
    let authRequestId;
    let requestCommitmentBytes = null;
    let blindedElementBytes = null;
    let clientPublicKeyBytes = [];
    let computedCommitment = null;
    let evaluated = null;
    let serverNonce = null;
    let createdLoginNonce = null;
    let challengeDelivered = false;
    let releaseExpensiveSlot = null;
    let otRecords = null;
    let evaluatedElementBase64 = null;
    let powChallenge = null;
    let authChannelBinding = null;
    try {
      authRequestId = requireUuidV4(data?.authRequestId, 'authentication request identifier');
      const authState = SecureStateManager.getState(ws);
      if (
        authState.hasAuthenticated ||
        ws._authenticated ||
        ws._hasAuthenticated ||
        authState.pendingRegistration ||
        authState.registrationFinalizeInProgress ||
        authState.registrationReadyRecordId ||
        authState.registrationConfirmInProgress
      ) {
        return sendAuthError(ws, { message: 'Authentication already in progress', code: 'AUTH_IN_PROGRESS', authRequestId });
      }

      const { clientPubKeys, blindedElement } = data;
      const hasPreflightProof = Object.hasOwn(data, 'preflightPowSolution');
      const requestKeys = hasPreflightProof
        ? [
            'authRequestId',
            'authChannelBinding',
            'blindedElement',
            'clientPubKeys',
            'preflightPowSolution',
            'requestCommitment',
            'type'
          ]
        : ['authChannelBinding', 'authRequestId', 'blindedElement', 'requestCommitment', 'type'];
      if (!hasExactPlainObjectKeys(data, requestKeys)) {
        ws._authPreflight = null;
        return sendAuthError(ws, {
          message: 'Invalid private auth request',
          code: 'INVALID_PRIVATE_AUTH_REQUEST',
          authRequestId
        });
      }
      try {
        requestCommitmentBytes = decodeCanonicalBase64(data?.requestCommitment, HASH_OUTPUT_BYTES, 64);
      } catch {
        return sendAuthError(ws, { message: 'Invalid private auth request', code: 'INVALID_PRIVATE_AUTH_REQUEST', authRequestId });
      }

      if (!await requireAuthPreflight(
        ws,
        data,
        'login',
        SignalType.AUTH_OT_RESPONSE,
        data.requestCommitment
      )) {
        return { pending: true, preflight: true };
      }
      authChannelBinding = consumeVerifiedAuthChannelBinding(data);
      if (!authChannelBinding) {
        return sendAuthError(ws, {
          message: 'Invalid private auth request',
          code: 'INVALID_PRIVATE_AUTH_REQUEST',
          authRequestId
        });
      }

      releaseExpensiveSlot = await throttleExpensiveAuthRequest(ws._connectionAbortSignal);

      try {
        blindedElementBytes = decodeCanonicalBase64(blindedElement, OPAQUE_ELEMENT_BYTES);
        clientPublicKeyBytes = decodeMlKemPublicKeys(
          clientPubKeys,
          OPAQUEServer.getAnonymitySetSize()
        );
      } catch {
        return sendAuthError(ws, { message: 'Invalid private auth request', code: 'INVALID_PRIVATE_AUTH_REQUEST', authRequestId });
      }
      computedCommitment = privateAuthRequestCommitment(
        blindedElementBytes,
        clientPublicKeyBytes
      );
      if (!crypto.timingSafeEqual(requestCommitmentBytes, computedCommitment)) {
        return sendAuthError(ws, { message: 'Invalid private auth request', code: 'INVALID_PRIVATE_AUTH_REQUEST', authRequestId });
      }

      if (ws._loginRequestInProgress) {
        return sendAuthError(ws, { message: 'Authentication request already in progress', code: 'AUTH_IN_PROGRESS', authRequestId });
      }
      if (ws._loginServerNonce) {
        const nonceAge = Date.now() - Number(ws._loginServerNonceAt || 0);
        if (Number.isSafeInteger(nonceAge) && nonceAge >= 0 && nonceAge <= LOGIN_FINALIZE_TTL_MS) {
          return sendAuthError(ws, { message: 'Authentication finalization required', code: 'AUTH_IN_PROGRESS', authRequestId });
        }
        ws._loginServerNonce = null;
        ws._loginServerNonceAt = null;
        ws._loginAuthRequestId = null;
        wipeBytes(ws._loginAuthChannelBinding);
        ws._loginAuthChannelBinding = null;
        ws._loginPowSeed = null;
        ws._loginPowDifficulty = 0;
      }
      ws._loginRequestInProgress = true;

      try {
        try {
          const privateAuthRecords = await UserDatabase.getPrivateAuthRecords();

          evaluated = OPAQUEServer.createLoginResponseLocal(
            blindedElementBytes
          );

          otRecords = await OPAQUEServer.encryptAnonymitySetForOT(
            privateAuthRecords,
            clientPublicKeyBytes,
            ws._connectionAbortSignal
          );

          // generate server nonce for attempt
          serverNonce = crypto.randomBytes(OPAQUE_NONCE_BYTES);
          createdLoginNonce = serverNonce.toString('base64');
          ws._loginServerNonce = createdLoginNonce;
          ws._loginServerNonceAt = Date.now();
          ws._loginAuthRequestId = authRequestId;
          ws._loginAuthChannelBinding = authChannelBinding;
          authChannelBinding = null;
          powChallenge = createPowChallenge(await getAuthVerificationDifficulty());
          ws._loginPowSeed = powChallenge.seed;
          ws._loginPowDifficulty = powChallenge.difficulty;

          const evaluatedCopy = Buffer.from(evaluated);
          try {
            evaluatedElementBase64 = evaluatedCopy.toString('base64');
          } finally {
            evaluatedCopy.fill(0);
          }
        } finally {
          releaseExpensiveSlot?.();
          releaseExpensiveSlot = null;
          wipeBytes(requestCommitmentBytes);
          requestCommitmentBytes = null;
          wipeBytes(blindedElementBytes);
          blindedElementBytes = null;
          wipeByteArrays(clientPublicKeyBytes);
          clientPublicKeyBytes = [];
          wipeBytes(computedCommitment);
          computedCommitment = null;
          wipeBytes(evaluated);
          evaluated = null;
          wipeBytes(serverNonce);
          serverNonce = null;
        }

        const delivered = await sendSecureAuthResponse(ws, {
          type: SignalType.AUTH_OT_RESPONSE,
          authRequestId,
          otRecords,
          serverNonce: createdLoginNonce,
          evaluatedElement: evaluatedElementBase64,
          powChallenge
        });
        if (delivered === false) {
          throw new Error('Private authentication response was not delivered');
        }
        challengeDelivered = true;
      } finally {
        ws._loginRequestInProgress = false;
      }

    } catch (error) {
      if (createdLoginNonce && !challengeDelivered && ws._loginServerNonce === createdLoginNonce) {
        ws._loginServerNonce = null;
        ws._loginServerNonceAt = null;
        ws._loginAuthRequestId = null;
        wipeBytes(ws._loginAuthChannelBinding);
        ws._loginAuthChannelBinding = null;
        ws._loginPowSeed = null;
        ws._loginPowDifficulty = 0;
      }
      ws._loginRequestInProgress = false;
      console.error('[AUTH] OT login failed', { error: error?.message });
      return sendAuthError(ws, {
        message: error?.code === AUTH_SERVER_BUSY ? AUTH_SERVICE_BUSY_MESSAGE : 'Login request failed',
        code: error?.code === AUTH_SERVER_BUSY ? AUTH_SERVER_BUSY : 'LOGIN_REQUEST_FAILED',
        authRequestId
      });
    } finally {
      releaseExpensiveSlot?.();
      wipeBytes(requestCommitmentBytes);
      wipeBytes(blindedElementBytes);
      wipeByteArrays(clientPublicKeyBytes);
      wipeBytes(computedCommitment);
      wipeBytes(evaluated);
      wipeBytes(serverNonce);
      wipeBytes(authChannelBinding);
      otRecords = null;
      evaluatedElementBase64 = null;
      powChallenge = null;
    }
  }

  /**
   * OT Sign In finalization
   */
  async handleSignInFinalize(ws, data) {
    let authRequestId;
    let authProof = null;
    let stashedNonceBytes = null;
    let blindedTokenBytes = [];
    let issuedTokenBatch = null;
    let releaseVerificationSlot = null;
    let issuanceEpoch = null;
    let stashedAuthChannelBinding = null;
    try {
      try {
        authRequestId = requireUuidV4(data?.authRequestId, 'authentication request identifier');
      } catch {
        return sendAuthError(ws, { message: 'Invalid login finalization request', code: 'INVALID_FINALIZE_REQUEST' });
      }
      const stashedNonce = ws._loginServerNonce;
      const stashedNonceAt = Number(ws._loginServerNonceAt || 0);
      const stashedAuthRequestId = ws._loginAuthRequestId;
      stashedAuthChannelBinding = ws._loginAuthChannelBinding;
      ws._loginServerNonce = null;
      ws._loginServerNonceAt = null;
      ws._loginAuthRequestId = null;
      ws._loginAuthChannelBinding = null;

      const powDifficulty = ws._loginPowDifficulty || 0;
      const powSeed = ws._loginPowSeed;
      ws._loginPowSeed = null;
      ws._loginPowDifficulty = 0;

      const authState = SecureStateManager.getState(ws);
      if (
        authState.hasAuthenticated ||
        ws._authenticated ||
        ws._hasAuthenticated ||
        authState.pendingRegistration ||
        authState.registrationFinalizeInProgress ||
        authState.registrationReadyRecordId ||
        authState.registrationConfirmInProgress
      ) {
        return sendAuthError(ws, {
          message: 'Authentication already completed or another flow is in progress',
          code: 'AUTH_IN_PROGRESS',
          authRequestId
        });
      }

      if (!hasExactPlainObjectKeys(data, [
        'authProof',
        'authRequestId',
        'blindedTokens',
        'powSolution',
        'tokenEpoch',
        'type'
      ])) {
        return sendAuthError(ws, {
          message: 'Invalid login finalization request',
          code: 'INVALID_FINALIZE_REQUEST',
          authRequestId
        });
      }

      try {
        authProof = decodeCanonicalBase64(data?.authProof, ML_DSA_87_SIGNATURE_BYTES, 6200);
        if (!Array.isArray(data?.blindedTokens) || data.blindedTokens.length !== 250) {
          throw new Error('Invalid blinded token batch');
        }
        blindedTokenBytes = decodeCanonicalBase64List(
          data.blindedTokens,
          PRIVACY_PASS_BLINDED_TOKEN_BYTES,
          64
        );
        issuanceEpoch = this.ppServer.validateIssuanceEpoch(data.tokenEpoch);
      } catch {
        return sendAuthError(ws, { message: 'Invalid login finalization request', code: 'INVALID_FINALIZE_REQUEST', authRequestId });
      }

      const stashedNonceAgeMs = Date.now() - stashedNonceAt;
      if (
        !stashedNonce ||
        !(stashedAuthChannelBinding instanceof Uint8Array) ||
        stashedAuthChannelBinding.length !== AUTH_CHANNEL_BINDING_BYTES ||
        stashedAuthRequestId !== authRequestId ||
        !Number.isSafeInteger(stashedNonceAgeMs) ||
        stashedNonceAgeMs < 0 ||
        stashedNonceAgeMs > LOGIN_FINALIZE_TTL_MS
      ) {
        return sendAuthError(ws, { message: 'Invalid login finalization request', code: 'INVALID_FINALIZE_REQUEST', authRequestId });
      }
      stashedNonceBytes = decodeCanonicalBase64(stashedNonce, OPAQUE_NONCE_BYTES, 64);

      if (powDifficulty > 0 && !verifyPowSolution(powSeed, powDifficulty, data.powSolution)) {
        return sendAuthError(ws, { message: PROOF_OF_WORK_REQUIRED_MESSAGE, code: POW_REQUIRED, authRequestId });
      }

      await applyAdaptiveAuthDelay(ws._connectionAbortSignal);

      releaseVerificationSlot = await acquireExpensiveAuthVerificationSlot(ws._connectionAbortSignal);
      let loginResult;
      try {
        issuedTokenBatch = await this.ppServer.issueAccountAuthTokenBatch(
          blindedTokenBytes,
          issuanceEpoch,
          ws._connectionAbortSignal
        );
        const privateAuthRecords = await UserDatabase.getPrivateAuthRecords();
        if (!Array.isArray(privateAuthRecords)) {
          throw new Error('Private authentication records unavailable');
        }

        loginResult = await OPAQUEServer.finishLoginAcrossAnonymitySet(
          privateAuthRecords,
          authProof,
          stashedNonceBytes,
          stashedAuthChannelBinding,
          ws._connectionAbortSignal
        );
      } finally {
        releaseVerificationSlot?.();
        releaseVerificationSlot = null;
      }
      if (loginResult.success) {
        const formattedIssuedTokenBatch = PrivacyPassHelpers.formatResponse(issuedTokenBatch);
        const delivered = await sendSecureMessage(ws, {
          type: SignalType.AUTH_FULL_SUCCESS,
          authRequestId,
          authenticated: true,
          ...serverEntryResponseFields(ws),
          anonymousTokenBatch: formattedIssuedTokenBatch
        });
        if (delivered === false) throw new Error('Login success was not delivered');

        SecureStateManager.setState(ws, {
          hasAuthenticated: true
        });

        console.log('[AUTH] Successful blind login');
        return { success: true };
      } else {
        try {
          await sendSecureMessage(ws, {
            type: SignalType.AUTH_FULL_SUCCESS,
            authRequestId,
            authenticated: false,
            ...serverEntryResponseFields(ws)
          });
        } finally {
          try {
            await recordAuthFailure();
          } catch {
            ws.close?.(1013, AUTH_SERVICE_UNAVAILABLE_MESSAGE);
          }
        }
      }
    } catch (error) {
      console.error('[AUTH] Login finalization failed', { error: error?.message });
      return sendAuthError(ws, { message: 'Login finalization failed', code: 'LOGIN_FINALIZATION_FAILED', authRequestId });
    } finally {
      releaseVerificationSlot?.();
      wipeIssuedTokenBatch(issuedTokenBatch);
      wipeBytes(authProof);
      wipeBytes(stashedNonceBytes);
      wipeBytes(stashedAuthChannelBinding);
      wipeByteArrays(blindedTokenBytes);
    }
  }

}
