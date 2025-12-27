import { blake3 } from '@noble/hashes/blake3.js';
import { initDatabase, getPgPool } from '../database/database.js';
import crypto from 'node:crypto';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { CryptoUtils } from '../crypto/unified-crypto.js';

let initialized = false;

async function ensureInitialized() {
  if (initialized) {
    return;
  }

  try {
    console.log('[TOKEN-DB] Initializing Postgres token database');
    await initDatabase();
    initialized = true;
    console.log('[TOKEN-DB] Postgres token database ready');
  } catch (error) {
    console.error('[TOKEN-DB] Database initialization failed:', error.message);
    throw error;
  }
}

/**
 * Token database manager
 * Handles secure storage, retrieval, and management of authentication tokens
 */
class TokenDatabase {
  static async storeRefreshToken(tokenData) {
    await ensureInitialized();
    
    const {
      tokenId,
      userId,
      deviceId,
      family,
      rawToken,
      generation = 1,
      expiresAt,
      deviceFingerprint,
      securityContext,
      createdFrom,
      userAgent
    } = tokenData;

    const tokenHash = await this.hashToken(rawToken);
    const now = Math.floor(Date.now() / 1000);

    const userExists = await this.userExists(userId);
    if (!userExists) {
      throw new Error(`User ${userId} does not exist in database`);
    }

    try {
      const maxActive = Math.max(1, Math.min(10, Number.parseInt(process.env.MAX_ACTIVE_REFRESH_TOKENS || '2', 10) || 2));
      const enforcement = await this.enforceMaxActiveRefreshTokens(userId, maxActive, 'revoke_oldest');
      if (enforcement.rejected) {
        await this.logAuthEvent({
          userId,
          deviceId,
          action: 'token_cap_reject',
          tokenType: 'refresh',
          tokenId,
          success: false,
          failureReason: 'maximum_active_refresh_tokens_reached',
          userAgent
        });
        throw new Error('Maximum active refresh tokens reached');
      }
      if (enforcement.tokensRevoked > 0) {
        await this.logAuthEvent({
          userId,
          deviceId,
          action: 'token_cap_enforced',
          tokenType: 'refresh',
          tokenId: null,
          success: true,
          userAgent,
          securityFlags: JSON.stringify({ tokensRevoked: enforcement.tokensRevoked, maxActive })
        });
      }
    } catch (capError) {
      if (capError?.message?.includes('Maximum active refresh tokens')) {
        throw capError;
      }
      console.warn('[TOKEN-DB] Failed to enforce max active refresh tokens cap:', capError?.message || capError);
    }

    const pool = await getPgPool();

    try {
      const protectedUserId = TokenDatabase.maybeEncryptField(userId, 'userId');
      const protectedDeviceId = TokenDatabase.maybeEncryptField(deviceId, 'deviceId');

      const sanitizedSecurityContext = TokenDatabase.prepareSecurityContext(securityContext);
      const expiresAtSeconds = expiresAt instanceof Date ? Math.floor(expiresAt.getTime() / 1000) : expiresAt;

      await pool.query(
        `
        INSERT INTO refresh_tokens (
          tokenId, userId, deviceId, userIdProtected, deviceIdProtected,
          family, tokenHash, generation, issuedAt, expiresAt,
          deviceFingerprint, securityContext, createdFrom, userAgent
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        `,
        [
          tokenId,
          userId,
          deviceId,
          protectedUserId,
          protectedDeviceId,
          family,
          tokenHash,
          generation,
          now,
          expiresAtSeconds,
          deviceFingerprint || null,
          sanitizedSecurityContext,
          createdFrom || null,
          userAgent || null,
        ],
      );

      await this.updateTokenFamily(family, userId, deviceId);
      
      await this.logAuthEvent({
        userId,
        deviceId,
        action: 'token_issued',
        tokenType: 'refresh',
        tokenId,
        success: true,
        userAgent: null,
        securityContext: null
      });

      console.log(`[TOKEN-DB] Stored refresh token for user ${userId}, device ${deviceId}`);
      return tokenId;
    } catch (error) {
      console.error('[TOKEN-DB] Failed to store refresh token:', error);
      
      await this.logAuthEvent({
        userId,
        deviceId,
        action: 'token_issued',
        tokenType: 'refresh',
        tokenId,
        success: false,
        failureReason: error.message,
        userAgent
      });
      
      throw new Error('Failed to store refresh token');
    }
  }

  // Retrieve and validate refresh token
  static async getRefreshToken(tokenId, rawToken = null) {
    await ensureInitialized();

    const pool = await getPgPool();
    const { rows } = await pool.query(
      'SELECT * FROM refresh_tokens WHERE tokenId = $1 AND revokedAt IS NULL',
      [tokenId]
    );

    const tokenRecord = rows[0];
    if (!tokenRecord) {
      return null;
    }

    const tokenHashDb = tokenRecord.tokenHash ?? tokenRecord.tokenhash;
    const expiresAtDb = tokenRecord.expiresAt ?? tokenRecord.expiresat;

    // Check if token is expired
    const now = Math.floor(Date.now() / 1000);
    const expiresAtSeconds = Number(expiresAtDb ?? 0);
    if (!Number.isFinite(expiresAtSeconds) || expiresAtSeconds < now) {
      console.log(`[TOKEN-DB] Token ${tokenId} has expired`);
      return null;
    }

    // Verify token hash if raw token provided
    if (rawToken) {
      let normalizedTokenHash = '';
      if (tokenHashDb && 
          typeof tokenHashDb === 'string' && 
          /^[0-9a-fA-F]+$/.test(tokenHashDb) && 
          tokenHashDb.length % 2 === 0) {
        normalizedTokenHash = tokenHashDb;
      } else {
        normalizedTokenHash = '0'.repeat(64); 
      }
      
      const dummyToken = rawToken || 'dummy_token_for_constant_time_comparison';
      const expectedHash = await this.hashToken(dummyToken);
      
      const storedHashBuffer = Buffer.alloc(32);
      const expectedHashBuffer = Buffer.alloc(32);
      
      try {
        const storedHashBytes = Buffer.from(normalizedTokenHash, 'hex');
        storedHashBytes.copy(storedHashBuffer, 0, 0, Math.min(32, storedHashBytes.length));
      } catch (_e) {
      }
      
      try {
        const expectedHashBytes = Buffer.from(expectedHash, 'hex');
        expectedHashBytes.copy(expectedHashBuffer, 0, 0, Math.min(32, expectedHashBytes.length));
      } catch (_e) {
      }
      
      const hashMatches = this.constantTimeCompare(storedHashBuffer, expectedHashBuffer);
      
      if (!hashMatches || !tokenHashDb || 
          !/^[0-9a-fA-F]+$/.test(tokenHashDb) || 
          tokenHashDb.length % 2 !== 0) {
        console.error(`[TOKEN-DB] Token validation failed for ${tokenId}`);
        return null;
      }
    }

    try {
      await this.updateTokenLastUsed(tokenId);
    } catch (error) {
      console.error(`[TOKEN-DB] Failed to update lastUsed timestamp for ${tokenId}:`, error.message);
    }

    const userIdDb = tokenRecord.userId ?? tokenRecord.userid;
    const deviceIdDb = tokenRecord.deviceId ?? tokenRecord.deviceid;
    const securityContextRaw = tokenRecord.securityContext ?? tokenRecord.securitycontext;
    let parsedSecurityContext = {};
    try {
      parsedSecurityContext = securityContextRaw ? JSON.parse(securityContextRaw) : {};
    } catch {
      parsedSecurityContext = {};
    }

    const userIdProtectedDb = tokenRecord.userIdProtected ?? tokenRecord.useridprotected;
    const deviceIdProtectedDb = tokenRecord.deviceIdProtected ?? tokenRecord.deviceidprotected;

    return {
      id: tokenRecord.tokenId ?? tokenRecord.tokenid,
      tokenId: tokenRecord.tokenId ?? tokenRecord.tokenid,
      userId: userIdDb,
      deviceId: deviceIdDb,
      family: tokenRecord.family,
      generation: tokenRecord.generation,
      issuedAt: tokenRecord.issuedAt ?? tokenRecord.issuedat,
      expiresAt: expiresAtSeconds,
      lastUsed: tokenRecord.lastUsed ?? tokenRecord.lastused,
      revokedAt: tokenRecord.revokedAt ?? tokenRecord.revokedat,
      revokeReason: tokenRecord.revokeReason ?? tokenRecord.revokereason,
      deviceFingerprint: tokenRecord.deviceFingerprint ?? tokenRecord.devicefingerprint,
      securityContext: parsedSecurityContext,
      rawSecurityContext: securityContextRaw,
      createdFrom: tokenRecord.createdFrom ?? tokenRecord.createdfrom,
      userAgent: tokenRecord.userAgent ?? tokenRecord.useragent,
      userIdProtected: userIdProtectedDb,
      deviceIdProtected: deviceIdProtectedDb,
      protectedUserId: TokenDatabase.maybeDecryptField(userIdProtectedDb, 'userId'),
      protectedDeviceId: TokenDatabase.maybeDecryptField(deviceIdProtectedDb, 'deviceId'),
    };
  }

  // Revoke refresh token and optionally entire token family
  static async revokeRefreshToken(tokenId, reason = 'manual_revoke', revokeFamily = false) {
    await ensureInitialized();

    const tokenRecord = await this.getRefreshToken(tokenId);
    if (!tokenRecord) {
      return false;
    }

    const now = Math.floor(Date.now() / 1000);
    const pool = await getPgPool();
    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      if (revokeFamily) {
        // Revoke entire token family
        const result = await client.query(
          'UPDATE refresh_tokens SET revokedAt = $1, revokeReason = $2 WHERE family = $3 AND revokedAt IS NULL',
          [now, `family_revoke: ${reason}`, tokenRecord.family],
        );
        await client.query(
          'UPDATE token_families SET revokedAt = $1, revokeReason = $2 WHERE familyId = $3',
          [now, reason, tokenRecord.family],
        );
        console.log(`[TOKEN-DB] Revoked token family ${tokenRecord.family} for user ${tokenRecord.userId}`);
        await client.query('COMMIT');
        return (result.rowCount || 0) > 0;
      } else {
        // Revoke single token
        const result = await client.query(
          'UPDATE refresh_tokens SET revokedAt = $1, revokeReason = $2 WHERE tokenId = $3 AND revokedAt IS NULL',
          [now, reason, tokenId],
        );
        console.log(`[TOKEN-DB] Revoked token ${tokenId} for user ${tokenRecord.userId}`);
        
        await client.query('COMMIT');
        return (result.rowCount || 0) > 0;
      }
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('[TOKEN-DB] Token revocation failed:', error);
      throw new Error(`Token revocation failed: ${error.message}`);
    } finally {
      client.release();
    
      try {
        await this.logAuthEvent({
          userId: tokenRecord.userId,
          deviceId: tokenRecord.deviceId,
          action: 'token_revoked',
          tokenType: 'refresh',
          tokenId,
          success: true,
          securityFlags: JSON.stringify({ revokeFamily, reason }),
        });
      } catch {
        console.warn('[TOKEN-DB] Failed to log token revocation event');
      }
      
      return true;
    }
  }

  
  // Rotate refresh token (create new token in same family)
  static async rotateRefreshToken(_oldTokenId, _newTokenData) {
    throw new Error('TokenDatabase.rotateRefreshToken is not supported in the Postgres-only backend; use revokeRefreshToken + storeRefreshToken instead');
  }

  // Blacklist token
  static async blacklistToken(tokenId, tokenType, userId = null, reason = 'security_incident', revokedBy = 'system') {
    await ensureInitialized();

    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + (7 * 24 * 60 * 60);

    const pool = await getPgPool();

    try {
      await pool.query(
        `
        INSERT INTO token_blacklist (tokenId, tokenType, userId, blacklistedAt, expiresAt, reason, revokedBy)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (tokenId) DO UPDATE SET
          tokenType = EXCLUDED.tokenType,
          userId = EXCLUDED.userId,
          blacklistedAt = EXCLUDED.blacklistedAt,
          expiresAt = EXCLUDED.expiresAt,
          reason = EXCLUDED.reason,
          revokedBy = EXCLUDED.revokedBy
        `,
        [tokenId, tokenType, userId, now, expiresAt, reason, revokedBy],
      );

      await this.logAuthEvent({
        userId,
        action: 'token_blacklisted',
        tokenType,
        tokenId,
        success: true,
        securityFlags: { reason, revokedBy },
      });

      console.log(`[TOKEN-DB] Blacklisted ${tokenType} token ${tokenId} for user ${userId}`);
      return true;
    } catch (error) {
      console.error('[TOKEN-DB] Failed to blacklist token:', error);
      return false;
    }
  }

  // Check if token is blacklisted
  static async isTokenBlacklisted(tokenId) {
    await ensureInitialized();

    const pool = await getPgPool();
    const now = Math.floor(Date.now() / 1000);
    const { rows } = await pool.query(
      'SELECT 1 FROM token_blacklist WHERE tokenId = $1 AND expiresAt > $2',
      [tokenId, now],
    );
    return rows.length > 0;
  }

  // Manage device sessions
  static async createOrUpdateDeviceSession(deviceData) {
    await ensureInitialized();

    const {
      deviceId,
      userId,
      deviceName,
      deviceType,
      fingerprint,
      riskScore = 'low',
      location,
      userAgent,
      clientVersion,
      securityFlags = {},
    } = deviceData;

    const now = Math.floor(Date.now() / 1000);
    const pool = await getPgPool();

    try {
      await pool.query(
        `
        INSERT INTO device_sessions (
          deviceId, userId, deviceName, deviceType, fingerprint, firstSeen, lastSeen,
          isActive, riskScore, location, userAgent, clientVersion, securityFlags
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
        ON CONFLICT (deviceId) DO UPDATE SET
          userId = EXCLUDED.userId,
          deviceName = EXCLUDED.deviceName,
          deviceType = EXCLUDED.deviceType,
          fingerprint = EXCLUDED.fingerprint,
          lastSeen = EXCLUDED.lastSeen,
          isActive = EXCLUDED.isActive,
          riskScore = EXCLUDED.riskScore,
          location = EXCLUDED.location,
          userAgent = EXCLUDED.userAgent,
          clientVersion = EXCLUDED.clientVersion,
          securityFlags = EXCLUDED.securityFlags
        `,
        [
          deviceId,
          userId,
          deviceName || null,
          deviceType || null,
          fingerprint || null,
          now,
          now,
          1,
          riskScore || null,
          location || null,
          userAgent || null,
          clientVersion || null,
          JSON.stringify(securityFlags || {}),
        ],
      );

      console.log(`[TOKEN-DB] Updated device session ${deviceId} for user ${userId}`);
      return true;
    } catch (error) {
      console.error('[TOKEN-DB] Failed to update device session:', error);
      return false;
    }
  }

  // Get all active sessions for a user
  static async getUserSessions(userId) {
    await ensureInitialized();

    const pool = await getPgPool();
    const { rows } = await pool.query(
      'SELECT * FROM device_sessions WHERE userId = $1 AND isActive = 1 ORDER BY lastSeen DESC',
      [userId],
    );

    return (rows || []).map((session) => ({
      deviceId: session.deviceId ?? session.deviceid,
      userId: session.userId ?? session.userid,
      deviceName: session.deviceName ?? session.devicename,
      deviceType: session.deviceType ?? session.devicetype,
      fingerprint: session.fingerprint,
      firstSeen: session.firstSeen ?? session.firstseen,
      lastSeen: session.lastSeen ?? session.lastseen,
      isActive: session.isActive ?? session.isactive,
      riskScore: session.riskScore ?? session.riskscore,
      location: session.location,
      userAgent: session.userAgent ?? session.useragent,
      clientVersion: session.clientVersion ?? session.clientversion,
      createdAt: session.firstSeen ?? session.firstseen,
      securityFlags: (() => {
        try {
          return session.securityFlags ? JSON.parse(session.securityFlags) : {};
        } catch {
          return {};
        }
      })(),
    }));
  }

  // Revoke all tokens for user (logout from all devices)
  static async revokeAllUserTokens(userId, reason = 'user_logout') {
    await ensureInitialized();

    const now = Math.floor(Date.now() / 1000);
    const pool = await getPgPool();
    const client = await pool.connect();

    let revokedCount = 0;

    try {
      await client.query('BEGIN');

      const tokenResult = await client.query(
        'UPDATE refresh_tokens SET revokedAt = $1, revokeReason = $2 WHERE userId = $3 AND revokedAt IS NULL',
        [now, reason, userId],
      );
      revokedCount = tokenResult.rowCount || 0;

      await client.query(
        'UPDATE token_families SET revokedAt = $1, revokeReason = $2 WHERE userId = $3 AND revokedAt IS NULL',
        [now, reason, userId],
      );

      await client.query(
        'UPDATE device_sessions SET isActive = 0 WHERE userId = $1',
        [userId],
      );

      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('[TOKEN-DB] Failed to revoke all user tokens:', error);
      throw error;
    } finally {
      client.release();
    }

    await this.logAuthEvent({
      userId,
      action: 'logout_all_devices',
      success: true,
      securityFlags: JSON.stringify({
        reason,
        tokensRevoked: revokedCount,
      }),
    });

    console.log(`[TOKEN-DB] Revoked all tokens for user ${userId}, reason: ${reason}`);
    return revokedCount;
  }

  // Revoke all tokens for a specific device (logout single device)
  static async revokeDeviceTokens(userId, deviceId, reason = 'device_revocation') {
    await ensureInitialized();

    const now = Math.floor(Date.now() / 1000);
    const pool = await getPgPool();
    const client = await pool.connect();

    let revokedCount = 0;

    try {
      await client.query('BEGIN');

      const tokenResult = await client.query(
        'UPDATE refresh_tokens SET revokedAt = $1, revokeReason = $2 WHERE userId = $3 AND deviceId = $4 AND revokedAt IS NULL',
        [now, reason, userId, deviceId],
      );
      revokedCount = tokenResult.rowCount || 0;

      await client.query(
        'UPDATE token_families SET revokedAt = $1, revokeReason = $2 WHERE userId = $3 AND deviceId = $4 AND revokedAt IS NULL',
        [now, reason, userId, deviceId],
      );

      await client.query(
        'UPDATE device_sessions SET isActive = 0 WHERE userId = $1 AND deviceId = $2',
        [userId, deviceId],
      );

      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('[TOKEN-DB] Failed to revoke device tokens:', error);
      throw error;
    } finally {
      client.release();
    }

    await this.logAuthEvent({
      userId,
      deviceId,
      action: 'logout_device',
      success: true,
      securityFlags: JSON.stringify({
        reason,
        tokensRevoked: revokedCount,
      }),
    });

    console.log(`[TOKEN-DB] Revoked ${revokedCount} tokens for user ${userId}, device ${deviceId}, reason: ${reason}`);
    return revokedCount;
  }

  // Clean up expired tokens and blacklist entries
  static async cleanupExpiredTokens() {
    await ensureInitialized();

    const now = Math.floor(Date.now() / 1000);
    const pool = await getPgPool();

    try {
      const tokensDeleted = await pool.query(
        'DELETE FROM refresh_tokens WHERE expiresAt < $1',
        [now],
      );
      const blacklistDeleted = await pool.query(
        'DELETE FROM token_blacklist WHERE expiresAt < $1',
        [now],
      );
      const auditDeleted = await pool.query(
        'DELETE FROM auth_audit_log WHERE timestamp < $1',
        [now - 90 * 24 * 60 * 60],
      );

      const tokens = tokensDeleted.rowCount || 0;
      const blacklist = blacklistDeleted.rowCount || 0;
      const audit = auditDeleted.rowCount || 0;

      if (tokens > 0 || blacklist > 0 || audit > 0) {
        console.log(`[TOKEN-DB] Cleanup: ${tokens} tokens, ${blacklist} blacklist entries, ${audit} audit logs`);
      }

      return { tokens, blacklist, audit };
    } catch (error) {
      console.error('[TOKEN-DB] Cleanup failed:', error);
      return null;
    }
  }

  // Log authentication events for security monitoring
  static async logAuthEvent(eventData) {
    await ensureInitialized();

    const {
      userId,
      deviceId,
      action,
      tokenType,
      tokenId,
      success,
      failureReason,
      userAgent: _userAgent,
      riskScore,
      securityFlags,
    } = eventData;

    if (!action || typeof action !== 'string') {
      console.error('[TOKEN-DB] logAuthEvent: Missing or invalid action field');
      return;
    }

    if (typeof success !== 'boolean') {
      console.error('[TOKEN-DB] logAuthEvent: Missing or invalid success field');
      return;
    }

    const pool = await getPgPool();
    const timestamp = Math.floor(Date.now() / 1000);

    try {
      await pool.query(
        `
        INSERT INTO auth_audit_log (
          userId, deviceId, action, tokenType, tokenId, success, failureReason,
          userAgent, riskScore, securityFlags, timestamp
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        `,
        [
          FieldEncryption.encryptField(userId || null, 'userId'),
          FieldEncryption.encryptField(deviceId || null, 'deviceId'),
          action,
          tokenType || null,
          tokenId || null,
          success ? 1 : 0,
          failureReason || null,
          null,
          riskScore || null,
          typeof securityFlags === 'string'
            ? securityFlags
            : JSON.stringify(TokenDatabase.sanitizeJSON(securityFlags || {})),
          timestamp,
        ],
      );
    } catch (error) {
      console.error('[TOKEN-DB] Failed to log auth event:', error);
    }
  }

  // Check if a user exists in the database
  static async userExists(username) {
    await ensureInitialized();

    const pool = await getPgPool();
    const { rows } = await pool.query(
      'SELECT 1 FROM users WHERE username = $1 LIMIT 1',
      [username],
    );
    return rows.length > 0;
  }

  // Private helper methods
  static async _getOrCreatePepper() {
    const env = process.env.TOKEN_PEPPER;
    if (env && Buffer.from(env).length >= 32) return Buffer.from(env);
    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    const configDir = path.join(__dirname, '../config');
    const pepperPath = path.join(configDir, 'token.pepper');
    try {
      const p = await fs.readFile(pepperPath);
      if (p.length >= 32) return p;
    } catch {}
    await fs.mkdir(configDir, { recursive: true });
    const strong = crypto.randomBytes(64);
    await fs.writeFile(pepperPath, strong, { mode: 0o600 });
    return strong;
  }

  static async hashToken(token) {
    const pepper = await this._getOrCreatePepper();
    const hmacInput = Buffer.concat([
      pepper,
      Buffer.from(String(token)),
      Buffer.from('token-hash-v1')
    ]);
    return blake3(hmacInput).toString('hex');
  }

  static constantTimeCompare(a, b) {
    const bufferA = Buffer.isBuffer(a) ? a : Buffer.from(a);
    const bufferB = Buffer.isBuffer(b) ? b : Buffer.from(b);
    if (bufferA.length !== bufferB.length) {
      const maxLen = Math.max(bufferA.length, bufferB.length);
      const paddedA = Buffer.alloc(maxLen);
      const paddedB = Buffer.alloc(maxLen);
      bufferA.copy(paddedA);
      bufferB.copy(paddedB);
      return crypto.timingSafeEqual(paddedA, paddedB) && bufferA.length === bufferB.length;
    }
    return crypto.timingSafeEqual(bufferA, bufferB);
  }

  static async updateTokenLastUsed(tokenId) {
    try {
      await ensureInitialized();

      const pool = await getPgPool();
      const now = Math.floor(Date.now() / 1000);
      const result = await pool.query(
        'UPDATE refresh_tokens SET lastUsed = $1 WHERE tokenId = $2',
        [now, tokenId],
      );

      if ((result.rowCount || 0) === 0) {
        console.warn(`[TOKEN-DB] No token found to update lastUsed for tokenId: ${tokenId}`);
      }

      return (result.rowCount || 0) > 0;
    } catch (error) {
      console.error(`[TOKEN-DB] Failed to update lastUsed for tokenId ${tokenId}:`, error.message);
      throw new Error(`Failed to update token last used timestamp: ${error.message}`);
    }
  }

  static async updateTokenFamily(familyId, userId, deviceId) {
    await ensureInitialized();

    const pool = await getPgPool();
    const now = Math.floor(Date.now() / 1000);

    await pool.query(
      `
      INSERT INTO token_families (familyId, userId, deviceId, createdAt, tokenCount, lastRotation)
      VALUES ($1,$2,$3,$4,1,NULL)
      ON CONFLICT (familyId) DO UPDATE SET
        userId = EXCLUDED.userId,
        deviceId = EXCLUDED.deviceId,
        tokenCount = token_families.tokenCount + 1
      `,
      [familyId, userId, deviceId, now],
    );
  }

  // Count active refresh tokens for a user
  static async countActiveRefreshTokens(userId) {
    await ensureInitialized();
    const now = Math.floor(Date.now() / 1000);
    const pool = await getPgPool();
    const { rows } = await pool.query(
      'SELECT COUNT(*) AS count FROM refresh_tokens WHERE userId = $1 AND revokedAt IS NULL AND expiresAt > $2',
      [userId, now],
    );
    const row = rows[0];
    return Number(row?.count || 0);
  }

  // Get active refresh tokens for a user ordered from oldest to newest by lastUsed/issuedAt
  static async getActiveRefreshTokens(userId) {
    await ensureInitialized();
    const now = Math.floor(Date.now() / 1000);
    const pool = await getPgPool();
    const { rows } = await pool.query(
      `
      SELECT tokenId, userId, deviceId, family, issuedAt, lastUsed, expiresAt
      FROM refresh_tokens
      WHERE userId = $1 AND revokedAt IS NULL AND expiresAt > $2
      ORDER BY COALESCE(lastUsed, issuedAt) ASC, issuedAt ASC
      `,
      [userId, now],
    );
    return rows || [];
  }

  // Revoke the oldest active refresh tokens for a user
  static async revokeOldestActiveTokens(userId, countToRevoke, reason = 'token_cap_enforced') {
    await ensureInitialized();
    const count = Math.max(0, Number(countToRevoke || 0));
    if (count === 0) return { revoked: 0, tokenIds: [] };

    const now = Math.floor(Date.now() / 1000);
    const pool = await getPgPool();
    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      const { rows: toRevoke } = await client.query(
        `
        SELECT tokenId, deviceId
        FROM refresh_tokens
        WHERE userId = $1 AND revokedAt IS NULL AND expiresAt > $2
        ORDER BY COALESCE(lastUsed, issuedAt) ASC, issuedAt ASC
        LIMIT $3
        `,
        [userId, now, count],
      );

      if (!toRevoke || toRevoke.length === 0) {
        await client.query('ROLLBACK');
        return { revoked: 0, tokenIds: [] };
      }

      const ids = toRevoke.map((r) => r.tokenid ?? r.tokenId);

      await client.query(
        'UPDATE refresh_tokens SET revokedAt = $1, revokeReason = $2 WHERE tokenId = ANY($3::text[]) AND revokedAt IS NULL',
        [now, reason, ids],
      );

      await client.query('COMMIT');

      for (const r of toRevoke) {
        await this.logAuthEvent({
          userId,
          deviceId: r.deviceid ?? r.deviceId,
          action: 'token_revoked',
          tokenType: 'refresh',
          tokenId: r.tokenid ?? r.tokenId,
          success: true,
          securityFlags: JSON.stringify({ reason }),
        });
      }

      return { revoked: ids.length, tokenIds: ids };
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('[TOKEN-DB] Failed to revoke oldest active tokens:', error);
      return { revoked: 0, tokenIds: [] };
    } finally {
      client.release();
    }
  }

  /**
   * Enforce a maximum number of active refresh tokens per user.
   * 'revoke_oldest' will revoke the oldest tokens to make room for the new one.
   * 'reject' returns { rejected: true } without mutating state.
   */
  static async enforceMaxActiveRefreshTokens(userId, maxActive = 3, strategy = 'revoke_oldest') {
    await ensureInitialized();
    const max = Math.max(1, Number(maxActive || 3));
    const activeCount = await this.countActiveRefreshTokens(userId);

    if (activeCount < max) {
      return { enforced: false, rejected: false, activeCount, tokensRevoked: 0 };
    }

    const tokensToRevoke = Math.max(0, (activeCount + 1) - max);

    if (strategy === 'reject') {
      return { enforced: false, rejected: true, activeCount, tokensRevoked: 0 };
    }

    const { revoked } = await this.revokeOldestActiveTokens(userId, tokensToRevoke, 'token_cap_enforced');
    return { enforced: true, rejected: false, activeCount: activeCount - revoked, tokensRevoked: revoked };
  }
}

class FieldEncryption {
  static deriveFieldKey(fieldName) {
    const masterRaw = process.env.DB_FIELD_KEY || '';
    const masterBuf = Buffer.from(masterRaw, 'utf8');
    if (!masterRaw || masterBuf.length < 32) {
      throw new Error('DB_FIELD_KEY environment variable must be set with at least 32 bytes for database field encryption');
    }

    const ikm = new Uint8Array(masterBuf);
    const salt = new TextEncoder().encode('db-field-key-salt-v2');
    const info = `db-field-key-v2:${fieldName}`;
    const keyBytes = CryptoUtils.KDF.deriveKey(ikm, salt, info, 32);
    return Buffer.from(keyBytes);
  }

  static encryptField(value, fieldName) {
    if (value === null || value === undefined) return null;
    const key = this.deriveFieldKey(fieldName);
    const nonce = crypto.randomBytes(36);
    const aad = Buffer.from(`db-field:${fieldName}:v3`, 'utf8');
    const aead = new CryptoUtils.PostQuantumAEAD(key);
    const plaintext = Buffer.from(String(value), 'utf8');
    const { ciphertext, tag } = aead.encrypt(plaintext, nonce, aad);

    const combined = Buffer.concat([nonce, tag, ciphertext]);
    return combined.toString('base64');
  }

  static decryptField(encrypted, fieldName) {
    if (!encrypted) return null;
    const data = Buffer.from(encrypted, 'base64');

    if (data.length < 36 + 32 + 1) {
      throw new Error('Encrypted field payload too short');
    }

    const nonce = data.slice(0, 36);
    const tag = data.slice(36, 68);
    const ciphertext = data.slice(68);
    const key = this.deriveFieldKey(fieldName);
    const aad = Buffer.from(`db-field:${fieldName}:v3`, 'utf8');
    const aead = new CryptoUtils.PostQuantumAEAD(key);
    const plaintext = aead.decrypt(ciphertext, nonce, tag, aad);
    return Buffer.from(plaintext).toString('utf8');
  }
}

// JSON sanitizer
TokenDatabase.sanitizeJSON = function(obj, maxDepth = 3, currentDepth = 0) {
  if (currentDepth >= maxDepth) return {};
  if (!obj || typeof obj !== 'object') return {};
  const out = {};
  const allowed = ['string', 'number', 'boolean'];
  for (const [k, v] of Object.entries(obj)) {
    if (!/^[a-zA-Z0-9_]{1,50}$/.test(k)) continue;
    if (v === null || v === undefined) { out[k] = null; continue; }
    if (allowed.includes(typeof v)) {
      out[k] = typeof v === 'string' ? v.substring(0, 1000).replace(/[^\x20-\x7E]/g, '') : v;
    } else if (typeof v === 'object') {
      out[k] = TokenDatabase.sanitizeJSON(v, maxDepth, currentDepth + 1);
    }
  }
  return out;
};

TokenDatabase.maybeDecryptField = function(value, fieldName) {
  if (!value) {
    return value;
  }
  if (typeof value !== 'string') {
    return value;
  }

  const base64Pattern = /^[A-Za-z0-9+/=]+$/;
  if (value.length % 4 !== 0 || !base64Pattern.test(value)) {
    return value;
  }

  try {
    return FieldEncryption.decryptField(value, fieldName);
  } catch (error) {
    console.error(`[TOKEN-DB] CRITICAL: Failed to decrypt ${fieldName}:`, error.message);
    throw new Error(`Database field decryption failed for ${fieldName} - data corruption or key mismatch`);
  }
};

TokenDatabase.maybeEncryptField = function(value, fieldName) {
  if (value === null || value === undefined) {
    return null;
  }

  try {
    return FieldEncryption.encryptField(value, fieldName);
  } catch (error) {
    console.error(`[TOKEN-DB] CRITICAL: Failed to encrypt ${fieldName}:`, error.message);
    throw new Error(`Database field encryption failed for ${fieldName} - encryption key not properly initialized`);
  }
};

TokenDatabase.prepareSecurityContext = function(context) {
  try {
    return JSON.stringify(TokenDatabase.sanitizeJSON(context || {}));
  } catch (error) {
    console.warn('[TOKEN-DB] Failed to sanitize security context:', error.message);
    return JSON.stringify({});
  }
};

export { TokenDatabase };
export default TokenDatabase;
