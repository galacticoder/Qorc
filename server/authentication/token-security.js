import { TokenDatabase } from './token-database.js';
import { TokenService } from './token-service.js';
import crypto from 'node:crypto';

// Security configuration constants for hardened token refresh thresholds
const SECURITY_CONFIG = {
  // Token refresh abuse detection thresholds (per 24 hours)
  CRITICAL_REFRESH_THRESHOLD: 8,
  HIGH_REFRESH_THRESHOLD: 5,
  MODERATE_REFRESH_THRESHOLD: 3,

  MAX_DEVICES_PER_DAY: 3,
  MAX_FAILED_ATTEMPTS: 5,

  DETECTION_WINDOW_HOURS: 24,

  RATE_LIMIT_BASE_DELAY: 2000,
  RATE_LIMIT_MAX_DELAY: 60000,

  RISK_WEIGHTS: {
    MULTIPLE_DEVICES: 2,
    EXCESSIVE_FAILURES: 2,
    TOKEN_ABUSE: 4
  }
};

function safeJsonParse(raw) {
  if (typeof raw !== 'string') return null;
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * Token security manager
 * Handles revocation, blacklisting, suspicious activity detection,
 * and more
 */
class TokenSecurityManager {
  static async revokeToken(tokenId, reason = 'manual_revoke', revokedBy = 'system', revokeFamily = false) {
    try {
      await this.enforceSecurityOpRateLimit('system', 'revokeToken');
      console.log(`[TOKEN-SEC] Revoking token ${tokenId}, reason: ${reason}`);

      const tokenInfo = await TokenDatabase.getRefreshToken(tokenId);
      if (!tokenInfo) {
        console.warn(`[TOKEN-SEC] Token ${tokenId} not found for revocation`);
        return false;
      }

      const revoked = await TokenDatabase.revokeRefreshToken(tokenId, reason, revokeFamily);

      if (revoked) {
        await TokenDatabase.blacklistToken(tokenId, 'refresh', tokenInfo.userId, reason, revokedBy);

        await this.logSecureAuthEvent({
          userId: tokenInfo.userId,
          deviceId: tokenInfo.deviceId,
          action: 'token_revoked',
          tokenType: 'refresh',
          tokenId: tokenId,
          success: true,
          securityFlags: JSON.stringify({
            reason,
            revokedBy,
            familyRevoked: revokeFamily,
            securityLevel: 'high'
          })
        });

        console.log(`[TOKEN-SEC] Successfully revoked token ${tokenId}`);
        return true;
      }

      return false;
    } catch (error) {
      console.error('[TOKEN-SEC] Error revoking token:', error);
      return false;
    }
  }

  // Logout user from all devices
  static async logoutFromAllDevices(userId, reason = 'user_request', initiatedBy = 'user') {
    try {
      console.log(`[TOKEN-SEC] Logging out user ${userId} from all devices`);

      const sessions = await TokenDatabase.getUserSessions(userId);
      const revokedCount = await TokenDatabase.revokeAllUserTokens(userId, `logout_all:${reason}`);

      await this.logSecureAuthEvent({
        userId,
        action: 'logout_all_devices',
        success: true,
        securityFlags: JSON.stringify({
          reason,
          initiatedBy,
          sessionsCount: sessions.length,
          tokensRevoked: revokedCount,
          timestamp: Date.now()
        })
      });

      console.log(`[TOKEN-SEC] Logged out user ${userId} from ${sessions.length} devices`);
      return {
        success: true,
        devicesLoggedOut: sessions.length,
        tokensRevoked: revokedCount
      };

    } catch (error) {
      console.error('[TOKEN-SEC] Error in logout from all devices:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Detect suspicious token activity
  static async detectSuspiciousActivity(userId, tokenId, activityContext = {}) {
    try {
      await this.enforceSecurityOpRateLimit(userId, 'detectSuspiciousActivity');
      const lockKey = `activity:${userId}`;
      const lock = await this.acquireLock(lockKey, 5000);
      if (!lock) {
        throw new Error('Failed to acquire activity lock');
      }
      try {
        const suspiciousFlags = [];
        const recentEvents = await this.getRecentAuthEvents(userId, SECURITY_CONFIG.DETECTION_WINDOW_HOURS);
        const adaptive = await this.getAdaptiveThresholds(userId);
        const tokenRequests = recentEvents.filter(e => e.action === 'token_refreshed');
        const refreshCount = tokenRequests.length;

        if (refreshCount >= adaptive.CRITICAL_REFRESH_THRESHOLD) {
          suspiciousFlags.push('critical_token_refresh');
          await this.logSecureAuthEvent({
            userId,
            tokenId,
            action: 'critical_token_abuse',
            success: true,
            riskScore: 'critical',
            securityFlags: JSON.stringify({
              refreshCount,
              threshold: adaptive.CRITICAL_REFRESH_THRESHOLD,
              action: 'invalidate_all_tokens',
              securityLevel: 'maximum'
            })
          });

          await this.logoutFromAllDevices(userId, 'critical_token_abuse_detected', 'security_system');

        } else if (refreshCount >= adaptive.HIGH_REFRESH_THRESHOLD) {
          suspiciousFlags.push('excessive_token_refresh');
          await this.logSecureAuthEvent({
            userId,
            tokenId,
            action: 'high_token_abuse_detected',
            success: true,
            riskScore: 'high',
            securityFlags: JSON.stringify({
              refreshCount,
              threshold: adaptive.HIGH_REFRESH_THRESHOLD,
              action: 'apply_rate_limiting'
            })
          });

        } else if (refreshCount >= adaptive.MODERATE_REFRESH_THRESHOLD) {
          suspiciousFlags.push('moderate_token_refresh');
          await this.logSecureAuthEvent({
            userId,
            tokenId,
            action: 'moderate_token_abuse_detected',
            success: true,
            riskScore: 'medium',
            securityFlags: JSON.stringify({
              refreshCount,
              threshold: adaptive.MODERATE_REFRESH_THRESHOLD,
              action: 'apply_rate_limiting'
            })
          });
        }

        const loginEvents = recentEvents.filter(e => e.action === 'login');
        const uniqueDevices = new Set(loginEvents.map(e => e.deviceId).filter(Boolean));
        if (uniqueDevices.size > adaptive.MAX_DEVICES_PER_DAY) {
          suspiciousFlags.push('multiple_device_login');
          console.warn(`[TOKEN-SEC] Multiple device login detected: ${uniqueDevices.size} devices for user ${userId}`);
        }

        // Detect brute force patterns with stricter threshold
        const failedAttempts = recentEvents.filter(e => !e.success);
        if (failedAttempts.length > SECURITY_CONFIG.MAX_FAILED_ATTEMPTS) {
          suspiciousFlags.push('excessive_failed_attempts');
          console.warn(`[TOKEN-SEC] Excessive failed attempts detected: ${failedAttempts.length} for user ${userId}`);
        }

        // Calculate risk score
        let riskScore = 'low';
        if (suspiciousFlags.length >= 3) riskScore = 'critical';
        else if (suspiciousFlags.length >= 2) riskScore = 'high';
        else if (suspiciousFlags.length >= 1) riskScore = 'medium';

        // Log suspicious activity if detected
        if (suspiciousFlags.length > 0) {
          await this.logSecureAuthEvent({
            userId,
            tokenId,
            action: 'suspicious_activity_detected',
            success: true,
            riskScore,
            securityFlags: JSON.stringify({
              flags: suspiciousFlags,
              eventCount: recentEvents.length,
              riskScore,
              context: activityContext
            })
          });

          console.warn(`[TOKEN-SEC] Suspicious activity detected for user ${userId}:`, suspiciousFlags);

          if (riskScore === 'critical') {
            await this.handleCriticalRisk(userId, suspiciousFlags);
          }
        }

        return {
          suspicious: suspiciousFlags.length > 0,
          flags: suspiciousFlags,
          riskScore,
          recommendedAction: this.getRecommendedAction(riskScore)
        };
      } finally {
        await this.releaseLock(lockKey, lock);
      }

    } catch (error) {
      console.error('[TOKEN-SEC] Error detecting suspicious activity:', error);
      return {
        suspicious: false,
        error: error.message
      };
    }
  }

  // Handle critical security risk
  static async handleCriticalRisk(userId, flags) {
    console.error(`[TOKEN-SEC] CRITICAL RISK detected for user ${userId}:`, flags);

    // Automatically revoke all tokens
    await this.logoutFromAllDevices(userId, 'critical_security_risk', 'system');

    // Additional actions for critical risk
    try {
      await TokenDatabase.logAuthEvent({
        userId,
        action: 'security_alert_sent',
        success: true,
        securityFlags: JSON.stringify({ level: 'critical', method: 'log_only' })
      });
    } catch { }

    await TokenDatabase.logAuthEvent({
      userId,
      action: 'critical_risk_action',
      success: true,
      securityFlags: JSON.stringify({
        flags,
        action: 'logout_all_devices',
        timestamp: Date.now()
      })
    });
  }

  // Get recommended action based on risk score
  static getRecommendedAction(riskScore) {
    switch (riskScore) {
      case 'critical':
        return 'immediate_logout_all_devices';
      case 'high':
        return 'require_additional_verification';
      case 'medium':
        return 'monitor_closely';
      case 'low':
      default:
        return 'continue_monitoring';
    }
  }

  // Validate token against security policies
  static async validateTokenSecurity(token, context = {}) {
    try {
      await this.enforceSecurityOpRateLimit(context.userId || 'anonymous', 'validateTokenSecurity');
      const payload = TokenService.parseTokenUnsafe(token);
      if (!payload) {
        return {
          valid: false,
          reason: 'invalid_token_format'
        };
      }

      const isBlacklisted = await TokenDatabase.isTokenBlacklisted(payload.jti);
      if (isBlacklisted) {
        return {
          valid: false,
          reason: 'token_blacklisted'
        };
      }

      const tokenAge = Date.now() / 1000 - payload.iat;
      const maxAge = this.getMaxTokenAge(payload.type || 'access');

      if (tokenAge > maxAge) {
        if (context && context.initialLogin === true && tokenAge <= (maxAge + 3600)) {
        } else {
          return {
            valid: false,
            reason: 'token_too_old',
            metadata: { ageHours: Math.floor(tokenAge / 3600) }
          };
        }
      }

      await this.updateTokenUsage(payload.jti, context);
      const recentUsage = await this.checkRecentTokenUsage(payload.jti);
      if (recentUsage.suspicious) {
        return {
          valid: false,
          reason: 'suspicious_token_usage',
          metadata: recentUsage
        };
      }

      return {
        valid: true,
        metadata: {
          ageHours: Math.floor(tokenAge / 3600),
          riskScore: this.calculateTokenRiskScore(payload, context)
        }
      };

    } catch (error) {
      console.error('[TOKEN-SEC] Error validating token security:', error);
      return {
        valid: false,
        reason: 'validation_error',
        error: error.message
      };
    }
  }

  // Check for suspicious token usage patterns
  static async checkRecentTokenUsage(tokenId) {
    const usageKey = `token:usage:${tokenId}`;
    const now = Date.now();
    const oneMinuteAgo = now - 60000;

    try {
      const { withRedisClient } = await import('../presence/presence.js');
      return await withRedisClient(async (client) => {
        const count = await client.zcount(usageKey, oneMinuteAgo, now);

        // Detect rapid token usage
        if (count > 20) {
          return {
            suspicious: true,
            reason: 'rapid_token_usage',
            metadata: {
              requestCount: count,
              timeWindow: '1_minute'
            }
          };
        }

        return { suspicious: false };
      });
    } catch (error) {
      console.error('[TOKEN-SEC] Failed to check token usage from Redis:', error);
      return { suspicious: true, reason: 'backend_unavailable' };
    }
  }

  // Calculate risk score for token
  static calculateTokenRiskScore(payload, context) {
    let score = 0;

    const ageHours = (Date.now() / 1000 - payload.iat) / 3600;
    if (ageHours > 12) score += 1;
    if (ageHours > 20) score += 2;

    if (payload.sec?.risk === 'high') score += 3;
    else if (payload.sec?.risk === 'medium') score += 1;

    if (context.newDevice) score += 2;

    if (score >= 6) return 'high';
    if (score >= 3) return 'medium';
    return 'low';
  }

  static async enforceSecurityOpRateLimit(userId, operation) {
    const key = `secop:ratelimit:${userId}:${operation}`;
    const maxOps = {
      validateTokenSecurity: 100,
      detectSuspiciousActivity: 20,
      revokeToken: 10
    };
    const maxAllowed = maxOps[operation] || 50;

    try {
      const { withRedisClient } = await import('../presence/presence.js');
      await withRedisClient(async (client) => {
        const count = await client.incr(key);
        if (count === 1) {
          await client.expire(key, 60);
        }

        if (count > maxAllowed) {
          throw new Error(`Rate limit exceeded for ${operation}`);
        }
      });
    } catch (error) {
      if (error.message && error.message.includes('Rate limit exceeded')) {
        throw error;
      }
      console.error('[TOKEN-SEC] Failed to enforce rate limit via Redis:', error);
      throw new Error('Rate limit backend unavailable');
    }
  }

  static getMaxTokenAge(tokenType) {
    const maxAges = {
      access: 7 * 24 * 60 * 60,   // 7 days
      refresh: 7 * 24 * 60 * 60,  // 7 days
      device: 60 * 60,            // 1 hour
      session: 4 * 60 * 60        // 4 hours
    };
    return maxAges[tokenType] || 60 * 60;
  }

  static async updateTokenUsage(tokenId, _context = {}) {
    const usageKey = `token:usage:${tokenId}`;
    const now = Date.now();

    try {
      const { withRedisClient } = await import('../presence/presence.js');
      await withRedisClient(async (client) => {
        await client.zadd(usageKey, now, `${now}:${crypto.randomBytes(4).toString('hex')}`);
        await client.zremrangebyscore(usageKey, 0, now - 60000);
        await client.expire(usageKey, 120);
      });
    } catch (error) {
      console.error('[TOKEN-SEC] Failed to update token usage in Redis:', error);
    }
  }

  static async acquireLock(key, timeoutMs) {
    const lockKey = `lock:${key}`;
    const lockId = crypto.randomBytes(16).toString('hex');
    const ttlSeconds = Math.ceil(timeoutMs / 1000);
    const deadline = Date.now() + timeoutMs;

    try {
      const { withRedisClient } = await import('../presence/presence.js');

      let attempt = 0;
      while (Date.now() < deadline) {
        const acquired = await withRedisClient(async (client) => {
          const result = await client.set(lockKey, lockId, 'NX', 'EX', ttlSeconds);
          return result === 'OK';
        });

        if (acquired) {
          return lockId;
        }

        attempt += 1;
        const remaining = deadline - Date.now();
        if (remaining <= 0) break;

        const base = Math.min(250, 10 * Math.pow(1.5, Math.min(attempt, 10)));
        const jitter = crypto.randomInt(0, Math.max(1, Math.floor(base * 0.2)));
        const sleepMs = Math.min(remaining, Math.floor(base + jitter));
        if (sleepMs > 0) {
          await new Promise((r) => setTimeout(r, sleepMs));
        }
      }

      return null;
    } catch (error) {
      console.error('[TOKEN-SEC] Failed to acquire distributed lock:', error);
      return null;
    }
  }

  static async releaseLock(key, lockId) {
    const lockKey = `lock:${key}`;

    try {
      const { withRedisClient } = await import('../presence/presence.js');
      await withRedisClient(async (client) => {
        const luaScript = `
          if redis.call("get", KEYS[1]) == ARGV[1] then
            return redis.call("del", KEYS[1])
          else
            return 0
          end
        `;
        await client.eval(luaScript, 1, lockKey, lockId);
      });
    } catch (error) {
      console.error('[TOKEN-SEC] Failed to release distributed lock:', error);
    }
  }

  static async deriveAuditHMACKey() {
    const keyFromEnv = process.env.AUTH_AUDIT_HMAC_KEY;
    if (keyFromEnv && Buffer.from(keyFromEnv).length >= 32) return Buffer.from(keyFromEnv);
    const { promises: fs } = await import('fs');
    const path = (await import('path')).default;
    const { fileURLToPath } = await import('url');
    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    const configDir = path.join(__dirname, '../config');
    const secretPath = path.join(configDir, 'auth_audit.hmac');
    let secret;

    try {
      secret = await fs.readFile(secretPath);
      if (secret.length >= 32) return secret;
    } catch { }

    await fs.mkdir(configDir, { recursive: true });
    const strong = (await import('node:crypto')).randomBytes(64);
    await fs.writeFile(secretPath, strong, { mode: 0o600 });
    return strong;
  }

  static async logSecureAuthEvent(eventData) {
    const event = {
      ...eventData,
      timestamp: Date.now(),
      nonce: crypto.randomBytes(16).toString('hex')
    };
    const hmacKey = await this.deriveAuditHMACKey();
    const hmac = crypto.createHmac('sha256', hmacKey);
    hmac.update(JSON.stringify(event));
    event.hmac = hmac.digest('hex');

    await TokenDatabase.logAuthEvent(event);
  }

  static async verifyAuditIntegrity(event) {
    const { hmac, ...eventData } = event;
    const hmacKey = await this.deriveAuditHMACKey();
    const computed = crypto.createHmac('sha256', hmacKey);
    computed.update(JSON.stringify(eventData));
    try {
      return crypto.timingSafeEqual(
        Buffer.from(hmac, 'hex'),
        Buffer.from(computed.digest('hex'), 'hex')
      );
    } catch {
      return false;
    }
  }

  static async trackAccessToken(tokenId, userId, expiresAt) {
    const key = `access:token:${tokenId}`;
    const now = Math.floor(Date.now() / 1000);
    const ttl = Math.max(1, expiresAt - now + 60);

    try {
      const { withRedisClient } = await import('../presence/presence.js');
      await withRedisClient(async (client) => {
        await client.set(key, JSON.stringify({ userId, expiresAt, revoked: false }), 'EX', ttl);
      });
    } catch (error) {
      console.error('[TOKEN-SEC] Failed to track access token in Redis:', error);
    }
  }

  static async isAccessTokenRevoked(tokenId) {
    const key = `access:token:${tokenId}`;

    try {
      const { withRedisClient } = await import('../presence/presence.js');
      const data = await withRedisClient(async (client) => {
        return await client.get(key);
      });

      if (!data) return false;
      const token = safeJsonParse(data);
      if (!token) return true;
      return token.revoked || false;
    } catch (error) {
      console.error('[TOKEN-SEC] Failed to check token revocation from Redis:', error);
      return true;
    }
  }

  static async revokeAccessToken(tokenId) {
    const key = `access:token:${tokenId}`;

    try {
      const { withRedisClient } = await import('../presence/presence.js');
      return await withRedisClient(async (client) => {
        const data = await client.get(key);
        if (!data) return false;

        const token = safeJsonParse(data);
        if (!token) return false;
        token.revoked = true;

        const ttl = await client.ttl(key);
        if (ttl > 0) {
          await client.set(key, JSON.stringify(token), 'EX', ttl);
          return true;
        }
        return false;
      });
    } catch (error) {
      console.error('[TOKEN-SEC] Failed to revoke access token in Redis:', error);
      return false;
    }
  }

  static async getAdaptiveThresholds(userId) {
    const baseline = await this.getUserBaseline(userId);
    return {
      CRITICAL_REFRESH_THRESHOLD: Math.max(3, Math.ceil(baseline.avgRefreshes * 3)),
      HIGH_REFRESH_THRESHOLD: Math.max(2, Math.ceil(baseline.avgRefreshes * 2)),
      MODERATE_REFRESH_THRESHOLD: Math.max(1, Math.ceil(baseline.avgRefreshes * 1.5)),
      MAX_DEVICES_PER_DAY: Math.max(2, Math.ceil(baseline.avgDevices * 2))
    };
  }
  static async getUserBaseline(userId) {
    const events = await this.getRecentAuthEvents(userId, 30 * 24);
    const dailyStats = {};
    events.forEach(event => {
      const day = new Date(event.event_time * 1000).toDateString();
      if (!dailyStats[day]) { dailyStats[day] = { refreshes: 0, devices: new Set() }; }
      if (event.action === 'token_refreshed') dailyStats[day].refreshes++;
      if (event.deviceId) dailyStats[day].devices.add(event.deviceId);
    });
    const days = Object.values(dailyStats);
    return {
      avgRefreshes: days.length ? (days.reduce((s, d) => s + d.refreshes, 0) / days.length) : 1,
      avgDevices: days.length ? (days.reduce((s, d) => s + d.devices.size, 0) / days.length) : 1
    };
  }

  static async broadcastSecurityEvent(event) {
    const message = {
      instanceId: process.env.SERVER_ID || 'default',
      timestamp: Date.now(),
      event
    };
    try {
      const { withRedisClient } = await import('../presence/presence.js');
      await withRedisClient(async (client) => client.publish('security:auth-events', JSON.stringify(message)));
    } catch { }
  }
  static async initializeDistributedMonitoring() {
    try {
      const { createSubscriber } = await import('../presence/presence.js');
      const sub = await createSubscriber();
      const channel = 'security:auth-events';
      await sub.subscribe(channel);
      const handler = async (_channel, msg) => {
        try {
          if (_channel !== channel) return;
          if (typeof msg !== 'string' || msg.length === 0 || msg.length > 65536) return;
          const parsed = JSON.parse(msg);
          if (!parsed || typeof parsed !== 'object' || !parsed.event) return;
          if (parsed.event?.hmac && !(await this.verifyAuditIntegrity(parsed.event))) {
            return;
          }
          try { await TokenDatabase.storeDistributedEvent?.(parsed); } catch { }
        } catch { }
      };
      sub.on('message', handler);
      if (!this._securitySubscribers) this._securitySubscribers = new Set();
      this._securitySubscribers.add({ sub, handler, channel });
    } catch (error) {
      console.error('[TOKEN-SEC] Failed to initialize distributed monitoring:', error);
    }
  }

  static async generateTokenChain(userId, parentTokenId = null) {
    const chainId = crypto.randomBytes(16).toString('hex');
    const version = parentTokenId ? (await this.getTokenVersion(parentTokenId)) + 1 : 1;
    return {
      chainId,
      parentTokenId,
      version,
      createdAt: Date.now(),
      binding: await this.generateChainBinding(chainId, parentTokenId, version)
    };
  }

  static async validateTokenChain(tokenId, chainData) {
    const expected = await this.generateChainBinding(chainData.chainId, chainData.parentTokenId, chainData.version);
    if (!crypto.timingSafeEqual(Buffer.from(chainData.binding, 'hex'), Buffer.from(expected, 'hex'))) {
      throw new Error('Invalid token chain');
    }
    if (chainData.parentTokenId) {
      const parentRevoked = await TokenDatabase.isTokenBlacklisted(chainData.parentTokenId);
      if (parentRevoked) throw new Error('Parent token revoked - chain broken');
    }
  }

  static async generateChainBinding(chainId, parentTokenId, version) {
    const h = crypto.createHash('sha256');
    h.update(String(chainId));
    h.update(String(parentTokenId || 'root'));
    h.update(String(version));
    return h.digest('hex');
  }

  static async getTokenVersion(tokenId) {
    try {
      const token = await TokenDatabase.getRefreshToken(tokenId);
      return token?.generation || 1;
    } catch (error) {
      console.error('[TOKEN-SEC] Failed to get token version:', error);
      return 1;
    }
  }

  // Get recent authentication events for analysis
  static async getRecentAuthEvents(userId, hours = 24) {
    try {
      const now = Math.floor(Date.now() / 1000);
      const cutoffTime = now - hours * 60 * 60;
      const pool = (await import('../database/database.js')).getPgPool
        ? await (await import('../database/database.js')).getPgPool()
        : null;

      if (!pool) {
        console.error('[TOKEN-SEC] Postgres pool not available for getRecentAuthEvents');
        return [];
      }

      const { rows } = await pool.query(
        `
        SELECT action, deviceId, tokenId, tokenType, timestamp as event_time,
               ipAddressHash as ip_address, userAgent as user_agent, success,
               failureReason, riskScore, securityFlags
        FROM auth_audit_log
        WHERE userId = $1 AND timestamp >= $2
        ORDER BY timestamp DESC
        `,
        [TokenDatabase.maybeEncryptField(userId, 'userId'), cutoffTime],
      );

      return (rows || []).map((row) => ({
        action: row.action,
        deviceId: row.deviceId ?? row.deviceid,
        tokenId: row.tokenId ?? row.tokenid,
        tokenType: row.tokenType ?? row.tokentype,
        event_time: row.event_time ?? row.timestamp,
        ip_address: row.ip_address ?? row.ipaddresshash,
        user_agent: row.user_agent ?? row.useragent,
        success: Boolean(row.success),
        failure_reason: row.failureReason ?? row.failurereason,
        risk_score: (row.riskScore ?? row.riskscore) || 'low',
        security_flags: (() => {
          try {
            const raw = row.securityFlags ?? row.securityflags;
            return raw ? JSON.parse(raw) : {};
          } catch (_parseError) {
            console.warn('[TOKEN-SEC] Failed to parse security flags:', row.securityFlags ?? row.securityflags);
            return {};
          }
        })(),
      }));
    } catch (error) {
      console.error('[TOKEN-SEC] Error getting recent auth events:', error);
      return [];
    }
  }

  // Schedule cleanup of expired security data
  static async scheduleSecurityCleanup() {
    try {
      const cleanup = await TokenDatabase.cleanupExpiredTokens();

      if (cleanup && (cleanup.tokens > 0 || cleanup.blacklist > 0 || cleanup.audit > 0)) {
        console.log(`[TOKEN-SEC] Security cleanup completed:`, cleanup);

        await TokenDatabase.logAuthEvent({
          action: 'security_cleanup',
          success: true,
          securityFlags: JSON.stringify({
            ...cleanup,
            timestamp: Date.now()
          })
        });
      }

      return cleanup;
    } catch (error) {
      console.error('[TOKEN-SEC] Error in security cleanup:', error);
      return null;
    }
  }

  // Generate security report for monitoring
  static async generateSecurityReport(timeframeHours = 24, userId = null) {
    try {
      const report = {
        timeframe: `${timeframeHours} hours`,
        timestamp: Date.now(),
        userId: userId || 'system',
        summary: {
          totalEvents: 0,
          successfulLogins: 0,
          failedAttempts: 0,
          tokensIssued: 0,
          tokensRevoked: 0,
          suspiciousActivity: 0,
          criticalIncidents: 0
        },
        recommendations: []
      };

      if (userId) {
        const events = await this.getRecentAuthEvents(userId, timeframeHours);
        report.summary = {
          totalEvents: events.length,
          successfulLogins: events.filter(e => e.action === 'login' && e.success).length,
          failedAttempts: events.filter(e => e.action === 'login' && !e.success).length,
          tokensIssued: events.filter(e => e.action === 'token_refreshed' || e.action === 'token_issued').length,
          tokensRevoked: events.filter(e => e.action === 'token_revoked').length,
          suspiciousActivity: events.filter(e => e.action === 'suspicious_activity_detected').length,
          criticalIncidents: events.filter(e => e.action === 'critical_token_abuse' || e.action === 'critical_risk_action').length
        };
        report.recommendations = [];
      }

      console.log(`[TOKEN-SEC] Generated security report for ${timeframeHours}h timeframe${userId ? ` (user: ${userId})` : ' (system-wide)'}`);
      return report;
    } catch (error) {
      console.error('[TOKEN-SEC] Error generating security report:', error);
      return null;
    }
  }

  // Static properties to track intervals
  static _securityCleanupInterval = null;
  static _securityReportInterval = null;

  // Initialize security monitoring
  static async initializeSecurityMonitoring() {
    console.log('[TOKEN-SEC] Initializing token security monitoring...');

    this.stopSecurityMonitoring();

    this._securityCleanupInterval = setInterval(async () => {
      try {
        await this.scheduleSecurityCleanup();
      } catch (error) {
        console.error('[TOKEN-SEC] Error in periodic cleanup:', error);
      }
    }, 4 * 60 * 60 * 1000);

    this._securityReportInterval = setInterval(async () => {
      try {
        await this.generateSecurityReport();
      } catch (error) {
        console.error('[TOKEN-SEC] Error in periodic report generation:', error);
      }
    }, 24 * 60 * 60 * 1000);

    this._setupProcessCleanupHandlers();

    await this.initializeDistributedMonitoring();

    console.log('[TOKEN-SEC] Security monitoring initialized');
  }

  // Stop security monitoring and clear intervals
  static stopSecurityMonitoring() {
    if (this._securityCleanupInterval) {
      clearInterval(this._securityCleanupInterval);
      this._securityCleanupInterval = null;
    }

    if (this._securityReportInterval) {
      clearInterval(this._securityReportInterval);
      this._securityReportInterval = null;
    }

    if (this._securitySubscribers && this._securitySubscribers.size) {
      (async () => {
        for (const entry of this._securitySubscribers) {
          try {
            if (entry?.sub) {
              try { await entry.sub.unsubscribe(entry.channel); } catch { }
              entry.sub.off('message', entry.handler);
              await (await import('../presence/presence.js')).closeSubscriber(entry.sub);
            }
          } catch { }
        }
      })();
      this._securitySubscribers.clear();
    }

    console.log('[TOKEN-SEC] Security monitoring stopped');
  }

  static _cleanupHandlersSetup = false;

  // Set up process cleanup handlers
  static _setupProcessCleanupHandlers() {
    if (this._cleanupHandlersSetup) {
      return;
    }

    const cleanup = () => {
      console.log('[TOKEN-SEC] Process shutting down, cleaning up security monitoring timers...');
      this.stopSecurityMonitoring();
    };

    process.once('SIGINT', cleanup);
    process.once('SIGTERM', cleanup);

    this._cleanupHandlersSetup = true;
    console.log('[TOKEN-SEC] Process cleanup handlers registered');
  }
}

export { TokenSecurityManager };
export default TokenSecurityManager;
