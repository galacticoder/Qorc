/**
 * Notification handler
 */

const { Notification, app } = require('electron');

// Notification limits
const MAX_TITLE_LENGTH = 64;
const MAX_BODY_LENGTH = 256;
const RATE_LIMIT_WINDOW_MS = 1000;
const MAX_NOTIFICATIONS_PER_WINDOW = 5;

class NotificationHandler {
  constructor() {
    this.notificationTimes = [];
    this.enabled = true;
    this.onNotificationClick = null;
  }

  initialize({ onNotificationClick } = {}) {
    this.onNotificationClick = onNotificationClick;
    return { success: true };
  }

// Sanitize text input
  sanitizeText(text, maxLength) {
    if (typeof text !== 'string') return '';
    let sanitized = text.replace(/[\x00-\x1F\x7F]/g, '');
    sanitized = sanitized.trim().slice(0, maxLength);
    sanitized = sanitized.replace(/<[^>]*>/g, '');

    return sanitized;
  }

// Check if rate limited
  isRateLimited() {
    const now = Date.now();
    this.notificationTimes = this.notificationTimes.filter(
      t => now - t < RATE_LIMIT_WINDOW_MS
    );
    
    return this.notificationTimes.length >= MAX_NOTIFICATIONS_PER_WINDOW;
  }

// Record notification for rate limiting
  recordNotification() {
    this.notificationTimes.push(Date.now());
  
    if (this.notificationTimes.length > MAX_NOTIFICATIONS_PER_WINDOW * 2) {
      this.notificationTimes = this.notificationTimes.slice(-MAX_NOTIFICATIONS_PER_WINDOW);
    }
  }

// Show notification
  show({ title, body, silent = false, urgency = 'normal', data = null }) {
    if (!this.enabled) {
      return { success: false, reason: 'disabled' };
    }

    if (!Notification.isSupported()) {
      return { success: false, reason: 'not_supported' };
    }

    if (this.isRateLimited()) {
      return { success: false, reason: 'rate_limited' };
    }

    try {
      const sanitizedTitle = this.sanitizeText(title, MAX_TITLE_LENGTH) || 'New Message';
      const sanitizedBody = this.sanitizeText(body, MAX_BODY_LENGTH);

      const notification = new Notification({
        title: sanitizedTitle,
        body: sanitizedBody,
        silent: Boolean(silent),
        urgency: ['low', 'normal', 'critical'].includes(urgency) ? urgency : 'normal',
        icon: undefined
      });

      notification.on('click', () => {
        if (typeof this.onNotificationClick === 'function') {
          const safeData = data ? {
            type: typeof data.type === 'string' ? data.type.slice(0, 32) : undefined,
            conversationId: typeof data.conversationId === 'string' ? data.conversationId.slice(0, 64) : undefined
          } : null;
          this.onNotificationClick(safeData);
        }
      });

      notification.show();
      this.recordNotification();

      return { success: true };
    } catch (e) {
      console.error('[Notification] Failed to show:', e.message);
      return { success: false, reason: 'error', error: e.message };
    }
  }

// Show message notification
  showMessageNotification({ sender, preview, conversationId }) {
    const sanitizedSender = this.sanitizeText(sender, 32) || 'Someone';
    const sanitizedPreview = this.sanitizeText(preview, 100) || 'New message';

    return this.show({
      title: `Message from ${sanitizedSender}`,
      body: sanitizedPreview,
      data: { type: 'message', conversationId }
    });
  }

  setEnabled(enabled) {
    this.enabled = Boolean(enabled);
  }

  isEnabled() {
    return this.enabled;
  }

// Set badge count
  setBadgeCount(count) {
    if (typeof count !== 'number' || count < 0) return;
    
    try {
      if (app.setBadgeCount) {
        app.setBadgeCount(Math.min(count, 9999));
      }
    } catch (e) {}
  }

// Clear badge
  clearBadge() {
    this.setBadgeCount(0);
  }
}

module.exports = { NotificationHandler };
