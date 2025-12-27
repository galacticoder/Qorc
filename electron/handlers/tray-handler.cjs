/**
 * Tray Handler
 * Manages system tray for background running
 */

const { Tray, Menu, nativeImage, app } = require('electron');

class TrayHandler {
  constructor() {
    this.tray = null;
    this.isQuitting = false;
    this.unreadCount = 0;
    this.onShowWindow = null;
    this.onQuit = null;
  }

  // Will use my real app icon when i create one
  initialize({ iconPath, onShowWindow, onQuit }) {
    if (this.tray) return { success: true };

    try {
      this.onShowWindow = onShowWindow;
      this.onQuit = onQuit;

      let icon;
      try {
        icon = nativeImage.createFromPath(iconPath);
        icon = icon.resize({ width: 16, height: 16 });
      } catch (e) {
        icon = nativeImage.createEmpty();
      }

      this.tray = new Tray(icon);
      this.tray.setToolTip('Qor Chat');

      this.updateContextMenu();

      this.tray.on('double-click', () => {
        if (typeof this.onShowWindow === 'function') {
          this.onShowWindow();
        }
      });

      return { success: true };
    } catch (e) {
      console.error('[Tray] Failed to initialize:', e.message);
      return { success: false, error: e.message };
    }
  }

  // Update context menu with unread count
  updateContextMenu() {
    if (!this.tray) return;

    const unreadLabel = this.unreadCount > 0 
      ? `${this.unreadCount} unread message${this.unreadCount > 1 ? 's' : ''}`
      : 'No new messages';

    const contextMenu = Menu.buildFromTemplate([
      {
        label: unreadLabel,
        enabled: false
      },
      { type: 'separator' },
      {
        label: 'Open Qor Chat',
        click: () => {
          if (typeof this.onShowWindow === 'function') {
            this.onShowWindow();
          }
        }
      },
      { type: 'separator' },
      {
        label: 'Quit',
        click: () => {
          this.isQuitting = true;
          if (typeof this.onQuit === 'function') {
            this.onQuit();
          } else {
            app.quit();
          }
        }
      }
    ]);

    this.tray.setContextMenu(contextMenu);
  }

  // Set unread count and update UI
  setUnreadCount(count) {
    if (typeof count !== 'number' || count < 0) return;
    this.unreadCount = Math.min(count, 9999);
    this.updateContextMenu();

    if (this.tray) {
      const tooltip = this.unreadCount > 0 
        ? `Qor Chat (${this.unreadCount} unread)`
        : 'Qor Chat';
      this.tray.setToolTip(tooltip);
    }
  }

  // Increment unread count
  incrementUnread() {
    this.setUnreadCount(this.unreadCount + 1);
  }

  // Clear unread count
  clearUnread() {
    this.setUnreadCount(0);
  }

  // Get quitting state
  getIsQuitting() {
    return this.isQuitting;
  }

  // Set quitting state
  setIsQuitting(value) {
    this.isQuitting = Boolean(value);
  }

  // Destroy tray
  destroy() {
    if (this.tray) {
      try {
        this.tray.destroy();
      } catch (e) {
        console.warn('[Tray] Error destroying tray:', e.message);
      }
      this.tray = null;
    }
  }
}

module.exports = { TrayHandler };
