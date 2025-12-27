import React from 'react';
import { AnimatedSwitch } from '../../ui/AnimatedSwitch';

interface NotificationSettingsProps {
    notifications: { desktop: boolean; sound: boolean };
    setNotifications: (notifications: { desktop: boolean; sound: boolean }) => void;
    saveSettings: (updates: any) => void;
}

export const NotificationSettings = ({ notifications, setNotifications, saveSettings }: NotificationSettingsProps) => {
    return (
        <div>
            <h2 className="settings-section-title">Notifications</h2>

            <div className="settings-group">
                <div className="settings-row">
                    <div>
                        <div className="settings-label">Desktop Notifications</div>
                        <div className="settings-description">
                            Show a notification popup when you receive a new message
                        </div>
                    </div>
                    <AnimatedSwitch
                        checked={notifications.desktop}
                        onCheckedChange={(checked) => {
                            const updated = { ...notifications, desktop: checked };
                            setNotifications(updated);
                            saveSettings({ notifications: updated });
                            (window as any).edgeApi?.setNotificationsEnabled?.(checked).catch(() => { });
                        }}
                    />
                </div>

                <div className="settings-row">
                    <div>
                        <div className="settings-label">Sound Notifications</div>
                        <div className="settings-description">
                            Play a sound when you receive a new message
                        </div>
                    </div>
                    <AnimatedSwitch
                        checked={notifications.sound}
                        onCheckedChange={(checked) => {
                            const updated = { ...notifications, sound: checked };
                            setNotifications(updated);
                            saveSettings({ notifications: updated });
                        }}
                    />
                </div>
            </div>
        </div>
    );
};

export default NotificationSettings;
