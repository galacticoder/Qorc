import React, { useState, useEffect, useRef } from 'react';
import { Camera, Shield, X } from 'lucide-react';
import { toast } from 'sonner';
import { profilePictureSystem } from '../../../lib/avatar/profile-picture-system';
import { isPlainObject, hasPrototypePollutionKeys } from '../../../lib/sanitizers';
import { sanitizeEventText } from '../../../lib/sanitizers';
import { AnimatedSwitch } from '../../ui/AnimatedSwitch';
import { SignalType } from '../../../lib/types/signal-types';
import { EventType } from '../../../lib/types/event-types';
import {
    DEFAULT_EVENT_RATE_WINDOW_MS,
    DEFAULT_EVENT_RATE_MAX,
    MAX_EVENT_TYPE_LENGTH,
    MAX_PROFILE_IMAGE_SIZE
} from '../../../lib/constants';

interface AccountSettingsProps {
    currentUsername: string;
    currentDisplayName: string;
    avatarUrl: string | null;
    setAvatarUrl: (url: string | null) => void;
    shareWithOthers: boolean;
    setShareWithOthers: (share: boolean) => void;
}

export const AccountSettings = ({
    currentUsername,
    currentDisplayName,
    avatarUrl,
    setAvatarUrl,
    shareWithOthers,
    setShareWithOthers
}: AccountSettingsProps) => {
    const [isUploadingAvatar, setIsUploadingAvatar] = useState(false);
    const avatarInputRef = useRef<HTMLInputElement>(null);
    const profilePictureEventRateRef = useRef<{ windowStart: number; count: number }>({ windowStart: Date.now(), count: 0 });

    useEffect(() => {
        const handleAvatarUpdate = (event: Event) => {
            try {
                const now = Date.now();
                const bucket = profilePictureEventRateRef.current;
                if (now - bucket.windowStart > DEFAULT_EVENT_RATE_WINDOW_MS) {
                    bucket.windowStart = now;
                    bucket.count = 0;
                }
                bucket.count += 1;
                if (bucket.count > DEFAULT_EVENT_RATE_MAX) {
                    return;
                }

                if (!(event instanceof CustomEvent)) return;
                const detail = event.detail;
                if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

                const type = sanitizeEventText((detail as any).type, MAX_EVENT_TYPE_LENGTH);
                if (type !== 'own') return;

                setAvatarUrl(profilePictureSystem.getOwnAvatar());
            } catch { }
        };

        window.addEventListener(EventType.PROFILE_PICTURE_UPDATED, handleAvatarUpdate as EventListener);
        return () => window.removeEventListener(EventType.PROFILE_PICTURE_UPDATED, handleAvatarUpdate as EventListener);
    }, [setAvatarUrl]);

    const handleAvatarChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (!file || isUploadingAvatar) return;

        e.target.value = '';

        if (file.size > MAX_PROFILE_IMAGE_SIZE) {
            toast.error(`Image too large (max ${MAX_PROFILE_IMAGE_SIZE / 1024 / 1024}MB)`);
            return;
        }

        setIsUploadingAvatar(true);

        const reader = new FileReader();
        reader.onloadend = async () => {
            try {
                const result = reader.result as string;
                const uploadResult = await profilePictureSystem.setOwnAvatar(result);

                if (uploadResult.success) {
                    setAvatarUrl(profilePictureSystem.getOwnAvatar());
                    toast.success('Profile picture updated');
                } else {
                    toast.error(uploadResult.error || 'Failed to upload avatar');
                }
            } catch {
                toast.error('Failed to process image');
            } finally {
                setIsUploadingAvatar(false);
            }
        };
        reader.onerror = () => {
            toast.error('Failed to read image file');
            setIsUploadingAvatar(false);
        };
        reader.readAsDataURL(file);
    };

    const handleRemoveAvatar = async () => {
        await profilePictureSystem.removeOwnAvatar(currentUsername);
        setAvatarUrl(profilePictureSystem.getOwnAvatar());
        toast.success('Profile picture removed');
    };

    const handleShareToggle = async (share: boolean) => {
        await profilePictureSystem.setShareWithOthers(share);
        setShareWithOthers(share);
    };

    const displayUsername = currentDisplayName || currentUsername || 'User';
    const truncatedHash = currentUsername?.length > 20 ? `${currentUsername.slice(0, 8)}...${currentUsername.slice(-8)}` : currentUsername;

    return (
        <div>
            <h2 className="settings-section-title">My Account</h2>

            <div className="account-card">
                <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
                    <div
                        className="avatar-container"
                        onClick={() => avatarInputRef.current?.click()}
                    >
                        {avatarUrl ? (
                            <img src={avatarUrl} alt="Avatar" className="avatar-image" />
                        ) : (
                            <div className="avatar-placeholder animate-pulse" style={{ backgroundColor: 'var(--color-secondary)' }} />
                        )}
                        <div className="avatar-overlay">
                            <Camera size={20} color="white" />
                            <span style={{ fontSize: '10px', color: 'white', marginTop: '4px' }}>CHANGE</span>
                        </div>
                    </div>
                    <input
                        ref={avatarInputRef}
                        type={SignalType.FILE}
                        accept="image/*"
                        onChange={handleAvatarChange}
                        style={{ display: 'none' }}
                    />
                    <div>
                        <div style={{ fontSize: '20px', fontWeight: 600, color: 'hsl(var(--foreground))' }}>
                            {displayUsername}
                        </div>
                        {currentUsername && currentUsername !== displayUsername && (
                            <div style={{ fontSize: '13px', color: 'hsl(var(--muted-foreground))', marginTop: '4px' }}>
                                {truncatedHash}
                            </div>
                        )}
                    </div>
                </div>

                {avatarUrl && !profilePictureSystem.isOwnAvatarDefault() && (
                    <button
                        onClick={handleRemoveAvatar}
                        style={{
                            marginTop: '16px',
                            padding: '8px 16px',
                            fontSize: '13px',
                            color: 'hsl(var(--muted-foreground))',
                            background: 'transparent',
                            border: '1px solid hsl(var(--border))',
                            borderRadius: '4px',
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '6px'
                        }}
                    >
                        <X size={14} />
                        Remove Avatar
                    </button>
                )}
            </div>

            <div className="settings-group">
                <div className="settings-group-title">Profile Picture</div>
                <div className="settings-row">
                    <div>
                        <div className="settings-label">Share with Others</div>
                        <div className="settings-description">
                            Allow other users to see your profile picture. When disabled, they'll see a default avatar.
                        </div>
                    </div>
                    <AnimatedSwitch
                        checked={shareWithOthers}
                        onCheckedChange={handleShareToggle}
                    />
                </div>
            </div>

            <div className="settings-group">
                <div className="settings-group-title">Security</div>
                <div style={{ background: 'hsl(var(--secondary) / 0.3)', borderRadius: '8px', padding: '16px' }}>
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                        <Shield size={24} style={{ color: '#5865F2', flexShrink: 0, marginTop: '2px' }} />
                        <div>
                            <div className="settings-label">End-to-End Encrypted</div>
                            <div className="settings-description">
                                Your messages are guaranteed protected with hybrid post-quantum cryptography.
                                Only you and your recipients can ever read them.
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default AccountSettings;
