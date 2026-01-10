import { encryptLongTerm, decryptLongTerm, LongTermEnvelope } from '../cryptography/long-term-encryption';
import websocketClient from '../websocket/websocket';
import { STORAGE_KEYS } from '../database/storage-keys';
import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';
import { AVATAR_SERVER_FETCH_DEBOUNCE_MS } from '../constants';
import { generateDefaultAvatar, validateImageData, hashAvatarData } from '../utils/avatar-utils';
import { cachePeerAvatar } from './cache';
import type { AvatarSystemState } from '../types/avatar-types';

// Upload avatar to server
export async function uploadToServer(state: AvatarSystemState): Promise<{ success: boolean; error?: string }> {
    if (!state.ownAvatar || !state.ownKyberPublicKey) {
        return { success: false, error: 'No avatar or keys available' };
    }

    try {
        const envelope = await encryptLongTerm(
            JSON.stringify({
                data: state.ownAvatar.data,
                mimeType: state.ownAvatar.mimeType,
                hash: state.ownAvatar.hash
            }),
            state.ownKyberPublicKey
        );

        if (!websocketClient?.isConnectedToServer() || !websocketClient?.isPQSessionEstablished()) {
            return { success: false, error: 'Not connected to server' };
        }

        const uploadMessage: any = {
            type: SignalType.AVATAR_UPLOAD,
            envelope,
            shareWithOthers: state.settings.shareWithOthers
        };

        if (state.settings.shareWithOthers) {
            uploadMessage.publicData = {
                data: state.ownAvatar.data,
                mimeType: state.ownAvatar.mimeType,
                hash: state.ownAvatar.hash
            };
        }

        await websocketClient.sendSecureControlMessage(uploadMessage);

        return { success: true };
    } catch (error) {
        return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
}

// Fetch own avatar from server
export async function fetchOwnFromServer(state: AvatarSystemState): Promise<{ success: boolean; error?: string }> {
    const timeSinceLastFetch = Date.now() - state.ownAvatarFetchTimestamp;
    if (timeSinceLastFetch < AVATAR_SERVER_FETCH_DEBOUNCE_MS) {
        return { success: false, error: 'Debounced' };
    }
    state.ownAvatarFetchTimestamp = Date.now();

    if (!state.ownKyberSecretKey) {
        return { success: false, error: 'No keys available' };
    }

    try {
        if (!websocketClient?.isConnectedToServer() || !websocketClient?.isPQSessionEstablished()) {
            return { success: false, error: 'Not connected to server' };
        }

        await websocketClient.sendSecureControlMessage({
            type: SignalType.AVATAR_FETCH,
            target: 'own'
        });

        return { success: true };
    } catch (error) {
        return { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
}

// Fetch peer avatar from server
export async function fetchPeerFromServer(state: AvatarSystemState, username: string): Promise<void> {
    const lastFetch = state.serverFetchTimestamps.get(username) || 0;
    const timeSinceLastFetch = Date.now() - lastFetch;

    if (timeSinceLastFetch < AVATAR_SERVER_FETCH_DEBOUNCE_MS) {
        return;
    }
    state.serverFetchTimestamps.set(username, Date.now());

    try {
        const isConnected = websocketClient?.isConnectedToServer();
        const isPQReady = websocketClient?.isPQSessionEstablished();

        if (!isConnected || !isPQReady) {
            return;
        }

        await websocketClient.sendSecureControlMessage({
            type: SignalType.AVATAR_FETCH,
            target: username
        });
    } catch (err) {
    }
}

// Handle server avatar response
export async function handleServerAvatarResponse(
    state: AvatarSystemState,
    response: {
        target: string;
        envelope?: LongTermEnvelope | any;
        found: boolean;
        isDefault?: boolean;
        publicData?: any;
    },
    removeOwnAvatarFn: () => Promise<void>
): Promise<void> {
    const isOwn = response.target === 'own';
    const isDefault = !!response.isDefault;

    try {
        let avatarData: { data: string; mimeType: string; hash: string } | null = null;

        if (!response.found) {
            if (isOwn) {
                await removeOwnAvatarFn();
            }
        } else if (isOwn && !isDefault && state.ownKyberSecretKey) {
            if (response.envelope.version !== 'lt-v1') {
                await removeOwnAvatarFn();
                return;
            }

            const result = await decryptLongTerm(response.envelope, state.ownKyberSecretKey);
            if (result.json && typeof result.json === 'object') {
                avatarData = result.json as any;
            }
        } else {
            avatarData = response.envelope as any;
        }

        if (avatarData && typeof avatarData.data === 'string') {
            const validation = validateImageData(avatarData.data);
            if (!validation.valid) {
                return;
            }

            if (isOwn) {
                state.ownAvatar = {
                    data: avatarData.data,
                    mimeType: avatarData.mimeType || 'image/webp',
                    hash: avatarData.hash || '',
                    updatedAt: Date.now()
                };
                if (state.secureDB) {
                    await state.secureDB.store(STORAGE_KEYS.PROFILE_AVATARS, 'own', state.ownAvatar);
                }
                window.dispatchEvent(new CustomEvent(EventType.PROFILE_PICTURE_UPDATED, {
                    detail: { type: 'own', fromServer: true }
                }));
            } else {
                // Cache peer avatar
                await cachePeerAvatar(
                    state,
                    response.target,
                    avatarData.data,
                    avatarData.mimeType || 'image/webp',
                    avatarData.hash
                );
            }
        } else if (!response.found) {
            if (isOwn) {
                if (state.secureDB) {
                    await state.secureDB.delete(STORAGE_KEYS.PROFILE_AVATARS, 'own');
                }
                state.ownAvatar = null;
                window.dispatchEvent(new CustomEvent(EventType.PROFILE_PICTURE_UPDATED, { detail: { type: 'own', fromServer: true } }));
            } else {
                try {
                    const defaultAvatar = generateDefaultAvatar(response.target);
                    const fallbackHash = await hashAvatarData(defaultAvatar);

                    await cachePeerAvatar(
                        state,
                        response.target,
                        defaultAvatar,
                        'image/svg+xml',
                        fallbackHash
                    );

                    window.dispatchEvent(new CustomEvent(EventType.PROFILE_PICTURE_UPDATED, {
                        detail: { type: 'peer', username: response.target, fromServer: false, isDefault: true }
                    }));

                } catch {
                    window.dispatchEvent(new CustomEvent(EventType.PROFILE_PICTURE_UPDATED, {
                        detail: { type: 'peer', username: response.target, notFound: true }
                    }));
                }
            }
        }

    } catch {
    }
}

export type { LongTermEnvelope };
