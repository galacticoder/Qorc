/** All storage keys for local and encrypted storage. */

export const STORAGE_KEYS = {
    CLUSTER_KEY_STORAGE: 'qorchat_cluster_keys_v2',
    SCREEN_SHARING_SETTINGS: 'screen_sharing_settings_v1',
    SCREEN_SHARING_DEVICE_KEY: 'screen_sharing_settings_device_key_v1',
    SECURE_MESSAGE_QUEUE: 'secure_message_queue_v1',
    OFFLINE_MESSAGE_QUEUE: 'offlineMessageQueue',
    OFFLINE_QUEUE_DEVICE_ID: 'offlineQueueDeviceId',
    CALL_HISTORY: 'call_history_v1',
    BLOCKING_QUEUE: 'secure_block_queue',
    PROFILE_AVATARS: 'profile_avatars',
    PROFILE_SETTINGS: 'profile_settings',
    SECURE_CRITICAL_ERRORS: 'secure_critical_errors_v1',
    USAGE_STATS: 'usage_stats',
    TOR_ENABLED: 'tor_enabled',
} as const;
