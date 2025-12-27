// Shared UI constants and limits
export const USERNAME_MIN_LENGTH = 3;
export const USERNAME_MAX_LENGTH = 32;
export const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,32}$/;

export const DEFAULT_MAX_TYPING_USERS = 200;
export const DEFAULT_TYPING_TIMEOUT_MS = 5500;
export const DEFAULT_RATE_LIMIT_PER_MINUTE = 240;
export const DEFAULT_TYPING_EVENT_RATE_WINDOW_MS = 60_000;

export const DEFAULT_EVENT_RATE_WINDOW_MS = 10_000;
export const DEFAULT_EVENT_RATE_MAX = 200;
export const DEFAULT_UI_EVENT_RATE_MAX = 500;

export const VALID_EMOJI_PICKER_ID = /^[A-Za-z0-9_-]+$/;

export const MAX_EVENT_TYPE_LENGTH = 32;
export const MAX_EVENT_USERNAME_LENGTH = 256;

export const PASSWORD_MAX_LENGTH = 1000;

export const QUALITY_OPTIONS = ['low', 'medium', 'high'] as const;
export const DEFAULT_QUALITY: QualityOption = 'medium';
export type QualityOption = (typeof QUALITY_OPTIONS)[number];
export const QUALITY_LABELS: Record<QualityOption, string> = {
    low: 'Low',
    medium: 'Medium',
    high: 'High'
};

export const QUALITY_DESCRIPTIONS: Record<QualityOption, string> = {
    low: 'Lower bandwidth usage',
    medium: 'Balanced quality and bandwidth',
    high: 'Best quality, higher bandwidth'
};
