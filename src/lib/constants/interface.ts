import { SignalType } from '../types/signal-types';
import { BLOCK_RATE_LIMIT_WINDOW_MS, BLOCK_RATE_LIMIT_MAX_EVENTS } from './events';

export const SCROLL_THRESHOLD = 200;
export const NEAR_BOTTOM_THRESHOLD = 100;
export const SEGMENT_UNLOAD_IDLE_MS = 3 * 60 * 1000;
export const INITIAL_LOAD_DELAY_MS = 500;
export const MAX_UI_MESSAGES_TOTAL = 2_048;
export const MAX_LINK_PREVIEW_MESSAGE_TARGETS = 2048;

export const MAX_CLIPBOARD_SIZE = 100 * 1024;
export const MAX_INPUT_SIZE = 1024 * 1024;
export const SAVED_SERVER_LIMIT = 32;
export const MAX_APP_SETTINGS_CHARS = 32 * 1024;
export const NAVIGATION_SWITCH_MS = 180;
export const SERVER_SETUP_URL = 'https://www.qorc.app/docs.html#SERVER_SETUP.md';

export const MAX_TRACKED_EMOJIS = 256;
export const MAX_EMOJI_USAGE_COUNT = 1_000_000;
export const DEFAULT_FREQUENT_EMOJI_LIMIT = 32;
export const DEFAULT_EMOJI_SEARCH_LIMIT = 240;
export const EMOJI_PICKER_GRID_COLUMNS = 6;
export const EMOJI_PICKER_PAGE_SIZE = 160;

export const TERMS_URL = 'https://www.qorc.app/terms';
export const PRIVACY_URL = 'https://www.qorc.app/privacy';
export const DEFAULT_ALLOWED_TYPES: Set<string> = new Set([
  SignalType.PQ_HANDSHAKE_ACK,
  SignalType.PQ_HANDSHAKE_CONFIRMED,
  SignalType.PQ_HEARTBEAT_PONG,
  SignalType.AUTH_ERROR,
  SignalType.TOKEN_VALIDATION_RESPONSE,
  SignalType.ERROR,
  SignalType.SERVER_PUBLIC_KEY,
  SignalType.AUTH_FULL_SUCCESS,
  SignalType.SERVER_ENTRY_CREDENTIAL_ROTATED,
  SignalType.SEALED_ENVELOPE,
]);
export const DEFAULT_ENCRYPTED_TYPES = new Set<string>([
  SignalType.SERVER_ENTRY_CREDENTIAL_ROTATED,
  SignalType.SEALED_ENVELOPE,
]);
export const DEFAULT_RATE_LIMIT = {
  windowMs: BLOCK_RATE_LIMIT_WINDOW_MS,
  maxEvents: BLOCK_RATE_LIMIT_MAX_EVENTS
} as const;
export const DEFAULT_FREQUENT_VALUES = [
  '😂', '❤️', '👍', '🤣', '😊', '🙏', '😍', '🔥',
  '🥰', '👏', '🎉', '😁', '💯', '😭', '🤔', '😎',
  '✅', '👀', '🙌', '✨', '💪', '😉', '🥳', '🤝',
] as const;
export const QUICK_CHAT_REACTIONS = ['👍', '👎', '❤️', '😂', '😮', '😢'];
export const APP_SETTINGS_KEYS = new Set([
  'navigationLayout',
  'chatBackground',
  'notifications',
  'preferredCallMicId',
  'preferredSpeakerId',
  'preferredCameraId',
]);
export const TAURI_BINDINGS_BYTES_BYTES_EXPECTED = 24;
export const TAURI_BINDINGS_PARSE_NATIVE_CAMERA_FRAME_BYTES_BYTES_EXPECTED = 32;
export const TAURI_BINDINGS_BYTES_BYTES_MINIMUM = 32;
export const TAURI_BINDINGS_BYTES_BYTES_LIMIT = 4 * 1024 * 1024 + 32;
export const TAURI_BINDINGS_WIDTH_LIMIT = 1280;
export const TAURI_BINDINGS_HEIGHT_LIMIT = 720;
export const TAURI_BINDINGS_PARSE_NATIVE_CAMERA_FRAME_HEIGHT_LIMIT = 1280 * 720;
export const TAURI_BINDINGS_JPEG_BYTES_MINIMUM = 4;
export const TAURI_BINDINGS_FETCH_TIMEOUT_MS = 30_000;
export const TAURI_BINDINGS_ON_WS_BINARY_DELAY_MS = 250;
export const TAURI_BINDINGS_ON_P2_PMESSAGE_DELAY_MS = 250;
export const DIALOG_CONTENT_TIMEOUT_MS = 200;
export const DATABASE_UTILS_FILE_ID_LENGTH_LIMIT = 255;
export const SERVER_ADDRESS_ADDRESS_LENGTH_LIMIT = 2048;
export const SERVER_ADDRESS_URL_HOSTNAME_LENGTH_LIMIT = 253;
export const NOISE_UTILS_PRIVATE_KEY_LENGTH_EXPECTED = 32;
export const NOISE_UTILS_PUBLIC_KEY_LENGTH_EXPECTED = 32;
export const AUTH_UTILS_B64_LENGTH_LIMIT = 10000;
export const AUTH_UTILS_X_LENGTH_EXPECTED = 32;
export const AUTH_UTILS_K_LENGTH_EXPECTED = 1568;
export const AUTH_UTILS_D_LENGTH_EXPECTED = 2592;
export const AUTH_UTILS_RAW_LENGTH_LIMIT = 10_000;
export const AUTH_UTILS_PREVIOUS_RAW_LENGTH_LIMIT = 10_000;
export const SAVED_SERVERS_RAW_LENGTH_LIMIT = 1_500_000;
export const LOCAL_ACCOUNT_SCOPE_SERVER_URL_LENGTH_LIMIT = 2048;
export const AUTH_LIFECYCLE_MAX_VISITED = 16_384;
export const KEY_MANAGEMENT_TIMEOUT_MS = 15000;
export const KEY_MANAGEMENT_CREATE_WAIT_FOR_SERVER_KEYS_TIMEOUT_MS = 100;
export const ACCOUNT_CREDENTIALS_IS_VALID_ACCOUNT_CREDENTIAL_VALUE_LENGTH_LIMIT = 1024;
export const REGISTRATION_ATTEMPT_VALIDATE_ATTEMPT_ID_VALUE_LENGTH_EXPECTED = 44;
export const REGISTRATION_ATTEMPT_DECODED_LENGTH_EXPECTED = 32;
export const HANDLERS_WORKER_HASH_LENGTH_EXPECTED = 32;
export const HANDLERS_CANDIDATE_BLINDED_ELEMENT_LENGTH_EXPECTED = 32;
export const HANDLERS_ATTEMPT_MINIMUM = 3;
export const HANDLERS_CREATE_HANDLE_ACCOUNT_SUBMIT_DELAY_MS = 500;
export const AUTH_SUCCESS_CREATE_HANDLE_AUTH_SUCCESS_TIMEOUT_MS = 1000;
export const BLOCKING_UTILS_USERNAME_LENGTH_MINIMUM = 3;
export const BLOCKING_UTILS_USERNAME_LENGTH_LIMIT = 128;
export const AUTH_HANDLERS_HANDLE_TOKEN_VALIDATION_RESPONSE_DATA_ERROR_LENGTH_LIMIT = 128;
export const USE_AUTH_TIMEOUT_MS = 45000;
export const DATE_UTILS_MINUTES_MINIMUM = 60;
export const DATE_UTILS_DAYS_MINIMUM = 7;
export const SECURE_CANVAS_TEXT_MAX_WIDTH = 400;
export const SECURE_CANVAS_TEXT_FONT_SIZE = 14;
export const SECURE_CANVAS_TEXT_ATTEMPT_MINIMUM = 5;
export const SECURE_CANVAS_TEXT_ATTEMPT_EXPECTED = 4;
export const BANNER_MESSAGE_PREVIEW_MAX_WIDTH = 800;
export const BANNER_MESSAGE_PREVIEW_FONT_SIZE = 11;
export const BANNER_MESSAGE_PREVIEW_HOST_CLIENT_WIDTH_MINIMUM = 20;
export const BANNER_MESSAGE_PREVIEW_SCHEDULE_MEASURE_TIMEOUT_MS = 100;
export const UNREAD_INDICATOR_COUNT_LIMIT = 99;
export const NOTIFICATION_PREFERENCES_RAW_LENGTH_LIMIT = 128 * 1024;
export const CONVERSATION_SWIPE_ROW_ACTION_WIDTH = 112;
export const CONVERSATION_SWIPE_ROW_MATH_MAX_MINIMUM = 8;
export const CONVERSATION_LIST_MIN_AGE_MS_LIMIT = 7 * 24 * 60 * 60 * 1000;
export const CONVERSATION_LIST_GET_REFRESH_INTERVAL_MIN_AGE_MS_LIMIT = 24 * 60 * 60 * 1000;
export const EMOJI_PICKER_HANDLE_WHEEL_TIMEOUT_MS = 180;
export const MESSAGE_LINK_PREVIEW_ATTEMPT_MINIMUM = 5;
export const MESSAGE_LINK_PREVIEW_ATTEMPT_EXPECTED = 4;
export const CHAT_MESSAGE_TIMEOUT_MS = 3000;
export const CHAT_MESSAGE_HANDLE_DOWNLOAD_TIMEOUT_MS = 3000;
export const CHAT_VIEWPORT_MATH_MAX_MINIMUM = 24;
export const CHAT_INTERFACE_TIMEOUT_MS = 120;
export const CHAT_INTERFACE_HANDLE_REPLY_CLICK_TIMEOUT_MS = 1500;
export const USE_WEBSOCKET_TYPE_LENGTH_LIMIT = 128;
export const USE_EVENT_HANDLERS_MAYBE_KYBER_LENGTH_LIMIT = 10_000;
export const USE_EVENT_HANDLERS_MAYBE_DILITHIUM_LENGTH_LIMIT = 10_000;
export const USE_EVENT_HANDLERS_MAYBE_X25519_LENGTH_LIMIT = 1_000;
export const USE_EVENT_HANDLERS_PROCESSED_KEYS_AVAILABLE_REF_SIZE_LIMIT = 512;
export const USE_ENCRYPTION_PROVIDER_TIMEOUT_MS = 8000;
export const USE_ENCRYPTION_PROVIDER_LAST_ATTEMPT_MINIMUM = 15000;
export const PIR_FETCH_INDEX_LENGTH_LIMIT = (1 << 20);
export const USE_PREFETCHED_COMPONENT_RUN_TIMEOUT_MS = 200;
export const SECTION_PAGER_FINISH_COMPLETE_TIMEOUT_MS = 280;
export const SECTION_PAGER_MATH_MAX_MINIMUM = 10;
export const APP_SETTINGS_MICROPHONES_LENGTH_LIMIT = 64;
export const APP_SETTINGS_SPEAKERS_LENGTH_LIMIT = 64;
export const APP_SETTINGS_CAMERAS_LENGTH_LIMIT = 32;
export const APP_SETTINGS_HANDLE_COPY_USERNAME_TIMEOUT_MS = 900;
export const INDEX_WIDTH_LIMIT = 260;
export const INDEX_WIDTH_MINIMUM = 520;

export const CATEGORY_SEARCH_ALIASES: Readonly<Record<string, string>> = {
  'smileys-and-emotion': 'face smile happy sad laugh love heart feeling reaction',
  'people-and-body': 'person people body hand gesture human skin tone',
  'animals-and-nature': 'animal nature plant flower weather pet',
  'food-and-drink': 'food drink meal fruit vegetable restaurant',
  'travel-and-places': 'travel place transport vehicle building map weather',
  activities: 'activity sport game event celebration art',
  objects: 'object tool technology office household clothing',
  symbols: 'symbol sign arrow shape mark button',
  flags: 'flag country nation region',
};
export const EMOJI_SEARCH_ALIASES: Readonly<Record<string, string>> = {
  '😀': 'happy grin smile',
  '😁': 'happy grin smile',
  '😅': 'nervous relief sweat',
  '🤣': 'lol lmao rofl laugh laughing funny',
  '😂': 'lol lmao laugh laughing funny cry crying',
  '🙂': 'happy smile',
  '🙃': 'sarcasm sarcastic silly',
  '😉': 'wink flirty',
  '😊': 'happy blush smile',
  '🥰': 'love affection hearts',
  '😍': 'love crush heart eyes',
  '😘': 'kiss love',
  '🤔': 'think thinking hmm',
  '🫡': 'salute respect',
  '😐': 'blank neutral meh',
  '🙄': 'eyeroll eye roll annoyed',
  '😬': 'awkward grimace nervous',
  '😴': 'sleep sleeping tired',
  '🥳': 'party celebrate celebration birthday',
  '😎': 'cool sunglasses',
  '🥺': 'please pleading puppy eyes',
  '😢': 'sad cry crying tear',
  '😭': 'sad cry crying sob',
  '😱': 'shock shocked scream scared',
  '😡': 'angry mad rage',
  '🤬': 'angry mad swear cursing',
  '💀': 'dead dying funny skull',
  '👻': 'ghost halloween spooky',
  '❤️': 'love heart red',
  '💔': 'heartbreak broken heart sad',
  '🔥': 'fire hot lit',
  '✨': 'sparkle sparkles magic',
  '🎉': 'party celebrate celebration confetti',
  '👍': 'yes like approve approved okay ok good thumbs up',
  '👎': 'no dislike disapprove bad thumbs down',
  '👏': 'clap applause congratulations',
  '🙌': 'hooray praise celebrate hands',
  '🙏': 'please pray prayer thanks thank you',
  '🤝': 'deal agreement handshake',
  '💪': 'strong strength muscle',
  '👀': 'eyes look watching',
  '✅': 'yes done check correct complete',
  '❌': 'no wrong cancel cross',
  '⚠️': 'warning caution alert',
  '💯': 'hundred perfect agree',
  '🚀': 'rocket launch fast ship',
  '🇺🇸': 'usa america united states us flag',
  '🇬🇧': 'uk britain british united kingdom flag',
};
export const READ_RECEIPTABLE_MESSAGE_TYPES: ReadonlySet<string> = new Set([
  SignalType.MESSAGE,
  SignalType.TEXT,
  SignalType.FILE,
  SignalType.FILE_MESSAGE,
]);
export const DEFERRABLE_SIGNAL_TYPES: ReadonlySet<string> = new Set([
  'typing-start',
  'typing-stop',
]);

export const SELECT_TYPEAHEAD_RESET_MS = 700;
export const CHAT_MESSAGE_GROUP_INTERVAL_MS = 3 * 60 * 1_000;
export const CHAT_ARRIVAL_ANIMATION_MAX_AGE_MS = 5_000;
export const NATIVE_MESSAGE_RENDER_RETRY_STEP_MS = 50;
