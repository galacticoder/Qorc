export const SESSION_ID_RE = /^[a-f0-9]{32}$/;
export const SESSION_FINGERPRINT_RE = /^[a-f0-9]{64}$/;
export const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const CANONICAL_BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
export const BASE64URL_32_RE = /^[A-Za-z0-9_-]{43}$/;
export const DISCOVERY_EPOCH_ID_RE = /^\d{10,16}$/;
export const PUBLICATION_ID_RE = /^pub-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const DIGITS_RE = /^[0-9]+$/;
