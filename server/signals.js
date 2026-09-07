export const SignalType = {
  //connection and auth
  SERVER_PUBLIC_KEY: "server-public-key",
  TOKEN_VALIDATION: "token-validation",
  TOKEN_VALIDATION_RESPONSE: "token-validation-response",

  //errors and status
  ERROR: "error",
  OK: "ok",
  AUTH_ERROR: "AUTH_ERROR",
  REQUEST_SERVER_PUBLIC_KEY: "request-server-public-key",

  // Session management
  PQ_HANDSHAKE_INIT: "pq-handshake-init",
  PQ_HANDSHAKE_ACK: "pq-handshake-ack",
  PQ_HANDSHAKE_CONFIRM: "pq-handshake-confirm",
  PQ_HANDSHAKE_CONFIRMED: "pq-handshake-confirmed",
  PQ_HEARTBEAT_PING: "pq-heartbeat-ping",
  PQ_HEARTBEAT_PONG: "pq-heartbeat-pong",

  // Blind Routing
  BLIND_ROUTE: "blind-route",
  BLIND_ROUTE_ACK: "blind-route-ack",

  SEALED_ENVELOPE: "sealed-envelope",

  ACTIVATE_DELIVERY: "activate-delivery",
  ACTIVATE_DELIVERY_RESPONSE: "activate-delivery-response",

  // Authentication
  AUTH_REGISTER_REQUEST: "auth-register-request",
  AUTH_REGISTER_RESPONSE: "auth-register-response",
  AUTH_REGISTER_FINALIZE: "auth-register-finalize",
  AUTH_REGISTER_READY: "auth-register-ready",
  AUTH_REGISTER_CONFIRM: "auth-register-confirm",
  PRIVACY_PASS_REDEMPTION: "privacy-pass-redemption",
  AUTH_FULL_SUCCESS: "AUTH_FULL_SUCCESS",
  AUTH_PIR_REQUEST: "auth-pir-request",
  AUTH_PIR_RESPONSE: "auth-pir-response",
  AUTH_PIR_FINALIZE: "auth-pir-finalize",
  SECURE_CHUNK: "secure-chunk",

  // Discovery
  OPRF_DISCOVERY_PUBLIC_KEY: "oprf-discovery-public-key",
  PUBLISH_DISCOVERY: "publish-discovery",

  // Server Gatekeeper
  SERVER_ENTRY_REQUEST: "server-entry-request",
  SERVER_ENTRY_CHALLENGE: "server-entry-challenge",
  SERVER_ENTRY_TOKEN_ISSUANCE: "server-entry-token-issuance",
  SERVER_ENTRY_CREDENTIAL_ROTATED: "server-entry-credential-rotated",

  ACCOUNT_AUTH_TOKEN_REFRESH: "account-auth-token-refresh",
  ACCOUNT_AUTH_TOKEN_REFRESH_RESPONSE: "account-auth-token-refresh-response",
};

const RATE_LIMITED_AUTH_SIGNAL_TYPES = new Set([
  SignalType.AUTH_REGISTER_REQUEST,
  SignalType.AUTH_REGISTER_FINALIZE,
  SignalType.AUTH_REGISTER_CONFIRM,
  SignalType.AUTH_PIR_REQUEST,
  SignalType.AUTH_PIR_FINALIZE,
  SignalType.SERVER_ENTRY_REQUEST,
  SignalType.SERVER_ENTRY_TOKEN_ISSUANCE,
  SignalType.ACCOUNT_AUTH_TOKEN_REFRESH,
  SignalType.PRIVACY_PASS_REDEMPTION,
  SignalType.TOKEN_VALIDATION,
]);

const ACCOUNT_AUTH_SIGNAL_TYPES = new Set([
  SignalType.AUTH_REGISTER_REQUEST,
  SignalType.AUTH_REGISTER_FINALIZE,
  SignalType.AUTH_REGISTER_CONFIRM,
  SignalType.AUTH_PIR_REQUEST,
  SignalType.AUTH_PIR_FINALIZE,
]);

const SERVER_ENTRY_SIGNAL_TYPES = new Set([
  SignalType.SERVER_ENTRY_REQUEST,
  SignalType.SERVER_ENTRY_TOKEN_ISSUANCE,
  SignalType.PRIVACY_PASS_REDEMPTION,
]);

const LINKED_AUTHENTICATION_SIGNAL_TYPES = new Set([
  ...ACCOUNT_AUTH_SIGNAL_TYPES,
  SignalType.SERVER_ENTRY_REQUEST,
  SignalType.SERVER_ENTRY_TOKEN_ISSUANCE,
]);

const UNLINKED_APPLICATION_SIGNAL_TYPES = new Set([
  SignalType.TOKEN_VALIDATION,
  SignalType.ACTIVATE_DELIVERY,
  SignalType.BLIND_ROUTE,
  SignalType.OPRF_DISCOVERY_PUBLIC_KEY,
  SignalType.PUBLISH_DISCOVERY,
  SignalType.ACCOUNT_AUTH_TOKEN_REFRESH,
]);

const PRE_SERVER_ENTRY_SIGNAL_TYPES = new Set([
  SignalType.REQUEST_SERVER_PUBLIC_KEY,
  SignalType.PQ_HANDSHAKE_INIT,
  SignalType.PQ_HEARTBEAT_PING,
  SignalType.SERVER_ENTRY_REQUEST,
  SignalType.SERVER_ENTRY_TOKEN_ISSUANCE,
  SignalType.PRIVACY_PASS_REDEMPTION,
  SignalType.TOKEN_VALIDATION,
]);

export function isRateLimitedAuthSignalType(type) {
  return RATE_LIMITED_AUTH_SIGNAL_TYPES.has(type);
}

export function isAccountAuthSignalType(type) {
  return ACCOUNT_AUTH_SIGNAL_TYPES.has(type);
}

export function isServerEntrySignalType(type) {
  return SERVER_ENTRY_SIGNAL_TYPES.has(type);
}

export function isLinkedAuthenticationSignalType(type) {
  return LINKED_AUTHENTICATION_SIGNAL_TYPES.has(type);
}

export function isUnlinkedApplicationSignalType(type) {
  return UNLINKED_APPLICATION_SIGNAL_TYPES.has(type);
}

export function isPreServerEntrySignalType(type) {
  return PRE_SERVER_ENTRY_SIGNAL_TYPES.has(type);
}
