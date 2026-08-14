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
  PQ_ENVELOPE: "pq-envelope",

  // Misc
  PING: "ping",
  PONG: "pong",

  // Blind Routing
  BLIND_ROUTE: "blind-route",
  BLIND_ROUTE_ACK: "blind-route-ack",

  SEALED_ENVELOPE: "sealed-envelope",

  ACTIVATE_DELIVERY: "activate-delivery",
  ACTIVATE_DELIVERY_RESPONSE: "activate-delivery-response",

  // Authentication
  AUTH_OT_REGISTER_REQUEST: "auth-ot-register-request",
  AUTH_OT_REGISTER_RESPONSE: "auth-ot-register-response",
  AUTH_OT_REGISTER_FINALIZE: "auth-ot-register-finalize",
  AUTH_OT_REGISTER_READY: "auth-ot-register-ready",
  AUTH_OT_REGISTER_CONFIRM: "auth-ot-register-confirm",
  PRIVACY_PASS_REDEMPTION: "privacy-pass-redemption",
  AUTH_FULL_SUCCESS: "AUTH_FULL_SUCCESS",
  AUTH_OT_REQUEST: "auth-ot-request",
  AUTH_OT_RESPONSE: "auth-ot-response",
  AUTH_OT_FINALIZE: "auth-ot-finalize",
  SECURE_CHUNK: "secure-chunk",

  // Discovery
  OPRF_DISCOVERY_PUBLIC_KEY: "oprf-discovery-public-key",
  PUBLISH_DISCOVERY: "publish-discovery",

  // Server Gatekeeper
  SERVER_ENTRY_REQUEST: "server-entry-request",
  SERVER_ENTRY_CHALLENGE: "server-entry-challenge",
  SERVER_ENTRY_TOKEN_ISSUANCE: "server-entry-token-issuance",

  ACCOUNT_AUTH_TOKEN_REFRESH: "account-auth-token-refresh",
  ACCOUNT_AUTH_TOKEN_REFRESH_RESPONSE: "account-auth-token-refresh-response",
};

const RATE_LIMITED_AUTH_SIGNAL_TYPES = new Set([
  SignalType.AUTH_OT_REGISTER_REQUEST,
  SignalType.AUTH_OT_REGISTER_FINALIZE,
  SignalType.AUTH_OT_REGISTER_CONFIRM,
  SignalType.AUTH_OT_REQUEST,
  SignalType.AUTH_OT_FINALIZE,
  SignalType.SERVER_ENTRY_REQUEST,
  SignalType.SERVER_ENTRY_TOKEN_ISSUANCE,
  SignalType.ACCOUNT_AUTH_TOKEN_REFRESH,
  SignalType.PRIVACY_PASS_REDEMPTION,
  SignalType.TOKEN_VALIDATION,
]);

const ACCOUNT_AUTH_SIGNAL_TYPES = new Set([
  SignalType.AUTH_OT_REGISTER_REQUEST,
  SignalType.AUTH_OT_REGISTER_FINALIZE,
  SignalType.AUTH_OT_REGISTER_CONFIRM,
  SignalType.AUTH_OT_REQUEST,
  SignalType.AUTH_OT_FINALIZE,
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
