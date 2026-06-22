export const SignalType = {
  //connection and auth
  SERVER_PUBLIC_KEY: "server-public-key",
  TOKEN_VALIDATION: "token-validation",
  TOKEN_VALIDATION_RESPONSE: "token-validation-response",

  //messaging
  ENCRYPTED_MESSAGE: "encrypted-message",

  //errors and status
  ERROR: "error",
  OK: "ok",
  AUTH_ERROR: "AUTH_ERROR",
  SERVERMESSAGE: "server-message",

  HYBRID_KEYS: "hybrid-keys",

  REQUEST_SERVER_PUBLIC_KEY: "request-server-public-key",

  //rate limiting and admin
  RATE_LIMIT_STATUS: "rate-limit-status",

  // Session management
  PQ_HANDSHAKE_INIT: "pq-handshake-init",
  PQ_HANDSHAKE_ACK: "pq-handshake-ack",
  PQ_HEARTBEAT_PING: "pq-heartbeat-ping",
  PQ_HEARTBEAT_PONG: "pq-heartbeat-pong",
  PQ_ENVELOPE: "pq-envelope",

  // Blocking system
  BLOCK_LIST_SYNC: "block-list-sync",
  BLOCK_LIST_UPDATE: "block-list-update",
  RETRIEVE_BLOCK_LIST: "retrieve-block-list",
  BLOCK_LIST_RESPONSE: "block-list-response",

  // Misc
  PING: "ping",
  PONG: "pong",

  // Blind Routing
  BLIND_ROUTE: "blind-route",
  BLIND_ROUTE_ACK: "blind-route-ack",

  SEALED_ENVELOPE: "sealed-envelope",

  CLAIM_INBOX: "claim-inbox",
  CLAIM_INBOX_RESPONSE: "claim-inbox-response",

  ROTATE_INBOX: "rotate-inbox",
  ROTATE_INBOX_RESPONSE: "rotate-inbox-response",

  // Blind Credentials
  BLIND_SIGNATURE_REQUEST: "blind-signature-request",
  BLIND_SIGNATURE_RESPONSE: "blind-signature-response",

  // Authentication
  AUTH_OT_REGISTER_REQUEST: "auth-ot-register-request",
  AUTH_OT_REGISTER_RESPONSE: "auth-ot-register-response",
  AUTH_OT_REGISTER_FINALIZE: "auth-ot-register-finalize",
  PRIVACY_PASS_ISSUANCE: "privacy-pass-issuance",
  PRIVACY_PASS_REDEMPTION: "privacy-pass-redemption",
  ZK_REFRESH_CHALLENGE: "zk-refresh-challenge",
  ZK_REFRESH_RESPONSE: "zk-refresh-response",
  ZK_DEVICE_REGISTER: "zk-device-register",
  ZK_DEVICE_REGISTER_RESPONSE: "zk-device-register-response",
  AUTH_FULL_SUCCESS: "AUTH_FULL_SUCCESS",
  AUTH_OT_REQUEST: "auth-ot-request",
  AUTH_OT_RESPONSE: "auth-ot-response",
  AUTH_OT_FINALIZE: "auth-ot-finalize",
  SECURE_CHUNK: "secure-chunk",

  // Discovery
  OPRF_DISCOVERY_PUBLIC_KEY: "oprf-discovery-public-key",
  OPRF_BLIND_EVALUATE: "oprf-blind-evaluate",
  OPRF_BLIND_EVALUATE_RESPONSE: "oprf-blind-evaluate-response",
  PUBLISH_DISCOVERY: "publish-discovery",
  DISCOVERY_SNAPSHOT_REQUEST: "discovery-snapshot-request",
  DISCOVERY_SNAPSHOT: "discovery-snapshot",
  PIR_MANIFEST_REQUEST: "pir-manifest-request",
  PIR_MANIFEST: "pir-manifest",
  PIR_QUERY: "pir-query",
  PIR_RESPONSE: "pir-response",

  // Server Gatekeeper
  SERVER_ENTRY_REQUEST: "server-entry-request",
  SERVER_ENTRY_CHALLENGE: "server-entry-challenge",
  SERVER_ENTRY_TOKEN_ISSUANCE: "server-entry-token-issuance",
};
