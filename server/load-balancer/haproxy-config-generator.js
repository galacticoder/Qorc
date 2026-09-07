/**
 * HAProxy config generator for lb
 */

import path from 'path';
import {
  haproxyStatsSocketPath,
} from '../config/infrastructure.js';
import { CLUSTER_SERVER_ID_RE } from '../cluster/signed-message.js';

const HAPROXY_USERNAME_RE = /^[A-Za-z0-9_.-]{3,64}$/;
const HAPROXY_PASSWORD_RE = /^[A-Za-z0-9_~!@$%^&*+=,.?/-]{16,128}$/;
const HAPROXY_HOST_RE = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;
const HAPROXY_SAFE_PATH_RE = /^[^\s#\0]+$/;
const HAPROXY_TIMEOUT_RE = /^(?:[1-9]\d{0,8})(?:ms|s|m|h|d)$/;
function exactInteger(value, minimum, maximum, label) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

export function parseHAProxyPort(value, label = 'HAProxy port') {
  const port = typeof value === 'string' && /^\d{1,5}$/.test(value)
    ? Number(value)
    : value;
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${label} must be an integer from 1 to 65535`);
  }
  return port;
}

function safeConfigPath(value, label) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 4096 || !HAPROXY_SAFE_PATH_RE.test(value)) {
    throw new Error(`${label} contains unsupported characters`);
  }
  return value;
}

function safeTimeouts(timeouts) {
  const expected = ['client', 'connect', 'httpKeepAlive', 'httpRequest', 'server', 'tunnel'];
  if (
    !timeouts ||
    Object.getPrototypeOf(timeouts) !== Object.prototype ||
    Object.keys(timeouts).sort().join(',') !== expected.join(',')
  ) throw new Error('Invalid HAProxy timeout configuration');
  for (const value of Object.values(timeouts)) {
    if (typeof value !== 'string' || !HAPROXY_TIMEOUT_RE.test(value)) {
      throw new Error('Invalid HAProxy timeout value');
    }
  }
  return { ...timeouts };
}

export class HAProxyConfigGenerator {
  constructor({
    listenPort,
    statsPort,
    tlsCertPath,
    maxConnections = 100000,
    statsUsername,
    statsPassword,
    statsBindAddress,
    timeouts = {
      connect: '30s',
      client: '24d',
      server: '24d',
      tunnel: '24d',
      httpKeepAlive: '60s',
      httpRequest: '60s',
    }
  } = {}) {
    this.listenPort = parseHAProxyPort(listenPort, 'HAProxy listen port');
    this.statsPort = parseHAProxyPort(statsPort, 'HAProxy statistics port');
    this.tlsCertPath = safeConfigPath(tlsCertPath, 'HAProxy certificate path');
    this.maxConnections = exactInteger(maxConnections, 1, 10_000_000, 'HAProxy maximum connections');
    this.statsUsername = statsUsername;
    this.statsPassword = statsPassword;
    if (!HAPROXY_USERNAME_RE.test(this.statsUsername || '') || !HAPROXY_PASSWORD_RE.test(this.statsPassword || '')) {
      throw new Error('HAProxy statistics credentials contain unsupported characters or lengths');
    }
    if (!['127.0.0.1', '0.0.0.0'].includes(statsBindAddress)) {
      throw new Error('HAPROXY_STATS_BIND_ADDRESS must be 127.0.0.1 or 0.0.0.0');
    }
    this.statsBindAddress = statsBindAddress;
    this.timeouts = safeTimeouts(timeouts);
    this.certFile = safeConfigPath(path.join(this.tlsCertPath, 'cert.pem'), 'HAProxy certificate file');
    this.backendCaFile = safeConfigPath(
      path.join(this.tlsCertPath, 'backend-ca.pem'),
      'HAProxy backend CA file'
    );
    this.dhParamFile = safeConfigPath(path.join(this.tlsCertPath, 'dhparams.pem'), 'HAProxy DH parameter file');
    this.statsSocketPath = safeConfigPath(
      haproxyStatsSocketPath(),
      'HAProxy statistics socket path'
    );
    this.backends = [];
  }

  // Add backend server to configuration
  addBackend({
    name,
    host,
    port,
    weight = 100,
    maxconn = 10000,
  }) {
    if (!name) {
      throw new Error('Backend name is required');
    }

    if (typeof name !== 'string' || !CLUSTER_SERVER_ID_RE.test(name)) {
      throw new Error('Invalid HAProxy backend name');
    }

    if (typeof host !== 'string' || !HAPROXY_HOST_RE.test(host)) {
      throw new Error('Invalid HAProxy backend host');
    }

    const portNum = parseHAProxyPort(port, 'HAProxy backend port');

    if (!Number.isSafeInteger(weight) || weight < 1 || weight > 256) {
      throw new Error('Invalid HAProxy backend weight');
    }
    if (!Number.isSafeInteger(maxconn) || maxconn < 1 || maxconn > 10_000_000) {
      throw new Error('Invalid HAProxy backend connection limit');
    }

    this.backends.push({
      name,
      host,
      port: portNum,
      weight,
      maxconn,
    });
  }

  // Generate complete HAProxy configuration
  generateConfig() {
    const config = `# HAProxy Configuration for qorc Server Cluster
# Generated automatically - DO NOT EDIT MANUALLY
# Generated at: ${new Date().toISOString()}

#---------------------------------------------------------------------
# Global settings
#---------------------------------------------------------------------
global
    # Daemon mode
    daemon
    
    # Maximum connections
    maxconn ${this.maxConnections}
    
    # Logging
    log /dev/log local0
    log /dev/log local1 notice
    
    # Quantum-Secure SSL/TLS settings
    ssl-default-bind-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-curves X25519MLKEM768
    ssl-default-bind-options no-tlsv10 no-tlsv11 no-tlsv12 no-sslv3 no-tls-tickets
    
    ssl-default-server-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-server-curves X25519MLKEM768
    ssl-default-server-options no-tlsv10 no-tlsv11 no-tlsv12 no-sslv3 no-tls-tickets
    
    # Performance tuning 
    tune.ssl.cachesize 0
    tune.ssl.default-dh-param 2048
    tune.bufsize 32768
    tune.maxrewrite 8192
    
    # Stats socket for management
    stats socket ${this.statsSocketPath} mode 660 level admin expose-fd listeners
    stats timeout 30s

#---------------------------------------------------------------------
# Default settings
#---------------------------------------------------------------------
defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    option  http-server-close
    option  forwardfor except 127.0.0.0/8
    option  redispatch
    
    # Timeouts
    timeout connect ${this.timeouts.connect}
    timeout client  ${this.timeouts.client}
    timeout server  ${this.timeouts.server}
    timeout tunnel  ${this.timeouts.tunnel}
    timeout http-keep-alive ${this.timeouts.httpKeepAlive}
    timeout http-request    ${this.timeouts.httpRequest}
    
    # Retry policy
    retries 3
    
    # Compression
    compression algo gzip
    compression type text/html text/plain text/css text/javascript application/javascript application/json

#---------------------------------------------------------------------
# Stats interface
#---------------------------------------------------------------------
listen stats
    bind ${this.statsBindAddress}:${this.statsPort}
    stats enable
    stats uri /haproxy-stats
    stats refresh 30s
    stats show-legends
    stats show-node
    
    # SECURITY: Require authentication
    stats auth ${this.statsUsername}:${this.statsPassword}

#---------------------------------------------------------------------
# HTTPS frontend (main entry point)
#---------------------------------------------------------------------
frontend https-in
    bind *:${this.listenPort} ssl crt ${this.certFile} alpn http/1.1
    
    mode http
    
    # Security headers
    http-response set-header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    http-response set-header X-Frame-Options DENY
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header X-XSS-Protection "0"
    http-response set-header Referrer-Policy "strict-origin-when-cross-origin"
    http-response set-header Permissions-Policy "microphone=(self), camera=(self), usb=()"
    http-response set-header X-Permitted-Cross-Domain-Policies "none"
    http-response del-header Server
    http-response del-header X-Powered-By
    
    # Rate limiting
    stick-table type ip size 100k expire 30s store http_req_rate(10s),http_err_rate(10s),conn_rate(3s),conn_cur
    acl from_local_tor src 127.0.0.0/8
    http-request track-sc0 src unless from_local_tor
    
    # Deny excessive requests (rate limiting)
    http-request deny deny_status 429 if !from_local_tor { sc_http_req_rate(0) gt 100 }
    
    # Deny clients with too many errors (potential attacks)
    http-request deny deny_status 403 if !from_local_tor { sc_http_err_rate(0) gt 20 }
    
    # Deny clients with too many concurrent connections
    http-request deny deny_status 429 if !from_local_tor { sc_conn_cur(0) gt 50 }
    
    # Deny rapid connection attempts (DDoS protection)
    http-request deny deny_status 429 if !from_local_tor { sc_conn_rate(0) gt 20 }
    
    # WebSocket detection (case-insensitive, substring match)
    acl is_websocket hdr(Upgrade) -m sub -i websocket
    acl is_connection_upgrade hdr(Connection) -m sub -i upgrade
    # Use WebSocket backend for WebSocket connections
    use_backend websocket_backend if is_websocket is_connection_upgrade
    
    # Default backend for HTTP requests
    default_backend http_backend

#---------------------------------------------------------------------
# Backend: HTTP traffic
#---------------------------------------------------------------------
backend http_backend
    mode http
    balance roundrobin
    
    # Cookie-based sticky sessions
    cookie SERVERID insert indirect nocache
    
    # Health check with auto-recovery
    option httpchk GET /api/health
    http-check expect status 200
    
    # Automatically remove failed servers and redistribute connections
    option redispatch
    
    # Backend servers
${this.generateBackendServers('http')}

#---------------------------------------------------------------------
# Backend: WebSocket traffic
#---------------------------------------------------------------------
backend websocket_backend
    mode http
    balance leastconn
    
    # WebSocket-specific options
    no option http-server-close
    no option httpclose
    option http-keep-alive
    option forwardfor
    no option http-buffer-request
    
    # Forward WebSocket upgrade headers to backend
    http-request set-header X-Forwarded-Proto https if { ssl_fc }
    http-request set-header X-Forwarded-For %[src]
    
    # Health check for WebSocket
    option httpchk GET /api/health
    http-check expect status 200
    
    # Automatically reconnect to healthy server if current fails
    option redispatch
    
    # Backend servers
${this.generateBackendServers('websocket')}

#---------------------------------------------------------------------
# Cache for static content
#---------------------------------------------------------------------
cache quantum_cache
    total-max-size 256
    max-object-size 10000
    max-age 300
`;
    const httpBindPattern = /frontend\s+http-in\b|bind\s+\*:\s*80\b|bind\s+\*:\s*8080\b/i;
    if (httpBindPattern.test(config)) {
      throw new Error('HTTP bind detected in HAProxy config; HTTPS-only mode enforced.');
    }
    return config;
  }

  // Generate backend server configuration
  generateBackendServers(type) {
    if (this.backends.length === 0) {
      return `\t# No backend servers available - HAProxy will return 503 Service Unavailable`;
    }
    return this.backends.map(backend => {
      const checkParams = `check inter 2s fall 2 rise 2`;
      const sslParams = `ssl verify required ca-file ${this.backendCaFile}`;
      const alpnParam = type === 'websocket' ? 'alpn http/1.1' : 'alpn h2,http/1.1';
      const cookieParam = type === 'websocket' ? '' : 'cookie SERVERID ';

      return type === 'websocket'
        ? `\tserver ${backend.name} ${backend.host}:${backend.port} ${sslParams} ${alpnParam} weight ${backend.weight} maxconn ${backend.maxconn} ${checkParams}`
        : `\tserver ${backend.name} ${backend.host}:${backend.port} ${cookieParam}${sslParams} ${alpnParam} weight ${backend.weight} maxconn ${backend.maxconn} ${checkParams}`;
    }).join('\n');
  }

}
