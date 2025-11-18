/**
 * HAProxy Configuration Generator for Load Balancing
 * 
 * Generates HAProxy configuration with:
 * - Health checks for backend servers
 * - TLS termination 
 * - Rate limiting and DDoS protection
 * - Security headers and hardening
 */

import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';

export class HAProxyConfigGenerator {
  constructor({ 
    listenPort = 443, 
    httpPort = 80,
    statsPort = 8404,
    tlsCertPath = process.env.HAPROXY_CERT_PATH || path.join(process.cwd(), 'server', 'config', 'certs'),
    maxConnections = 100000,
    statsUsername = 'admin', // will be prompted for a new one. this is the default
    statsPassword = 'adminpass', // will be prompted for a new one. this is the default
    timeouts = {
      connect: '30s',
      client: '3600s',  // 1 hour for WebSocket
      server: '3600s',
      tunnel: '3600s',
      httpKeepAlive: '60s',
      httpRequest: '60s',
    }
  } = {}) {
    this.listenPort = listenPort;
    this.httpPort = httpPort;
    this.statsPort = statsPort;
    this.tlsCertPath = tlsCertPath;
    this.maxConnections = maxConnections;
    this.statsUsername = statsUsername;
    this.statsPassword = statsPassword;
    this.timeouts = timeouts;
    const envCert = process.env.HAPROXY_CERT_FILE;
    const candidate = envCert || path.join(this.tlsCertPath, 'cert.pem');
    this.certFile = candidate;
    this.dhParamFile = path.join(this.tlsCertPath, 'dhparams.pem');
    // Stats socket path per-user in tmpdir unless overridden
    const uid = (typeof process.getuid === 'function') ? String(process.getuid()) : 'nouid';
    this.statsSocketPath = process.env.HAPROXY_STATS_SOCKET || path.join(os.tmpdir(), `haproxy-admin-${uid}.sock`);
    this.backends = [];
  }
  
  /**
   * Add backend server to configuration
   */
  addBackend({ 
    name, 
    host = '127.0.0.1', 
    port, 
    weight = 100, 
    maxconn = 10000,
    checkInterval = '5s',
    checkTimeout = '3s',
  }) {
    if (!name) {
      throw new Error('Backend name is required');
    }
    
    // Validate port is a valid number
    const portNum = parseInt(port, 10);
    if (!portNum || portNum <= 0 || portNum > 65535) {
      const errorMsg = `Server "${name}" at ${host}:${port} has invalid port - skipping from load balancer`;
      cryptoLogger.error('[HAPROXY] Invalid backend port', { name, host, port });
      console.error(`\n[ERROR] ${errorMsg}`);
      console.error(`[ERROR] Server "${name}" needs to be restarted with a valid port\n`);
      return; 
    }
    
    this.backends.push({
      name,
      host,
      port,
      weight,
      maxconn,
      checkInterval,
      checkTimeout,
    });
  }
  
  /**
   * Generate complete HAProxy configuration
   */
  generateConfig() {
    // Allow 0 backends to maintain tunnel URL when no servers are active
    
    return `# HAProxy Configuration for Quantum-Secure Server Cluster
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
    
    # Quantum-Secure SSL/TLS settings (TLS 1.3 only + PQC key exchange)
    ssl-default-bind-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options no-tlsv10 no-tlsv11 no-tlsv12 no-sslv3
    
    ssl-default-server-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-server-options no-tlsv10 no-tlsv11 no-tlsv12 no-sslv3
    
    # Performance tuning 
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
# Stats interface (protected)
#---------------------------------------------------------------------
listen stats
    bind *:${this.statsPort}
    stats enable
    stats uri /haproxy-stats
    stats refresh 30s
    stats show-legends
    stats show-node
    
    # SECURITY: Require authentication (configured at startup)
    stats auth ${this.statsUsername}:${this.statsPassword}
    stats admin if TRUE
    
    # Restrict to localhost only for security
    acl local_network src 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
    http-request deny if !local_network

#---------------------------------------------------------------------
# HTTP frontend (redirect to HTTPS)
#---------------------------------------------------------------------
frontend http-in
    bind *:${this.httpPort}
    
    # Security headers
    http-response set-header X-Frame-Options DENY
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header X-XSS-Protection "1; mode=block"
    http-response set-header Referrer-Policy "strict-origin-when-cross-origin"
    
    # Redirect all HTTP to HTTPS
    redirect scheme https code 301 if !{ ssl_fc }

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
    http-response set-header X-XSS-Protection "1; mode=block"
    http-response set-header Referrer-Policy "strict-origin-when-cross-origin"
    http-response set-header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
    http-response set-header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' wss: https:; media-src 'self' blob:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    http-response set-header X-Permitted-Cross-Domain-Policies "none"
    http-response del-header Server
    http-response del-header X-Powered-By
    
    # Rate limiting
    stick-table type ip size 100k expire 30s store http_req_rate(10s),http_err_rate(10s),conn_rate(3s),conn_cur
    http-request track-sc0 src
    
    # Deny excessive requests (rate limiting)
    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }
    
    # Deny clients with too many errors (potential attacks)
    http-request deny deny_status 403 if { sc_http_err_rate(0) gt 20 }
    
    # Deny clients with too many concurrent connections
    http-request deny deny_status 429 if { sc_conn_cur(0) gt 50 }
    
    # Deny rapid connection attempts (DDoS protection)
    http-request deny deny_status 429 if { sc_conn_rate(0) gt 20 }
    
    # WebSocket detection (case-insensitive, substring match)
    acl is_websocket hdr(Upgrade) -m sub -i websocket
    acl is_connection_upgrade hdr(Connection) -m sub -i upgrade
    acl is_websocket_path path_beg /
    
    # Use WebSocket backend for WebSocket connections
    use_backend websocket_backend if is_websocket or is_connection_upgrade or is_websocket_path
    
    # Default backend for HTTP requests
    default_backend http_backend

#---------------------------------------------------------------------
# Backend: HTTP traffic
#---------------------------------------------------------------------
backend http_backend
    mode http
    balance roundrobin
    
    # Cookie-based sticky sessions (allows better load distribution)
    cookie SERVERID insert indirect nocache
    
    # Health check with auto-recovery
    option httpchk GET /api/health
    http-check expect status 200
    
    # Automatically remove failed servers and redistribute connections
    option redispatch
    
    # Backend servers
${this.generateBackendServers('http')}

#---------------------------------------------------------------------
# Backend: WebSocket traffic (sticky sessions required)
#---------------------------------------------------------------------
backend websocket_backend
    mode http
    balance leastconn
    
    # Sticky sessions for WebSocket using source IP (cookies don't work for WS upgrade)
    stick-table type ip size 100k expire 3600s
    stick on src
    
    # WebSocket-specific options - keep connections alive indefinitely
    no option http-server-close
    no option httpclose
    option http-keep-alive
    option forwardfor
    
    # CRITICAL: Disable request buffering for real-time WebSocket communication
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
# Cache for static content (optional)
#---------------------------------------------------------------------
cache quantum_cache
    total-max-size 256
    max-object-size 10000
    max-age 300
`;
  }
  
  /**
   * Generate backend server configuration
   */
  generateBackendServers(type) {
    if (this.backends.length === 0) {
      return `\t# No backend servers available - HAProxy will return 503 Service Unavailable`;
    }
    return this.backends.map(backend => {
      // health checks and failover (check every 2s, fail after 2 failures)
      const checkParams = `check inter 2s fall 2 rise 2`;
      const sslParams = 'ssl verify none'; // Backend servers use self-signed certs
      const alpnParam = type === 'websocket' ? 'alpn http/1.1' : 'alpn h2,http/1.1';
      const cookieParam = type === 'websocket' ? '' : 'cookie SERVERID ';
      
      return type === 'websocket'
        ? `\tserver ${backend.name} ${backend.host}:${backend.port} ${sslParams} ${alpnParam} weight ${backend.weight} maxconn ${backend.maxconn} ${checkParams}`
        : `\tserver ${backend.name} ${backend.host}:${backend.port} ${cookieParam}${sslParams} ${alpnParam} weight ${backend.weight} maxconn ${backend.maxconn} ${checkParams}`;
    }).join('\n');
  }
  
  /**
   * Write configuration to file
   */
  async writeConfig(outputPath) {
    try {
      const config = this.generateConfig();
      await fs.writeFile(outputPath, config, { encoding: 'utf8', mode: 0o600 });
      cryptoLogger.info('[HAPROXY] Configuration written', { outputPath });
      return config;
    } catch (error) {
      cryptoLogger.error('[HAPROXY] Failed to write configuration', error);
      throw error;
    }
  }
  
  /**
   * Validate configuration using HAProxy binary
   */
  async validateConfig(configPath) {
    const { execFile } = await import('child_process');
    const { promisify } = await import('util');
    const execFileAsync = promisify(execFile);
    
    try {
      await execFileAsync('haproxy', ['-c', '-f', configPath], { env: { ...process.env } });
      cryptoLogger.info('[HAPROXY] Configuration validated successfully');
      return true;
    } catch (error) {
      cryptoLogger.error('[HAPROXY] Configuration validation failed', error);
      throw new Error(`HAProxy configuration is invalid: ${error.message}`);
    }
  }
  
  /**
   * Reload HAProxy with new configuration 
   */
  async reloadHAProxy(configPath) {
    const { execFile } = await import('child_process');
    const { promisify } = await import('util');
    const execFileAsync = promisify(execFile);
    
    try {
      // Validate first
      await this.validateConfig(configPath);
      
      // Determine PID file path
      const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
      const pidFile = process.env.HAPROXY_PID_FILE || (isRoot && process.platform !== 'win32' ? '/var/run/haproxy-auto.pid' : path.join(os.tmpdir(), 'haproxy-auto.pid'));
      let oldPid = null;
      try {
        const pidStr = await fs.readFile(pidFile, 'utf8');
        const n = parseInt(pidStr, 10);
        if (Number.isFinite(n) && n > 0) oldPid = n;
      } catch {}
      
      // Build arguments for a soft reload
      const args = ['-f', configPath, '-D', '-p', pidFile];
      if (oldPid) args.push('-sf', String(oldPid));
      
      const env = { ...process.env };
      if (process.env.LD_LIBRARY_PATH) env.LD_LIBRARY_PATH = process.env.LD_LIBRARY_PATH;
      if (process.env.OPENSSL_CONF) env.OPENSSL_CONF = process.env.OPENSSL_CONF;

      await execFileAsync('haproxy', args, { env });
      cryptoLogger.info('[HAPROXY] Reloaded successfully');
      return true;
    } catch (error) {
      cryptoLogger.error('[HAPROXY] Reload failed', error);
      throw error;
    }
  }
}

/**
 * Generate HAProxy configuration from cluster state
 */
export async function generateConfigFromCluster(clusterManager, outputPath) {
  try {
    const status = await clusterManager.getClusterStatus();
    
    const generator = new HAProxyConfigGenerator({
      listenPort: parseInt(process.env.HAPROXY_HTTPS_PORT || '8443', 10),
      httpPort: parseInt(process.env.HAPROXY_HTTP_PORT || '8080', 10),
      statsPort: parseInt(process.env.HAPROXY_STATS_PORT || '8404', 10),
      tlsCertPath: process.env.HAPROXY_CERT_PATH || path.join(process.cwd(), 'server', 'config', 'certs'),
      statsUsername: process.env.HAPROXY_STATS_USERNAME || 'admin',
      statsPassword: process.env.HAPROXY_STATS_PASSWORD || 'adminpass',
    });
    
    // Add all healthy servers as backends
    for (const server of status.servers) {
      if (server.health?.status === 'healthy') {
        const serverUrl = process.env[`SERVER_${server.serverId}_URL`] || `127.0.0.1:${3000 + parseInt(server.serverId.slice(-4), 16) % 1000}`;
        const [host, portStr] = serverUrl.split(':');
        const port = parseInt(portStr, 10);
        
        generator.addBackend({
          name: server.serverId,
          host,
          port,
          weight: 100,
          maxconn: 10000,
        });
      }
    }
    
    // Write configuration
    await generator.writeConfig(outputPath);
    
    cryptoLogger.info('[HAPROXY] Generated configuration from cluster', {
      serverCount: status.serverCount,
      outputPath
    });
    
    return generator;
  } catch (error) {
    cryptoLogger.error('[HAPROXY] Failed to generate configuration from cluster', error);
    throw error;
  }
}