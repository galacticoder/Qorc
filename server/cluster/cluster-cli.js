#!/usr/bin/env node
/**
 * Cluster Management CLI Tool
 * 
 * Command-line interface for managing the server cluster:
 * - View cluster status
 * - Approve/reject pending servers
 * - Monitor server health
 * - Manage HAProxy configuration
 */

import { program } from 'commander';
import fetch from 'node-fetch';
import chalk from 'chalk';
import Table from 'cli-table3';

// Configuration
const API_BASE_URL = process.env.CLUSTER_API_URL || 'https://localhost:3000/api/cluster';
const ADMIN_TOKEN = process.env.CLUSTER_ADMIN_TOKEN;

if (!ADMIN_TOKEN) {
  console.error(chalk.red('Error: CLUSTER_ADMIN_TOKEN environment variable not set'));
  process.exit(1);
}

/**
 * Make authenticated API request
 */
async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  const headers = {
    'X-Admin-Token': ADMIN_TOKEN,
    'Content-Type': 'application/json',
    ...options.headers,
  };
  
  const response = await fetch(url, {
    ...options,
    headers,
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`API request failed: ${response.status} - ${error}`);
  }
  
  return await response.json();
}

/**
 * Format timestamp
 */
function formatTimestamp(timestamp) {
  return new Date(timestamp).toLocaleString();
}

/**
 * Format duration
 */
function formatDuration(ms) {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  
  if (days > 0) return `${days}d ${hours % 24}h`;
  if (hours > 0) return `${hours}h ${minutes % 60}m`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

/**
 * Command: status - Show cluster status
 */
program
  .command('status')
  .description('Show cluster status and server health')
  .action(async () => {
    try {
      console.log(chalk.blue('Fetching cluster status...\n'));
      
      const { cluster } = await apiRequest('/status');
      
      // Summary
      console.log(chalk.bold('Cluster Summary:'));
      console.log(`\tMaster Server: ${chalk.green(cluster.master || 'None')}`);
      console.log(`\tTotal Servers: ${chalk.green(cluster.serverCount)}`);
      console.log(`\tPending Approval: ${chalk.yellow(cluster.pendingCount)}\n`);
      
      // Active servers table
      if (cluster.servers.length > 0) {
        console.log(chalk.bold('Active Servers:'));
        const table = new Table({
          head: ['Server ID', 'Role', 'Status', 'Uptime', 'Last Heartbeat'],
          style: { head: ['cyan'] }
        });
        
        for (const server of cluster.servers) {
          const uptime = server.joinedAt ? Date.now() - server.joinedAt : 0;
          const timeSinceHeartbeat = Date.now() - server.lastHeartbeat;
          const heartbeatColor = timeSinceHeartbeat < 10000 ? chalk.green : 
                                 timeSinceHeartbeat < 30000 ? chalk.yellow : chalk.red;
          
          table.push([
            server.serverId,
            server.isPrimary ? chalk.bold.green('Primary') : 'Secondary',
            server.health?.status === 'healthy' ? chalk.green('Healthy') : chalk.red('Unhealthy'),
            formatDuration(uptime),
            heartbeatColor(formatDuration(timeSinceHeartbeat) + ' ago')
          ]);
        }
        
        console.log(table.toString() + '\n');
      }
      
      // Pending servers table
      if (cluster.pending.length > 0) {
        console.log(chalk.bold('Pending Approval:'));
        const table = new Table({
          head: ['Server ID', 'Requested At', 'Waiting For'],
          style: { head: ['yellow'] }
        });
        
        for (const server of cluster.pending) {
          const waitingTime = Date.now() - server.requestedAt;
          table.push([
            server.serverId,
            formatTimestamp(server.requestedAt),
            formatDuration(waitingTime)
          ]);
        }
        
        console.log(table.toString() + '\n');
      }
    } catch (error) {
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

/**
 * Command: pending - List pending servers
 */
program
  .command('pending')
  .description('List servers awaiting approval')
  .action(async () => {
    try {
      console.log(chalk.blue('Fetching pending servers...\n'));
      
      const { pending } = await apiRequest('/pending');
      
      if (pending.length === 0) {
        console.log(chalk.green('No servers pending approval'));
        return;
      }
      
      const table = new Table({
        head: ['Server ID', 'Requested At', 'Public Keys'],
        style: { head: ['yellow'] }
      });
      
      for (const server of pending) {
        const hasKeys = server.publicKeys ? 
          `Kyber: ${!!server.publicKeys.kyber}, Dilithium: ${!!server.publicKeys.dilithium}, X25519: ${!!server.publicKeys.x25519}` :
          'None';
        
        table.push([
          server.serverId,
          formatTimestamp(server.requestedAt),
          hasKeys
        ]);
      }
      
      console.log(table.toString() + '\n');
      console.log(chalk.gray('To approve a server: npm run cluster:approve <serverId>'));
      console.log(chalk.gray('To reject a server:  npm run cluster:reject <serverId>'));
    } catch (error) {
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

/**
 * Command: approve - Approve a pending server
 */
program
  .command('approve <serverId>')
  .description('Approve a pending server to join the cluster')
  .action(async (serverId) => {
    try {
      console.log(chalk.blue(`Approving server ${serverId}...\n`));
      
      const result = await apiRequest(`/approve/${serverId}`, {
        method: 'POST',
      });
      
      console.log(chalk.green('+'), result.message);
      console.log(chalk.gray(`Server ${serverId} is now part of the cluster`));
    } catch (error) {
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

/**
 * Command: reject - Reject a pending server
 */
program
  .command('reject <serverId>')
  .description('Reject a pending server')
  .option('-r, --reason <reason>', 'Reason for rejection')
  .action(async (serverId, options) => {
    try {
      console.log(chalk.blue(`Rejecting server ${serverId}...\n`));
      
      const result = await apiRequest(`/reject/${serverId}`, {
        method: 'POST',
        body: JSON.stringify({
          reason: options.reason || 'Rejected by admin'
        }),
      });
      
      console.log(chalk.yellow('-'), result.message);
      if (result.reason) {
        console.log(chalk.gray(`Reason: ${result.reason}`));
      }
    } catch (error) {
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

/**
 * Command: keys - View server public keys
 */
program
  .command('keys')
  .description('View all server public keys')
  .action(async () => {
    try {
      console.log(chalk.blue('Fetching server public keys...\n'));
      
      const response = await fetch(`${API_BASE_URL}/server-keys`, {
      });
      
      if (!response.ok) {
        throw new Error(`Failed to fetch keys: ${response.status}`);
      }
      
      const { serverKeys } = await response.json();
      
      if (serverKeys.length === 0) {
        console.log(chalk.yellow('No servers found'));
        return;
      }
      
      for (const server of serverKeys) {
        console.log(chalk.bold(`Server: ${server.serverId}`));
        console.log(`\tKyber:     ${server.publicKeys.kyber.substring(0, 32)}...`);
        console.log(`\tDilithium: ${server.publicKeys.dilithium.substring(0, 32)}...`);
        console.log(`\tX25519:    ${server.publicKeys.x25519.substring(0, 32)}...`);
        console.log();
      }
    } catch (error) {
      console.error(chalk.red('Error:'), error.message);
      process.exit(1);
    }
  });

/**
 * Command: health - Check server health
 */
program
  .command('health')
  .description('Check cluster health')
  .action(async () => {
    try {
      console.log(chalk.blue('Checking cluster health...\n'));
      
      const response = await fetch(`${API_BASE_URL}/health`, {
      });
      
      const health = await response.json();
      
      if (health.status === 'healthy') {
        console.log(chalk.green('* Cluster is healthy'));
        console.log(`\tServer ID: ${health.serverId}`);
      } else {
        console.log(chalk.red('- Cluster is unhealthy'));
        console.log(`\tReason: ${health.reason || health.error}`);
      }
    } catch (error) {
      console.error(chalk.red('Error: '), error.message);
      process.exit(1);
    }
  });

/**
 * Command: watch - Watch cluster status (live updates)
 */
program
  .command('watch')
  .description('Watch cluster status with live updates')
  .option('-i, --interval <seconds>', 'Update interval in seconds', '5')
  .action(async (options) => {
    const interval = parseInt(options.interval, 10) * 1000;
    
    console.log(chalk.blue('Watching cluster status (press Ctrl+C to exit)...\n'));
    
    async function update() {
      try {
        // Clear console
        console.clear();
        
        const { cluster } = await apiRequest('/status');
        
        console.log(chalk.bold.blue('=== Cluster Status ==='));
        console.log(chalk.gray(new Date().toLocaleString()));
        console.log();
        
        console.log(`Master: ${chalk.green(cluster.master || 'None')}`);
        console.log(`Servers: ${chalk.green(cluster.serverCount)} active, ${chalk.yellow(cluster.pendingCount)} pending\n`);
        
        if (cluster.servers.length > 0) {
          const table = new Table({
            head: ['Server ID', 'Role', 'Status', 'Last Heartbeat'],
            style: { head: ['cyan'] }
          });
          
          for (const server of cluster.servers) {
            const timeSinceHeartbeat = Date.now() - server.lastHeartbeat;
            const heartbeatColor = timeSinceHeartbeat < 10000 ? chalk.green : 
                                   timeSinceHeartbeat < 30000 ? chalk.yellow : chalk.red;
            
            table.push([
              server.serverId.substring(0, 20) + '...',
              server.isPrimary ? chalk.bold.green('Primary') : 'Secondary',
              server.health?.status === 'healthy' ? chalk.green('●') : chalk.red('●'),
              heartbeatColor(formatDuration(timeSinceHeartbeat) + ' ago')
            ]);
          }
          
          console.log(table.toString());
        }
        
        console.log(chalk.gray(`\nUpdating every ${options.interval}s...`));
      } catch (error) {
        console.error(chalk.red('Error: '), error.message);
      }
    }
    
    await update();    
    const intervalId = setInterval(update, interval);
    
    process.on('SIGINT', () => {
      clearInterval(intervalId);
      console.log(chalk.yellow('\nStopped watching'));
      process.exit(0);
    });
  });

program.parse(process.argv);

if (!process.argv.slice(2).length) {
  program.outputHelp();
}