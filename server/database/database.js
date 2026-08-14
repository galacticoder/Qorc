/**
 * Main Database Module
 */

export {
  closePgPool,
  destroyDatabaseSecrets,
  getPgPool,
  privateLookupId
} from './core.js';

export { initDatabase } from './schema.js';
export { UserDatabase } from './user-db.js';
export { DiscoveryDB } from './discovery-db.js';
