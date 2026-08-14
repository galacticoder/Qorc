import { NO_STORE_CACHE_CONTROL } from '../config/infrastructure.js';

export function setNoStoreHeaders(res) {
  res.setHeader('Cache-Control', NO_STORE_CACHE_CONTROL);
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
}
