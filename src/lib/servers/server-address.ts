import {
  SERVER_ADDRESS_ADDRESS_LENGTH_LIMIT,
  SERVER_ADDRESS_URL_HOSTNAME_LENGTH_LIMIT,
} from '../constants';
export function normalizeToWss(value: string): string {
  let address = value.trim();
  if (!address || address.length > SERVER_ADDRESS_ADDRESS_LENGTH_LIMIT) return '';
  if (/^(?:https?|ws):\/\//i.test(address)) address = address.replace(/^[^:]+:/, 'wss:');
  else if (!/^wss:\/\//i.test(address)) address = `wss://${address}`;
  try {
    const url = new URL(address);
    if (url.protocol !== 'wss:' || !url.hostname || url.hostname.length > SERVER_ADDRESS_URL_HOSTNAME_LENGTH_LIMIT ||
      url.username || url.password || url.search || url.hash || url.pathname !== '/') return '';
    return url.toString();
  } catch {
    return '';
  }
}
