export function normalizeToWss(value: string): string {
  let address = value.trim();
  if (!address || address.length > 2048) return '';
  if (/^(?:https?|ws):\/\//i.test(address)) address = address.replace(/^[^:]+:/, 'wss:');
  else if (!/^wss:\/\//i.test(address)) address = `wss://${address}`;
  try {
    const url = new URL(address);
    if (url.protocol !== 'wss:' || !url.hostname || url.hostname.length > 253 ||
      url.username || url.password || url.search || url.hash || url.pathname !== '/') return '';
    return url.toString();
  } catch {
    return '';
  }
}
