export function safeServiceEndpointForDisplay(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) return null;
  try {
    const url = new URL(rawUrl);
    if (!url.protocol || !url.hostname) return null;
    const port = url.port ? `:${url.port}` : '';
    const pathname = url.pathname && url.pathname !== '/' ? url.pathname : '';
    return `${url.protocol}//${url.hostname}${port}${pathname}`;
  } catch {
    return null;
  }
}
