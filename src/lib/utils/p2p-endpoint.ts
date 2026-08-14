export type ParsedP2PEndpoint = {
  endpointUrl: string;
  endpointId: string;
  hasDirectAddress: boolean;
};

const ONION_PREFIX = 'onion://';
const ONION_HOST_RE = /^[a-z2-7]{56}\.onion$/;
export function normalizeP2PEndpointUrl(input: string | null | undefined): string | undefined {
  if (typeof input !== 'string') return undefined;
  if (input !== input.trim() || !input || input.length > 512) return undefined;
  if (!input.startsWith(ONION_PREFIX)) return undefined;

  const host = input.slice(ONION_PREFIX.length).toLowerCase();
  if (!ONION_HOST_RE.test(host)) return undefined;

  return `${ONION_PREFIX}${host}`;
}

export function parseP2PEndpointUrl(input: string | null | undefined): ParsedP2PEndpoint | null {
  const normalized = normalizeP2PEndpointUrl(input);
  if (!normalized) return null;

  const host = normalized.slice(ONION_PREFIX.length);
  return {
    endpointUrl: normalized,
    endpointId: host,
    hasDirectAddress: true
  };
}
