export type ParsedP2PEndpoint = {
  endpointUrl: string;
  endpointId: string;
};

const IROH_PREFIX = 'iroh://';

// Accept only iroh endpoints in iroh://<endpoint_id_hex> form
export function normalizeP2PEndpointUrl(input: string | null | undefined): string | undefined {
  if (typeof input !== 'string') return undefined;
  const trimmed = input.trim();
  if (!trimmed) return undefined;

  if (!trimmed.startsWith(IROH_PREFIX)) return undefined;

  const rawRest = trimmed.slice(IROH_PREFIX.length).trim();
  const endpointId = rawRest.split('?', 1)[0]?.trim();
  if (!endpointId || endpointId.length < 16) return undefined;

  return `${IROH_PREFIX}${rawRest}`;
}

export function parseP2PEndpointUrl(input: string | null | undefined): ParsedP2PEndpoint | null {
  const normalized = normalizeP2PEndpointUrl(input);
  if (!normalized) return null;

  const endpointId = normalized.slice(IROH_PREFIX.length).split('?', 1)[0];
  return {
    endpointUrl: normalized,
    endpointId
  };
}
