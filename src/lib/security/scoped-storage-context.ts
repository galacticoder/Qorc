export interface ScopedStorageOwnership {
  accountOwner: string;
  domain: string;
  parts: readonly string[];
}

const contexts = new Map<string, ScopedStorageOwnership>();
const MAX_CONTEXTS = 32_768;

export function rememberScopedStorageContext(key: string, context: ScopedStorageOwnership): void {
  if (contexts.has(key)) contexts.delete(key);
  contexts.set(key, { ...context, parts: [...context.parts] });
  if (contexts.size > MAX_CONTEXTS) contexts.delete(contexts.keys().next().value!);
}

export function scopedStorageContext(key: string): ScopedStorageOwnership | undefined {
  const context = contexts.get(key);
  return context ? { ...context, parts: [...context.parts] } : undefined;
}
