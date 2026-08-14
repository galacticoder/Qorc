import { exactPlainObject } from '../../../shared/key-transparency-protocol.js';

export function parseProtocolCollectionStore<T>(
  raw: string | null,
  options: {
    protocol: string;
    collectionKey: string;
    maxEntries: number;
    parseEntry: (value: unknown) => T;
    corrupt: (message: string) => never;
    parseError: string;
    structureError: string;
    emptyStringIsEmpty?: boolean;
  },
): T[] {
  if (raw === null || (options.emptyStringIsEmpty && raw === '')) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return options.corrupt(options.parseError);
  }
  const value = parsed as Record<string, unknown>;
  if (
    !exactPlainObject(value, ['protocol', options.collectionKey]) ||
    value.protocol !== options.protocol ||
    !Array.isArray(value[options.collectionKey]) ||
    value[options.collectionKey].length > options.maxEntries
  ) return options.corrupt(options.structureError);
  return value[options.collectionKey].map(options.parseEntry);
}

export function hasUniqueCollectionFields<T extends Record<string, unknown>>(
  values: T[],
  fields: Array<keyof T>,
): boolean {
  return fields.every((field) => new Set(values.map((value) => value[field])).size === values.length);
}
