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
  },
): T[] {
  if (raw === null) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return options.corrupt(options.parseError);
  }
  const value = parsed as Record<string, unknown>;
  const collection = value[options.collectionKey];
  if (
    !exactPlainObject(value, ['protocol', options.collectionKey]) ||
    value.protocol !== options.protocol ||
    !Array.isArray(collection) ||
    collection.length > options.maxEntries
  ) return options.corrupt(options.structureError);
  return collection.map(options.parseEntry);
}

export function hasUniqueCollectionFields<T>(
  values: T[],
  fields: Array<keyof T>,
): boolean {
  return fields.every((field) => new Set(values.map((value) => value[field])).size === values.length);
}
