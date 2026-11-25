import {
  DEFAULT_EMOJI_SEARCH_LIMIT,
  DEFAULT_FREQUENT_EMOJI_LIMIT,
  MAX_EMOJI_USAGE_COUNT,
  MAX_TRACKED_EMOJIS,
  DEFAULT_FREQUENT_VALUES,
  CATEGORY_SEARCH_ALIASES,
  EMOJI_SEARCH_ALIASES,
} from './constants';
import { STORAGE_KEYS, STORAGE_STORES } from './database/storage-keys';
import type { SecureDB } from './database/secureDB';
import { hasPrototypePollutionKeys, isPlainObject } from './sanitizers';

export interface EmojiRecord {
  readonly emoji: string;
  readonly name: string;
  readonly categoryId: string;
  readonly subgroupId: string;
}

export interface EmojiCategory {
  readonly id: string;
  readonly label: string;
  readonly emojis: readonly EmojiRecord[];
}

export interface EmojiCatalogView {
  readonly version: string;
  readonly categories: readonly EmojiCategory[];
  readonly frequent: readonly EmojiRecord[];
}

interface IndexedEmojiRecord extends EmojiRecord {
  readonly order: number;
  readonly normalizedName: string;
  readonly searchText: string;
}

interface UsageEntry {
  count: number;
  lastUsed: number;
}

interface UsageState {
  stats: Map<string, UsageEntry>;
  loaded: boolean;
  loadPromise: Promise<void> | null;
  persistChain: Promise<void>;
  persistDirty: boolean;
  persistRunning: boolean;
}

type PersistedUsage = Record<string, readonly [count: number, lastUsed: number]>;

function normalizeText(value: string): string {
  return value
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLocaleLowerCase('en-US')
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}

let localEmojiVersion = 'unknown';
let allEmojiRecords: IndexedEmojiRecord[] = [];
let emojiCategories: readonly EmojiCategory[] = [];
let emojiByValue = new Map<string, IndexedEmojiRecord>();
let emojiCatalogPromise: Promise<void> | null = null;

function validateEmojiCatalogLoaded(): Promise<void> {
  if (!emojiCatalogPromise) {
    emojiCatalogPromise = import('../data/emoji-catalog').then((localCatalog) => {
      const nextRecords: IndexedEmojiRecord[] = [];
      const nextCategories = localCatalog.LOCAL_EMOJI_CATEGORIES.map((category) => {
        const records: IndexedEmojiRecord[] = [];
        const categoryAliases = CATEGORY_SEARCH_ALIASES[category.id] ?? '';

        for (const entry of category.emojis) {
          const subgroupWords = entry.subgroupId.replace(/-/g, ' ');
          const normalizedName = normalizeText(entry.name);
          const record: IndexedEmojiRecord = {
            emoji: entry.emoji,
            name: entry.name,
            categoryId: category.id,
            subgroupId: entry.subgroupId,
            order: nextRecords.length,
            normalizedName,
            searchText: normalizeText(
              `${entry.name} ${category.label} ${subgroupWords} ${categoryAliases} ${EMOJI_SEARCH_ALIASES[entry.emoji] ?? ''}`,
            ),
          };
          records.push(record);
          nextRecords.push(record);
        }

        return { id: category.id, label: category.label, emojis: records };
      });

      localEmojiVersion = localCatalog.LOCAL_EMOJI_VERSION;
      allEmojiRecords = nextRecords;
      emojiCategories = nextCategories;
      emojiByValue = new Map(nextRecords.map((record) => [record.emoji, record]));
    });
  }
  return emojiCatalogPromise;
}

function newUsageState(loaded: boolean): UsageState {
  return {
    stats: new Map(),
    loaded,
    loadPromise: null,
    persistChain: Promise.resolve(),
    persistDirty: false,
    persistRunning: false,
  };
}

const usageByDatabase = new WeakMap<SecureDB, UsageState>();

function getUsageState(secureDB: SecureDB): UsageState {
  let state = usageByDatabase.get(secureDB);
  if (!state) {
    state = newUsageState(false);
    usageByDatabase.set(secureDB, state);
  }
  return state;
}

function parseUsageEntry(value: unknown): UsageEntry {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new Error('Stored emoji usage entry is invalid');
  }

  const count = value[0];
  const lastUsed = value[1];
  if (
    !Number.isSafeInteger(count) ||
    count <= 0 ||
    count > MAX_EMOJI_USAGE_COUNT ||
    !Number.isSafeInteger(lastUsed) ||
    lastUsed < 0 ||
    lastUsed > Date.now()
  ) throw new Error('Stored emoji usage entry is invalid');
  return {
    count,
    lastUsed,
  };
}

function parsePersistedUsage(value: unknown): Map<string, UsageEntry> {
  const parsed = new Map<string, UsageEntry>();
  if (value === null || value === undefined) return parsed;
  if (!isPlainObject(value) || hasPrototypePollutionKeys(value)) {
    throw new Error('Stored emoji usage state is invalid');
  }

  for (const [emoji, rawEntry] of Object.entries(value)) {
    if (!emojiByValue.has(emoji)) throw new Error('Stored emoji usage state is invalid');
    const entry = parseUsageEntry(rawEntry);
    parsed.set(emoji, entry);
  }

  return parsed;
}

async function validateUsageLoaded(state: UsageState, secureDB: SecureDB): Promise<void> {
  if (state.loaded) return;
  if (!state.loadPromise) {
    state.loadPromise = (async () => {
      const stored = await secureDB.retrieve(STORAGE_STORES.EMOJI_DATA, STORAGE_KEYS.USAGE_STATS);
      state.stats = parsePersistedUsage(stored);
      state.loaded = true;
    })();
  }
  await state.loadPromise;
}

function usageScore(entry: UsageEntry | undefined, now: number): number {
  if (!entry) return 0;
  const frequency = Math.log2(entry.count + 1) * 10;
  if (!entry.lastUsed) return frequency;

  const ageDays = Math.max(0, now - entry.lastUsed) / 86_400_000;
  const recency = 12 * Math.exp(-ageDays / 21);
  return frequency + recency;
}

function pruneUsage(state: UsageState): void {
  if (state.stats.size <= MAX_TRACKED_EMOJIS) return;
  const now = Date.now();
  const entries = [...state.stats.entries()].sort(
    (left, right) => usageScore(left[1], now) - usageScore(right[1], now),
  );
  for (let index = 0; index < entries.length - MAX_TRACKED_EMOJIS; index += 1) {
    state.stats.delete(entries[index][0]);
  }
}

function persistUsage(state: UsageState, secureDB: SecureDB): Promise<void> {
  state.persistDirty = true;
  if (state.persistRunning) return state.persistChain;

  state.persistRunning = true;
  state.persistChain = (async () => {
    while (state.persistDirty) {
      state.persistDirty = false;
      const payload: PersistedUsage = Object.fromEntries(
        [...state.stats.entries()].map(([emoji, entry]) => [
          emoji,
          [entry.count, entry.lastUsed] as const,
        ]),
      );
      await secureDB.store(STORAGE_STORES.EMOJI_DATA, STORAGE_KEYS.USAGE_STATS, payload);
    }
  })().finally(() => {
    state.persistRunning = false;
  });
  return state.persistChain;
}

function getFrequentRecords(state: UsageState, limit = DEFAULT_FREQUENT_EMOJI_LIMIT): EmojiRecord[] {
  const now = Date.now();
  const ranked = [...state.stats.entries()]
    .map(([emoji, usage]) => ({ record: emojiByValue.get(emoji), score: usageScore(usage, now) }))
    .filter((item): item is { record: IndexedEmojiRecord; score: number } => Boolean(item.record))
    .sort((left, right) => right.score - left.score || left.record.order - right.record.order)
    .map((item) => item.record);

  const seen = new Set(ranked.map((record) => record.emoji));
  for (const emoji of DEFAULT_FREQUENT_VALUES) {
    if (ranked.length >= limit) break;
    const record = emojiByValue.get(emoji);
    if (record && !seen.has(emoji)) {
      ranked.push(record);
      seen.add(emoji);
    }
  }

  return ranked.slice(0, limit);
}

function searchScore(
  record: IndexedEmojiRecord,
  normalizedQuery: string,
  terms: readonly string[],
  state: UsageState,
  now: number,
): number {
  if (!terms.every((term) => record.searchText.includes(term))) return -1;

  let score = 100;
  if (record.normalizedName === normalizedQuery) score += 500;
  else if (record.normalizedName.startsWith(normalizedQuery)) score += 300;
  else if (record.normalizedName.includes(normalizedQuery)) score += 180;
  else if (record.searchText.includes(normalizedQuery)) score += 90;

  const paddedName = ` ${record.normalizedName} `;
  for (const term of terms) {
    if (paddedName.includes(` ${term} `)) score += 35;
    else if (record.normalizedName.includes(term)) score += 15;
  }

  return score + Math.min(50, usageScore(state.stats.get(record.emoji), now));
}

export async function getEmojiCatalog(secureDB: SecureDB): Promise<EmojiCatalogView> {
  await validateEmojiCatalogLoaded();
  const state = getUsageState(secureDB);
  await validateUsageLoaded(state, secureDB);
  return {
    version: localEmojiVersion,
    categories: emojiCategories,
    frequent: getFrequentRecords(state),
  };
}

export function searchEmojiCatalog(
  query: string,
  secureDB: SecureDB,
  limit = DEFAULT_EMOJI_SEARCH_LIMIT,
): readonly EmojiRecord[] {
  const trimmed = query.trim().slice(0, 80);
  if (!trimmed) return [];

  const exactEmoji = emojiByValue.get(trimmed);
  if (exactEmoji) return [exactEmoji];

  const normalizedQuery = normalizeText(trimmed);
  if (!normalizedQuery) return [];

  const terms = normalizedQuery.split(' ').filter(Boolean);
  const state = getUsageState(secureDB);
  const now = Date.now();
  const safeLimit = Math.max(1, Math.min(Math.floor(limit), 500));

  return allEmojiRecords
    .map((record) => ({
      record,
      score: searchScore(record, normalizedQuery, terms, state, now),
    }))
    .filter((item) => item.score >= 0)
    .sort((left, right) => right.score - left.score || left.record.order - right.record.order)
    .slice(0, safeLimit)
    .map((item) => item.record);
}

export async function recordEmojiUsage(emoji: string, secureDB: SecureDB): Promise<void> {
  await validateEmojiCatalogLoaded();
  if (!emojiByValue.has(emoji)) return;

  const state = getUsageState(secureDB);
  await validateUsageLoaded(state, secureDB);

  const previous = state.stats.get(emoji);
  state.stats.set(emoji, {
    count: Math.min((previous?.count ?? 0) + 1, MAX_EMOJI_USAGE_COUNT),
    lastUsed: Date.now(),
  });
  pruneUsage(state);

  await persistUsage(state, secureDB);
}
