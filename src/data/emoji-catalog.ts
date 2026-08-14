import emojiTestSource from '../../data/unicode/emoji/17.0/emoji-test.txt?raw';

export interface LocalEmojiEntry {
  readonly emoji: string;
  readonly name: string;
  readonly subgroupId: string;
}

export interface LocalEmojiCategory {
  readonly id: string;
  readonly label: string;
  readonly emojis: readonly LocalEmojiEntry[];
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/&/g, ' and ')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

function sequenceToEmoji(sequence: string): string {
  return String.fromCodePoint(
    ...sequence.trim().split(/\s+/).map((value) => Number.parseInt(value, 16)),
  );
}

function parseEmojiTest(source: string): readonly LocalEmojiCategory[] {
  const categories: Array<{ id: string; label: string; emojis: LocalEmojiEntry[] }> = [];
  let currentCategory: (typeof categories)[number] | null = null;
  let currentSubgroupId = '';

  for (const line of source.split(/\r?\n/)) {
    const groupMatch = line.match(/^# group: (.+)$/);
    if (groupMatch) {
      currentCategory = {
        id: slugify(groupMatch[1]),
        label: groupMatch[1],
        emojis: [],
      };
      currentSubgroupId = '';
      categories.push(currentCategory);
      continue;
    }

    const subgroupMatch = line.match(/^# subgroup: (.+)$/);
    if (subgroupMatch) {
      currentSubgroupId = slugify(subgroupMatch[1]);
      continue;
    }

    const emojiMatch = line.match(
      /^([0-9A-F ]+)\s*;\s*fully-qualified\s*#\s*(\S+)\s+E\d+(?:\.\d+)?\s+(.+)$/u,
    );
    if (!emojiMatch || !currentCategory || !currentSubgroupId) continue;

    const emoji = sequenceToEmoji(emojiMatch[1]);
    if (emoji !== emojiMatch[2]) {
      throw new Error(`Invalid Unicode emoji entry: ${emojiMatch[1].trim()}`);
    }
    currentCategory.emojis.push({
      emoji,
      name: emojiMatch[3].trim(),
      subgroupId: currentSubgroupId,
    });
  }

  return categories.filter((category) => category.emojis.length > 0);
}

const versionMatch = emojiTestSource.match(/^# Version: (.+)$/m);

export const LOCAL_EMOJI_VERSION = versionMatch?.[1].trim() ?? 'unknown';
export const LOCAL_EMOJI_CATEGORIES = parseEmojiTest(emojiTestSource);
