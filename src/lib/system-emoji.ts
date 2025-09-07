/**
 * Custom Emoji System
 *
 * Provides a curated set of commonly used emojis for reactions
 * without relying on external APIs that may fail due to CORS.
 */

// Curated emoji categories for reactions
const EMOJI_CATEGORIES = {
  faces: [
    '😀', '😃', '😄', '😁', '😆', '😅', '🤣', '😂', '🙂', '🙃',
    '😉', '😊', '😇', '🥰', '😍', '🤩', '😘', '😗', '😚', '😙',
    '😋', '😛', '😜', '🤪', '😝', '🤑', '🤗', '🤭', '🤫', '🤔',
    '🤐', '🤨', '😐', '😑', '😶', '😏', '😒', '🙄', '😬', '🤥',
    '😔', '😪', '🤤', '😴', '😷', '🤒', '🤕', '🤢', '🤮', '🤧',
    '🥵', '🥶', '🥴', '😵', '🤯', '🤠', '🥳', '😎', '🤓', '🧐'
  ],
  emotions: [
    '😕', '😟', '🙁', '☹️', '😮', '😯', '😲', '😳', '🥺', '😦',
    '😧', '😨', '😰', '😥', '😢', '😭', '😱', '😖', '😣', '😞',
    '😓', '😩', '😫', '🥱', '😤', '😡', '😠', '🤬', '😈', '👿'
  ],
  gestures: [
    '👍', '👎', '👌', '🤌', '🤏', '✌️', '🤞', '🤟', '🤘', '🤙',
    '👈', '👉', '👆', '🖕', '👇', '☝️', '👋', '🤚', '🖐️', '✋',
    '🖖', '👏', '🙌', '🤝', '🙏', '✊', '👊', '🤛', '🤜', '💪'
  ],
  hearts: [
    '❤️', '🧡', '💛', '💚', '💙', '💜', '🖤', '🤍', '🤎', '💔',
    '❣️', '💕', '💞', '💓', '💗', '💖', '💘', '💝', '💟', '♥️'
  ],
  objects: [
    '💢', '💥', '💫', '💦', '💨', '🕳️', '💣', '💬', '👁️‍🗨️',
    '🗨️', '🗯️', '💭', '💤', '🔥', '⭐', '🌟', '✨', '⚡',
    '☄️', '🔴', '🟠', '🟡', '🟢', '🔵', '🟣', '⚫', '⚪'
  ],
  symbols: [
    '✅', '❌', '❓', '❗', '⭕', '🚫', '💯', '🔞', '📵', '🚭',
    '🚯', '🚱', '🚷', '📴', '♻️', '⚠️', '🔱', '📛', '🔰', '✳️',
    '❇️', '✴️', '🆔', '🆚', '📳', '🆕', '🆓', '🆙', '🆗'
  ]
};

// Flatten all emojis into a single array and remove duplicates
const ALL_EMOJIS = [...new Set(Object.values(EMOJI_CATEGORIES).flat().filter(emoji => emoji.trim() !== ''))];

export interface EmojiCategory {
  name: string;
  emojis: string[];
}

export function getEmojiCategories(): EmojiCategory[] {
  return [
    { name: 'Faces', emojis: EMOJI_CATEGORIES.faces },
    { name: 'Emotions', emojis: EMOJI_CATEGORIES.emotions },
    { name: 'Gestures', emojis: EMOJI_CATEGORIES.gestures },
    { name: 'Hearts', emojis: EMOJI_CATEGORIES.hearts },
    { name: 'Objects', emojis: EMOJI_CATEGORIES.objects },
    { name: 'Symbols', emojis: EMOJI_CATEGORIES.symbols }
  ];
}

export async function getSystemEmojis(): Promise<string[]> {
  // Try Electron bridge first (if available)
  try {
    const bridge = (window as any).edgeApi || (window as any).electronAPI;
    if (bridge && typeof bridge.getSystemEmojis === 'function') {
      const list = await bridge.getSystemEmojis();
      if (Array.isArray(list) && list.length > 0) return list;
    }
  } catch (err) {
    console.warn('[system-emoji] edgeApi.getSystemEmojis failed:', err);
  }

  // Return our curated emoji set
  return ALL_EMOJIS;
}

export function paginateEmojis(emojis: string[], page: number, pageSize: number): string[] {
  const start = page * pageSize;
  return emojis.slice(start, start + pageSize);
}

export function searchEmojis(query: string, emojis: string[] = ALL_EMOJIS): string[] {
  if (!query.trim()) return emojis;

  // Simple search - could be enhanced with emoji names/descriptions
  return emojis.filter(() => {
    // For now, just return all emojis if there's a query
    // In the future, we could add emoji name mappings
    return true;
  });
}


