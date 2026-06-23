import { STORAGE_KEYS } from './database/storage-keys';
import { SecureDB } from './database/secureDB';
import { isTauri } from './tauri-bindings';

async function computeIntegrityHash(emojis: ReadonlyArray<string>): Promise<string> {
  const text = emojis.join('');

  if (typeof globalThis.crypto?.subtle === 'undefined') {
    let fallback = 0;
    for (let i = 0; i < text.length; i++) {
      fallback = Math.imul(31, fallback) + text.charCodeAt(i);
      fallback |= 0;
    }
    return fallback.toString(16);
  }

  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(digest));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function verifyEmojiIntegrity(emojis: string[], hash: string | null): Promise<boolean> {
  if (!hash) return false;
  const computed = await computeIntegrityHash(emojis);
  return computed === hash;
}

function deepFreeze<T>(obj: T): Readonly<T> {
  if (obj === null || typeof obj !== 'object' || Object.isFrozen(obj)) {
    return obj as Readonly<T>;
  }
  Object.freeze(obj);
  for (const key of Object.getOwnPropertyNames(obj)) {
    const record = obj as Record<string, unknown>;
    const value = record[key];
    if (value && typeof value === 'object') {
      deepFreeze(value);
    }
  }
  return obj as Readonly<T>;
}

function sanitizeSearchQuery(query: string): string {
  return query
    .replace(/<[^>]*>/g, '')
    .replace(/[<>'"]/g, '')
    .slice(0, CONFIG.MAX_SEARCH_QUERY_LENGTH)
    .trim();
}
/**
 * System emoji management
 */

interface SecureBridgeAPI {
  getSystemEmojis?: () => Promise<string[]>;
}

const CONFIG = Object.freeze({
  CACHE_TTL: 5 * 60 * 1000,
  MAX_EMOJI_LENGTH: 10,
  DEFAULT_CATEGORY_SIZE: 20,
  SEARCH_CACHE_LIMIT: 100,
  RATE_LIMIT_WINDOW: 1000,
  RATE_LIMIT_MAX_REQUESTS: 25,
  MAX_PAGE_SIZE: 100,
  MAX_PAGE_NUMBER: 1000,
  MAX_SEARCH_QUERY_LENGTH: 64,
  SEARCH_DEBOUNCE_MS: 150
} as const);

class LRUCache<K, V> {
  private cache = new Map<K, V>();

  constructor(private readonly maxSize: number) { }

  get(key: K): V | undefined {
    const value = this.cache.get(key);
    if (value !== undefined) {
      this.cache.delete(key);
      this.cache.set(key, value);
    }
    return value;
  }

  set(key: K, value: V): void {
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey !== undefined) {
        this.cache.delete(firstKey);
      }
    }
    this.cache.set(key, value);
  }

  clear(): void {
    this.cache.clear();
  }
}

const FALLBACK_EMOJIS = deepFreeze([
  '😀', '😃', '😄', '😁', '😆', '😅', '🤣', '😂', '🙂', '🙃', '🫠', '😉', '😊', '😇',
  '🥰', '😍', '🤩', '😘', '😗', '☺️', '😚', '😙', '🥲', '😋', '😛', '😜', '🤪', '😝',
  '🤑', '🤗', '🤭', '🫢', '🫣', '🤫', '🤔', '🫡', '🤐', '🤨', '😐', '😑', '😶', '🫥',
  '😏', '😒', '🙄', '😬', '🤥', '🫨', '😌', '😔', '😪', '🤤', '😴', '😷', '🤒', '🤕',
  '🤢', '🤮', '🤧', '🥵', '🥶', '🥴', '😵', '🤯', '🤠', '🥳', '🥸', '😎', '🤓', '🧐',
  '😕', '🫤', '😟', '🙁', '☹️', '😮', '😯', '😲', '😳', '🥺', '🥹', '😦', '😧', '😨',
  '😰', '😥', '😢', '😭', '😱', '😖', '😣', '😞', '😓', '😩', '😫', '🥱', '😤', '😡',
  '😠', '🤬', '😈', '👿', '💀', '☠️', '💩', '🤡', '👹', '👺', '👻', '👽', '👾', '🤖',
  '😺', '😸', '😹', '😻', '😼', '😽', '🙀', '😿', '😾', '🙈', '🙉', '🙊',
  '💋', '💌', '💘', '💝', '💖', '💗', '💓', '💞', '💕', '💟', '❣️', '💔', '❤️‍🔥', '❤️‍🩹',
  '❤️', '🩷', '🧡', '💛', '💚', '💙', '🩵', '💜', '🤎', '🖤', '🩶', '🤍', '💯', '💢',
  '💥', '💫', '💦', '💨', '🕳️', '💣', '💬', '👁️‍🗨️', '🗨️', '🗯️', '💭', '💤',
  '👋', '🤚', '🖐️', '✋', '🖖', '🫱', '🫲', '🫳', '🫴', '👌', '🤌', '🤏', '✌️', '🤞',
  '🫰', '🤟', '🤘', '🤙', '👈', '👉', '👆', '🖕', '👇', '☝️', '🫵', '👍', '👎', '✊',
  '👊', '🤛', '🤜', '👏', '🙌', '🫶', '👐', '🤲', '🤝', '🙏', '✍️', '💅', '🤳', '💪',
  '🦾', '🦿', '🦵', '🦶', '👂', '🦻', '👃', '🧠', '🫀', '🫁', '🦷', '🦴', '👀', '👁️',
  '👅', '👄', '🫦', '👶', '🧒', '👦', '👧', '🧑', '👱', '👨', '🧔', '👩', '🧓', '👴',
  '👵', '🙍', '🙎', '🙅', '🙆', '💁', '🙋', '🧏', '🙇', '🤦', '🤷', '👮', '🕵️', '💂',
  '🥷', '👷', '🫅', '🤴', '👸', '👳', '👲', '🧕', '🤵', '👰', '🤰', '🫃', '🫄', '🤱',
  '👼', '🎅', '🤶', '🦸', '🦹', '🧙', '🧚', '🧛', '🧜', '🧝', '🧞', '🧟', '🧌', '💆',
  '💇', '🚶', '🧍', '🧎', '🏃', '💃', '🕺', '🕴️', '👯', '🧖', '🧗', '🤸', '🏌️', '🏇',
  '⛷️', '🏂', '🏋️', '🤼', '🤽', '🤾', '🤺', '⛹️', '🏊', '🚣', '🧘', '🛀', '🛌',
  '👭', '👫', '👬', '💏', '💑', '👨‍👩‍👦', '👨‍👩‍👧', '👨‍👩‍👧‍👦', '👨‍👩‍👦‍👦', '👨‍👩‍👧‍👧', '👨‍👦', '👨‍👦‍👦',
  '👨‍👧', '👨‍👧‍👦', '👨‍👧‍👧', '👩‍👦', '👩‍👦‍👦', '👩‍👧', '👩‍👧‍👦', '👩‍👧‍👧',
  '🐵', '🐒', '🦍', '🦧', '🐶', '🐕', '🦮', '🐕‍🦺', '🐩', '🐺', '🦊', '🦝', '🐱', '🐈',
  '🐈‍⬛', '🦁', '🐯', '🐅', '🐆', '🐴', '🫎', '🫏', '🐎', '🦄', '🦓', '🦌', '🦬', '🐮',
  '🐂', '🐃', '🐄', '🐷', '🐖', '🐗', '🐽', '🐏', '🐑', '🐐', '🐪', '🐫', '🦙', '🦒',
  '🐘', '🦣', '🦏', '🦛', '🐭', '🐁', '🐀', '🐹', '🐰', '🐇', '🐿️', '🦫', '🦔', '🦇',
  '🐻', '🐻‍❄️', '🐨', '🐼', '🦥', '🦦', '🦨', '🦘', '🦡', '🐾', '🦃', '🐔', '🐓', '🐣',
  '🐤', '🐥', '🐦', '🐧', '🕊️', '🦅', '🦆', '🦢', '🦉', '🦤', '🪶', '🦩', '🦚', '🦜',
  '🪽', '🐦‍⬛', '🪿', '🐸', '🐊', '🐢', '🦎', '🐍', '🐲', '🐉', '🦕', '🦖', '🐳', '🐋',
  '🐬', '🦭', '🐟', '🐠', '🐡', '🦈', '🐙', '🐚', '🪸', '🪼', '🐌', '🦋', '🐛', '🐜',
  '🐝', '🪲', '🐞', '🦗', '🪳', '🕷️', '🕸️', '🦂', '🦟', '🪰', '🪱', '🦠', '💐', '🌸',
  '💮', '🪷', '🏵️', '🌹', '🥀', '🌺', '🌻', '🌼', '🌷', '🪻', '🌱', '🪴', '🌲', '🌳',
  '🌴', '🌵', '🌾', '🌿', '☘️', '🍀', '🍁', '🍂', '🍃', '🪹', '🪺', '🍄',
  '🍇', '🍈', '🍉', '🍊', '🍋', '🍌', '🍍', '🥭', '🍎', '🍏', '🍐', '🍑', '🍒', '🍓',
  '🫐', '🥝', '🍅', '🫒', '🥥', '🥑', '🍆', '🥔', '🥕', '🌽', '🌶️', '🫑', '🥒', '🥬',
  '🥦', '🧄', '🧅', '🍄', '🥜', '🫘', '🌰', '🫚', '🫛', '🍞', '🥐', '🥖', '🫓', '🥨',
  '🥯', '🥞', '🧇', '🧀', '🍖', '🍗', '🥩', '🥓', '🍔', '🍟', '🍕', '🌭', '🥪', '🌮',
  '🌯', '🫔', '🥙', '🧆', '🥚', '🍳', '🥘', '🍲', '🫕', '🥣', '🥗', '🍿', '🧈', '🧂',
  '🥫', '🍱', '🍘', '🍙', '🍚', '🍛', '🍜', '🍝', '🍠', '🍢', '🍣', '🍤', '🍥', '🥮',
  '🍡', '🥟', '🥠', '🥡', '🦀', '🦞', '🦐', '🦑', '🦪', '🍦', '🍧', '🍨', '🍩', '🍪',
  '🎂', '🍰', '🧁', '🥧', '🍫', '🍬', '🍭', '🍮', '🍯', '🍼', '🥛', '☕', '🫖', '🍵',
  '🍶', '🍾', '🍷', '🍸', '🍹', '🍺', '🍻', '🥂', '🥃', '🫗', '🥤', '🧋', '🧃', '🧉',
  '🧊', '🥢', '🍽️', '🍴', '🥄', '🔪', '🫙', '🏺',
  '⚽', '🏀', '🏈', '⚾', '🥎', '🎾', '🏐', '🏉', '🥏', '🎱', '🪀', '🏓', '🏸', '🏒',
  '🏑', '🥍', '🏏', '🪃', '🥅', '⛳', '🪁', '🏹', '🎣', '🤿', '🥊', '🥋', '🎽', '🛹',
  '🛼', '🛷', '⛸️', '🥌', '🎿', '⛷️', '🏂', '🪂', '🏋️', '🤸', '🤺', '⛹️', '🤾', '🏌️',
  '🏇', '🧘', '🏄', '🏊', '🤽', '🚣', '🧗', '🚴', '🚵', '🎖️', '🏆', '🏅', '🥇', '🥈',
  '🥉', '🎃', '🎄', '🎆', '🎇', '🧨', '✨', '🎈', '🎉', '🎊', '🎋', '🎍', '🎎', '🎏',
  '🎐', '🎑', '🧧', '🎀', '🎁', '🎗️', '🎟️', '🎫', '🎠', '🎡', '🎢', '🎪', '🤹', '🎭',
  '🎨', '🎬', '🎤', '🎧', '🎼', '🎹', '🪇', '🥁', '🪘', '🎷', '🎺', '🪗', '🎸', '🪕',
  '🎻', '🪈', '🎲', '♟️', '🎯', '🎳', '🎮', '🎰', '🧩',
  '🚗', '🚕', '🚙', '🚌', '🚎', '🏎️', '🚓', '🚑', '🚒', '🚐', '🛻', '🚚', '🚛', '🚜',
  '🏍️', '🛵', '🦽', '🦼', '🛺', '🚲', '🛴', '🛹', '🛼', '🚏', '🛣️', '🛤️', '🛢️', '⛽',
  '🛞', '🚨', '🚥', '🚦', '🛑', '🚧', '⚓', '🛟', '⛵', '🛶', '🚤', '🛳️', '⛴️', '🛥️',
  '🚢', '✈️', '🛩️', '🛫', '🛬', '🪂', '💺', '🚁', '🚟', '🚠', '🚡', '🛰️', '🚀', '🛸',
  '🌍', '🌎', '🌏', '🌐', '🗺️', '🧭', '🏔️', '⛰️', '🌋', '🗻', '🏕️', '🏖️', '🏜️', '🏝️',
  '🏞️', '🏟️', '🏛️', '🏗️', '🧱', '🪨', '🪵', '🛖', '🏘️', '🏚️', '🏠', '🏡', '🏢', '🏣',
  '🏤', '🏥', '🏦', '🏨', '🏩', '🏪', '🏫', '🏬', '🏭', '🏯', '🏰', '💒', '🗼', '🗽',
  '⛪', '🕌', '🛕', '🕍', '⛩️', '🕋', '⛲', '⛺', '🌁', '🌃', '🏙️', '🌄', '🌅', '🌆',
  '🌇', '🌉', '♨️', '🎠', '🛝', '🎡', '🎢', '💈', '🎪',
  '❤️', '🧡', '💛', '💚', '💙', '💜', '🖤', '🤍', '🤎', '💔', '❣️', '💕', '💞', '💓',
  '💗', '💖', '💘', '💝', '💟', '☮️', '✝️', '☪️', '🕉️', '☸️', '✡️', '🔯', '🕎', '☯️',
  '☦️', '🛐', '⛎', '♈', '♉', '♊', '♋', '♌', '♍', '♎', '♏', '♐', '♑', '♒', '♓',
  '🆔', '⚛️', '🉑', '☢️', '☣️', '📴', '📳', '🈶', '🈚', '🈸', '🈺', '🈷️', '✴️', '🆚',
  '💮', '🉐', '㊙️', '㊗️', '🈴', '🈵', '🈹', '🈲', '🅰️', '🅱️', '🆎', '🆑', '🅾️', '🆘',
  '❌', '⭕', '🛑', '⛔', '📛', '🚫', '💯', '💢', '♨️', '🚷', '🚯', '🚳', '🚱', '🔞',
  '📵', '🚭', '❗', '❕', '❓', '❔', '‼️', '⁉️', '🔅', '🔆', '〽️', '⚠️', '🚸', '🔱',
  '⚜️', '🔰', '♻️', '✅', '🈯', '💹', '❇️', '✳️', '❎', '🌐', '💠', 'Ⓜ️', '🌀', '💤',
  '🏧', '🚾', '♿', '🅿️', '🛗', '🈳', '🈂️', '🛂', '🛃', '🛄', '🛅', '🚹', '🚺', '🚼',
  '⚧️', '🚻', '🚮', '🎦', '📶', '🈁', '🔣', 'ℹ️', '🔤', '🔡', '🔠', '🆖', '🆗', '🆙',
  '🆒', '🆕', '🆓', '0️⃣', '1️⃣', '2️⃣', '3️⃣', '4️⃣', '5️⃣', '6️⃣', '7️⃣', '8️⃣', '9️⃣', '🔟',
  '🔢', '#️⃣', '*️⃣', '⏏️', '▶️', '⏸️', '⏯️', '⏹️', '⏺️', '⏭️', '⏮️', '⏩', '⏪', '⏫',
  '⏬', '◀️', '🔼', '🔽', '➡️', '⬅️', '⬆️', '⬇️', '↗️', '↘️', '↙️', '↖️', '↕️', '↔️',
  '↪️', '↩️', '⤴️', '⤵️', '🔀', '🔁', '🔂', '🔄', '🔃', '🎵', '🎶', '➕', '➖', '➗',
  '✖️', '🟰', '♾️', '💲', '💱', '™️', '©️', '®️', '👁️‍🗨️', '🔚', '🔙', '🔛', '🔝', '🔜',
  '〰️', '➰', '➿', '✔️', '☑️', '🔘', '🔴', '🟠', '🟡', '🟢', '🔵', '🟣', '⚫', '⚪',
  '🟤', '🔺', '🔻', '🔸', '🔹', '🔶', '🔷', '🔳', '🔲', '▪️', '▫️', '◾', '◽', '◼️',
  '◻️', '🟥', '🟧', '🟨', '🟩', '🟦', '🟪', '⬛', '⬜', '🟫', '🔈', '🔇', '🔉', '🔊',
  '🔔', '🔕', '📣', '📢', '💬', '💭', '🗯️', '♠️', '♣️', '♥️', '♦️', '🃏', '🎴', '🀄',
  '🕐', '🕑', '🕒', '🕓', '🕔', '🕕', '🕖', '🕗', '🕘', '🕙', '🕚', '🕛', '🕜', '🕝',
  '🕞', '🕟', '🕠', '🕡', '🕢', '🕣', '🕤', '🕥', '🕦', '🕧',
  '🏳️', '🏴', '🏁', '🚩', '🏳️‍🌈', '🏳️‍⚧️', '🏴‍☠️', '🇦🇨', '🇦🇩', '🇦🇪', '🇦🇫', '🇦🇬',
  '🇦🇮', '🇦🇱', '🇦🇲', '🇦🇴', '🇦🇶', '🇦🇷', '🇦🇸', '🇦🇹', '🇦🇺', '🇦🇼', '🇦🇽', '🇦🇿',
  '🇧🇦', '🇧🇧', '🇧🇩', '🇧🇪', '🇧🇫', '🇧🇬', '🇧🇭', '🇧🇮', '🇧🇯', '🇧🇱', '🇧🇲', '🇧🇳',
  '🇧🇴', '🇧🇶', '🇧🇷', '🇧🇸', '🇧🇹', '🇧🇻', '🇧🇼', '🇧🇾', '🇧🇿', '🇨🇦', '🇨🇨', '🇨🇩',
  '🇨🇫', '🇨🇬', '🇨🇭', '🇨🇮', '🇨🇰', '🇨🇱', '🇨🇲', '🇨🇳', '🇨🇴', '🇨🇵', '🇨🇷', '🇨🇺',
  '🇨🇻', '🇨🇼', '🇨🇽', '🇨🇾', '🇨🇿', '🇩🇪', '🇩🇬', '🇩🇯', '🇩🇰', '🇩🇲', '🇩🇴', '🇩🇿',
  '🇪🇦', '🇪🇨', '🇪🇪', '🇪🇬', '🇪🇭', '🇪🇷', '🇪🇸', '🇪🇹', '🇪🇺', '🇫🇮', '🇫🇯', '🇫🇰',
  '🇫🇲', '🇫🇴', '🇫🇷', '🇬🇦', '🇬🇧', '🇬🇩', '🇬🇪', '🇬🇫', '🇬🇬', '🇬🇭', '🇬🇮', '🇬🇱',
  '🇬🇲', '🇬🇳', '🇬🇵', '🇬🇶', '🇬🇷', '🇬🇸', '🇬🇹', '🇬🇺', '🇬🇼', '🇬🇾', '🇭🇰', '🇭🇲',
  '🇭🇳', '🇭🇷', '🇭🇹', '🇭🇺', '🇮🇨', '🇮🇩', '🇮🇪', '🇮🇱', '🇮🇲', '🇮🇳', '🇮🇴', '🇮🇶',
  '🇮🇷', '🇮🇸', '🇮🇹', '🇯🇪', '🇯🇲', '🇯🇴', '🇯🇵', '🇰🇪', '🇰🇬', '🇰🇭', '🇰🇮', '🇰🇲',
  '🇰🇳', '🇰🇵', '🇰🇷', '🇰🇼', '🇰🇾', '🇰🇿', '🇱🇦', '🇱🇧', '🇱🇨', '🇱🇮', '🇱🇰', '🇱🇷',
  '🇱🇸', '🇱🇹', '🇱🇺', '🇱🇻', '🇱🇾', '🇲🇦', '🇲🇨', '🇲🇩', '🇲🇪', '🇲🇫', '🇲🇬', '🇲🇭',
  '🇲🇰', '🇲🇱', '🇲🇲', '🇲🇳', '🇲🇴', '🇲🇵', '🇲🇶', '🇲🇷', '🇲🇸', '🇲🇹', '🇲🇺', '🇲🇻',
  '🇲🇼', '🇲🇽', '🇲🇾', '🇲🇿', '🇳🇦', '🇳🇨', '🇳🇪', '🇳🇫', '🇳🇬', '🇳🇮', '🇳🇱', '🇳🇴',
  '🇳🇵', '🇳🇷', '🇳🇺', '🇳🇿', '🇴🇲', '🇵🇦', '🇵🇪', '🇵🇫', '🇵🇬', '🇵🇭', '🇵🇰', '🇵🇱',
  '🇵🇲', '🇵🇳', '🇵🇷', '🇵🇸', '🇵🇹', '🇵🇼', '🇵🇾', '🇶🇦', '🇷🇪', '🇷🇴', '🇷🇸', '🇷🇺',
  '🇷🇼', '🇸🇦', '🇸🇧', '🇸🇨', '🇸🇩', '🇸🇪', '🇸🇬', '🇸🇭', '🇸🇮', '🇸🇯', '🇸🇰', '🇸🇱',
  '🇸🇲', '🇸🇳', '🇸🇴', '🇸🇷', '🇸🇸', '🇸🇹', '🇸🇻', '🇸🇽', '🇸🇾', '🇸🇿', '🇹🇦', '🇹🇨',
  '🇹🇩', '🇹🇫', '🇹🇬', '🇹🇭', '🇹🇯', '🇹🇰', '🇹🇱', '🇹🇲', '🇹🇳', '🇹🇴', '🇹🇷', '🇹🇹',
  '🇹🇻', '🇹🇼', '🇹🇿', '🇺🇦', '🇺🇬', '🇺🇲', '🇺🇳', '🇺🇸', '🇺🇾', '🇺🇿', '🇻🇦', '🇻🇨',
  '🇻🇪', '🇻🇬', '🇻🇮', '🇻🇳', '🇻🇺', '🇼🇫', '🇼🇸', '🇽🇰', '🇾🇪', '🇾🇹', '🇿🇦', '🇿🇲', '🇿🇼'
]) as ReadonlyArray<string>;

let fallbackEmojisHashPromise: Promise<string> | null = null;

function getFallbackEmojisHash(): Promise<string> {
  if (!fallbackEmojisHashPromise) {
    fallbackEmojisHashPromise = computeIntegrityHash(FALLBACK_EMOJIS);
  }
  return fallbackEmojisHashPromise;
}

const MINIMAL_EMOJIS = Object.freeze(['👍', '👎', '❤️', '✅', '❌'] as const);

const FALLBACK_GROUP_DEFINITIONS = deepFreeze({
  Popular: FALLBACK_EMOJIS.slice(0, CONFIG.DEFAULT_CATEGORY_SIZE),
  Smileys: ['😀', '😃', '😄', '😁', '😆', '😅', '😂', '🤣', '😊', '😍'],
  Gestures: ['👍', '👎', '👏', '🙏', '🤝', '✋', '👌', '🤌', '🤏', '💪'],
  Hearts: ['❤️', '💔', '💖'],
  Symbols: ['💯', '✨', '🔥', '⭐', '⚡', '✅', '❌', '❓', '❗']
}) as Readonly<Record<string, ReadonlyArray<string>>>;

let emojiCache: string[] | null = null;
let cacheTimestamp = 0;
let emojiCacheHash: string | null = null;

const searchCache = new LRUCache<string, string[]>(CONFIG.SEARCH_CACHE_LIMIT);

const searchRateLimit = {
  windowStart: 0,
  count: 0
};

let searchDebounceTimer: ReturnType<typeof setTimeout> | null = null;

const EMOJI_REGEX = /^(\p{Emoji_Presentation}|\p{Extended_Pictographic})(\uFE0F?(\u200D(\p{Emoji_Presentation}|\p{Extended_Pictographic}))*)?$/u;

function logSecurityEvent(event: string, _details?: Record<string, unknown>): void {
  console.error('[system-emoji] security', event);
}

function getSearchPenaltyMs(overLimitCount: number): number {
  const penalty = Math.min(overLimitCount * 100, 5000);
  return penalty;
}

class CircuitBreaker {
  private failureCount = 0;
  private lastFailureTime = 0;

  constructor(
    private readonly failureThreshold: number,
    private readonly resetTimeoutMs: number
  ) { }

  isOpen(): boolean {
    if (this.failureCount < this.failureThreshold) {
      return false;
    }
    const now = Date.now();
    return now - this.lastFailureTime < this.resetTimeoutMs;
  }

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (this.isOpen()) {
      throw new Error('Circuit breaker open - service unavailable');
    }

    try {
      const result = await operation();
      this.failureCount = 0;
      return result;
    } catch (_error) {
      this.failureCount += 1;
      this.lastFailureTime = Date.now();
      throw _error;
    }
  }
}

const bridgeCircuitBreaker = new CircuitBreaker(5, 60_000);

function getSecureBridge(): SecureBridgeAPI | null {
  if (typeof window === 'undefined') {
    return null;
  }
  if (!isTauri()) {
    return null;
  }
  return null;
}

import { torNetworkManager } from './transport/tor-network';

function isTorEnvironment(): boolean {
  if (typeof window === 'undefined') {
    return false;
  }
  try {
    if (typeof (window as any).__TOR_MODE__ === 'boolean') {
      if ((window as any).__TOR_MODE__ === true) return true;
    }

    if (torNetworkManager.isConnected()) {
      return true;
    }

    const hostname = window.location?.hostname ?? '';
    const isOnion = hostname.endsWith('.onion');
    const isTorBrowser = typeof navigator !== 'undefined' &&
      navigator.plugins?.length === 0 &&
      !(navigator as any).webkitTemporaryStorage;
    return isOnion || isTorBrowser;
  } catch {
    return false;
  }
}

function isValidEmoji(candidate: unknown): candidate is string {
  if (typeof candidate !== 'string') return false;
  const trimmed = candidate.trim();
  if (trimmed.length === 0 || trimmed.length > CONFIG.MAX_EMOJI_LENGTH) return false;
  const codePoints = Array.from(trimmed).map((char) => char.codePointAt(0) ?? 0);
  if (codePoints.some((code) => code > 0x10ffff)) {
    return false;
  }
  return EMOJI_REGEX.test(trimmed);
}

// Usage Tracking
const USAGE_STORE = 'emoji_data';
const USAGE_KEY = STORAGE_KEYS.USAGE_STATS;
let usageStats: Record<string, number> = {};
let statsLoaded = false;

async function loadAndMergeStats(secureDB: SecureDB) {
  if (!statsLoaded) {
    try {
      const stored = await secureDB.retrieve(USAGE_STORE, USAGE_KEY);
      if (stored && typeof stored === 'object') {
        const storedStats = stored as Record<string, number>;
        for (const [k, v] of Object.entries(usageStats)) {
          storedStats[k] = (storedStats[k] || 0) + v;
        }
        usageStats = storedStats;
        statsLoaded = true;
      }
    } catch (e) {
      console.error('[SystemEmoji] Failed to load usage stats securely', e);
    }
  }
}

export async function recordEmojiUsage(emoji: string, secureDB?: SecureDB) {
  if (!isValidEmoji(emoji)) return;

  if (secureDB) {
    await loadAndMergeStats(secureDB);
  }

  usageStats[emoji] = (usageStats[emoji] || 0) + 1;

  if (secureDB) {
    try {
      await secureDB.store(USAGE_STORE, USAGE_KEY, usageStats);
    } catch (e) {
      console.error('[SystemEmoji] Failed to save usage stats securely', e);
    }
  }
}

function sortEmojisByUsage(emojis: string[]): string[] {
  return emojis.sort((a, b) => {
    const countA = usageStats[a] || 0;
    const countB = usageStats[b] || 0;
    if (countA > countB) return -1;
    if (countA < countB) return 1;
    return 0;
  });
}

export async function getSystemEmojis(secureDB?: SecureDB): Promise<string[]> {
  if (secureDB) {
    await loadAndMergeStats(secureDB);
  }

  const now = Date.now();
  if (emojiCache && (now - cacheTimestamp) < CONFIG.CACHE_TTL) {
    const integrityOk = await verifyEmojiIntegrity(emojiCache, emojiCacheHash);
    if (!integrityOk) {
      logSecurityEvent('Emoji cache integrity check failed');
      await clearEmojiCache();
      return MINIMAL_EMOJIS.slice();
    }

    return sortEmojisByUsage(emojiCache.slice());
  }

  try {
    const bridge = getSecureBridge();
    if (bridge && typeof bridge.getSystemEmojis === 'function') {
      const list = await bridgeCircuitBreaker.execute(() => bridge.getSystemEmojis!());
      if (Array.isArray(list)) {
        const validated = list.filter(isValidEmoji);
        if (validated.length > 0) {
          const deduped = Array.from(new Set(validated));
          emojiCache = deduped;
          cacheTimestamp = now;
          emojiCacheHash = await computeIntegrityHash(deduped);
          return deduped.slice();
        }
      }
    }
  } catch (_err) {
    console.error('[system-emoji] getSystemEmojis-failed', _err instanceof Error ? _err.message : 'unknown');
  }

  const torActive = isTorEnvironment();
  if (torActive) {
    const remoteList = await fetchRemoteEmojis();
    if (remoteList.length > 0) {
      const deduped = Array.from(new Set(remoteList));
      const sorted = sortEmojisByUsage(deduped);

      emojiCache = sorted;
      cacheTimestamp = now;
      emojiCacheHash = await computeIntegrityHash(sorted);
      return sorted.slice();
    } else {
      console.warn('[SystemEmoji] Remote emoji fetch returned empty list');
    }
  } else {
  }

  const fallbackSorted = sortEmojisByUsage(FALLBACK_EMOJIS.slice());
  emojiCache = fallbackSorted;
  cacheTimestamp = now;
  emojiCacheHash = await getFallbackEmojisHash();
  return emojiCache.slice();
}

const EMOJI_KEYWORDS = deepFreeze({
  '😀': ['grin', 'smile', 'happy'],
  '😃': ['smile', 'happy'],
  '😄': ['laugh', 'happy'],
  '😁': ['grin', 'cheerful'],
  '😆': ['laughing', 'haha'],
  '😅': ['relief', 'sweat'],
  '😂': ['joy', 'tears', 'lol'],
  '🤣': ['rofl', 'rolling'],
  '😊': ['blush', 'smile'],
  '😍': ['love', 'hearts', 'eyes'],
  '😎': ['cool', 'sunglasses'],
  '🙂': ['smile'],
  '🙃': ['upside', 'playful'],
  '😉': ['wink'],
  '🥰': ['love', 'hearts'],
  '😘': ['kiss'],
  '😋': ['yum', 'delicious'],
  '😜': ['cheeky'],
  '🤪': ['wacky'],
  '😝': ['tongue'],
  '🤗': ['hug', 'embrace'],
  '🤔': ['think', 'question'],
  '😐': ['neutral'],
  '🙄': ['eyeroll'],
  '😏': ['smirk'],
  '🥳': ['party', 'celebrate'],
  '🤩': ['star', 'wow'],
  '🥺': ['plead'],
  '😭': ['cry', 'sad'],
  '😡': ['angry'],
  '😠': ['mad'],
  '👍': ['thumbs', 'up'],
  '👎': ['thumbs', 'down'],
  '👏': ['clap'],
  '🙏': ['pray', 'thanks'],
  '🤝': ['handshake'],
  '💪': ['muscle', 'strong'],
  '❤️': ['heart', 'love'],
  '💔': ['broken', 'heart'],
  '💖': ['sparkle', 'heart'],
  '💯': ['100', 'perfect'],
  '✨': ['sparkles'],
  '🔥': ['fire', 'lit'],
  '⭐': ['star'],
  '⚡': ['zap', 'power'],
  '✅': ['check', 'green'],
  '❌': ['cross', 'red'],
  '❓': ['question'],
  '❗': ['exclamation']
}) as Readonly<Record<string, ReadonlyArray<string>>>;

const EMOJI_API_URL = 'https://unpkg.com/emoji.json@15.0.0/emoji.json';

const emojiInvertedIndex = new Map<string, string[]>();
let sortedKeywords: string[] = [];
let fetchPromise: Promise<string[]> | null = null;

async function fetchRemoteEmojis(): Promise<string[]> {
  if (fetchPromise) return fetchPromise;

  fetchPromise = (async () => {
    try {
      const response = await fetch(EMOJI_API_URL, { cache: 'force-cache' });
      if (!response.ok) throw new Error(`Failed to fetch emojis: ${response.status}`);
      const data = await response.json();

      if (!Array.isArray(data)) return [];

      const emojis: string[] = [];
      const tempIndex = new Map<string, Set<string>>();

      data.forEach((item: any) => {
        if (item && typeof item.char === 'string' && isValidEmoji(item.char)) {
          const char = item.char;
          emojis.push(char);

          const keywords = new Set<string>();
          if (item.keywords) {
            const parts = typeof item.keywords === 'string'
              ? item.keywords.split(' ')
              : Array.isArray(item.keywords) ? item.keywords : [];
            parts.forEach((p: string) => keywords.add(p.toLowerCase()));
          }
          if (item.name) {
            keywords.add(item.name.toLowerCase());
          }

          keywords.forEach(k => {
            if (!tempIndex.has(k)) tempIndex.set(k, new Set());
            tempIndex.get(k)!.add(char);
          });
        }
      });

      tempIndex.forEach((set, keyword) => {
        emojiInvertedIndex.set(keyword, Array.from(set));
      });
      sortedKeywords = Array.from(emojiInvertedIndex.keys()).sort();

      return emojis;
    } catch (error) {
      console.error('Failed to fetch remote emojis:', error);
      fetchPromise = null;
      return [];
    }
  })();

  return fetchPromise;
}

export function searchEmojis(query: string, emojis: string[]): string[] {
  const now = Date.now();
  if (now - searchRateLimit.windowStart > CONFIG.RATE_LIMIT_WINDOW) {
    searchRateLimit.windowStart = now;
    searchRateLimit.count = 0;
  }
  searchRateLimit.count += 1;
  if (searchRateLimit.count > CONFIG.RATE_LIMIT_MAX_REQUESTS) {
    const overage = searchRateLimit.count - CONFIG.RATE_LIMIT_MAX_REQUESTS;
    const penalty = getSearchPenaltyMs(overage);
    logSecurityEvent('Emoji search rate limit exceeded', { overage, penalty });
    throw new Error(`Too many requests. Try again in ${Math.ceil(penalty / 1000)} seconds.`);
  }

  const trimmed = sanitizeSearchQuery(query).toLowerCase();
  if (!trimmed) {
    return emojis;
  }

  const emojiSignature = emojis.length > 50
    ? `${emojis.length}:${emojis[0] ?? ''}:${emojis[emojis.length - 1] ?? ''}`
    : Array.from(new Set(emojis)).sort().join('|').substring(0, 200);
  const cacheKey = `${trimmed}:${emojiSignature}`;

  const cached = searchCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  const matches = new Set<string>();

  if (sortedKeywords.length > 0) {
    for (const keyword of sortedKeywords) {
      if (keyword.includes(trimmed)) {
        const hits = emojiInvertedIndex.get(keyword);
        if (hits) {
          for (const h of hits) matches.add(h);
        }
      }
    }

    for (const emoji of emojis) {
      if (emoji.includes(trimmed)) matches.add(emoji);
    }

  } else {
    const seen = new Set<string>();
    for (const emoji of emojis) {
      if (seen.has(emoji)) continue;
      if (emoji.includes(trimmed)) {
        matches.add(emoji);
        seen.add(emoji);
        continue;
      }

      const keywords = EMOJI_KEYWORDS[emoji];
      if (keywords && keywords.some((word: string) => word.includes(trimmed))) {
        matches.add(emoji);
        seen.add(emoji);
      }
    }
  }

  const result = Array.from(matches);
  if (result.length === 0 && emojis.includes(trimmed)) {
    result.push(trimmed);
  }

  const behaviorResult = result.length > 0 ? result : emojis;

  searchCache.set(cacheKey, behaviorResult);
  return behaviorResult;
}

export async function clearEmojiCache(): Promise<void> {
  emojiCache = null;
  cacheTimestamp = 0;
  emojiCacheHash = null;
  fallbackEmojisHashPromise = null;
  searchCache.clear();
}



