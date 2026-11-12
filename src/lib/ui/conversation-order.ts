// Compare the usernames shown in the New Conversation picker.
const names = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });

export function compareConversationNames(a: { username: string }, b: { username: string }): number {
  return names.compare(a.username.trim(), b.username.trim())
    || (a.username < b.username ? -1 : a.username > b.username ? 1 : 0);
}

export function groupConversationsByLetter<T extends { username: string }>(conversations: ReadonlyArray<T>): Array<{ letter: string; conversations: T[] }> {
  const groups = new Map<string, T[]>();
  for (const conversation of conversations) {
    const first = Array.from(conversation.username.trim())[0] || '';
    const letter = /^\p{L}$/u.test(first)
      ? first.normalize('NFD').replace(/\p{M}/gu, '').toLocaleUpperCase()
      : '#';
    const group = groups.get(letter) || [];
    group.push(conversation);
    groups.set(letter, group);
  }
  return [...groups].sort(([a], [b]) => names.compare(a, b)).map(([letter, entries]) => ({ letter, conversations: entries.sort(compareConversationNames) }));
}
