import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import ts from 'typescript';

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const compiled = new Map();

function load(relativePath, mocks = {}) {
  const filename = path.resolve(root, relativePath);
  if (!compiled.has(filename)) {
    compiled.set(filename, ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
      compilerOptions: {
        module: ts.ModuleKind.CommonJS,
        target: ts.ScriptTarget.ES2022,
        jsx: ts.JsxEmit.ReactJSX,
        esModuleInterop: true,
      },
      fileName: filename,
    }).outputText);
  }
  const module = { exports: {} };
  new Function('require', 'module', 'exports', compiled.get(filename))(id => {
    if (Object.hasOwn(mocks, id)) return mocks[id];
    if (id === 'react/jsx-runtime' || id === 'date-fns') return require(id);
    throw new Error(`Unmocked dependency: ${id}`);
  }, module, module.exports);
  return module.exports;
}

function hookHost() {
  const slots = [];
  let index = 0;
  let effects = [];
  const sameDeps = (a, b) => a && b && a.length === b.length && a.every((value, i) => Object.is(value, b[i]));
  const react = {
    memo: component => component,
    useRef(value) {
      return slots[index++] ??= { current: value };
    },
    useState(initial) {
      const slot = index++;
      slots[slot] ??= { value: typeof initial === 'function' ? initial() : initial };
      return [slots[slot].value, value => {
        slots[slot].value = typeof value === 'function' ? value(slots[slot].value) : value;
      }];
    },
    useMemo(callback, deps) {
      const slot = index++;
      if (!sameDeps(slots[slot]?.deps, deps)) slots[slot] = { deps, value: callback() };
      return slots[slot].value;
    },
    useCallback(callback, deps) { return react.useMemo(() => callback, deps); },
    useEffect(effect, deps) {
      const slot = index++;
      if (sameDeps(slots[slot]?.deps, deps)) return;
      const previous = slots[slot];
      slots[slot] = { deps };
      effects.push(() => {
        previous?.cleanup?.();
        slots[slot].cleanup = effect();
      });
    },
  };
  react.useLayoutEffect = react.useEffect;
  return {
    react,
    render(callback) {
      index = 0;
      const tree = callback();
      const pending = effects;
      effects = [];
      for (const effect of pending) effect();
      return tree;
    },
    unmount() { for (const slot of slots) slot?.cleanup?.(); },
  };
}

function find(tree, predicate) {
  if (!tree || typeof tree !== 'object') return null;
  if (predicate(tree)) return tree;
  for (const child of [tree.props?.children].flat(Infinity)) {
    const result = find(child, predicate);
    if (result) return result;
  }
  return null;
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

const dates = load('src/lib/utils/date-utils.ts');
const signalTypes = load('src/lib/types/signal-types.ts');
const shared = { cn: (...values) => values.filter(Boolean).join(' ') };
const icons = Object.fromEntries(['Check', 'CheckCheck', 'Loader2', 'Download', 'Paperclip', 'SendHorizontal', 'Pencil', 'Reply', 'Trash2', 'SmilePlus', 'Copy'].map(name => [name, `${name}-icon`]));
const fileUtils = {
  formatFileSize: () => '65 MB',
  hasExtension: () => false,
  isSafeFileUrl: url => url?.startsWith('blob:') ? url : null,
  parseCurrentVoiceNoteFilename: () => null,
};

test('selected conversations keep the same options pill and readable theme colors', () => {
  const css = fs.readFileSync(path.join(root, 'src/index.css'), 'utf8');
  const pill = css.match(/\.qorc-conversation-action-pill\s*\{([^}]+)\}/)?.[1];
  assert.match(pill, /background:\s*#e9e9e9/);
  assert.match(pill, /color:\s*var\(--qorc-text\)/);
  assert.match(css, /\.dark \.qorc-conversation-action-pill\s*\{\s*background:\s*var\(--qorc-conversation-card-bg\)/);
  assert.doesNotMatch(css, /\.is-selected\s+\.qorc-conversation-(?:action-pill|tiny-btn)(?::hover)?\s*\{/);
});

test('composer sends newlines, preserves Shift+Enter, and does not send IME confirmation', () => {
  const host = hookHost();
  const sent = [];
  const { sanitizeMessage } = load('src/lib/sanitizers.ts', { './constants': {}, './types/signal-types': signalTypes });
  const { ChatInput } = load('src/components/chat/ChatInput.tsx', {
    react: host.react,
    './messaging/UserList': {},
    '../../lib/types/signal-types': signalTypes,
    './ChatInput/useFileSender': { useFileSender: () => ({ progress: 0, isSendingFile: false }) },
    './ChatInput/EditingBanner': { EditingBanner: 'editing-banner' },
    './ChatInput/ReplyBanner': { ReplyBanner: 'reply-banner' },
    './calls/VoiceRecorder': { VoiceRecorder: 'voice-recorder' },
    './ChatInput/VoiceRecorderButton': { VoiceRecorderButton: 'voice-button' },
    '@/lib/constants': { HEX_PATTERN: /^[a-f0-9]{32,}$/i },
    '@/lib/sanitizers': { sanitizeMessage },
    sonner: { toast: {} },
    'lucide-react': icons,
    './assets/icons': { Cross2Icon: 'close-icon' },
    '../ui/MaterialFileIcon': { MaterialFileIcon: 'file-icon' },
  });
  const props = {
    currentUsername: 'me', selectedConversation: 'peer', users: [],
    onSendMessage: (...args) => sent.push(args), onCancelReply() {}, onTyping() {},
  };
  const render = () => host.render(() => ChatInput(props));
  const input = () => find(render(), element => element.type === 'textarea');
  let prevented = 0;
  const key = (shiftKey, isComposing) => ({ key: 'Enter', shiftKey, nativeEvent: { isComposing }, preventDefault: () => prevented++ });
  try {
    assert.equal(input().props.rows, 1);
    input().props.onChange({ target: { value: 'first\nsecond' } });
    input().props.onKeyDown(key(true, false));
    input().props.onKeyDown(key(false, true));
    assert.equal(prevented, 0);
    assert.equal(sent.length, 0);
    assert.equal(input().props.value, 'first\nsecond');
    input().props.onKeyDown(key(false, false));
    assert.equal(prevented, 1);
    assert.equal(sent.length, 1);
    assert.equal(sent[0][1], 'first\nsecond');
    assert.equal(input().props.value, '');
    props.disabled = true;
    input().props.onChange({ target: { value: 'blocked' } });
    input().props.onKeyDown(key(false, false));
    assert.equal(sent.length, 1);
  } finally { host.unmount(); }
});

test('receipts show their original status labels and short timestamps', () => {
  const { MessageReceipt } = load('src/components/chat/messaging/MessageReceipt.tsx', {
    react: {}, 'lucide-react': icons,
    '../../../lib/utils/shared-utils': shared,
    '../../../lib/utils/date-utils': dates,
  });
  const deliveredAt = new Date('2026-10-12T16:20:30Z');
  const readAt = new Date('2026-10-12T16:21:40Z');
  for (const [receipt, icon, label, accessibleLabel] of [
    [{ sending: true, delivered: false, read: false }, 'Loader2-icon', 'Sending...', 'Sending'],
    [{ delivered: false, read: false }, null, 'Sent', 'Sent'],
    [{ delivered: true, read: false, deliveredAt }, 'Check-icon', `Delivered ${dates.formatReceiptTime(deliveredAt)}`, `Delivered at ${dates.formatReceiptTime(deliveredAt)}`],
    [{ delivered: true, read: true, deliveredAt, readAt }, 'CheckCheck-icon', `Read ${dates.formatReceiptTime(readAt)}`, `Read at ${dates.formatReceiptTime(readAt)}`],
    [{ delivered: true, read: false }, 'Check-icon', 'Delivered', 'Delivered'],
    [{ delivered: true, read: true }, 'CheckCheck-icon', 'Read', 'Read'],
  ]) {
    const tree = MessageReceipt({ receipt, isCurrentUser: true });
    assert.equal(tree.type, 'div');
    const renderedIcon = find(tree, element => Object.values(icons).includes(element.type));
    assert.equal(renderedIcon?.type ?? null, icon);
    if (renderedIcon) assert.equal(renderedIcon.props['aria-hidden'], 'true');
    assert.equal(find(tree, element => element.type === 'span').props.children, label);
    assert.equal(tree.props['aria-label'], accessibleLabel);
    assert.equal(tree.props.title, undefined);
  }
  assert.equal(dates.formatReceiptTime(deliveredAt).includes('2026'), false);
  assert.equal(MessageReceipt({ receipt: undefined, isCurrentUser: true }), null);
  assert.equal(MessageReceipt({ receipt: { delivered: true, read: true }, isCurrentUser: false }), null);
});

test('generic and media download controls show busy feedback and release it after completion', async () => {
  for (const mimeType of ['application/octet-stream', 'image/webp', 'video/mp4', 'audio/mpeg']) {
    const host = hookHost();
    const requests = [];
    let downloads = 0;
    const { FileContent } = load('src/components/chat/messaging/ChatMessage/FileMessage.tsx', {
      react: host.react, 'react-dom': { createPortal: tree => tree }, 'lucide-react': icons,
      '../../../../lib/utils/shared-utils': shared,
      '../../../../hooks/file-handling/useFileUrl': { useFileUrl: options => { requests.push(options); return { url: null, error: null }; } },
      '../../../../lib/utils/file-utils': fileUtils,
      '../../../../lib/constants': { IMAGE_EXTENSIONS: [], AUDIO_EXTENSIONS: [], VIDEO_EXTENSIONS: [] },
      '../../../ui/MaterialFileIcon': { MaterialFileIcon: 'file-icon' },
    });
    const props = {
      message: { id: 'file', filename: 'file.dat', fileSize: 65_000_000, mimeType },
      secureDB: {}, loadFile: true, onRendered() {},
      onDownload: async () => { downloads++; }, isDownloading: false,
    };
    const render = () => host.render(() => FileContent(props));
    try {
      const initial = render();
      const control = find(initial, element => element.props?.['aria-label'] === 'Download file');
      assert.ok(control);
      await control.props.onClick();
      assert.equal(downloads, 1);
      assert.ok(requests.every(request => request.enabled === false));
      props.isDownloading = true;
      const busy = render();
      assert.ok(find(busy, element => element.props?.['aria-busy'] === true));
      assert.ok(find(busy, element => element.type === 'Loader2-icon'));
      const busyControl = find(busy, element => element.props?.['aria-label'] === 'Preparing download…');
      assert.ok(busyControl.props.disabled || busyControl.props['aria-disabled']);
      assert.ok(find(busy, element => element.props?.className === 'qorc-file-size' && element.props.children === 'Preparing download…'));
      props.isDownloading = false;
      const finished = render();
      assert.ok(find(finished, element => element.type === 'Download-icon'));
      assert.equal(find(finished, element => element.type === 'Loader2-icon'), null);
    } finally { host.unmount(); }
  }
});

function messageHost(getFile) {
  const host = hookHost();
  const downloads = [];
  const { ChatMessage } = load('src/components/chat/messaging/ChatMessage.tsx', {
    react: host.react, '../../../lib/utils/shared-utils': shared,
    '../../ui/EmojiPicker': { EmojiPicker: 'emoji-picker' },
    '../../../contexts/EmojiPickerContext': { useEmojiPicker: () => ({ isPickerOpen: () => false }) },
    './ChatMessage/SystemMessage': { SystemMessage: 'system-message' },
    '../../../lib/system-emoji': { recordEmojiUsage() {} },
    './ChatMessage/DeletedMessage': { DeletedMessage: 'deleted-message' },
    './ChatMessage/FileMessage': { FileContent: 'file-content' },
    '../calls/VoiceMessage': { VoiceMessage: 'voice-message' },
    './MessageReceipt': { MessageReceipt: 'message-receipt' },
    '../../../hooks/database/useDisplayUsername': { useDisplayUsername: ({ username }) => username },
    './MessageContextMenu': { MessageContextMenu: 'context-menu' },
    '../../ui/UserAvatar': { UserAvatar: 'user-avatar' },
    './SecureCanvasText': { SecureCanvasText: 'secure-text' },
    '../ChatInput/BannerMessagePreview': { BannerMessagePreview: 'banner-preview' },
    '../../../lib/utils/file-utils': { ...fileUtils, createDownloadLink: (...args) => downloads.push(args) },
    '../../../lib/tauri-bindings': { nativeMessageContent: {} },
    './MessageLinkPreview': { MessageLinkPreviews: 'link-previews' },
    '../../../lib/utils/date-utils': dates,
    '../../../lib/types/event-types': { EventType: {} },
    '../../../lib/types/signal-types': signalTypes,
  });
  const props = {
    message: { id: 'file', filename: 'file.dat', mimeType: 'application/octet-stream', type: signalTypes.SignalType.FILE, timestamp: new Date(), sender: 'me', isCurrentUser: true },
    smartReceipt: { sending: true, delivered: false, read: false },
    secureDB: { getFile },
  };
  return { host, props, downloads, render: () => host.render(() => ChatMessage(props)) };
}

test('file-card and context downloads share one pending operation and reset on success', async () => {
  const request = deferred();
  let reads = 0;
  const ui = messageHost(() => { reads++; return request.promise; });
  try {
    const control = find(ui.render(), element => element.type === 'file-content');
    const first = control.props.onDownload();
    const second = control.props.onDownload();
    assert.equal(reads, 1);
    assert.equal(find(ui.render(), element => element.type === 'file-content').props.isDownloading, true);
    request.resolve(new Blob(['file bytes']));
    await Promise.all([first, second]);
    assert.equal(ui.downloads.length, 1);
    assert.equal(ui.downloads[0][1], 'file.dat');
    assert.equal(find(ui.render(), element => element.type === 'file-content').props.isDownloading, false);
  } finally { ui.host.unmount(); }
});

test('a failed download clears busy state and can be retried', async context => {
  context.mock.method(console, 'error', () => {});
  const previousAlert = globalThis.alert;
  globalThis.alert = context.mock.fn();
  let reads = 0;
  const ui = messageHost(async () => {
    if (++reads === 1) throw new Error('Encrypted storage read failed');
    return new Blob(['retry']);
  });
  try {
    await find(ui.render(), element => element.type === 'file-content').props.onDownload();
    const control = find(ui.render(), element => element.type === 'file-content');
    assert.equal(control.props.isDownloading, false);
    await control.props.onDownload();
    assert.equal(ui.downloads.length, 1);
    assert.equal(reads, 2);
  } finally {
    ui.host.unmount();
    if (previousAlert === undefined) delete globalThis.alert;
    else globalThis.alert = previousAlert;
  }
});

test('stale downloads cannot save another account file or clear its pending indicator', async () => {
  const oldRequest = deferred();
  const newRequest = deferred();
  const ui = messageHost(id => id === 'file' ? oldRequest.promise : newRequest.promise);
  try {
    const oldDownload = find(ui.render(), element => element.type === 'file-content').props.onDownload();
    ui.props.message = { ...ui.props.message, id: 'new-file', filename: 'new.dat' };
    const newDownload = find(ui.render(), element => element.type === 'file-content').props.onDownload();
    oldRequest.resolve(new Blob(['old']));
    await oldDownload;
    assert.equal(ui.downloads.length, 0);
    assert.equal(find(ui.render(), element => element.type === 'file-content').props.isDownloading, true);
    newRequest.resolve(new Blob(['new']));
    await newDownload;
    assert.equal(ui.downloads.length, 1);
    assert.equal(ui.downloads[0][1], 'new.dat');
  } finally { ui.host.unmount(); }
});

test('receipts stay below both first and grouped messages instead of beside header timestamps', () => {
  const ui = messageHost(async () => new Blob());
  try {
    for (const grouped of [false, true]) {
      ui.props.previousMessage = grouped ? { ...ui.props.message, id: 'previous' } : undefined;
      const tree = ui.render();
      const receipt = find(tree, element => element.type === 'message-receipt');
      assert.equal(receipt.props.className, 'mt-1');
      assert.equal(receipt.props.isCurrentUser, true);
      assert.equal(find(tree, element => element.props?.className === 'qorc-message-metadata select-none'), null);
      const timestamp = find(tree, element => element.props?.role === 'time');
      assert.equal(Boolean(timestamp), !grouped);
      if (timestamp) assert.equal(find(timestamp, element => element.type === 'message-receipt'), null);
    }
  } finally { ui.host.unmount(); }
});

test('a context-menu download stays visible with a spinner until file preparation finishes', async () => {
  const previousDocument = globalThis.document;
  const previousWindow = globalThis.window;
  globalThis.document = { body: {}, addEventListener() {}, removeEventListener() {} };
  globalThis.window = { addEventListener() {}, removeEventListener() {} };
  const host = hookHost();
  const request = deferred();
  let closed = 0;
  const { MessageContextMenu } = load('src/components/chat/messaging/MessageContextMenu.tsx', {
    react: host.react, 'react-dom': { createPortal: tree => tree }, 'lucide-react': icons,
  });
  const props = {
    anchorRect: { top: 0, left: 0, right: 20, bottom: 20 }, triggerId: 'file',
    isCurrentUser: true, canEdit: false, canDelete: false, isFile: true,
    isDownloading: false, onDownload: () => request.promise, onClose: () => closed++,
  };
  const render = () => host.render(() => MessageContextMenu(props));
  try {
    const initial = render();
    initial.props.ref.current = {};
    const completion = find(initial, element => element.props?.['aria-label'] === 'Download').props.onClick({ stopPropagation() {} });
    assert.equal(closed, 0);
    props.isDownloading = true;
    const busy = find(render(), element => element.props?.['aria-label'] === 'Preparing download…');
    assert.equal(busy.props.disabled, true);
    assert.equal(busy.props.children.type, 'Loader2-icon');
    request.resolve();
    await completion;
    assert.equal(closed, 1);
  } finally {
    host.unmount();
    if (previousDocument === undefined) delete globalThis.document;
    else globalThis.document = previousDocument;
    if (previousWindow === undefined) delete globalThis.window;
    else globalThis.window = previousWindow;
  }
});
