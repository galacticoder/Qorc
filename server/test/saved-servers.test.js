import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { crc32, deflateSync } from 'node:zlib';
import { EventEmitter } from 'node:events';
import ts from 'typescript';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex } from '../../shared/bytes.js';
import { SERVER_ICON_MAX_BYTES, SERVER_ICON_MAX_DIMENSION, encodeServerProfileTranscript, validateServerIcon, validateServerProfile } from '../../shared/server-profile.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { loadServerProfile, SERVER_ICON_SOURCE_MAX_BYTES, SERVER_ICON_SOURCE_MAX_DIMENSION, SERVER_ICON_SOURCE_MAX_PIXELS } from '../config/server-profile.js';
import sharp from 'sharp';
import { validatePngContainer } from '../../shared/image-png.js';
import { ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES, ML_KEM_1024_PUBLIC_KEY_BYTES } from '../../shared/crypto-sizes.js';

function load(file, dependencies = {}) {
  const ast = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
  const source = ast.statements.filter((node) => !ts.isImportDeclaration(node)).map((node) => node.getText(ast)).join('\n');
  const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
  const exports = {};
  new Function('exports', ...Object.keys(dependencies), compiled)(exports, ...Object.values(dependencies));
  return exports;
}

const keys = load('src/lib/database/storage-keys.ts');
const addresses = load('src/lib/servers/server-address.ts');
const png = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=';

function pngChunk(type, data) {
  const chunk = Buffer.alloc(data.length + 12);
  chunk.writeUInt32BE(data.length);
  chunk.write(type, 4, 4, 'ascii');
  data.copy(chunk, 8);
  chunk.writeUInt32BE(crc32(chunk.subarray(4, -4)), chunk.length - 4);
  return chunk;
}

function pngFixture(width, height, extra = []) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 6;
  return Buffer.concat([
    Buffer.from('89504e470d0a1a0a', 'hex'), pngChunk('IHDR', header), ...extra,
    pngChunk('IDAT', deflateSync(Buffer.alloc((width * 4 + 1) * height))), pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

function noisyPng(width, height) {
  const pixels = Buffer.alloc((width * 4 + 1) * height);
  let seed = 0x62f357a1;
  for (let row = 0; row < height; row += 1) {
    for (let column = 1; column <= width * 4; column += 1) {
      seed ^= seed << 13;
      seed ^= seed >>> 17;
      seed ^= seed << 5;
      pixels[row * (width * 4 + 1) + column] = seed & 0xff;
    }
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 6;
  return Buffer.concat([
    Buffer.from('89504e470d0a1a0a', 'hex'), pngChunk('IHDR', header),
    pngChunk('IDAT', deflateSync(pixels)), pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

const iconData = (bytes) => 'data:image/png;base64,' + bytes.toString('base64');

function fixture(data = new Map()) {
  const storage = {
    fail: false,
    async get(key) { return data.get(key) ?? null; },
    async set(key, value) { if (this.fail) return false; data.set(key, value); return true; },
    async remove(key) { data.delete(key); return true; },
  };
  const { savedServers } = load('src/lib/servers/saved-servers.ts', { storage, ...keys, ...addresses, validateServerProfile });
  return { storage, data, savedServers };
}

test('server addresses are normalized and reject credentials, paths, queries and fragments', () => {
  assert.equal(addresses.normalizeToWss(' EXAMPLE.onion:443 '), 'wss://example.onion/');
  assert.equal(addresses.normalizeToWss('https://example.org'), 'wss://example.org/');
  for (const value of ['', 'wss://user:pass@example.org', 'wss://example.org/path', 'wss://example.org?token=secret', 'wss://example.org/#x', 'file:///etc/passwd']) {
    assert.equal(addresses.normalizeToWss(value), '', value);
  }
});

test('saved servers persist before login, notify observers, edit, remove and reload', async () => {
  const f = fixture();
  const observed = [];
  const unsubscribe = f.savedServers.subscribe(() => observed.push(f.savedServers.getSnapshot()));
  await f.savedServers.save({ name: 'Home', url: 'home.onion', icon: png });
  assert.equal(f.savedServers.getSnapshot().servers[0].url, 'wss://home.onion/');
  assert.equal(observed.length, 2);
  const reloaded = fixture(f.data);
  await reloaded.savedServers.load();
  assert.deepEqual(reloaded.savedServers.getSnapshot().servers, f.savedServers.getSnapshot().servers);
  await reloaded.savedServers.save({ name: 'Renamed', url: 'other.onion', icon: null }, 'wss://home.onion/');
  assert.equal(reloaded.savedServers.getSnapshot().servers.length, 1);
  assert.equal(reloaded.savedServers.getSnapshot().servers[0].name, 'Renamed');
  await reloaded.savedServers.remove('wss://other.onion/');
  assert.deepEqual(reloaded.savedServers.getSnapshot().servers, []);
  unsubscribe();
});

test('concurrent saves do not lose entries and duplicate canonical addresses are rejected', async () => {
  const f = fixture();
  await Promise.all(Array.from({ length: 10 }, (_, index) => f.savedServers.save({ name: `Server ${index}`, url: `s${index}.onion`, icon: null })));
  assert.equal(f.savedServers.getSnapshot().servers.length, 10);
  await assert.rejects(f.savedServers.save({ name: 'Duplicate', url: 'WSS://S0.ONION:443/', icon: null }), /already saved/);
  await assert.rejects(f.savedServers.save({ name: 'Duplicate edit', url: 's1.onion', icon: null }, 'wss://s0.onion/'), /already saved/);
});

test('failed writes do not show unsaved changes or poison later mutations', async () => {
  const f = fixture();
  await f.savedServers.load();
  f.storage.fail = true;
  await assert.rejects(f.savedServers.save({ name: 'Home', url: 'home.onion', icon: null }), /could not be stored/);
  assert.equal(f.savedServers.getSnapshot().servers.length, 0);
  f.storage.fail = false;
  await f.savedServers.save({ name: 'Home', url: 'home.onion', icon: null });
  await f.savedServers.updateIcon('wss://home.onion/', png);
  assert.equal(f.savedServers.getSnapshot().servers[0].name, 'Home');
  assert.equal(f.savedServers.getSnapshot().servers[0].icon, png);
});

test('corrupt device storage is reported and never overwritten with an empty list', async () => {
  const f = fixture(new Map([[keys.STORAGE_KEYS.SAVED_SERVERS, '{bad json']]));
  await assert.rejects(f.savedServers.load());
  await assert.rejects(f.savedServers.save({ name: 'Home', url: 'home.onion', icon: null }));
  assert.ok(f.savedServers.getSnapshot().error);
  assert.equal(f.data.get(keys.STORAGE_KEYS.SAVED_SERVERS), '{bad json');
});

test('only bounded inline static PNG icons and valid display names are accepted', () => {
  assert.equal(validateServerIcon(png), true);
  assert.equal(validateServerProfile({ name: 'Home', icon: png }), true);
  for (const icon of ['https://tracking.example/icon.png', 'data:image/svg+xml;base64,PHN2Zz4=', 'data:image/png;base64,' + 'A'.repeat(50000), png + '!', 'data:image/png;base64,aGVsbG8=']) {
    assert.equal(validateServerIcon(icon), false);
  }
  for (const name of ['', ' Name ', 'A'.repeat(81), 'bad\nname', 'bad\u202ename']) assert.equal(validateServerProfile({ name, icon: null }), false);
  const oversized = Buffer.from(png.split(',')[1], 'base64');
  oversized.writeUInt32BE(SERVER_ICON_MAX_DIMENSION + 1, 16);
  assert.equal(validateServerIcon('data:image/png;base64,' + oversized.toString('base64')), false);
});

test('server administrator profile settings are loaded locally and invalid files fail explicitly', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'qorc-profile-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const iconPath = path.join(directory, 'icon.png');
  fs.writeFileSync(iconPath, Buffer.from(png.split(',')[1], 'base64'));
  const previousName = process.env.SERVER_NAME;
  const previousIcon = process.env.SERVER_ICON_PATH;
  try {
    delete process.env.SERVER_NAME;
    delete process.env.SERVER_ICON_PATH;
    assert.deepEqual(await loadServerProfile('server-main'), { name: 'server-main', icon: null });
    process.env.SERVER_NAME = 'Home';
    process.env.SERVER_ICON_PATH = iconPath;
    assert.deepEqual(await loadServerProfile('server-main'), { name: 'Home', icon: png });
    process.env.SERVER_ICON_PATH = path.join(directory, 'missing.png');
    await assert.rejects(loadServerProfile('server-main'), /ENOENT/);
    process.env.SERVER_ICON_PATH = directory;
    await assert.rejects(loadServerProfile('server-main'), /regular PNG/);
    process.env.SERVER_ICON_PATH = iconPath;
    fs.writeFileSync(iconPath, Buffer.alloc(SERVER_ICON_SOURCE_MAX_BYTES + 1));
    await assert.rejects(loadServerProfile('server-main'), /no larger than/);
    fs.writeFileSync(iconPath, Buffer.alloc(0));
    await assert.rejects(loadServerProfile('server-main'), /Invalid image PNG/);
  } finally {
    if (previousName === undefined) delete process.env.SERVER_NAME; else process.env.SERVER_NAME = previousName;
    if (previousIcon === undefined) delete process.env.SERVER_ICON_PATH; else process.env.SERVER_ICON_PATH = previousIcon;
  }
});

test('oversized server PNGs compress once at startup, preserve source files and aspect ratio, and remain within wire limits', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'qorc-icon-compression-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const iconPath = path.join(directory, 'large.png');
  const previousName = process.env.SERVER_NAME;
  const previousIcon = process.env.SERVER_ICON_PATH;
  try {
    process.env.SERVER_NAME = 'Compressed server';
    process.env.SERVER_ICON_PATH = iconPath;
    for (const source of [pngFixture(1024, 512), noisyPng(128, 128), noisyPng(256, 256)]) {
      fs.writeFileSync(iconPath, source);
      const profile = await loadServerProfile('server-main');
      assert.equal(validateServerProfile(profile), true);
      const encoded = Buffer.from(profile.icon.split(',')[1], 'base64');
      assert.ok(encoded.length <= SERVER_ICON_MAX_BYTES);
      const dimensions = validatePngContainer(encoded, { maxWidth: 128, maxHeight: 128, maxPixels: 128 * 128 });
      const decoded = await sharp(encoded).raw().toBuffer({ resolveWithObject: true });
      assert.equal(decoded.info.width, dimensions.width);
      assert.equal(decoded.info.height, dimensions.height);
      assert.deepEqual(fs.readFileSync(iconPath), source);
      if (source.readUInt32BE(16) === 1024) assert.deepEqual(dimensions, { width: 128, height: 64 });
      else assert.ok(dimensions.width < 128, 'high-entropy icons should be reduced further to meet the byte limit');
    }
    const recompress = await sharp({ create: { width: 80, height: 80, channels: 4, background: { r: 100, g: 50, b: 200, alpha: 0.5 } } }).png({ compressionLevel: 0 }).toBuffer();
    assert.ok(recompress.length > SERVER_ICON_MAX_BYTES);
    fs.writeFileSync(iconPath, recompress);
    const profile = await loadServerProfile('server-main');
    const metadata = await sharp(Buffer.from(profile.icon.split(',')[1], 'base64')).metadata();
    assert.equal(metadata.width, 80);
    assert.equal(metadata.height, 80);
    assert.equal(metadata.hasAlpha, true);
  } finally {
    if (previousName === undefined) delete process.env.SERVER_NAME; else process.env.SERVER_NAME = previousName;
    if (previousIcon === undefined) delete process.env.SERVER_ICON_PATH; else process.env.SERVER_ICON_PATH = previousIcon;
  }
});

test('icon compression never bypasses source PNG validation or input resource limits', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'qorc-icon-invalid-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const iconPath = path.join(directory, 'invalid.png');
  const previousIcon = process.env.SERVER_ICON_PATH;
  try {
    process.env.SERVER_ICON_PATH = iconPath;
    for (const source of [
      pngFixture(SERVER_ICON_SOURCE_MAX_DIMENSION + 1, 1),
      pngFixture(1, 1, [pngChunk('acTL', Buffer.alloc(8))]),
      Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"></svg>'),
    ]) {
      fs.writeFileSync(iconPath, source);
      await assert.rejects(loadServerProfile('server-main'));
    }
    const bad = pngFixture(1, 1);
    fs.writeFileSync(iconPath, Buffer.concat([bad.subarray(0, 33), pngChunk('IDAT', Buffer.alloc(9000)), bad.subarray(-12)]));
    await assert.rejects(loadServerProfile('server-main'));
    fs.writeFileSync(iconPath, Buffer.alloc(SERVER_ICON_SOURCE_MAX_BYTES + 1));
    await assert.rejects(loadServerProfile('server-main'), /no larger than/);
  } finally {
    if (previousIcon === undefined) delete process.env.SERVER_ICON_PATH; else process.env.SERVER_ICON_PATH = previousIcon;
  }
});

test('large source icons discard text and compressed metadata before decoding while the wire validator stays strict', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'qorc-icon-metadata-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const iconPath = path.join(directory, 'metadata.png');
  const previousIcon = process.env.SERVER_ICON_PATH;
  const chunks = [
    pngChunk('tEXt', Buffer.from('Software\0Editor name')),
    pngChunk('tEXt', Buffer.from('Comment\0Private description')),
    pngChunk('zTXt', Buffer.from('Not valid compressed metadata')),
    pngChunk('iTXt', Buffer.from('Private international text')),
    pngChunk('iCCP', Buffer.from('Not a valid compressed profile')),
    pngChunk('eXIf', Buffer.from('Not valid EXIF')),
  ];
  try {
    process.env.SERVER_ICON_PATH = iconPath;
    for (const [width, height] of [[1, 1], [3072, 1920]]) {
      const source = pngFixture(width, height, chunks);
      fs.writeFileSync(iconPath, source);
      const profile = await loadServerProfile('server-main');
      const output = Buffer.from(profile.icon.split(',')[1], 'base64');
      assert.equal(validateServerIcon(profile.icon), true);
      assert.equal(validateServerIcon(iconData(source)), false);
      assert.throws(() => validatePngContainer(source, {
        maxWidth: SERVER_ICON_SOURCE_MAX_DIMENSION, maxHeight: SERVER_ICON_SOURCE_MAX_DIMENSION, maxPixels: SERVER_ICON_SOURCE_MAX_PIXELS,
      }), /Unsupported image PNG chunk/);
      assert.deepEqual(validatePngContainer(output, { maxWidth: 128, maxHeight: 128, maxPixels: 16384 }), width === 1 ? { width: 1, height: 1 } : { width: 128, height: 80 });
      assert.equal(output.includes(Buffer.from('Private')), false);
      assert.deepEqual(fs.readFileSync(iconPath), source);
    }
    const damagedMetadata = pngFixture(1, 1, chunks);
    damagedMetadata[45] ^= 1;
    fs.writeFileSync(iconPath, damagedMetadata);
    await assert.rejects(loadServerProfile('server-main'), /checksum/);
    fs.writeFileSync(iconPath, pngFixture(4097, 4096));
    await assert.rejects(loadServerProfile('server-main'), /dimensions.*exceed limits/);
  } finally {
    if (previousIcon === undefined) delete process.env.SERVER_ICON_PATH; else process.env.SERVER_ICON_PATH = previousIcon;
  }
});

test('server startup awaits icon preparation before opening the listening socket', () => {
  const source = fs.readFileSync('server/server.js', 'utf8');
  const start = source.indexOf('async function onServerReady');
  const ready = source.slice(start, source.indexOf('server.listen(', start));
  assert.match(ready, /gateway = await attachGateway\(/);
  const gateway = fs.readFileSync('server/websocket/gateway.js', 'utf8');
  assert.ok(gateway.indexOf('await loadServerProfile(serverId)') < gateway.indexOf("wss.on('connection'"));
});

function pinFixture() {
  const f = fixture();
  let address = 'wss://first.onion/';
  const websocket = { getServerUrl: async () => address };
  const CryptoUtils = { Base64: { base64ToUint8Array: (value) => Uint8Array.from(Buffer.from(value, 'base64')), arrayBufferToBase64: (value) => Buffer.from(value).toString('base64') } };
  const { PinnedServer } = load('src/lib/utils/auth-utils.ts', { storage: f.storage, websocket, CryptoUtils, blake3, bytesToHex, ...keys, ...addresses });
  const key = (byte) => ({ kyberPublicBase64: Buffer.alloc(1568, byte).toString('base64'), dilithiumPublicBase64: Buffer.alloc(2592, byte).toString('base64'), x25519PublicBase64: Buffer.alloc(32, byte).toString('base64') });
  return { ...f, PinnedServer, key, setAddress: (value) => { address = value; } };
}

test('different servers retain separate identity pins and a changed identity is blocked', async () => {
  const f = pinFixture();
  await f.PinnedServer.establish(f.key(1), () => true);
  f.setAddress('wss://second.onion/');
  assert.equal(await f.PinnedServer.load(), null);
  await f.PinnedServer.establish(f.key(2), () => true);
  f.setAddress('wss://first.onion/');
  assert.deepEqual(await f.PinnedServer.load(), f.key(1));
  await assert.rejects(f.PinnedServer.establish(f.key(2), () => true), /identity changed/);
  assert.equal(f.data.size, 2);
});

test('an address change during pin persistence rolls back only that address', async () => {
  const f = pinFixture();
  const set = f.storage.set.bind(f.storage);
  f.storage.set = async (key, value) => { const result = await set(key, value); f.setAddress('wss://second.onion/'); return result; };
  await assert.rejects(f.PinnedServer.establish(f.key(1), () => true), /no longer current/);
  assert.equal(f.data.size, 0);
  assert.equal(f.PinnedServer.get(), null);
});

test('the save offer expires after ten seconds but saving disables expiration and declining never saves', async () => {
  const f = fixture();
  const offers = [];
  const dismissed = [];
  const toast = {
    custom: (render, options) => offers.push({ element: render(), options }),
    dismiss: (id) => dismissed.push(id),
  };
  toast.error = (error) => { throw new Error(error); };
  const createElement = (component, props) => ({ component, props });
  const SaveServerPrompt = () => {};
  const { offerToSaveServer } = load('src/lib/servers/save-server-prompt.ts', { toast, createElement, SaveServerPrompt, savedServers: f.savedServers, validateServerProfile, ...addresses });
  await offerToSaveServer('home.onion', { name: 'Home', icon: png });
  assert.equal(offers[0].options.duration, 10000);
  assert.equal(offers[0].options.unstyled, true);
  assert.equal(offers[0].options.className, 'server-save-toast');
  assert.equal(offers[0].element.component, SaveServerPrompt);
  assert.equal(f.savedServers.getSnapshot().servers.length, 0);
  assert.deepEqual(offers[0].element.props.profile, { name: 'Home', icon: png });
  assert.equal('onStartNaming' in offers[0].element.props, false);
  offers[0].element.props.onSaveStart();
  assert.equal(offers[1].options.id, offers[0].options.id);
  assert.equal(offers[1].options.duration, Infinity);
  assert.equal(offers[1].options.dismissible, false);
  assert.equal(f.savedServers.getSnapshot().servers.length, 0);
  offers[1].element.props.onDismiss();
  assert.deepEqual(dismissed, [offers[0].options.id]);
  assert.equal(f.savedServers.getSnapshot().servers.length, 0);
  await f.savedServers.save({ name: 'Chosen name', url: 'home.onion', icon: png });
  await offerToSaveServer('home.onion', { name: 'Renamed by server', icon: null });
  assert.equal(offers.length, 2);
  assert.equal(f.savedServers.getSnapshot().servers[0].name, 'Chosen name');
  await offerToSaveServer('untrusted.onion', { name: 'Untrusted', icon: 'https://tracking.example/icon.png' });
  assert.equal(offers.length, 2);
});

test('client bootstrap accepts the server profile and rejects missing or unsafe profiles', async () => {
  const file = 'src/lib/websocket/websocket.ts';
  const ast = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
  const statement = ast.statements.find((node) => ts.isVariableStatement(node) && node.declarationList.declarations.some((declaration) => declaration.name.getText(ast) === 'parseServerKeyBootstrap'));
  assert.ok(statement);
  const compiled = ts.transpileModule(statement.getText(ast), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const dependencies = {
    isPlainObject: (value) => value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype,
    hasPrototypePollutionKeys: (value) => Object.keys(value).some((key) => ['__proto__', 'constructor', 'prototype'].includes(key)),
    SignalType: { SERVER_PUBLIC_KEY: 'server-public-key' },
    validateServerProfile, ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES, ML_KEM_1024_PUBLIC_KEY_BYTES,
    decodeServerResponseBase64: (value, length) => { const bytes = Buffer.from(value, 'base64'); if (bytes.length !== length) throw new Error('Invalid size'); return bytes; },
  };
  const parse = new Function(...Object.keys(dependencies), compiled + '\nreturn parseServerKeyBootstrap;')(...Object.values(dependencies));
  const message = { type: 'server-public-key', serverId: 'server-main', serverProfile: await loadServerProfile('server-main'), serverProfileSignature: Buffer.alloc(ML_DSA_87_SIGNATURE_BYTES).toString('base64'), serverTime: Date.now(), requiresServerPassword: false, hybridKeys: pinFixture().key(1) };
  assert.equal(parse(message), message);
  assert.equal(parse({ ...message, serverProfile: { name: 'Home', icon: png } })?.serverProfile.icon, png);
  const { serverProfile, ...missing } = message;
  assert.ok(serverProfile);
  assert.equal(parse(missing), null);
  assert.equal(parse({ ...message, serverProfile: { name: 'Home', icon: 'https://tracking.example/icon.png' } }), null);
  assert.equal(parse({ ...message, serverProfileSignature: '' }), null);
  const { serverProfileSignature, ...unsigned } = message;
  assert.ok(serverProfileSignature);
  assert.equal(parse(unsigned), null);
});

test('server icons reject corrupt CRCs, animation, unsupported chunks, and exact size/dimension overflow', () => {
  const bytes = Buffer.from(png.split(',')[1], 'base64');
  const damaged = Buffer.from(bytes);
  damaged[50] ^= 1;
  assert.equal(validateServerIcon('data:image/png;base64,' + damaged.toString('base64')), false);
  assert.equal(validateServerIcon('data:image/png;base64,' + Buffer.concat([bytes, bytes]).toString('base64')), false);
  assert.equal(validateServerIcon('data:image/png;base64,' + Buffer.alloc(SERVER_ICON_MAX_BYTES + 1).toString('base64')), false);
  assert.equal(validateServerIcon('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aGZkAAAAASUVORK5CYII='), false);
  assert.equal(validateServerIcon(iconData(pngFixture(128, 128))), true);
  for (const [width, height] of [[0, 1], [1, 0], [129, 1], [1, 129]]) {
    assert.equal(validateServerIcon(iconData(pngFixture(width, height))), false);
  }
  for (const chunk of [pngChunk('acTL', Buffer.alloc(8)), pngChunk('tEXt', Buffer.from('Key\0value')), pngChunk('iCCP', Buffer.from('Profile\0\0'))]) {
    assert.equal(validateServerIcon(iconData(pngFixture(1, 1, [chunk]))), false);
  }
  const image = pngFixture(1, 1);
  const boundary = Buffer.concat([
    image.subarray(0, -12), pngChunk('IDAT', Buffer.alloc(SERVER_ICON_MAX_BYTES - image.length - 12)), image.subarray(-12),
  ]);
  assert.equal(boundary.length, SERVER_ICON_MAX_BYTES);
  assert.equal(validateServerIcon(iconData(boundary)), true);
  assert.equal(validateServerIcon(iconData(Buffer.concat([boundary, Buffer.alloc(1)]))), false);
});

test('ML-DSA server profile signatures bind the server identifier, icon, name, and all transport keys', async () => {
  const pair = ml_dsa87.keygen(new Uint8Array(32).fill(0x51));
  const profile = { serverId: 'server-main', serverProfile: { name: 'Home', icon: png }, hybridKeys: { ...pinFixture().key(1), dilithiumPublicBase64: Buffer.from(pair.publicKey).toString('base64') } };
  const signature = ml_dsa87.sign(encodeServerProfileTranscript(profile), pair.secretKey);
  try {
    assert.equal(ml_dsa87.verify(signature, encodeServerProfileTranscript(profile), pair.publicKey), true);
    for (const changed of [
      { ...profile, serverId: 'other-server' },
      { ...profile, serverProfile: { ...profile.serverProfile, name: 'Forged' } },
      { ...profile, serverProfile: { ...profile.serverProfile, icon: null } },
      { ...profile, hybridKeys: { ...profile.hybridKeys, kyberPublicBase64: pinFixture().key(2).kyberPublicBase64 } },
      { ...profile, hybridKeys: { ...profile.hybridKeys, x25519PublicBase64: pinFixture().key(2).x25519PublicBase64 } },
    ]) assert.equal(ml_dsa87.verify(signature, encodeServerProfileTranscript(changed), pair.publicKey), false);
  } finally {
    pair.secretKey.fill(0);
    signature.fill(0);
  }
});

test('gateway bootstraps carry an inline signed profile and refresh only the timestamp', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'qorc-bootstrap-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const iconPath = path.join(directory, 'icon.png');
  const source = pngFixture(512, 256);
  fs.writeFileSync(iconPath, source);
  const previousName = process.env.SERVER_NAME;
  const previousIcon = process.env.SERVER_ICON_PATH;
  const pair = ml_dsa87.keygen(new Uint8Array(32).fill(0x62));
  let gateway;
  try {
    process.env.SERVER_NAME = 'Signed server';
    process.env.SERVER_ICON_PATH = iconPath;
    const wss = new EventEmitter();
    wss.clients = new Set();
    const encodeKey = (bytes) => Buffer.from(bytes).toString('base64');
    const { attachGateway } = load('server/websocket/gateway.js', {
      loadServerProfile, encodeServerProfileTranscript,
      SignalType: { SERVER_PUBLIC_KEY: 'server-public-key' },
      require: (module) => { assert.equal(module, '../config/config.js'); return { isServerPasswordGateReady: () => false }; },
      rateLimitMiddleware: {}, envInt: (_name, defaultValue) => defaultValue,
      TimingProtection: { stopCoverTraffic: async () => {} },
      CryptoUtils: {
        Hybrid: { exportDilithiumPublicBase64: encodeKey, exportKyberPublicBase64: encodeKey, exportX25519PublicBase64: encodeKey },
        Dilithium: { sign: async (transcript, key) => ml_dsa87.sign(transcript, key) },
      },
    });
    gateway = await attachGateway({ wss, serverId: 'server-main', logger: { info() {} }, serverHybridKeyPair: {
      dilithium: pair, kyber: { publicKey: Buffer.alloc(ML_KEM_1024_PUBLIC_KEY_BYTES, 1) }, x25519: { publicKey: Buffer.alloc(32, 2) },
    } });
    const bootstrap = await gateway.getServerPublicKeyPayload();
    assert.equal(bootstrap.serverProfile.name, 'Signed server');
    assert.equal(validateServerProfile(bootstrap.serverProfile), true);
    assert.notEqual(bootstrap.serverProfile.icon, iconData(source));
    assert.deepEqual(validatePngContainer(Buffer.from(bootstrap.serverProfile.icon.split(',')[1], 'base64'), {
      maxWidth: 128, maxHeight: 128, maxPixels: 128 * 128,
    }), { width: 128, height: 64 });
    const signature = Buffer.from(bootstrap.serverProfileSignature, 'base64');
    assert.equal(signature.length, ML_DSA_87_SIGNATURE_BYTES);
    assert.equal(ml_dsa87.verify(signature, encodeServerProfileTranscript(bootstrap), pair.publicKey), true);
    fs.writeFileSync(iconPath, noisyPng(256, 256));
    const next = JSON.parse(await gateway.getServerPublicKeyMessage());
    assert.deepEqual(next.serverProfile, bootstrap.serverProfile);
    assert.equal(next.serverProfileSignature, bootstrap.serverProfileSignature);
    assert.ok(next.serverTime >= bootstrap.serverTime);
  } finally {
    await gateway?.stop();
    pair.secretKey.fill(0);
    if (previousName === undefined) delete process.env.SERVER_NAME; else process.env.SERVER_NAME = previousName;
    if (previousIcon === undefined) delete process.env.SERVER_ICON_PATH; else process.env.SERVER_ICON_PATH = previousIcon;
  }
});

test('bookmark limits and malformed identity records fail without discarding data', async () => {
  const f = fixture();
  for (let index = 0; index < 32; index++) await f.savedServers.save({ name: `Server ${index}`, url: `s${index}.onion`, icon: null });
  await assert.rejects(f.savedServers.save({ name: 'Extra', url: 'extra.onion', icon: null }), /up to 32/);
  assert.equal(f.savedServers.getSnapshot().servers.length, 32);
  const pin = pinFixture();
  await pin.PinnedServer.establish(pin.key(1), () => true);
  const pinKey = [...pin.data.keys()][0];
  pin.data.set(pinKey, '{}');
  await assert.rejects(pin.PinnedServer.establish(pin.key(1), () => true), /Invalid server identity key material/);
  assert.equal(pin.data.get(pinKey), '{}');
  await assert.rejects(pin.PinnedServer.establish(pin.key(1), () => false));
});
