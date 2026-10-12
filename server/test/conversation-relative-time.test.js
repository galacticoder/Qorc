import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import test from 'node:test';
import ts from 'typescript';

function load(file, dependencies = {}) {
  const ast = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
  const source = ast.statements.filter(node => !ts.isImportDeclaration(node)).map(node => node.getText(ast)).join('\n');
  const compiled = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
  }).outputText;
  const exports = {};
  new Function('exports', 'require', ...Object.keys(dependencies), compiled)(exports, createRequire(path.resolve(file)), ...Object.values(dependencies));
  return exports;
}

const dates = load('src/lib/utils/date-utils.ts');

function fixture(t, timestamp = Date.now()) {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  t.mock.timers.setTime(timestamp);
  const document = Object.assign(new EventTarget(), { visibilityState: 'visible' });
  const window = new EventTarget();
  let state;
  let dependencies;
  let cleanup;
  const { RelativeMessageTime } = load('src/components/chat/messaging/RelativeMessageTime.tsx', {
    ...dates, document, window,
    memo: component => component,
    useState: initial => {
      if (state === undefined) state = initial();
      return [state, next => { state = next; }];
    },
    useEffect: (effect, next) => {
      if (!dependencies || next.some((value, index) => value !== dependencies[index])) {
        cleanup?.();
        dependencies = next;
        cleanup = effect();
      }
    },
  });
  t.after(() => cleanup?.());
  return {
    document, window,
    render: date => {
      RelativeMessageTime({ date, className: 'qorc-conversation-time' });
      return RelativeMessageTime({ date, className: 'qorc-conversation-time' }).props.children;
    },
    unmount: () => cleanup?.(),
  };
}

test('preview time changes from now to minutes without changing the conversation props', t => {
  const f = fixture(t, 100_000);
  const sent = new Date(100_000);
  assert.equal(f.render(sent), 'now');
  t.mock.timers.tick(59_999);
  assert.equal(f.render(sent), 'now');
  t.mock.timers.tick(1);
  assert.equal(f.render(sent), '1m');
  t.mock.timers.tick(120_000);
  assert.equal(f.render(sent), '3m');
});

test('preview time advances at hour and day boundaries', t => {
  const f = fixture(t, 100_000);
  assert.equal(f.render(100_000), 'now');
  t.mock.timers.tick(3_600_000);
  assert.equal(f.render(100_000), '1h');
  t.mock.timers.tick(86_400_000 - 3_600_000);
  assert.equal(f.render(100_000), '1d');
});

test('new messages replace the previous timestamp schedule', t => {
  const f = fixture(t, 100_000);
  assert.equal(f.render(100_000), 'now');
  t.mock.timers.tick(59_000);
  assert.equal(f.render(159_000), 'now');
  t.mock.timers.tick(1000);
  assert.equal(f.render(159_000), 'now');
  t.mock.timers.tick(59_000);
  assert.equal(f.render(159_000), '1m');
});

test('a backgrounded app catches up immediately on visibility or focus', t => {
  const f = fixture(t, 100_000);
  assert.equal(f.render(100_000), 'now');
  f.document.visibilityState = 'hidden';
  f.document.dispatchEvent(new Event('visibilitychange'));
  t.mock.timers.tick(300_000);
  assert.equal(f.render(100_000), 'now');
  f.document.visibilityState = 'visible';
  f.document.dispatchEvent(new Event('visibilitychange'));
  assert.equal(f.render(100_000), '5m');
  t.mock.timers.setTime(820_000);
  f.window.dispatchEvent(new Event('focus'));
  assert.equal(f.render(100_000), '12m');
});

test('preview clock stops when unmounted and invalid dates do not schedule updates', t => {
  const f = fixture(t, 100_000);
  assert.equal(f.render(100_000), 'now');
  f.unmount();
  t.mock.timers.tick(120_000);
  assert.equal(f.render(100_000), 'now');
  assert.equal(f.render(new Date(NaN)), '');
  t.mock.timers.tick(120_000);
  assert.equal(f.render(new Date(NaN)), '');
});

test('a future timestamp becomes visible when its send time arrives', t => {
  const f = fixture(t, 100_000);
  assert.equal(f.render(120_000), '');
  t.mock.timers.tick(20_000);
  assert.equal(f.render(120_000), 'now');
});

test('a week-old preview changes to its calendar date and stops ticking', t => {
  const timestamp = new Date('2026-10-11T12:00:00Z').getTime();
  const f = fixture(t, timestamp);
  f.render(timestamp);
  t.mock.timers.tick(6 * 86_400_000);
  assert.equal(f.render(timestamp), '6d');
  t.mock.timers.tick(86_400_000);
  assert.equal(f.render(timestamp), '10/11/26');
  t.mock.timers.tick(86_400_000);
  assert.equal(f.render(timestamp), '10/11/26');
});
