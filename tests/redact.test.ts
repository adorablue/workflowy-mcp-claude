import assert from 'node:assert/strict';
import { test } from 'node:test';
// @ts-ignore Node's built-in TypeScript runner requires the extension.
import { REDACTED, redactText, redactDoc, redactExportNodes, nodePolicy, ROOT_INHERITED, containsPlaceholder, containsAllowTag, secretPlaceholder } from '../app/lib/redact.ts';

test('greedy auto-detection hides common secret shapes', () => {
  const cases: Array<[string, string]> = [
    ['wifi password: hunter2 lol', 'wifi password: ' + REDACTED],
    ['api key = abc', 'api key = ' + REDACTED],
    ['my pin is 1234', 'my pin is ' + REDACTED],
    ['Bearer d3bd4736b004693c509d315d89a86bfdf0e77a07', 'Bearer ' + REDACTED],
    ['key d3bd4736b004693c509d315d89a86bfdf0e77a07', 'key ' + REDACTED],
    ['ghp_abcdefghijklmnopqrstuvwxyz0123', REDACTED],
    ['AKIAABCDEFGHIJKLMNOP here', REDACTED + ' here'],
    ['https://adora:s3cret@example.com/x', 'https://adora:' + REDACTED + '@example.com/x'],
    ['card 4111 1111 1111 1111 exp', 'card ' + REDACTED + ' exp'],
    ['ssn 123-45-6789', 'ssn ' + REDACTED],
    ['tok aB3dE5fG7hJ9kL1mN3pQ5r', 'tok ' + REDACTED],
  ];
  for (const [input, expected] of cases) assert.equal(redactText(input), expected, input);
});

test('ordinary text is left alone', () => {
  for (const text of [
    'buy milk and eggs',
    'call mom 206-555-1234',
    'https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz0123/edit',
    'state-of-the-art-2024-edition-final',
    'see https://workflowy.com/#/b24b650a6b91',
    'node 01234567-89ab-cdef-0123-456789abcdef',
    'passed the test #nosec',
  ]) assert.equal(redactText(text), text, text);
});

test('tags: #sec wins, #nosec skips one bullet, #nosecall skips a subtree', () => {
  assert.equal(nodePolicy(['wifi #sec'], ROOT_INHERITED).policy, 'secret');
  assert.equal(nodePolicy(['pw: x #nosec'], ROOT_INHERITED).policy, 'allow');
  assert.equal(nodePolicy(['pw: x #nosec #sec'], ROOT_INHERITED).policy, 'secret');
  assert.equal(nodePolicy(['#second thing'], ROOT_INHERITED).policy, 'auto');
  assert.equal(nodePolicy(['#nosecond'], ROOT_INHERITED).policy, 'auto');
  const tree = nodePolicy(['passwords #nosecall'], ROOT_INHERITED).children;
  assert.equal(nodePolicy(['gmail password: abc'], tree).policy, 'allow');
  const secretTree = nodePolicy(['vault #sec'], tree).children;
  assert.equal(nodePolicy(['anything'], secretTree).policy, 'secret');
  const one = nodePolicy(['x #nosec'], ROOT_INHERITED).children;
  assert.equal(nodePolicy(['password: abc'], one).policy, 'auto');
});

test('secret placeholder keeps tags so cache inheritance works', () => {
  assert.equal(secretPlaceholder('bank stuff #sec #money'), `${REDACTED} #sec #money`);
  assert.equal(secretPlaceholder('plain'), REDACTED);
});

test('read_doc trees respect ancestors, children, and notes', () => {
  const doc = {
    aaaaaaaaaaaa: 'Accounts',
    d: 'password: topsecret',
    c: [
      { bbbbbbbbbbbb: 'Bank #sec', c: [{ cccccccccccc: 'routing 123', d: 'note' }] },
      { dddddddddddd: 'shopping list' },
    ],
    ancestors: [{ None: 'Home' }, { eeeeeeeeeeee: 'Work' }],
  };
  const out = redactDoc(doc) as any;
  assert.equal(out.aaaaaaaaaaaa, 'Accounts');
  assert.equal(out.d, 'password: ' + REDACTED);
  assert.equal(out.c[0].bbbbbbbbbbbb, `${REDACTED} #sec`);
  assert.equal(out.c[0].c[0].cccccccccccc, REDACTED);
  assert.equal(out.c[0].c[0].d, REDACTED);
  assert.equal(out.c[1].dddddddddddd, 'shopping list');
  assert.deepEqual(out.ancestors, doc.ancestors);

  const underSecret = redactDoc({ ffffffffffff: 'child', ancestors: [{ x1: 'vault #sec' }] }) as any;
  assert.equal(underSecret.ffffffffffff, REDACTED);
  assert.equal(underSecret.ancestors[0].x1, `${REDACTED} #sec`);

  const fromCache = redactDoc({ ffffffffffff: 'child' }, { secret: true, allowAll: false }) as any;
  assert.equal(fromCache.ffffffffffff, REDACTED);
});

test('export redaction follows parent_id chains in any order', () => {
  const nodes = [
    { id: 'c', name: 'deep child', note: 'plain', parent_id: 'b' },
    { id: 'a', name: 'Vault #sec' },
    { id: 'b', name: 'middle', parent_id: 'a' },
    { id: 'd', name: 'pw: abc', parent_id: 'e' },
    { id: 'e', name: 'okay zone #nosecall' },
    { id: 'f', name: 'pw: abc' },
  ];
  const out = Object.fromEntries(redactExportNodes(nodes).map((n: any) => [n.id, n]));
  assert.equal(out.a.name, `${REDACTED} #sec`);
  assert.equal(out.b.name, REDACTED);
  assert.equal(out.c.name, REDACTED);
  assert.equal(out.c.note, REDACTED);
  assert.equal(out.d.name, 'pw: abc');
  assert.equal(out.f.name, 'pw: ' + REDACTED);
});

test('edit guards detect placeholders and allow tags', () => {
  assert.ok(containsPlaceholder([{ op: 'update', to: { n: `x ${REDACTED}` } }]));
  assert.ok(!containsPlaceholder([{ op: 'insert', items: [{ n: 'hi' }] }]));
  assert.ok(containsAllowTag([{ op: 'insert', items: [{ n: 'a', c: [{ n: 'b #nosecall' }] }] }]));
  assert.ok(!containsAllowTag([{ op: 'insert', items: [{ n: 'add #sec' }] }]));
});
