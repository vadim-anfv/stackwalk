// run: node --test (from the repo root)
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { MAX_TEXT, readLink, writeLink } from '../web/link.js';

const names = ['P2PK', 'P2WSH (2-of-3 multisig)'];

test('an example round-trips by name, with path and step', () => {
  const hash = writeLink({ example: 'P2WSH (2-of-3 multisig)', path: 2, step: 5 });
  assert.deepEqual(readLink(hash, names), { example: 1, path: 2, step: 5 });
});

test('a typed source round-trips, any characters', () => {
  const source = { kind: 'policy', text: 'or(99@pk(A),and(pk(B),older(144)))#&=?', wrap: 'sh' };
  const hash = writeLink({ source, path: 0, step: 0 });
  assert.deepEqual(readLink(hash, names), { source, path: 0, step: 0 });
});

test('step 0 / path 0 are left out', () => {
  assert.equal(writeLink({ example: 'P2PK', path: 0, step: 0 }), '#ex=P2PK');
});

test('a link from before the one page opens the same: its mode is ignored', () => {
  const source = { kind: 'script', text: 'OP_1 OP_2 OP_ADD', wrap: null };
  assert.deepEqual(readLink('#k=script&t=OP_1+OP_2+OP_ADD&p=1&m=script', names), { source, path: 1, step: 0 });
});

test('a descriptor or script has no wrap', () => {
  const source = { kind: 'descriptor', text: 'wsh(pk(A))', wrap: 'wsh' };
  const link = readLink(writeLink({ source, path: 0, step: 0 }), names);
  assert.deepEqual(link.source, { kind: 'descriptor', text: 'wsh(pk(A))', wrap: null });
});

test('anything unknown or malformed is dropped, not trusted', () => {
  // not ours (an old #explore, someone else's fragment): no link
  assert.equal(readLink('#explore', names), null);
  assert.equal(readLink('', names), null);
  // an unknown example, kind or wrap
  assert.equal(readLink('#ex=__proto__', names), null);
  assert.equal(readLink('#k=constructor&t=x', names), null);
  assert.equal(readLink('#k=policy&t=pk(A)&w=evil', names).source.wrap, null);
  // path / step: digits only, else 0 (the page bounds them by the run)
  assert.deepEqual(readLink('#ex=P2PK&p=NaN&s=-1', names), { example: 0, path: 0, step: 0 });
  assert.deepEqual(readLink('#ex=P2PK&p=1e3&s=99999', names), { example: 0, path: 0, step: 0 });
  // no text, or too much of it
  assert.equal(readLink('#k=policy&t=', names), null);
  assert.equal(readLink(`#k=policy&t=${'x'.repeat(MAX_TEXT + 1)}`, names), null);
});
