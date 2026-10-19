import assert from 'node:assert/strict';
import { test } from 'node:test';

import { privateKeyIn } from '../web/secret.js';

const WIF = 'L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ';
const XPRV = 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi';
const XPUB = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';

test('private keys are caught wherever they sit', () => {
  assert.ok(privateKeyIn(`wsh(pk(${WIF}))`));
  assert.ok(privateKeyIn(`pk(${XPRV}/0/*)`));
  assert.ok(privateKeyIn(`<${WIF}> OP_CHECKSIG`));
  assert.ok(privateKeyIn('5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'));
});

test('public keys, names and scripts are not', () => {
  assert.ok(!privateKeyIn(`wsh(pk(${XPUB}/0/*))`));
  assert.ok(!privateKeyIn('or(pk(A),and(pk(Bob),older(144)))'));
  assert.ok(!privateKeyIn('pk(02e5b88fdbd2e8a4e5c3b1d4f0b5e0e6a7d8c9b0a1f2e3d4c5b6a7980112233445)'));
  assert.ok(!privateKeyIn('OP_DUP OP_HASH160 <hash160(A)> OP_EQUALVERIFY OP_CHECKSIG'));
});
