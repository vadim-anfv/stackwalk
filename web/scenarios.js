// Examples for the picker. Each is compiled and run by the backend
// (POST /api/compile with `api`, see API.md); `about` explains the template.

export const groups = { templates: 'standard templates', miniscript: 'miniscript' };

export const scenarios = [
  {
    group: 'templates',
    name: 'P2PK',
    api: { kind: 'descriptor', text: 'pk(A)' },
    about: 'Pay to public key: the oldest form. The key sits in the output itself; the spender gives just a signature.',
  },
  {
    group: 'templates',
    name: 'P2PKH',
    api: { kind: 'descriptor', text: 'pkh(A)' },
    about: 'Pay to public key hash: the output holds only the key hash; the spender reveals the key and signs.',
  },
  {
    group: 'templates',
    name: 'P2MS (bare multisig)',
    api: { kind: 'descriptor', text: 'multi(1,A,B)' },
    about: 'Bare multisig: all keys sit in the output. Standard only up to 3 keys; mostly replaced by P2SH / P2WSH.',
  },
  {
    group: 'templates',
    name: 'P2SH (2-of-2 inside)',
    api: { kind: 'descriptor', text: 'sh(multi(2,A,B))' },
    about: 'Pay to script hash: the output commits to a script hash. Phase 1 checks the revealed redeemScript against it, phase 2 runs that script.',
  },
  {
    group: 'templates',
    name: 'P2WPKH',
    api: { kind: 'descriptor', text: 'wpkh(A)' },
    about: 'Segwit v0 key hash. The output is just a version + 20-byte program; nodes run the implied P2PKH script with the witness [sig, pubkey].',
  },
  {
    group: 'templates',
    name: 'P2WSH (2-of-3 multisig)',
    api: { kind: 'descriptor', text: 'wsh(multi(2,A,B,C))' },
    about: 'Segwit v0 script hash. The last witness item is the witnessScript; nodes check its sha256 against the program, then run it on the rest.',
  },
  {
    group: 'templates',
    name: 'OP_RETURN (data)',
    api: { kind: 'script', text: 'OP_RETURN <0x737461636b77616c6b>' },
    about: 'Data carrier output. Execution stops at OP_RETURN, so it can never be spent; nodes drop it from the UTXO set.',
  },
  { group: 'miniscript', name: 'A and B', api: { kind: 'policy', text: 'and(pk(A),pk(B))' } },
  { group: 'miniscript', name: 'A and B via alt stack', flag: 'altStack', api: { kind: 'miniscript', text: 'and_b(pk(A),a:pk(B))' } },
  { group: 'miniscript', name: 'key + timelocked recovery', api: { kind: 'policy', text: 'or(pk(A),and(pk(B),older(144)))' } },
  { group: 'miniscript', name: 'hash locks', api: { kind: 'policy', text: 'or(and(pk(A),sha256(H)),and(pk(B),older(10)))' } },
  {
    group: 'miniscript',
    name: 'long script (42 ops)',
    api: { kind: 'miniscript', text: 'andor(pk(A),or_i(and_v(v:pkh(B),hash160(H)),older(1008)),and_v(v:thresh(2,pkh(C),s:pk(D),s:pk(E)),sha256(H)))' },
  },
];
