// Op names, short aliases and token normalization for typing Script quickly.

export const OPS = [
  'DUP', 'DROP', 'SWAP', 'SIZE', 'VERIFY', 'EQUAL', 'EQUALVERIFY',
  'CHECKSIG', 'CHECKSIGVERIFY', 'CHECKMULTISIG', 'CHECKMULTISIGVERIFY',
  'CHECKSEQUENCEVERIFY', 'CHECKLOCKTIMEVERIFY',
  'HASH160', 'HASH256', 'SHA256', 'RIPEMD160',
  'IF', 'NOTIF', 'ELSE', 'ENDIF', 'IFDUP',
  'ADD', 'BOOLAND', 'BOOLOR', '0NOTEQUAL', 'NUMEQUAL', 'NUMEQUALVERIFY',
];

export const ALIASES = {
  sig: 'CHECKSIG',
  sigv: 'CHECKSIGVERIFY',
  msig: 'CHECKMULTISIG',
  msigv: 'CHECKMULTISIGVERIFY',
  csv: 'CHECKSEQUENCEVERIFY',
  cltv: 'CHECKLOCKTIMEVERIFY',
  eq: 'EQUAL',
  eqv: 'EQUALVERIFY',
  h160: 'HASH160',
  h256: 'HASH256',
  sha: 'SHA256',
  rmd: 'RIPEMD160',
  v: 'VERIFY',
  fi: 'ENDIF',
  band: 'BOOLAND',
  bor: 'BOOLOR',
  nz: '0NOTEQUAL',
  numeq: 'NUMEQUAL',
};

const numTok = (n) => (n === 0 ? 'OP_0' : n > 0 && n <= 16 ? `OP_${n}` : `<${n}>`);

// Returns {ok, canon, kind}: canon is the canonical display form of the token.
export function normalize(raw) {
  const t = raw.replace(/^<(.*)>$/, '$1');
  if (/^-?\d+$/.test(t)) return { ok: true, canon: numTok(Number(t)), kind: 'num' };

  const h = /^(?:h|hash160)\(([A-Za-z]\w*)\)$/i.exec(t);
  if (h) return { ok: true, canon: `<HASH160(${h[1].toUpperCase()})>`, kind: 'push' };
  if (/^[A-Z]\d*$/.test(t)) return { ok: true, canon: `<${t}>`, kind: 'push' };

  const low = t.toLowerCase().replace(/^op_/, '');
  if (/^\d+$/.test(low)) return { ok: true, canon: numTok(Number(low)), kind: 'num' };
  if (low === 'true') return { ok: true, canon: 'OP_1', kind: 'num' };
  if (low === 'false') return { ok: true, canon: 'OP_0', kind: 'num' };

  const name = ALIASES[low] ?? OPS.find((o) => o.toLowerCase() === low);
  if (!name) return { ok: false, canon: raw, kind: 'error' };
  return { ok: true, canon: `OP_${name}`, kind: ['IF', 'NOTIF', 'ELSE', 'ENDIF'].includes(name) ? 'flow' : 'op' };
}

export const tokenize = (text) => text.split(/\s+/).filter(Boolean).map(normalize);

// Completion candidates for a partially typed op: aliases first, then full names.
export function suggest(prefix) {
  const p = prefix.toLowerCase().replace(/^op_/, '');
  if (!p || !/^[a-z0-9]+$/.test(p) || /^\d+$/.test(p)) return [];
  const out = new Map();
  for (const [alias, op] of Object.entries(ALIASES)) if (alias.startsWith(p) && !out.has(op)) out.set(op, alias);
  for (const op of OPS) if (op.toLowerCase().startsWith(p) && !out.has(op)) out.set(op, op.toLowerCase());
  return [...out].map(([op, typed]) => ({ op: `OP_${op}`, typed })).slice(0, 8);
}
