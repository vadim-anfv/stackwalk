// How instructions from the backend (server/src/model.rs: Ins) are shown and explained.

export function opText(ins) {
  if (ins.op === 'PHASE') return `· ${ins.label} ·`;
  if (ins.op !== 'PUSH') return ins.op;
  const x = ins.item;
  if (x.kind === 'num' && x.value >= 0 && x.value <= 16) return `OP_${x.value}`;
  return `<${x.label}>`;
}

const DESCR = {
  PUSH: 'Push data onto the stack.',
  OP_DUP: 'Duplicate the top item.',
  OP_DROP: 'Remove the top item.',
  OP_SWAP: 'Swap the top two items.',
  OP_SIZE: 'Push the byte length of the top item (the item stays).',
  OP_HASH160: 'Pop x, push RIPEMD160(SHA256(x)).',
  OP_HASH256: 'Pop x, push SHA256(SHA256(x)).',
  OP_SHA256: 'Pop x, push SHA256(x).',
  OP_RIPEMD160: 'Pop x, push RIPEMD160(x).',
  OP_EQUAL: 'Pop two items, push 1 if they are equal, else 0.',
  OP_EQUALVERIFY: 'Pop two items, fail the script if they differ.',
  OP_NUMEQUAL: 'Pop two numbers, push 1 if they are equal, else 0.',
  OP_NUMEQUALVERIFY: 'Pop two numbers, fail the script if they differ.',
  OP_VERIFY: 'Pop x, fail the script if x is false.',
  OP_CHECKSIG: 'Pop pubkey and signature, push 1 if the signature is valid, else 0.',
  OP_CHECKSIGVERIFY: 'Like CHECKSIG, but fails instead of pushing 0, and pushes nothing on success.',
  OP_CHECKSIGADD: 'Pop pubkey, n and signature; push n + 1 if the signature is valid, else n.',
  OP_CHECKMULTISIG: 'Pop n, n pubkeys, m, m signatures and one extra dummy item. Push 1 if every signature matches a key, in key order.',
  OP_CHECKMULTISIGVERIFY: 'Like CHECKMULTISIG, but fails instead of pushing 0, and pushes nothing on success.',
  OP_IFDUP: 'Duplicate the top item only if it is true (non-zero).',
  OP_IF: 'Pop x. Run the branch if x is true.',
  OP_NOTIF: 'Pop x. Run the branch if x is false.',
  OP_ELSE: 'Switch to the other branch.',
  OP_ENDIF: 'End of the IF block.',
  OP_CHECKSEQUENCEVERIFY: 'Fail unless the input\'s nSequence is a relative lock of the same kind as n (blocks or time) and at least n. BIP68 then keeps the spend out until the coin is that old. Leaves n on the stack.',
  OP_CHECKLOCKTIMEVERIFY: 'Fail unless the transaction locktime is of the same kind as n (height or time) and at least n (absolute timelock). Leaves n on the stack.',
  OP_TOALTSTACK: 'Move the top item to the alt stack.',
  OP_FROMALTSTACK: 'Move the top item of the alt stack back to the main stack.',
  OP_BOOLAND: 'Pop two items, push 1 if both are true, else 0.',
  OP_BOOLOR: 'Pop two items, push 1 if either is true, else 0.',
  OP_ADD: 'Pop two numbers, push their sum.',
  OP_0NOTEQUAL: 'Pop x, push 1 if x is not 0, else 0.',
  OP_RETURN: 'Fail immediately. Outputs starting with OP_RETURN are provably unspendable (used to embed data).',
  PHASE: 'P2SH second phase: the scriptPubKey matched the script hash, so the redeemScript now runs on the scriptSig stack.',
};

export const describe = (ins) => DESCR[ins.op] ?? '';
