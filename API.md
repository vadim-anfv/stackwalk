# stackwalk API (UI <-> backend)

The Rust server (`server/`) serves both the page and `/api/*` on one origin, by default `127.0.0.1:5173` (`BIND` sets the addresses). Debug builds serve `web/` from disk with live reload; release builds serve `web/` embedded in the binary (`server/build.rs`), so a deploy is the one binary. Dev: `cd server && bacon`. JSON in, JSON out.

First iteration scope: test keys only (symbolic key names), policy / miniscript as `bare`, `sh`, `wsh` (default), `pkh` or `wpkh`, legacy and segwit v0 templates. No taproot.

## POST /api/compile

Request:

```json
{ "kind": "policy" | "miniscript" | "descriptor" | "script", "text": "...", "wrap": "wsh" }
```

- `wrap` (optional, policy / miniscript only, default `wsh`): the output type to build. `bare`, `sh`, `wsh` compile / parse the miniscript in that script context and wrap it; `pkh`, `wpkh` take a single key (`pk(A)`, or miniscript `pk(A)` / `pkh(A)`) and build that template, anything else -> error; `tr` -> error "taproot is not supported yet". Ignored for `descriptor` (it names its own) and `script` (always segwit v0).
- `policy`: concrete policy with key names, e.g. `or(pk(A),and(pk(B),older(144)))`. Compiled to miniscript for `wrap`.
- `miniscript`: e.g. `and_v(v:pk(A),pk(B))`, parsed for `wrap`. No policy is lifted from it.
- `descriptor`: may end in `#checksum`: it is verified against the text as typed, a mismatch is an error `checksum mismatch: got #..., expected #...` (never silently fixed). Forms: `pk(A)`, `pkh(A)`, `wpkh(A)`, `sh(<ms>)`, `wsh(<ms>)`, bare `<ms>` (e.g. `multi(1,A,B)`). `tr(...)` -> error "taproot is not supported yet".
- `script`: Script as text, tokens separated by whitespace: `OP_*` names (also `OP_0`..`OP_16`, `OP_TRUE`/`OP_FALSE`), decimal numbers (pushed as script numbers), `<pk(A)>`, `<hash160(A)>`, `<sha256(H)>` / `<hash256(H)>` / `<ripemd160(H)>` / `<hash160(H)>` for preimage hashes, `<144>` (number), `<0x...>` / `<hex>` raw push. The backend first tries to parse the Script as segwit v0 miniscript; if it is, the result is as for `miniscript`. If not, it is run once as a segwit v0 witness script with an empty witness (one path, named "empty witness").

Response 200: a **scenario**:

```json
{
  "policy": "or(pk(A),and(pk(B),older(144)))" | null,
  "miniscript": "or_d(pk(A),and_v(v:pk(B),older(144)))" | null,
  "descriptor": "wsh(or_d(pk(A),and_v(v:pk(B),older(144))))",
  "checksum": "…",
  "importable": false,
  "wrap": "wsh",
  "outside_bip379": false,
  "keys": [],
  "spk": "OP_0 <sha256(witnessScript)>",
  "about": null,
  "tree": Node | null,
  "script": [Ins],
  "script_bytes": 105,
  "paths": [{ "name": "A signs", "fails": false, "spend": Spend }],
  "traces": [Trace]
}
```

- `policy`: the input policy (kind `policy` only), else null: fields flow one way, policy -> miniscript -> descriptor.
- `descriptor`: with key names, no checksum (so the field stays editable).
- `checksum`: the BIP-380 checksum of `descriptor` as shown (real keys included), without `#`; null when there is no descriptor (a script). A wallet takes `descriptor#checksum`.
- `importable`: true when every key of the descriptor is a real one. With test keys (or a mix) the checksum is still right, but no wallet can use the descriptor.
- `wrap`: the output type actually built: `bare`, `sh`, `wsh`, `pkh` or `wpkh` (for a descriptor: its own; for a script: `wsh`).
- `keys`: real keys of the input (`[{ "name": "A", "key": "02e5…" }]`, empty for test keys only). In policy / miniscript / descriptor text, a key argument (of `pk`, `pkh`, `multi`, ...) that parses as a descriptor key (hex pubkey, xpub with origin / path) is built as the test key `name` (a free one: A, B, ... not used in the text), since we cannot sign for it. `policy`, `miniscript`, `descriptor` show the real keys again; `script`, `tree`, items and path names use `name`. Something that looks like a key (hex of 64+ chars, `xpub` / `tpub`, `[origin]`) but does not parse is an error "invalid key ...". Not done for `script`.
- `outside_bip379`: true for miniscript in `bare` / `sh` other than `pk()` (BIP-381) and `multi()` (BIP-383). BIP-379 specifies miniscript for `wsh` and `tr` only; rust-miniscript still builds it.
- `spk`: scriptPubKey as text with labels (`OP_DUP OP_HASH160 <hash160(A)> OP_EQUALVERIFY OP_CHECKSIG`, `OP_0 <sha256(witnessScript)>`, `OP_HASH160 <hash160(redeemScript)> OP_EQUAL`).
- `script`: the script that is executed step by step, as a flat list of instructions. For `wsh` it is the witness script. For `pk` / `pkh` / bare it is the scriptPubKey (legacy). For `wpkh` it is the P2PKH script code `OP_DUP OP_HASH160 <hash160(A)> OP_EQUALVERIFY OP_CHECKSIG` (segwit v0). For `sh(ms)` it is the scriptPubKey, then a `PHASE` marker, then the redeemScript (two phases, see below).
- `script_bytes`: size of the script that runs: witnessScript (wsh, script), redeemScript (sh), scriptPubKey (bare), the P2PKH script code (pkh, wpkh).
- `paths[i]` and `traces[i]` belong together: one trace per spend path.

### Spend (the input as sent)

```json
{ "field": "witness" | "scriptSig", "items": [Item], "script_last": true, "bytes": 254, "vbytes": 105 }
```

- `items`: in transaction order (= stack order, bottom first). For wsh the last one is the witnessScript, for sh the redeemScript (`script_last: true`): checked against the scriptPubKey hash, then run, not stack data. Item ids here are only unique within `items`.
- `bytes`: serialized size of the witness (item count + length-prefixed items) or of the scriptSig (minimal pushes).
- `vbytes`: the whole input: outpoint, scriptSig length, scriptSig and sequence at 4 weight units per byte, the witness at 1, divided by 4 and rounded up.

### Ins (instruction)

```json
{ "op": "OP_CHECKSIG" }
{ "op": "PUSH", "item": Item }
{ "op": "PHASE", "label": "redeemScript" }
```

Small numbers are pushes too: `OP_0` .. `OP_16` are `{ "op": "PUSH", "item": { "kind": "num", "value": n, ... } }`; the UI renders num pushes 0..16 as `OP_n`, everything else as `<label>`.

### Item (stack element / pushed data)

```json
{ "id": 7, "kind": "sig" | "pubkey" | "hash" | "num" | "script", "label": "sig(A)", "hex": "3044...01", "value": 144, "name": "A" }
```

- `label` is semantic: `sig(A)`, `pk(A)`, `hash160(A)` (hash160 of A's key), `preimage(H)`, `sha256(H)`, `144`, `<empty>`, `witnessScript`, `redeemScript`. Unknown bytes: label = hex (shortened if long).
- `kind`: `sig` signatures; `pubkey` keys; `hash` hashes and preimages; `script` serialized scripts (redeemScript, witnessScript); `num` script numbers (including empty = 0). Unknown bytes: `num` if they decode as a minimal script number up to 4 bytes, else `hash`.
- `value`: only for `num`, the decoded script number. An empty element is `{kind: "num", value: 0, label: "<empty>", hex: ""}`.
- `name`: the key name for items derived from a test key (`sig(A)`, `pk(A)`, `hash160(A)`), absent otherwise. The UI uses its presence to detect that a scenario needs test keys.
- `id`: unique within one trace. An item keeps its id while it stays on the stack unchanged; every newly pushed element gets a new id (also copies, e.g. OP_DUP). Items inside `script` (pushes) have ids too, unique within the scenario; they are not linked to stack ids.

### Node (miniscript fragment tree)

```json
{ "text": "pk(A)", "ops": [0, 1] }
{ "wrap": "v:", "ops": [5], "child": Node }
{ "head": "and_v", "ops": [], "children": [Node, Node] }
```

- Concatenating the tree (`text`; `wrap` + child; `head(` children joined by `,` `)`) must give exactly the `miniscript` string. So sugar is a leaf: `c:pk_k(A)` is `{text: "pk(A)"}`, `c:pk_h(A)` is `{text: "pkh(A)"}`, and stacked wrappers follow `Display`: `sdv:older(144)` is `{wrap: "s", child: {wrap: "d", child: {wrap: "v:", child: {text: "older(144)"}}}}`.
- `ops`: indices into `script` of the instructions this node emits itself (not its children). Indices count `PHASE` entries too (for `sh`, redeemScript nodes are offset accordingly).
- Templates without miniscript (`pkh`, `wpkh`) may return `tree: null`.

### Trace

```json
{
  "steps": [Step],
  "result": { "ok": true, "message": "valid spend" },
  "ops": 4
}
```

`ops`: opcodes counted toward the 201 limit as Core does (every op above OP_16, executed or not, plus the keys of an executed CHECKMULTISIG), up to where the run stops; for sh the larger of the two scripts.

`steps[0]` is the initial state: `pc: -1`, `stack` = the initial stack (witness without the witness script for wsh; scriptSig pushes for legacy), `popped`/`pushed` empty, `executed: true`, `note` names the source: `Initial stack = witness without its last item (witnessScript): [sig(A)]` (wsh), `Initial stack = witness: [sig(A), pk(A)]` (wpkh), `Initial stack = scriptSig: [sig(A), pk(A)]` (legacy, sh), `Initial stack: empty` (a bare script).

### Step

```json
{
  "pc": 3,
  "stack": [Item],
  "alt": [Item],
  "popped": [Item],
  "pushed": [Item],
  "executed": true,
  "note": "sig(A) is valid for pk(A)",
  "error": "OP_CHECKSIGVERIFY: signature check failed",
  "toAlt": Item
}
```

- One step per instruction in `script` that the engine reached (including skipped ones in a non-taken IF branch, `executed: false`, note `Skipped: inside a branch that is not taken.`). Execution stops at the first error; that step has `error`.
- `pc`: index into `script`.
- `stack`, `alt`: bottom first (last element = top).
- `popped`: items removed from the main stack by this step (top first); `pushed`: items added (bottom first). Computed by diffing with the previous step: the longest common bottom part (same ids) stays, the rest of the previous stack is popped, the rest of the new stack is pushed. Moving to / from the alt stack shows as popped / pushed on the main stack; `toAlt` is the item that landed on the alt stack.
- `note`: short human explanation where useful: signature checks (`sig(A) is valid for pk(A)` / `sig(B) does not match pk(A)`), equality (`hash160(A) == hash160(A)`), timelocks (`input age 144 >= 144 blocks`), verify results, skips. Empty string otherwise.
- `PHASE` (sh only): a step with `pc` of the PHASE entry, note `redeemScript matches the hash: it now runs on the remaining stack`; its `stack` is the stack phase 2 starts with.

`result`: `{ok: true, message: "valid spend"}`, or `{ok: false, message: "fails at #8 OP_CHECKSIGVERIFY: signature check failed"}`. Also fails if the final stack is not exactly one true element (clean stack, segwit) or false on top (legacy): message says so.

## Paths

Generated by the backend from the policy / miniscript (asset combinations + satisfier templates, see `server/src/paths.rs`), smallest first, supersets dropped. Names are readable: `A signs`, `A + B`, `B after 144 blocks`, `preimage H + A`.

For each passing path, up to two failing variants (`fails: true`):
- `<name>: timelock not reached` if the path uses `older(n)` / `after(n)`: tx sequence / locktime one below the requirement; the satisfier is told the timelock is fine so it still builds the witness, and the engine fails at CSV / CLTV.
- `<name>: wrong signer` if the path has a signature: the first signature is made by another key (another key of the policy if it is not in the path, else a fresh name `X`).

Templates: `pk` / `pkh` / `wpkh`: `A signs`, plus `B tries` (wrong signer). `multi(k, ...)`: one path per k-subset in key order, plus one wrong order variant.

## Errors

Status 400: `{ "error": "human readable message" }` (parse / compile errors, taproot, too many assets, etc.).

## GET /api/ping

`{ "ok": true }`.
