//! JSON of the page <-> server contract: `POST /api/compile` takes a [`CompileReq`] and
//! answers a [`Scenario`] (200) or `{"error": "..."}` (status codes in `api.rs`).
//! Test keys only: key names (`A`, `B`, ...) are built as fixed test keys, real keys as test
//! keys of free names (see [`Scenario::keys`]). No taproot.
use serde::{Deserialize, Serialize};

/// An unknown `kind` or `wrap` is a JSON error, as a missing field is.
#[derive(Deserialize, Clone)]
pub struct CompileReq {
    pub kind: Kind,
    pub text: String,
    /// output type for policy / miniscript, `wsh` if absent. A descriptor names its own; a
    /// script is always wsh.
    #[serde(default)]
    pub wrap: Option<Wrap>,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// compiled to miniscript for `wrap`, e.g. `or(pk(A),and(pk(B),older(144)))`
    Policy,
    /// parsed for `wrap`; no policy is lifted from it (fields flow one way)
    Miniscript,
    /// `pk`, `pkh`, `wpkh`, `sh(ms)`, `wsh(ms)` or bare `ms`. A trailing `#checksum` is
    /// verified against the text as typed, never silently fixed
    Descriptor,
    /// Whitespace separated tokens: `OP_*` (`OP_0`..`OP_16`, `OP_TRUE`), decimal numbers,
    /// `<pk(A)>`, `<hash160(A)>`, `<sha256(H)>` (also hash256, ripemd160, hash160 of a
    /// preimage), `<144>`, `<0x...>`. Parsed as segwit v0 miniscript if it is one (then as
    /// kind miniscript), else run once as a witness script with an empty witness.
    Script,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Wrap {
    Bare,
    /// pkh and wpkh take a single key
    Pkh,
    Sh,
    Wpkh,
    Wsh,
    /// refused: no taproot yet
    Tr,
}

impl Kind {
    /// as sent, for logs and metrics
    pub fn name(self) -> &'static str {
        match self {
            Kind::Policy => "policy",
            Kind::Miniscript => "miniscript",
            Kind::Descriptor => "descriptor",
            Kind::Script => "script",
        }
    }
}

impl Wrap {
    /// as sent, for logs
    pub fn name(self) -> &'static str {
        match self {
            Wrap::Bare => "bare",
            Wrap::Pkh => "pkh",
            Wrap::Sh => "sh",
            Wrap::Wpkh => "wpkh",
            Wrap::Wsh => "wsh",
            Wrap::Tr => "tr",
        }
    }
}

/// A stack element or pushed data.
#[derive(Serialize, Clone, Debug)]
pub struct Item {
    /// Unique within one trace. An item keeps its id while it stays on the stack unchanged;
    /// every newly pushed element gets a new one, copies too (OP_DUP). Pushes in
    /// `Scenario::script` have their own ids, not linked to stack ids; in `SpendData::items`
    /// ids are unique only within the list.
    pub id: u64,
    /// `sig`, `pubkey`, `hash` (hashes and preimages), `script` (redeemScript, witnessScript)
    /// or `num` (script numbers, empty = 0). Unknown bytes: `num` if they decode as a minimal
    /// number up to 4 bytes, else `hash`. Always one of these: the page uses it in class names.
    pub kind: &'static str,
    /// What it is, not its bytes: `sig(A)`, `pk(A)`, `hash160(A)` (of A's key), `preimage(H)`,
    /// `sha256(H)`, `144`, `<empty>`, `witnessScript`. Unknown bytes: the (shortened) hex.
    pub label: String,
    pub hex: String,
    /// `num` only: the decoded script number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<i64>,
    /// the key name of an item made from a test key (`sig(A)`, `pk(A)`, `hash160(A)`): the
    /// page tells by it that a scenario needs test keys
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// One instruction of the script that runs: `{op: "OP_CHECKSIG"}`, `{op: "PUSH", item}`, or
/// `{op: "PHASE", label: "redeemScript"}` between the two scripts of P2SH. Small numbers are
/// pushes too (`OP_0`..`OP_16` are num items); the page shows those as `OP_n`.
#[derive(Serialize, Clone, Debug)]
pub struct Ins {
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item: Option<Item>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// A miniscript fragment: a leaf `{text, ops}`, a wrapper `{wrap: "v:", ops, child}` or a
/// node `{head: "and_v", ops, children}`. Joined back (text; wrap + child; `head(` children
/// joined by `,` `)`) they give exactly `Scenario::miniscript`, so sugar is a leaf
/// (`c:pk_k(A)` is `{text: "pk(A)"}`) and stacked wrappers follow its Display.
#[derive(Serialize, Clone, Debug, Default)]
pub struct Node {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrap: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    /// indices into `Scenario::script` of what this fragment emits itself, not its children
    /// (PHASE entries count: for sh the redeemScript fragments are offset)
    pub ops: Vec<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child: Option<Box<Node>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<Node>>,
}

/// One instruction the engine reached. `steps[0]` of a trace is the start, not a step:
/// `pc: -1`, the initial stack, nothing popped or pushed, a note naming where the stack
/// came from (witness without the witnessScript, witness, scriptSig, or empty).
#[derive(Serialize, Clone, Debug)]
pub struct Step {
    /// index into `Scenario::script`
    pub pc: i64,
    /// bottom first: the last element is the top
    pub stack: Vec<Item>,
    pub alt: Vec<Item>,
    /// Diffed against the previous step: the longest common bottom (same ids) stays, the rest
    /// of the old stack is popped (top first), the rest of the new one pushed (bottom first).
    /// A move to / from the alt stack shows here too; `to_alt` is what landed there.
    pub popped: Vec<Item>,
    pub pushed: Vec<Item>,
    /// false for an op in a branch not taken: the interpreter reads it, the stack is untouched
    pub executed: bool,
    /// a short explanation where it helps (signature checks, equality, timelocks), else ""
    pub note: String,
    /// the run stops here
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(rename = "toAlt", skip_serializing_if = "Option::is_none")]
    pub to_alt: Option<Item>,
}

#[derive(Serialize, Clone, Debug)]
pub struct TraceResult {
    pub ok: bool,
    /// "valid spend", or where and why it failed. Also a failure: a final stack that is not
    /// exactly one true element (segwit clean stack) or false on top (legacy).
    pub message: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Trace {
    pub steps: Vec<Step>,
    pub result: TraceResult,
    /// opcodes counted toward the 201 limit as Core does: every op above OP_16, executed or
    /// not, plus the keys of an executed CHECKMULTISIG, up to where the run stops; for P2SH
    /// the larger of the two scripts
    pub ops: usize,
}

/// A spend path: `paths[i]` goes with `traces[i]`. Smallest first, supersets dropped,
/// at most 64 (see `paths.rs`). Names read like `A signs`, `A + B`, `B after 144 blocks`.
/// Each passing path may get failing variants (`fails`): `<name>: timelock not reached`
/// (locktime one short; the satisfier is told it is fine, the engine fails at CSV / CLTV),
/// `<name>: wrong signer` (the first signature by another key), and for `multi` one
/// `wrong order`. A failing variant that passes after all is dropped.
#[derive(Serialize, Clone, Debug)]
pub struct PathInfo {
    pub name: String,
    pub fails: bool,
    pub spend: SpendData,
}

/// What the spending input carries, as serialized in the transaction.
#[derive(Serialize, Clone, Debug)]
pub struct SpendData {
    /// "witness" (segwit) or "scriptSig" (legacy)
    pub field: &'static str,
    /// in transaction order (= stack order, bottom first)
    pub items: Vec<Item>,
    /// the last item is the witnessScript / redeemScript: checked against the hash, then run
    pub script_last: bool,
    /// serialized size of the witness (count + length-prefixed items) or of the scriptSig (pushes)
    pub bytes: usize,
    /// the whole input in vbytes: outpoint, scriptSig, sequence at 4 WU per byte, witness at 1
    pub vbytes: usize,
}

#[derive(Serialize, Clone, Debug)]
pub struct KeyAlias {
    pub name: String,
    pub key: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Scenario {
    /// the input policy (kind policy only), else null: never lifted back from a miniscript
    pub policy: Option<String>,
    pub miniscript: Option<String>,
    /// with key names and without the checksum (so the field stays editable); null for a raw script
    pub descriptor: Option<String>,
    /// BIP-380 checksum of `descriptor` (as shown, real keys included), without `#`
    pub checksum: Option<String>,
    /// every key of the descriptor is a real one: a wallet can import it
    pub importable: bool,
    /// output type actually built: bare, sh, wsh, pkh or wpkh
    pub wrap: &'static str,
    /// miniscript in bare / sh other than pk() / multi(): BIP-379 specifies it for wsh and tr only
    pub outside_bip379: bool,
    /// Real keys of the input (hex pubkeys, xpubs with origin / path), each built as the
    /// test key `name`, a free one: we cannot sign for them. `policy`, `miniscript` and
    /// `descriptor` show the real keys again; script, tree, items and path names use `name`.
    pub keys: Vec<KeyAlias>,
    /// the scriptPubKey as text with labels, e.g. `OP_0 <sha256(witnessScript)>`
    pub spk: String,
    pub about: Option<String>,
    /// null for templates without miniscript (pkh, wpkh) and raw scripts
    pub tree: Option<Node>,
    /// What runs, step by step: the witnessScript (wsh), the scriptPubKey (bare, pkh), the
    /// P2PKH script code (wpkh), or for sh the scriptPubKey, a PHASE entry, the redeemScript.
    pub script: Vec<Ins>,
    /// size of the script that runs: witnessScript, redeemScript or the scriptPubKey (bare, pkh)
    pub script_bytes: usize,
    pub paths: Vec<PathInfo>,
    pub traces: Vec<Trace>,
}
