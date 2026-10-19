//! JSON shapes of the UI <-> backend contract (see API.md).
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct CompileReq {
    pub kind: String,
    pub text: String,
    /// output type for policy / miniscript: bare, sh, wsh (default), pkh, wpkh, tr
    #[serde(default)]
    pub wrap: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Item {
    pub id: u64,
    pub kind: &'static str,
    pub label: String,
    pub hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Ins {
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item: Option<Item>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Node {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrap: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    pub ops: Vec<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child: Option<Box<Node>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<Node>>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Step {
    pub pc: i64,
    pub stack: Vec<Item>,
    pub alt: Vec<Item>,
    pub popped: Vec<Item>,
    pub pushed: Vec<Item>,
    pub executed: bool,
    pub note: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(rename = "toAlt", skip_serializing_if = "Option::is_none")]
    pub to_alt: Option<Item>,
}

#[derive(Serialize, Clone, Debug)]
pub struct TraceResult {
    pub ok: bool,
    pub message: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Trace {
    pub steps: Vec<Step>,
    pub result: TraceResult,
    /// opcodes counted toward the 201 limit, as Core does (CHECKMULTISIG adds its keys);
    /// for P2SH the larger of the two scripts
    pub ops: usize,
}

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
    pub policy: Option<String>,
    pub miniscript: Option<String>,
    pub descriptor: Option<String>,
    /// BIP-380 checksum of `descriptor` (as shown, real keys included), without `#`
    pub checksum: Option<String>,
    /// every key of the descriptor is a real one: a wallet can import it
    pub importable: bool,
    /// output type actually built: bare, sh, wsh, pkh or wpkh
    pub wrap: &'static str,
    /// miniscript in bare / sh other than pk() / multi(): BIP-379 specifies it for wsh and tr only
    pub outside_bip379: bool,
    /// real keys of the input, each built as the test key `name` (we cannot sign for them)
    pub keys: Vec<KeyAlias>,
    pub spk: String,
    pub about: Option<String>,
    pub tree: Option<Node>,
    pub script: Vec<Ins>,
    /// size of the script that runs: witnessScript, redeemScript or the scriptPubKey (bare, pkh)
    pub script_bytes: usize,
    pub paths: Vec<PathInfo>,
    pub traces: Vec<Trace>,
}
