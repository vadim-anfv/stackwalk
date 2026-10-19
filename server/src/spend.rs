//! The spending input as serialized in the transaction: witness or scriptSig, sizes.
use crate::keys::KeyRing;
use crate::model::SpendData;

/// Item ids of the spend view: not linked to stack ids, only unique within it.
const ID_BASE: u64 = 1_000_000;

/// outpoint (32 + 4) and sequence (4)
const INPUT_FIXED: usize = 40;

#[derive(Clone, Copy)]
pub enum Field {
    Witness,
    ScriptSig,
}

/// `items` in transaction order; `script_last`: the last one is the witnessScript / redeemScript.
pub fn spend_data(ring: &KeyRing, field: Field, items: &[Vec<u8>], script_last: bool) -> SpendData {
    let (name, bytes, vbytes) = match field {
        Field::Witness => {
            let bytes = varint_len(items.len()) + items.iter().map(|d| varint_len(d.len()) + d.len()).sum::<usize>();
            // empty scriptSig: its length byte only; witness bytes weigh 1 WU, the rest 4
            ("witness", bytes, ((INPUT_FIXED + 1) * 4 + bytes).div_ceil(4))
        }
        Field::ScriptSig => {
            let bytes: usize = items.iter().map(|d| push_len(d)).sum();
            ("scriptSig", bytes, INPUT_FIXED + varint_len(bytes) + bytes)
        }
    };
    SpendData {
        field: name,
        items: items.iter().zip(ID_BASE..).map(|(d, id)| ring.item(id, d)).collect(),
        script_last,
        bytes,
        vbytes,
    }
}

fn varint_len(n: usize) -> usize {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// Size of a minimal push of `d` (MINIMALDATA): OP_0, OP_1..OP_16 / OP_1NEGATE, then direct
/// pushes and OP_PUSHDATA1 / 2 / 4.
fn push_len(d: &[u8]) -> usize {
    match d {
        [] => 1,
        [n] if (1..=16).contains(n) || *n == 0x81 => 1,
        _ => match d.len() {
            n @ 1..=75 => 1 + n,
            n @ 76..=0xff => 2 + n,
            n @ 0x100..=0xffff => 3 + n,
            n => 5 + n,
        },
    }
}
