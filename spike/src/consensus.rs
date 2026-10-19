//! Ground truth: libbitcoinconsensus (Bitcoin Core 26.0) via bitcoinconsensus 0.106.
use miniscript::bitcoin::{self, Transaction, TxOut, Witness};

pub fn verify(tx: &Transaction, witness: &[Vec<u8>], prevouts: &[TxOut]) -> Result<(), bitcoinconsensus::Error> {
    let mut t = tx.clone();
    t.input[0].witness = Witness::from_slice(witness);
    let bytes = bitcoin::consensus::serialize(&t);
    let utxos: Vec<bitcoinconsensus::Utxo> = prevouts
        .iter()
        .map(|o| bitcoinconsensus::Utxo {
            script_pubkey: o.script_pubkey.as_bytes().as_ptr(),
            script_pubkey_len: o.script_pubkey.len() as u32,
            value: o.value.to_sat() as i64,
        })
        .collect();
    let spk = prevouts[0].script_pubkey.as_bytes();
    // VERIFY_ALL_PRE_TAPROOT | VERIFY_TAPROOT
    bitcoinconsensus::verify(spk, prevouts[0].value.to_sat(), &bytes, Some(&utxos), 0)
}
