//! Dummy spending tx, sighash per context, and a Satisfier with real signatures.
use std::collections::BTreeMap;

use miniscript::bitcoin::hashes::{Hash, hash160, ripemd160, sha256};
use miniscript::bitcoin::secp256k1::Message;
use miniscript::bitcoin::sighash::{EcdsaSighashType, SighashCache};
use miniscript::bitcoin::{
    self, Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute, ecdsa,
    relative, transaction,
};
use miniscript::{Preimage32, Satisfier, hash256};

pub const PREVOUT_VALUE: Amount = Amount::from_sat(100_000);

/// Dummy tx spending a fake prevout (txid = sha256d("stackwalk")) of `spk`.
pub fn dummy_tx(spk: &ScriptBuf, sequence: Sequence, lock_time: absolute::LockTime) -> (Transaction, Vec<TxOut>) {
    let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::hash(b"stackwalk"));
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time,
        input: vec![TxIn { previous_output: OutPoint { txid, vout: 0 }, script_sig: ScriptBuf::new(), sequence, witness: Witness::new() }],
        output: vec![TxOut { value: Amount::from_sat(90_000), script_pubkey: ScriptBuf::new_op_return([]) }],
    };
    (tx, vec![TxOut { value: PREVOUT_VALUE, script_pubkey: spk.clone() }])
}

/// How signatures are hashed: legacy (script code) or BIP143 segwit v0 (script code).
#[derive(Clone)]
pub enum SigCtx {
    Legacy(ScriptBuf),
    SegwitV0(ScriptBuf),
}

impl SigCtx {
    pub fn message(&self, tx: &Transaction) -> Message {
        let cache = SighashCache::new(tx);
        match self {
            SigCtx::Legacy(code) => {
                let h = cache.legacy_signature_hash(0, code, EcdsaSighashType::All as u32).expect("input 0 exists");
                Message::from_digest(h.to_byte_array())
            }
            SigCtx::SegwitV0(code) => {
                let mut cache = cache;
                let h = cache.p2wsh_signature_hash(0, code, PREVOUT_VALUE, EcdsaSighashType::All).expect("input 0 exists");
                Message::from_digest(h.to_byte_array())
            }
        }
    }
}

pub struct Sat {
    pub ecdsa: BTreeMap<PublicKey, ecdsa::Signature>,
    sha256: BTreeMap<sha256::Hash, Preimage32>,
    hash256: BTreeMap<hash256::Hash, Preimage32>,
    ripemd160: BTreeMap<ripemd160::Hash, Preimage32>,
    hash160: BTreeMap<hash160::Hash, Preimage32>,
    sequence: Sequence,
    lock_time: absolute::LockTime,
    /// if true, the satisfier claims all timelocks are fine (to build a witness that must fail)
    lie: bool,
}

impl Sat {
    pub fn new(sequence: Sequence, lock_time: absolute::LockTime, lie: bool) -> Self {
        Sat {
            ecdsa: BTreeMap::new(),
            sha256: BTreeMap::new(),
            hash256: BTreeMap::new(),
            ripemd160: BTreeMap::new(),
            hash160: BTreeMap::new(),
            sequence,
            lock_time,
            lie,
        }
    }

    pub fn add_preimage(&mut self, p: [u8; 32]) {
        self.sha256.insert(sha256::Hash::hash(&p), p);
        self.hash256.insert(hash256::Hash::hash(&p), p);
        self.ripemd160.insert(ripemd160::Hash::hash(&p), p);
        self.hash160.insert(hash160::Hash::hash(&p), p);
    }
}

impl Satisfier<PublicKey> for Sat {
    fn lookup_ecdsa_sig(&self, pk: &PublicKey) -> Option<ecdsa::Signature> {
        self.ecdsa.get(pk).copied()
    }
    fn lookup_sha256(&self, h: &sha256::Hash) -> Option<Preimage32> {
        self.sha256.get(h).copied()
    }
    fn lookup_hash256(&self, h: &hash256::Hash) -> Option<Preimage32> {
        self.hash256.get(h).copied()
    }
    fn lookup_ripemd160(&self, h: &ripemd160::Hash) -> Option<Preimage32> {
        self.ripemd160.get(h).copied()
    }
    fn lookup_hash160(&self, h: &hash160::Hash) -> Option<Preimage32> {
        self.hash160.get(h).copied()
    }
    fn check_older(&self, n: relative::LockTime) -> bool {
        self.lie || Satisfier::<PublicKey>::check_older(&self.sequence, n)
    }
    fn check_after(&self, n: absolute::LockTime) -> bool {
        self.lie || Satisfier::<PublicKey>::check_after(&self.lock_time, n)
    }
}
