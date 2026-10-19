//! Satisfier with REAL signatures over a dummy spending tx.
use std::collections::{BTreeMap, BTreeSet};

use miniscript::bitcoin::hashes::{Hash, hash160, ripemd160, sha256};
use miniscript::bitcoin::secp256k1::Message;
use miniscript::bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use miniscript::bitcoin::taproot::{LeafVersion, TapLeafHash};
use miniscript::bitcoin::{
    self, Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute, ecdsa, relative, taproot, transaction,
};
use miniscript::{Preimage32, Satisfier, hash256};

use crate::keys::KeyRing;

pub const PREVOUT_VALUE: Amount = Amount::from_sat(100_000);

/// Dummy tx spending a fake prevout (txid = sha256d("stackwalk")) of `spk`.
pub fn dummy_tx(spk: &ScriptBuf, sequence: Sequence, lock_time: absolute::LockTime) -> (Transaction, Vec<TxOut>) {
    let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::hash(b"stackwalk"));
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(90_000), script_pubkey: ScriptBuf::new_op_return([]) }],
    };
    let prevouts = vec![TxOut { value: PREVOUT_VALUE, script_pubkey: spk.clone() }];
    (tx, prevouts)
}

/// What the "user" has for a given spend path.
#[derive(Default, Clone)]
pub struct Have {
    pub signers: BTreeSet<String>,
    pub preimages: BTreeSet<String>,
    /// If true, `check_older` lies and always says yes (to produce a witness that must fail in exec).
    pub lie_about_older: bool,
}

pub struct Sat {
    ecdsa: BTreeMap<PublicKey, ecdsa::Signature>,
    schnorr: BTreeMap<(bitcoin::secp256k1::XOnlyPublicKey, TapLeafHash), taproot::Signature>,
    sha256: BTreeMap<sha256::Hash, Preimage32>,
    hash256: BTreeMap<hash256::Hash, Preimage32>,
    ripemd160: BTreeMap<ripemd160::Hash, Preimage32>,
    hash160: BTreeMap<hash160::Hash, Preimage32>,
    sequence: Sequence,
    lock_time: absolute::LockTime,
    lie_about_older: bool,
}

impl Sat {
    fn base(ring: &mut KeyRing, have: &Have, tx: &Transaction) -> Self {
        let mut s = Sat {
            ecdsa: BTreeMap::new(),
            schnorr: BTreeMap::new(),
            sha256: BTreeMap::new(),
            hash256: BTreeMap::new(),
            ripemd160: BTreeMap::new(),
            hash160: BTreeMap::new(),
            sequence: tx.input[0].sequence,
            lock_time: tx.lock_time,
            lie_about_older: have.lie_about_older,
        };
        for h in &have.preimages {
            let p = ring.preimage(h);
            s.sha256.insert(sha256::Hash::hash(&p), p);
            s.hash256.insert(hash256::Hash::hash(&p), p);
            s.ripemd160.insert(ripemd160::Hash::hash(&p), p);
            s.hash160.insert(hash160::Hash::hash(&p), p);
        }
        s
    }

    /// Segwit v0: sign BIP143 sighash(ALL) of `witness_script` with each signer key.
    pub fn segwit_v0(ring: &mut KeyRing, have: &Have, tx: &Transaction, witness_script: &ScriptBuf) -> Self {
        let mut s = Self::base(ring, have, tx);
        let mut cache = SighashCache::new(tx);
        let sighash = cache
            .p2wsh_signature_hash(0, witness_script, PREVOUT_VALUE, EcdsaSighashType::All)
            .unwrap();
        let msg = Message::from_digest(sighash.to_byte_array());
        for name in &have.signers {
            let sk = ring.secret(name);
            let sig = ecdsa::Signature { signature: ring.secp.sign_ecdsa(&msg, &sk), sighash_type: EcdsaSighashType::All };
            ring.label_sig(&sig.to_vec(), name);
            s.ecdsa.insert(ring.pubkey(name), sig);
        }
        s
    }

    /// Tapscript: sign BIP341 script-path sighash(DEFAULT) for each given leaf.
    pub fn tapscript(ring: &mut KeyRing, have: &Have, tx: &Transaction, prevouts: &[TxOut], leaves: &[ScriptBuf]) -> Self {
        let mut s = Self::base(ring, have, tx);
        let mut cache = SighashCache::new(tx);
        for leaf in leaves {
            let lh = TapLeafHash::from_script(leaf, LeafVersion::TapScript);
            let sighash = cache
                .taproot_script_spend_signature_hash(0, &Prevouts::All(prevouts), lh, TapSighashType::Default)
                .unwrap();
            let msg = Message::from_digest(sighash.to_byte_array());
            for name in &have.signers {
                let kp = ring.keypair(name);
                let sig = taproot::Signature {
                    signature: ring.secp.sign_schnorr_no_aux_rand(&msg, &kp),
                    sighash_type: TapSighashType::Default,
                };
                ring.label_sig(&sig.to_vec(), name);
                s.schnorr.insert((kp.x_only_public_key().0, lh), sig);
            }
        }
        s
    }
}

impl Satisfier<PublicKey> for Sat {
    fn lookup_ecdsa_sig(&self, pk: &PublicKey) -> Option<ecdsa::Signature> {
        self.ecdsa.get(pk).copied()
    }
    fn lookup_tap_leaf_script_sig(&self, pk: &PublicKey, lh: &TapLeafHash) -> Option<taproot::Signature> {
        self.schnorr.get(&(pk.inner.x_only_public_key().0, *lh)).copied()
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
        self.lie_about_older || Satisfier::<PublicKey>::check_older(&self.sequence, n)
    }
    fn check_after(&self, n: absolute::LockTime) -> bool {
        Satisfier::<PublicKey>::check_after(&self.lock_time, n)
    }
}
