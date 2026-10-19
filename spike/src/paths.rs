//! Q3 sketch: enumerate spend paths by trying asset subsets with `build_template`
//! (miniscript plan machinery) and keeping only those where every given asset is used.
use std::collections::BTreeSet;

use miniscript::bitcoin::hashes::{Hash, hash160, ripemd160, sha256};
use miniscript::bitcoin::taproot::TapLeafHash;
use miniscript::bitcoin::{PublicKey, absolute, relative};
use miniscript::iter::TreeLike;
use miniscript::miniscript::satisfy::{Placeholder, Witness};
use miniscript::plan::AssetProvider;
use miniscript::{Miniscript, ScriptContext, Terminal, hash256};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Atom {
    Sig(PublicKey),
    Sha256(sha256::Hash),
    Hash256(hash256::Hash),
    Ripemd160(ripemd160::Hash),
    Hash160(hash160::Hash),
    Older(u32),
    After(u32),
}

struct Provider<'a>(&'a BTreeSet<Atom>);

impl AssetProvider<PublicKey> for Provider<'_> {
    fn provider_lookup_ecdsa_sig(&self, pk: &PublicKey) -> bool {
        self.0.contains(&Atom::Sig(*pk))
    }
    fn provider_lookup_tap_leaf_script_sig(&self, pk: &PublicKey, _: &TapLeafHash) -> Option<usize> {
        self.0.contains(&Atom::Sig(*pk)).then_some(64)
    }
    fn provider_lookup_sha256(&self, h: &sha256::Hash) -> bool {
        self.0.contains(&Atom::Sha256(*h))
    }
    fn provider_lookup_hash256(&self, h: &hash256::Hash) -> bool {
        self.0.contains(&Atom::Hash256(*h))
    }
    fn provider_lookup_ripemd160(&self, h: &ripemd160::Hash) -> bool {
        self.0.contains(&Atom::Ripemd160(*h))
    }
    fn provider_lookup_hash160(&self, h: &hash160::Hash) -> bool {
        self.0.contains(&Atom::Hash160(*h))
    }
    fn check_older(&self, n: relative::LockTime) -> bool {
        self.0.contains(&Atom::Older(n.to_consensus_u32()))
    }
    fn check_after(&self, n: absolute::LockTime) -> bool {
        self.0.contains(&Atom::After(n.to_consensus_u32()))
    }
}

pub fn atom_label(ring: &crate::keys::KeyRing, a: &Atom) -> String {
    let l = |b: &[u8]| ring.label_of(b).unwrap_or("?").to_string();
    match a {
        Atom::Sig(pk) => format!("sign:{}", l(&pk.to_bytes())),
        Atom::Sha256(h) => format!("preimage-of:{}", l(h.as_byte_array())),
        Atom::Hash256(h) => format!("preimage-of:{}", l(h.as_byte_array())),
        Atom::Ripemd160(h) => format!("preimage-of:{}", l(h.as_byte_array())),
        Atom::Hash160(h) => format!("preimage-of:{}", l(h.as_byte_array())),
        Atom::Older(n) => format!("older({n})"),
        Atom::After(n) => format!("after({n})"),
    }
}

pub fn placeholder_label(ring: &crate::keys::KeyRing, p: &Placeholder<PublicKey>) -> String {
    let l = |b: &[u8]| ring.label_of(b).unwrap_or("?").to_string();
    match p {
        Placeholder::EcdsaSigPk(pk) | Placeholder::SchnorrSigPk(pk, ..) => {
            format!("sig({})", l(&pk.to_bytes()).trim_start_matches("pk(").trim_end_matches(')'))
        }
        Placeholder::Pubkey(pk, _) => l(&pk.to_bytes()),
        Placeholder::Sha256Preimage(h) => format!("preimage[{}]", l(h.as_byte_array())),
        Placeholder::Hash160Preimage(h) => format!("preimage[{}]", l(h.as_byte_array())),
        Placeholder::Hash256Preimage(h) => format!("preimage[{}]", l(h.as_byte_array())),
        Placeholder::Ripemd160Preimage(h) => format!("preimage[{}]", l(h.as_byte_array())),
        Placeholder::PushZero => "<>".into(),
        Placeholder::PushOne => "1".into(),
        other => other.to_string(),
    }
}

pub fn atoms<Ctx: ScriptContext>(ms: &Miniscript<PublicKey, Ctx>) -> Vec<Atom> {
    let mut s = BTreeSet::new();
    for n in ms.pre_order_iter() {
        match n.as_inner() {
            Terminal::PkK(pk) | Terminal::PkH(pk) => {
                s.insert(Atom::Sig(*pk));
            }
            Terminal::Multi(t) => s.extend(t.iter().map(|pk| Atom::Sig(*pk))),
            Terminal::MultiA(t) => s.extend(t.iter().map(|pk| Atom::Sig(*pk))),
            Terminal::Sha256(h) => {
                s.insert(Atom::Sha256(*h));
            }
            Terminal::Hash256(h) => {
                s.insert(Atom::Hash256(*h));
            }
            Terminal::Ripemd160(h) => {
                s.insert(Atom::Ripemd160(*h));
            }
            Terminal::Hash160(h) => {
                s.insert(Atom::Hash160(*h));
            }
            Terminal::Older(t) => {
                s.insert(Atom::Older(t.to_consensus_u32()));
            }
            Terminal::After(t) => {
                s.insert(Atom::After(t.to_consensus_u32()));
            }
            _ => {}
        }
    }
    s.into_iter().collect()
}

/// Returns minimal asset sets that yield a (non-malleable) satisfaction, with the witness template.
pub fn enumerate<Ctx: ScriptContext>(ms: &Miniscript<PublicKey, Ctx>) -> Vec<(BTreeSet<Atom>, Vec<Placeholder<PublicKey>>)> {
    let all = atoms(ms);
    assert!(all.len() <= 16, "too many atoms for brute force");
    let mut found: Vec<(BTreeSet<Atom>, Vec<Placeholder<PublicKey>>)> = Vec::new();
    // iterate subsets by increasing size so that minimal sets come first
    let mut masks: Vec<u32> = (0..(1u32 << all.len())).collect();
    masks.sort_by_key(|m| m.count_ones());
    for m in masks {
        let set: BTreeSet<Atom> = all.iter().enumerate().filter(|(i, _)| m & (1 << i) != 0).map(|(_, a)| a.clone()).collect();
        if found.iter().any(|(f, _)| f.is_subset(&set)) {
            continue; // superset of an already-found path
        }
        let sat = ms.build_template(&Provider(&set));
        if let Witness::Stack(stack) = sat.stack {
            found.push((set, stack));
        }
    }
    found
}
