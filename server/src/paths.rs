//! Spend path enumeration: try asset subsets with `build_template` (non-malleable) and keep
//! the minimal ones (supersets of a found path are dropped).
use std::collections::BTreeSet;

use miniscript::bitcoin::hashes::{Hash, hash160, ripemd160, sha256};
use miniscript::bitcoin::taproot::TapLeafHash;
use miniscript::bitcoin::{PublicKey, absolute, relative};
use miniscript::iter::TreeLike;
use miniscript::miniscript::satisfy::Witness;
use miniscript::plan::AssetProvider;
use miniscript::{Miniscript, ScriptContext, Terminal, hash256};

use crate::keys::KeyRing;

pub const MAX_ATOMS: usize = 16;

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

/// Minimal asset sets that yield a non-malleable satisfaction, smallest first.
pub fn enumerate<Ctx: ScriptContext>(ms: &Miniscript<PublicKey, Ctx>) -> Result<Vec<BTreeSet<Atom>>, String> {
    let all = atoms(ms);
    if all.len() > MAX_ATOMS {
        return Err(format!("too many assets for path enumeration: {} (max {MAX_ATOMS})", all.len()));
    }
    let mut found: Vec<BTreeSet<Atom>> = Vec::new();
    let mut masks: Vec<u32> = (0..(1u32 << all.len())).collect();
    masks.sort_by_key(|m| m.count_ones());
    for m in masks {
        let set: BTreeSet<Atom> =
            all.iter().enumerate().filter(|(i, _)| m & (1 << i) != 0).map(|(_, a)| a.clone()).collect();
        if found.iter().any(|f| f.is_subset(&set)) {
            continue;
        }
        if let Witness::Stack(_) = ms.build_template(&Provider(&set)).stack {
            found.push(set);
        }
    }
    Ok(found)
}

/// What one spend path needs, in names.
#[derive(Clone, Debug, Default)]
pub struct PathSpec {
    pub signers: Vec<String>,
    pub preimages: Vec<String>,
    pub older: Option<u32>,
    pub after: Option<u32>,
}

impl PathSpec {
    pub fn from_atoms(ring: &KeyRing, set: &BTreeSet<Atom>) -> Self {
        let mut p = PathSpec::default();
        let hname = |b: &[u8]| ring.hash_names.get(b).cloned().unwrap_or_else(|| crate::keys::short_hex(&crate::keys::hex(b)));
        for a in set {
            match a {
                Atom::Sig(pk) => p.signers.push(ring.pk_names.get(pk).cloned().unwrap_or_else(|| "?".into())),
                Atom::Sha256(h) => p.preimages.push(hname(h.as_byte_array())),
                Atom::Hash256(h) => p.preimages.push(hname(&h.to_byte_array())),
                Atom::Ripemd160(h) => p.preimages.push(hname(h.as_byte_array())),
                Atom::Hash160(h) => p.preimages.push(hname(h.as_byte_array())),
                Atom::Older(n) => p.older = Some(p.older.map_or(*n, |o| o.max(*n))),
                Atom::After(n) => p.after = Some(p.after.map_or(*n, |o| o.max(*n))),
            }
        }
        let order = |n: &String| ring.key_order.iter().position(|k| k == n).unwrap_or(usize::MAX);
        p.signers.sort_by_key(order);
        p.preimages.sort();
        p.preimages.dedup();
        p
    }

    pub fn name(&self) -> String {
        let mut parts: Vec<String> = self.preimages.iter().map(|h| format!("preimage {h}")).collect();
        parts.extend(self.signers.iter().cloned());
        let mut tl = Vec::new();
        if let Some(n) = self.older {
            match relative::LockTime::from_consensus(n) {
                Ok(relative::LockTime::Time(t)) => tl.push(format!("after {} x 512 seconds", t.value())),
                _ => tl.push(format!("after {} blocks", n & 0xffff)),
            }
        }
        if let Some(n) = self.after {
            if n < 500_000_000 {
                tl.push(format!("at height {n}"))
            } else {
                tl.push(format!("at time {n}"))
            }
        }
        let tl = tl.join(" and ");
        if parts.is_empty() {
            if tl.is_empty() { "no conditions".into() } else { tl }
        } else if parts.len() == 1 && self.signers.len() == 1 && tl.is_empty() {
            format!("{} signs", parts[0])
        } else if tl.is_empty() {
            parts.join(" + ")
        } else {
            format!("{} {tl}", parts.join(" + "))
        }
    }
}
