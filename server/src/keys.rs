//! Deterministic test keys / preimages from names, name <-> key translators,
//! and the reverse "bytes -> semantic label" map used to build `Item`s.
use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;

use miniscript::bitcoin::PublicKey;
use miniscript::bitcoin::hashes::{Hash, hash160, ripemd160, sha256, sha256d};
use miniscript::bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey};
use miniscript::bitcoin::{ecdsa, sighash::EcdsaSighashType};
use miniscript::{Translator, hash256};

use crate::model::Item;
use crate::scriptexec::read_scriptint;

#[derive(Clone)]
pub struct Label {
    pub kind: &'static str,
    pub label: String,
    pub name: Option<String>,
}

pub struct KeyRing {
    pub secp: Secp256k1<All>,
    secrets: BTreeMap<String, SecretKey>,
    labels: HashMap<Vec<u8>, Label>,
    /// pubkey -> key name
    pub pk_names: BTreeMap<PublicKey, String>,
    /// key names in order of first appearance
    pub key_order: Vec<String>,
    /// any hash of a preimage (sha256/hash256/ripemd160/hash160 bytes) -> preimage name
    pub hash_names: HashMap<Vec<u8>, String>,
}

impl KeyRing {
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
            secrets: BTreeMap::new(),
            labels: HashMap::new(),
            pk_names: BTreeMap::new(),
            key_order: Vec::new(),
            hash_names: HashMap::new(),
        }
    }

    pub fn label(&mut self, bytes: &[u8], kind: &'static str, label: String, name: Option<&str>) {
        self.labels
            .entry(bytes.to_vec())
            .or_insert(Label { kind, label, name: name.map(str::to_string) });
    }

    fn secret(&mut self, name: &str) -> SecretKey {
        if let Some(sk) = self.secrets.get(name) {
            return *sk;
        }
        // Demo only: secret = sha256("stackwalk/key/" || name). NEVER use for real funds.
        let h = sha256::Hash::hash(format!("stackwalk/key/{name}").as_bytes());
        let sk = SecretKey::from_slice(h.as_byte_array()).expect("sha256 output is a valid key whp");
        self.secrets.insert(name.to_string(), sk);
        let pk = PublicKey::new(sk.public_key(&self.secp));
        self.pk_names.insert(pk, name.to_string());
        self.key_order.push(name.to_string());
        self.label(&pk.to_bytes(), "pubkey", format!("pk({name})"), Some(name));
        self.label(hash160::Hash::hash(&pk.to_bytes()).as_byte_array(), "hash", format!("hash160({name})"), Some(name));
        sk
    }

    pub fn pubkey(&mut self, name: &str) -> PublicKey {
        let sk = self.secret(name);
        PublicKey::new(sk.public_key(&self.secp))
    }

    /// 32-byte preimage for hash name H: sha256("stackwalk/preimage/" || H).
    pub fn preimage(&mut self, name: &str) -> [u8; 32] {
        let p = sha256::Hash::hash(format!("stackwalk/preimage/{name}").as_bytes()).to_byte_array();
        self.label(&p, "hash", format!("preimage({name})"), None);
        p
    }

    fn hash_label(&mut self, bytes: &[u8], f: &str, name: &str) {
        self.label(bytes, "hash", format!("{f}({name})"), None);
        self.hash_names.insert(bytes.to_vec(), name.to_string());
    }

    pub fn sha256(&mut self, name: &str) -> sha256::Hash {
        let h = sha256::Hash::hash(&self.preimage(name));
        self.hash_label(h.as_byte_array(), "sha256", name);
        h
    }

    pub fn hash256(&mut self, name: &str) -> hash256::Hash {
        let h = hash256::Hash::from_raw_hash(sha256d::Hash::hash(&self.preimage(name)));
        self.hash_label(&h.to_byte_array(), "hash256", name);
        h
    }

    pub fn ripemd160(&mut self, name: &str) -> ripemd160::Hash {
        let h = ripemd160::Hash::hash(&self.preimage(name));
        self.hash_label(h.as_byte_array(), "ripemd160", name);
        h
    }

    pub fn hash160(&mut self, name: &str) -> hash160::Hash {
        let h = hash160::Hash::hash(&self.preimage(name));
        self.hash_label(h.as_byte_array(), "hash160", name);
        h
    }

    /// ECDSA signature (SIGHASH_ALL) by key `name` over `msg`, labelled sig(name).
    pub fn sign(&mut self, name: &str, msg: &Message) -> ecdsa::Signature {
        let sk = self.secret(name);
        let sig = ecdsa::Signature { signature: self.secp.sign_ecdsa(msg, &sk), sighash_type: EcdsaSighashType::All };
        self.label(&sig.to_vec(), "sig", format!("sig({name})"), Some(name));
        sig
    }

    /// Build an `Item` for raw stack / push bytes.
    pub fn item(&self, id: u64, b: &[u8]) -> Item {
        let hex = hex(b);
        if let Some(l) = self.labels.get(b) {
            return Item { id, kind: l.kind, label: l.label.clone(), hex, value: None, name: l.name.clone() };
        }
        if b.is_empty() {
            return Item { id, kind: "num", label: "<empty>".into(), hex, value: Some(0), name: None };
        }
        if b.len() <= 4 {
            if let Ok(v) = read_scriptint(b, 4, true) {
                return Item { id, kind: "num", label: v.to_string(), hex, value: Some(v), name: None };
            }
        }
        Item { id, kind: "hash", label: short_hex(&hex), hex, value: None, name: None }
    }

    /// Label for display in notes / spk text.
    pub fn text(&self, b: &[u8]) -> String {
        self.item(0, b).label
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn short_hex(h: &str) -> String {
    if h.len() > 16 { format!("{}...{}", &h[..8], &h[h.len() - 4..]) } else { h.to_string() }
}

/// Translator String -> bitcoin::PublicKey (hash names -> hashes of deterministic preimages).
pub struct NameTranslator<'a>(pub &'a mut KeyRing);

impl Translator<String> for NameTranslator<'_> {
    type TargetPk = PublicKey;
    type Error = Infallible;

    fn pk(&mut self, pk: &String) -> Result<PublicKey, Infallible> {
        Ok(self.0.pubkey(pk))
    }
    fn sha256(&mut self, h: &String) -> Result<sha256::Hash, Infallible> {
        Ok(self.0.sha256(h))
    }
    fn hash256(&mut self, h: &String) -> Result<hash256::Hash, Infallible> {
        Ok(self.0.hash256(h))
    }
    fn ripemd160(&mut self, h: &String) -> Result<ripemd160::Hash, Infallible> {
        Ok(self.0.ripemd160(h))
    }
    fn hash160(&mut self, h: &String) -> Result<hash160::Hash, Infallible> {
        Ok(self.0.hash160(h))
    }
}

/// Translator bitcoin::PublicKey -> String using the names known to the ring.
/// Fails on any key / hash that does not come from a test name.
pub struct ReverseTranslator<'a>(pub &'a KeyRing);

impl ReverseTranslator<'_> {
    fn hash(&self, b: &[u8]) -> Result<String, ()> {
        self.0.hash_names.get(b).cloned().ok_or(())
    }
}

impl Translator<PublicKey> for ReverseTranslator<'_> {
    type TargetPk = String;
    type Error = ();

    fn pk(&mut self, pk: &PublicKey) -> Result<String, ()> {
        self.0.pk_names.get(pk).cloned().ok_or(())
    }
    fn sha256(&mut self, h: &sha256::Hash) -> Result<String, ()> {
        self.hash(h.as_byte_array())
    }
    fn hash256(&mut self, h: &hash256::Hash) -> Result<String, ()> {
        self.hash(&h.to_byte_array())
    }
    fn ripemd160(&mut self, h: &ripemd160::Hash) -> Result<String, ()> {
        self.hash(h.as_byte_array())
    }
    fn hash160(&mut self, h: &hash160::Hash) -> Result<String, ()> {
        self.hash(h.as_byte_array())
    }
}
