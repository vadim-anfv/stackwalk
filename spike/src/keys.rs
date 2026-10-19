//! Deterministic name -> key/preimage derivation, String -> bitcoin::PublicKey translator,
//! and the reverse "bytes -> semantic label" map.
use std::collections::BTreeMap;
use std::convert::Infallible;

use miniscript::bitcoin::hashes::{Hash, hash160, ripemd160, sha256, sha256d};
use miniscript::bitcoin::secp256k1::{All, Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use miniscript::bitcoin::{self, PublicKey};
use miniscript::{Translator, hash256};

/// Reserved name for the BIP341 NUMS point (unspendable internal key).
pub const NUMS: &str = "NUMS";
const NUMS_X: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

pub struct KeyRing {
    pub secp: Secp256k1<All>,
    /// name -> secret (only for real names, not NUMS)
    pub secrets: BTreeMap<String, SecretKey>,
    /// raw bytes (hex) -> semantic label
    pub labels: BTreeMap<String, String>,
}

impl KeyRing {
    pub fn new() -> Self {
        Self { secp: Secp256k1::new(), secrets: BTreeMap::new(), labels: BTreeMap::new() }
    }

    fn label(&mut self, bytes: &[u8], label: String) {
        self.labels.entry(hex(bytes)).or_insert(label);
    }

    pub fn label_of(&self, bytes: &[u8]) -> Option<&str> {
        self.labels.get(&hex(bytes)).map(String::as_str)
    }

    pub fn secret(&mut self, name: &str) -> SecretKey {
        if let Some(sk) = self.secrets.get(name) {
            return *sk;
        }
        // Demo only: secret = sha256("stackwalk/key/" || name). NEVER use for real funds.
        let h = sha256::Hash::hash(format!("stackwalk/key/{name}").as_bytes());
        let sk = SecretKey::from_slice(h.as_byte_array()).expect("sha256 output is a valid key whp");
        self.secrets.insert(name.to_string(), sk);
        let pk = PublicKey::new(sk.public_key(&self.secp));
        let (xonly, _) = sk.public_key(&self.secp).x_only_public_key();
        self.label(&pk.to_bytes(), format!("pk({name})"));
        self.label(&xonly.serialize(), format!("pk({name})"));
        self.label(hash160::Hash::hash(&pk.to_bytes()).as_byte_array(), format!("hash160(pk({name}))"));
        self.label(hash160::Hash::hash(&xonly.serialize()).as_byte_array(), format!("hash160(pk({name}))"));
        sk
    }

    pub fn keypair(&mut self, name: &str) -> Keypair {
        let sk = self.secret(name);
        Keypair::from_secret_key(&self.secp, &sk)
    }

    pub fn pubkey(&mut self, name: &str) -> PublicKey {
        if name == NUMS {
            let x: XOnlyPublicKey = NUMS_X.parse().unwrap();
            let pk = PublicKey::new(x.public_key(bitcoin::secp256k1::Parity::Even));
            self.label(&x.serialize(), "pk(NUMS)".into());
            return pk;
        }
        let sk = self.secret(name);
        PublicKey::new(sk.public_key(&self.secp))
    }

    /// 32-byte preimage for hash name H: sha256("stackwalk/preimage/" || H).
    pub fn preimage(&mut self, name: &str) -> [u8; 32] {
        let p = sha256::Hash::hash(format!("stackwalk/preimage/{name}").as_bytes()).to_byte_array();
        self.label(&p, format!("preimage({name})"));
        p
    }

    pub fn label_sig(&mut self, sig: &[u8], name: &str) {
        self.label(sig, format!("sig({name})"));
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Translator String -> bitcoin::PublicKey. Hash names are turned into real hashes
/// of the deterministic preimage.
pub struct NameTranslator<'a>(pub &'a mut KeyRing);

impl Translator<String> for NameTranslator<'_> {
    type TargetPk = PublicKey;
    type Error = Infallible;

    fn pk(&mut self, pk: &String) -> Result<PublicKey, Infallible> {
        Ok(self.0.pubkey(pk))
    }

    fn sha256(&mut self, h: &String) -> Result<sha256::Hash, Infallible> {
        let hash = sha256::Hash::hash(&self.0.preimage(h));
        self.0.label(hash.as_byte_array(), format!("sha256({h})"));
        Ok(hash)
    }

    fn hash256(&mut self, h: &String) -> Result<hash256::Hash, Infallible> {
        let d = sha256d::Hash::hash(&self.0.preimage(h));
        let hash = hash256::Hash::from_raw_hash(d);
        // NB: miniscript pushes hash256 in "display" (reversed?) order - label both to be safe.
        self.0.label(d.as_byte_array(), format!("hash256({h})"));
        let mut rev = d.to_byte_array();
        rev.reverse();
        self.0.label(&rev, format!("hash256({h})"));
        Ok(hash)
    }

    fn ripemd160(&mut self, h: &String) -> Result<ripemd160::Hash, Infallible> {
        let hash = ripemd160::Hash::hash(&self.0.preimage(h));
        self.0.label(hash.as_byte_array(), format!("ripemd160({h})"));
        Ok(hash)
    }

    fn hash160(&mut self, h: &String) -> Result<hash160::Hash, Infallible> {
        let hash = hash160::Hash::hash(&self.0.preimage(h));
        self.0.label(hash.as_byte_array(), format!("hash160({h})"));
        Ok(hash)
    }
}
