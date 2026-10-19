//! Script text -> ScriptBuf, and back to named miniscript when possible.
use std::collections::BTreeMap;

use miniscript::bitcoin::hashes::{Hash, hash160};
use miniscript::bitcoin::script::{Builder, PushBytesBuf};
use miniscript::bitcoin::{PublicKey, ScriptBuf};
use miniscript::{Miniscript, Segwitv0};

use crate::keys::{KeyRing, ReverseTranslator};
use crate::scriptexec::parse_opcode;

fn call<'a>(s: &'a str, f: &str) -> Option<&'a str> {
    s.strip_prefix(f)?.strip_prefix('(')?.strip_suffix(')')
}

fn hexbytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

pub fn parse(ring: &mut KeyRing, text: &str) -> Result<ScriptBuf, String> {
    let mut b = Builder::new();
    let toks: Vec<&str> = text.split_whitespace().collect();
    for (i, tok) in toks.iter().enumerate() {
        if let Some(inner) = tok.strip_prefix('<').and_then(|t| t.strip_suffix('>')) {
            let bytes: Vec<u8> = if let Ok(n) = inner.parse::<i64>() {
                b = b.push_int(n);
                continue;
            } else if let Some(n) = call(inner, "pk") {
                ring.pubkey(n).to_bytes()
            } else if let Some(n) = call(inner, "hash160") {
                // key hash if it follows OP_DUP OP_HASH160 (pkh pattern), else a preimage hash
                let pkh = i >= 2 && toks[i - 1] == "OP_HASH160" && toks[i - 2] == "OP_DUP";
                if pkh {
                    ring.pubkey(n).pubkey_hash().to_byte_array().to_vec()
                } else {
                    ring.hash160(n).to_byte_array().to_vec()
                }
            } else if let Some(n) = call(inner, "sha256") {
                ring.sha256(n).to_byte_array().to_vec()
            } else if let Some(n) = call(inner, "hash256") {
                ring.hash256(n).to_byte_array().to_vec()
            } else if let Some(n) = call(inner, "ripemd160") {
                ring.ripemd160(n).to_byte_array().to_vec()
            } else if let Some(h) = hexbytes(inner.strip_prefix("0x").unwrap_or(inner)) {
                h
            } else {
                return Err(format!("cannot parse push {tok}"));
            };
            // the minimal opcode where there is one (Core's MINIMALDATA): empty is OP_0,
            // 1..16 are OP_1..OP_16, 0x81 is OP_1NEGATE
            b = match bytes.as_slice() {
                [] => b.push_int(0),
                [n @ 1..=16] => b.push_int(i64::from(*n)),
                [0x81] => b.push_int(-1),
                _ => b.push_slice(PushBytesBuf::try_from(bytes).map_err(|_| format!("push too large: {tok}"))?),
            };
        } else if let Ok(n) = tok.parse::<i64>() {
            b = b.push_int(n);
        } else {
            let op = parse_opcode(tok).map_err(|_| format!("unknown opcode {tok}"))?;
            b = b.push_opcode(op);
        }
    }
    Ok(b.into_script())
}

/// Sane segwit v0 miniscript with only test keys / hashes, translated back to names.
pub fn as_miniscript(ring: &KeyRing, script: &ScriptBuf) -> Option<Miniscript<String, Segwitv0>> {
    let ext = miniscript::ExtParams::sane().raw_pkh();
    let ms = Miniscript::<PublicKey, Segwitv0>::decode_with_ext(script, &ext).ok()?;
    let map: BTreeMap<hash160::Hash, PublicKey> = ring
        .pk_names
        .keys()
        .map(|pk| (hash160::Hash::from_byte_array(pk.pubkey_hash().to_byte_array()), *pk))
        .collect();
    let ms = ms.substitute_raw_pkh(&map);
    let named = ms.translate_pk(&mut ReverseTranslator(ring)).ok()?;
    if named.to_string().contains("expr_raw") {
        return None;
    }
    Some(named)
}
