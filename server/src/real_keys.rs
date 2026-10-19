//! Real keys (hex pubkeys, xpubs with origin / path) and real hashes in policy, miniscript or
//! descriptor text. We cannot sign for those keys or know those preimages, so each one is
//! swapped for a free test name (A, B, ... for keys, H1, H2, ... for hashes) before building,
//! and swapped back in the texts shown to the user.
use std::collections::BTreeSet;
use std::str::FromStr;

use miniscript::DescriptorPublicKey;

/// A private key anywhere in the text: WIF or an extended private key (xprv / tprv). Decoded,
/// not guessed: the checksum must hold, so a key name never trips it.
pub fn has_private_key(text: &str) -> bool {
    use miniscript::bitcoin::PrivateKey;
    use miniscript::bitcoin::bip32::Xpriv;
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.len() >= 51)
        .any(|t| PrivateKey::from_wif(t).is_ok() || Xpriv::from_str(t).is_ok())
}

/// Fragments whose arguments are keys (multi's first argument is a number and never parses as one).
const KEY_FNS: &[&str] = &["pk", "pkh", "pk_k", "pk_h", "multi", "sortedmulti", "multi_a", "sortedmulti_a", "wpkh", "tr"];

/// Hash fragments and the hex length of a real hash in them.
const HASH_FNS: &[(&str, usize)] = &[("sha256", 64), ("hash256", 64), ("ripemd160", 40), ("hash160", 40)];

/// A real hash: hex of the fragment's length. Anything else is a preimage name.
fn real_hash(tok: &str, parent: &str) -> bool {
    HASH_FNS.iter().any(|(f, len)| *f == parent && tok.len() == *len && tok.chars().all(|c| c.is_ascii_hexdigit()))
}

/// (test name, real key or hash) pairs, in order of first appearance.
pub type Aliases = Vec<(String, String)>;

/// Rewrite every argument token of `text`: `f(token, enclosing fragment, argument index)`
/// returns the replacement, if any.
fn map_args(text: &str, mut f: impl FnMut(&str, &str, usize) -> Option<String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut fns: Vec<(String, usize)> = Vec::new();
    let mut tok = String::new();
    for c in text.chars() {
        match c {
            '(' => {
                // `s:pk`, `9@pk`: the fragment is what follows the last wrapper / weight
                let name = tok.rsplit([':', '@']).next().unwrap_or("").to_string();
                out.push_str(&tok);
                tok.clear();
                fns.push((name, 0));
                out.push(c);
            }
            ',' | ')' => {
                let (parent, i) = fns.last().map_or(("", 0), |(n, i)| (n.as_str(), *i));
                match f(tok.trim(), parent, i) {
                    Some(r) => out.push_str(&r),
                    None => out.push_str(&tok),
                }
                tok.clear();
                if c == ')' {
                    fns.pop();
                } else if let Some((_, i)) = fns.last_mut() {
                    *i += 1;
                }
                out.push(c);
            }
            _ => tok.push(c),
        }
    }
    out.push_str(&tok);
    out
}

/// Some(Ok) for a real key, Some(Err) for something that looks like one but does
/// not parse (a typo in an xpub must not silently become a test key name), None for a name.
fn real_key(tok: &str, parent: &str) -> Option<Result<(), String>> {
    if !KEY_FNS.contains(&parent) {
        return None;
    }
    let looks = tok.starts_with('[')
        || ["xpub", "tpub", "xprv", "tprv"].iter().any(|p| tok.starts_with(p))
        || (tok.len() >= 64 && tok.chars().all(|c| c.is_ascii_hexdigit()));
    match DescriptorPublicKey::from_str(tok) {
        Ok(_) => Some(Ok(())),
        Err(e) if looks => Some(Err(format!("invalid key {}: {e}", short(tok)))),
        Err(_) => None,
    }
}

pub fn short(k: &str) -> String {
    let chars: Vec<char> = k.chars().collect();
    if chars.len() <= 20 {
        return k.to_string();
    }
    // by characters, not bytes: a key with wide characters must not be cut inside one
    format!("{}…{}", chars[..10].iter().collect::<String>(), chars[chars.len() - 6..].iter().collect::<String>())
}

fn hash_name(i: usize) -> String {
    format!("H{i}")
}

/// The name `alias` gives a real hash (a key's name is a letter or `K1`, `K2`, ...).
pub fn is_hash_name(name: &str) -> bool {
    name.strip_prefix('H').is_some_and(|n| n.parse::<usize>().is_ok())
}

/// Swap real keys and hashes for free test names.
pub fn alias(text: &str) -> Result<(String, Aliases), String> {
    // every name already in the text (test keys, hash names) is taken
    let mut used = BTreeSet::new();
    map_args(text, |tok, _, _| {
        used.insert(tok.to_string());
        None
    });
    let mut aliases: Aliases = Vec::new();
    let mut free = ('A'..='Z').map(String::from).chain((1..).map(|i| format!("K{i}"))).filter(|n| !used.contains(n));
    let mut free_hash = (1..).map(hash_name).filter(|n| !used.contains(n));
    let mut err = None;
    // a key is one key wherever it is; a hash only within its hash function (no preimage
    // matches both sha256(h) and hash256(h))
    let mut seen: Vec<(&str, String, String)> = Vec::new();
    let out = map_args(text, |tok, parent, _| {
        let hash = real_hash(tok, parent);
        if !hash {
            match real_key(tok, parent)? {
                Ok(()) => {}
                Err(e) => {
                    err.get_or_insert(e);
                    return None;
                }
            }
        }
        let group = if hash { HASH_FNS.iter().find(|(f, _)| *f == parent).map_or("", |(f, _)| *f) } else { "" };
        if let Some((_, _, name)) = seen.iter().find(|(g, k, _)| *g == group && k == tok) {
            return Some(name.clone());
        }
        let name = if hash { free_hash.next() } else { free.next() }.expect("endless names");
        seen.push((group, tok.to_string(), name.clone()));
        aliases.push((name.clone(), tok.to_string()));
        Some(name)
    });
    match err {
        Some(e) => Err(e),
        None => Ok((out, aliases)),
    }
}

/// The test names (keys and hash names, not real ones) in a text, in order of first appearance.
pub fn test_names(text: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    map_args(text, |tok, parent, i| {
        let in_fn = KEY_FNS.contains(&parent) || HASH_FNS.iter().any(|(f, _)| *f == parent);
        // the threshold of multi, not a key; a name may be digits only (`pk(1)`)
        let threshold = i == 0 && parent.contains("multi");
        let name = in_fn && !tok.is_empty() && !threshold;
        if name && !real_hash(tok, parent) && real_key(tok, parent).is_none() && !names.iter().any(|n| n == tok) {
            names.push(tok.to_string());
        }
        None
    });
    names
}

/// Put the real keys and hashes back into a text built from the aliased one.
pub fn restore(text: &str, aliases: &Aliases) -> String {
    if aliases.is_empty() {
        return text.to_string();
    }
    map_args(text, |tok, parent, _| {
        if !KEY_FNS.contains(&parent) && !HASH_FNS.iter().any(|(f, _)| *f == parent) {
            return None;
        }
        aliases.iter().find(|(n, _)| n == tok).map(|(_, k)| k.clone())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "02e5b88fdb71c696e1a473f309a47535b7190e21a22bd25e7fc8bd055db3bba12f";
    // BIP-32 test vector 1, m
    const XPUB: &str = "[d34db33f/84'/0'/0']xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*";

    #[test]
    fn real_keys_get_free_names_and_come_back() {
        let text = format!("or(9@pk({HEX}),and(pk(A),pk({XPUB})))");
        let (out, al) = alias(&text).unwrap();
        assert_eq!(out, "or(9@pk(B),and(pk(A),pk(C)))");
        assert_eq!(al, vec![("B".into(), HEX.into()), ("C".into(), XPUB.into())]);
        assert_eq!(restore(&out, &al), text);
    }

    #[test]
    fn same_key_same_name_and_real_hashes_named_too() {
        // a real hash gets a hash name (we don't know its preimage); a key named H stays a name
        let h = "a".repeat(64);
        let text = format!("and_v(v:pk({HEX}),and_v(v:sha256({h}),multi(1,{HEX},H)))");
        let (out, al) = alias(&text).unwrap();
        assert_eq!(out, "and_v(v:pk(A),and_v(v:sha256(H1),multi(1,A,H)))");
        assert_eq!(al, vec![("A".to_string(), HEX.to_string()), ("H1".to_string(), h)]);
        assert_eq!(restore(&out, &al), text);
    }

    #[test]
    fn test_keys_only_is_a_no_op() {
        let (out, al) = alias("wsh(multi(2,A,B,C))").unwrap();
        assert_eq!(out, "wsh(multi(2,A,B,C))");
        assert!(al.is_empty());
    }

    #[test]
    fn a_broken_key_is_an_error_not_a_name() {
        let bad = XPUB.replace("FtXgS5", "FtXGS5");
        assert!(alias(&format!("pk({bad})")).unwrap_err().contains("invalid key"));
        assert!(alias(&format!("pk({})", &HEX[..65])).is_err());
    }
}
