//! Real keys (hex pubkeys, xpubs with origin / path) in policy, miniscript or
//! descriptor text. We cannot sign for them, so each one is swapped for a free
//! test key name (A, B, ...) before building, and swapped back in the texts
//! shown to the user.
use std::collections::BTreeSet;
use std::str::FromStr;

use miniscript::DescriptorPublicKey;

/// Fragments whose arguments are keys (multi's first argument is a number and never parses as one).
const KEY_FNS: &[&str] = &["pk", "pkh", "pk_k", "pk_h", "multi", "sortedmulti", "multi_a", "sortedmulti_a", "wpkh", "tr"];

/// (test key name, real key) pairs, in order of first appearance.
pub type Aliases = Vec<(String, String)>;

/// Rewrite every argument token of `text`: `f(token, enclosing fragment)` returns the replacement, if any.
fn map_args(text: &str, mut f: impl FnMut(&str, &str) -> Option<String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut fns: Vec<String> = Vec::new();
    let mut tok = String::new();
    for c in text.chars() {
        match c {
            '(' => {
                // `s:pk`, `9@pk`: the fragment is what follows the last wrapper / weight
                let name = tok.rsplit([':', '@']).next().unwrap_or("").to_string();
                out.push_str(&tok);
                tok.clear();
                fns.push(name);
                out.push(c);
            }
            ',' | ')' => {
                let parent = fns.last().map(String::as_str).unwrap_or("");
                match f(tok.trim(), parent) {
                    Some(r) => out.push_str(&r),
                    None => out.push_str(&tok),
                }
                tok.clear();
                if c == ')' {
                    fns.pop();
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

fn short(k: &str) -> String {
    if k.chars().count() <= 20 { k.to_string() } else { format!("{}…{}", &k[..10], &k[k.len() - 6..]) }
}

/// Swap real keys for free test key names.
pub fn alias(text: &str) -> Result<(String, Aliases), String> {
    // every name already in the text (test keys, hash names) is taken
    let mut used = BTreeSet::new();
    map_args(text, |tok, _| {
        used.insert(tok.to_string());
        None
    });
    let mut aliases: Aliases = Vec::new();
    let mut free = ('A'..='Z').map(String::from).chain((1..).map(|i| format!("K{i}"))).filter(|n| !used.contains(n));
    let mut err = None;
    let out = map_args(text, |tok, parent| {
        match real_key(tok, parent)? {
            Ok(()) => {}
            Err(e) => {
                err.get_or_insert(e);
                return None;
            }
        }
        if let Some((name, _)) = aliases.iter().find(|(_, k)| k == tok) {
            return Some(name.clone());
        }
        let name = free.next().expect("endless names");
        aliases.push((name.clone(), tok.to_string()));
        Some(name)
    });
    match err {
        Some(e) => Err(e),
        None => Ok((out, aliases)),
    }
}

/// Put the real keys back into a text built from the aliased one.
pub fn restore(text: &str, aliases: &Aliases) -> String {
    if aliases.is_empty() {
        return text.to_string();
    }
    map_args(text, |tok, parent| {
        if !KEY_FNS.contains(&parent) {
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
    fn same_key_same_name_and_hashes_untouched() {
        let h = "a".repeat(64);
        let (out, al) = alias(&format!("and_v(v:pk({HEX}),and_v(v:sha256({h}),multi(1,{HEX},H)))")).unwrap();
        assert_eq!(out, format!("and_v(v:pk(A),and_v(v:sha256({h}),multi(1,A,H)))"));
        assert_eq!(al.len(), 1);
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
