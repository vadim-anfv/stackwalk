use super::{MAX_POLICY_CONDITIONS, compile};
use crate::model::{CompileReq, Scenario};

fn run(kind: &str, text: &str, wrap: Option<&str>) -> Result<Scenario, String> {
    compile(&CompileReq { kind: kind.into(), text: text.into(), wrap: wrap.map(Into::into) })
}

fn ok(kind: &str, text: &str, wrap: Option<&str>) -> Scenario {
    run(kind, text, wrap).unwrap_or_else(|e| panic!("{kind} {text} {wrap:?}: {e}"))
}

#[test]
fn policy_without_wrap_is_wsh() {
    let sc = ok("policy", "and(pk(A),pk(B))", None);
    assert_eq!(sc.wrap, "wsh");
    assert!(sc.descriptor.unwrap().starts_with("wsh("));
}

#[test]
fn policy_wrapped_in_sh() {
    let sc = ok("policy", "and(pk(A),pk(B))", Some("sh"));
    assert_eq!(sc.wrap, "sh");
    assert!(sc.descriptor.unwrap().starts_with("sh("));
    assert_eq!(sc.spk, "OP_HASH160 <hash160(redeemScript)> OP_EQUAL");
}

#[test]
fn policy_bare() {
    let sc = ok("policy", "pk(A)", Some("bare"));
    assert_eq!(sc.wrap, "bare");
    assert_eq!(sc.descriptor.as_deref(), Some("pk(A)"));
    assert_eq!(sc.paths[0].name, "A signs");
}

#[test]
fn policy_key_as_pkh_and_wpkh() {
    let sc = ok("policy", "pk(A)", Some("pkh"));
    assert_eq!((sc.wrap, sc.descriptor.as_deref()), ("pkh", Some("pkh(A)")));
    assert_eq!(sc.policy.as_deref(), Some("pk(A)"));
    let sc = ok("policy", "pk(A)", Some("wpkh"));
    assert_eq!((sc.wrap, sc.descriptor.as_deref()), ("wpkh", Some("wpkh(A)")));
}

#[test]
fn pkh_needs_a_single_key() {
    let e = run("policy", "and(pk(A),pk(B))", Some("wpkh")).err().unwrap();
    assert!(e.contains("single key"), "{e}");
    let e = run("miniscript", "and_v(v:pk(A),pk(B))", Some("pkh")).err().unwrap();
    assert!(e.contains("single key"), "{e}");
}

#[test]
fn miniscript_wrapped_in_sh() {
    let sc = ok("miniscript", "and_v(v:pk(A),pk(B))", Some("sh"));
    assert_eq!(sc.descriptor.as_deref(), Some("sh(and_v(v:pk(A),pk(B)))"));
}

#[test]
fn miniscript_key_as_wpkh() {
    let sc = ok("miniscript", "pk(A)", Some("wpkh"));
    assert_eq!(sc.descriptor.as_deref(), Some("wpkh(A)"));
}

#[test]
fn taproot_is_refused() {
    let e = run("policy", "pk(A)", Some("tr")).err().unwrap();
    assert!(e.contains("taproot"), "{e}");
}

#[test]
fn unknown_wrap_is_refused() {
    assert!(run("policy", "pk(A)", Some("p2foo")).is_err());
}

#[test]
fn policy_is_never_lifted() {
    // fields flow one way, policy -> miniscript -> descriptor: only a policy input has a policy
    for (kind, text, wrap) in [
        ("miniscript", "and_v(v:pk(A),pk(B))", None),
        ("miniscript", "pk(A)", Some("pkh")),
        ("descriptor", "wsh(and_v(v:pk(A),pk(B)))", None),
        ("descriptor", "pkh(A)", None),
        ("script", "OP_1", None),
    ] {
        assert_eq!(ok(kind, text, wrap).policy, None, "{kind} {text}");
    }
}

#[test]
fn initial_stack_names_its_source() {
    let first = |sc: Scenario| sc.traces[0].steps[0].note.clone();
    // wsh: the witnessScript is the last witness item and never lands on the stack
    assert_eq!(first(ok("policy", "pk(A)", None)), "Initial stack = witness without its last item (witnessScript): [sig(A)]");
    assert_eq!(first(ok("policy", "pk(A)", Some("wpkh"))), "Initial stack = witness: [sig(A), pk(A)]");
    assert_eq!(first(ok("policy", "pk(A)", Some("pkh"))), "Initial stack = scriptSig: [sig(A), pk(A)]");
    // a bare script has no transaction behind it, so no witness either
    assert!(first(ok("script", "OP_1", None)).starts_with("Initial stack: empty."));
}

#[test]
fn descriptor_reports_its_wrap() {
    for (d, w) in [("pk(A)", "bare"), ("pkh(A)", "pkh"), ("multi(1,A,B)", "bare"), ("sh(multi(2,A,B))", "sh"), ("wpkh(A)", "wpkh"), ("wsh(pk(A))", "wsh")] {
        // the request's wrap does not apply to a descriptor: it names its own
        assert_eq!(ok("descriptor", d, Some("sh")).wrap, w, "{d}");
    }
}

#[test]
fn miniscript_outside_wsh_is_flagged() {
    // BIP-379: miniscript only in wsh / tr
    assert!(ok("policy", "and(pk(A),or(pk(B),pk(C)))", Some("sh")).outside_bip379);
    assert!(ok("miniscript", "and_v(v:pk(A),pk(B))", Some("bare")).outside_bip379);
    assert!(!ok("policy", "and(pk(A),or(pk(B),pk(C)))", Some("wsh")).outside_bip379);
}

#[test]
fn plain_descriptors_are_not_flagged() {
    // pk() (BIP-381) and multi() (BIP-383) are valid in sh() and bare
    for d in ["pk(A)", "multi(1,A,B)", "sh(multi(2,A,B))", "sh(pk(A))", "pkh(A)", "wpkh(A)", "wsh(multi(2,A,B,C))"] {
        assert!(!ok("descriptor", d, None).outside_bip379, "{d}");
    }
    assert!(!ok("policy", "pk(A)", Some("bare")).outside_bip379);
    assert!(!ok("script", "OP_1", None).outside_bip379);
}

#[test]
fn script_is_wsh() {
    assert_eq!(ok("script", "OP_1", None).wrap, "wsh");
    assert_eq!(ok("script", "<pk(A)> OP_CHECKSIG", None).wrap, "wsh");
}

const HEX: &str = "02e5b88fdb71c696e1a473f309a47535b7190e21a22bd25e7fc8bd055db3bba12f";

#[test]
fn descriptor_comes_with_its_checksum() {
    use miniscript::descriptor::checksum::verify_checksum;
    for (kind, text, wrap) in [("policy", "and(pk(A),pk(B))", None), ("policy", "pk(A)", Some("pkh")), ("descriptor", "sh(multi(2,A,B))", None)] {
        let sc = ok(kind, text, wrap);
        let (d, c) = (sc.descriptor.unwrap(), sc.checksum.unwrap());
        // the field stays editable: no checksum inside it
        assert!(!d.contains('#'), "{d}");
        assert_eq!(verify_checksum(&format!("{d}#{c}")), Ok(d.as_str()), "{kind} {text}");
    }
    assert_eq!(ok("script", "OP_1", None).checksum, None);
}

#[test]
fn checksum_is_over_the_real_keys() {
    use miniscript::descriptor::checksum::verify_checksum;
    let sc = ok("policy", &format!("pk({HEX})"), Some("wpkh"));
    let d = sc.descriptor.unwrap();
    assert_eq!(d, format!("wpkh({HEX})"));
    assert!(verify_checksum(&format!("{d}#{}", sc.checksum.unwrap())).is_ok());
    assert!(sc.importable);
    // test keys only, or test keys next to a real one: a wallet cannot use it
    assert!(!ok("policy", "pk(A)", None).importable);
    assert!(!ok("policy", &format!("and(pk({HEX}),pk(B))"), None).importable);
}

#[test]
fn descriptor_input_checksum_is_verified() {
    let sc = ok("descriptor", "wsh(pk(A))", None);
    let good = format!("wsh(pk(A))#{}", sc.checksum.unwrap());
    assert_eq!(ok("descriptor", &good, None).descriptor.as_deref(), Some("wsh(pk(A))"));
    // a typo is caught, never silently re-checksummed
    let err = run("descriptor", "wsh(pk(B))#", None).unwrap_err();
    assert!(err.contains("checksum"), "{err}");
    let err = run("descriptor", &good.replace("pk(A)", "pk(B)"), None).unwrap_err();
    assert!(err.starts_with("checksum mismatch: got #"), "{err}");
}

fn labels(items: &[crate::model::Item]) -> Vec<&str> {
    items.iter().map(|i| i.label.as_str()).collect()
}

fn hex_len(i: &crate::model::Item) -> usize {
    i.hex.len() / 2
}

#[test]
fn spend_shows_the_witness_as_sent() {
    // wsh: the witnessScript rides last, it is not stack data
    let sc = ok("policy", "pk(A)", None);
    let sp = &sc.paths[0].spend;
    assert_eq!((sp.field, labels(&sp.items), sp.script_last), ("witness", vec!["sig(A)", "witnessScript"], true));
    // count + each item with its length prefix (all < 253 bytes here)
    assert_eq!(sp.bytes, 1 + sp.items.iter().map(|i| 1 + hex_len(i)).sum::<usize>());
    // 41 non-witness bytes (outpoint, empty scriptSig, sequence) at 4 WU, the witness at 1 WU
    assert_eq!(sp.vbytes, (41 * 4 + sp.bytes).div_ceil(4));

    let sc = ok("policy", "pk(A)", Some("wpkh"));
    let sp = &sc.paths[0].spend;
    assert_eq!((sp.field, labels(&sp.items), sp.script_last), ("witness", vec!["sig(A)", "pk(A)"], false));

    let sc = ok("script", "OP_1", None);
    assert_eq!(labels(&sc.paths[0].spend.items), vec!["witnessScript"]);
}

#[test]
fn spend_shows_the_script_sig_as_sent() {
    let sc = ok("descriptor", "sh(multi(2,A,B))", None);
    let sp = &sc.paths[0].spend;
    assert_eq!((sp.field, labels(&sp.items), sp.script_last), ("scriptSig", vec!["<empty>", "sig(A)", "sig(B)", "redeemScript"], true));
    // OP_0, two direct pushes, the redeemScript (71 bytes: OP_PUSHDATA1)
    let pushes: usize = sp.items.iter().map(|i| match hex_len(i) { 0 => 1, n @ 1..=75 => 1 + n, n => 2 + n }).sum();
    assert_eq!(sp.bytes, pushes);
    // outpoint 36 + scriptSig length (1 byte below 253) + scriptSig + sequence 4, no witness
    assert_eq!(sp.vbytes, 36 + 1 + sp.bytes + 4);

    let sc = ok("descriptor", "pkh(A)", None);
    let sp = &sc.paths[0].spend;
    assert_eq!((sp.field, labels(&sp.items), sp.script_last), ("scriptSig", vec!["sig(A)", "pk(A)"], false));
}

#[test]
fn script_size_and_op_count() {
    // wsh(pk(A)): <33-byte key> OP_CHECKSIG
    let sc = ok("policy", "pk(A)", None);
    assert_eq!(sc.script_bytes, 35);
    assert_eq!(sc.traces[0].ops, 1);
    // CHECKMULTISIG counts its keys too, as in Core: 1 + 3
    let sc = ok("descriptor", "wsh(multi(2,A,B,C))", None);
    assert_eq!(sc.traces[0].ops, 4);
    // a failing run counts up to where it stops: the keys are added before the signatures are checked
    let wrong = sc.paths.iter().position(|p| p.fails).unwrap();
    assert_eq!(sc.traces[wrong].ops, 4);
}

/// `or(pk(A),or(pk(B),...))` over the first `n` of A..P
fn or_chain(n: usize) -> String {
    let keys: Vec<String> = ('A'..='P').take(n).map(|c| format!("pk({c})")).collect();
    keys.iter().rev().skip(1).fold(keys[n - 1].clone(), |acc, k| format!("or({k},{acc})"))
}

#[test]
fn a_policy_over_the_condition_limit_is_refused_before_compiling() {
    // the policy compiler is exponential in the size of an or-chain: 12 keys take seconds
    let err = run("policy", &or_chain(MAX_POLICY_CONDITIONS + 1), None).unwrap_err();
    assert!(err.contains("too many conditions"), "{err}");
    assert!(run("policy", &or_chain(MAX_POLICY_CONDITIONS), None).is_ok());
}

#[test]
fn too_many_spend_paths_are_refused() {
    // multi(3 of 9): 84 ways to pick the signers
    let err = run("miniscript", "multi(3,A,B,C,D,E,F,G,H,I)", None).unwrap_err();
    assert!(err.contains("too many spend paths"), "{err}");
    // 2 of 10: 45
    assert!(run("miniscript", "multi(2,A,B,C,D,E,F,G,H,I,J)", None).is_ok());
}

#[test]
fn a_script_that_is_not_miniscript_says_why_its_stack_is_empty() {
    // needs an input it cannot get: fails at once, and must not look like a bug
    let sc = ok("script", "OP_IF OP_1 OP_ENDIF", None);
    let start = sc.traces[0].steps[0].note.clone();
    assert!(start.contains("not a miniscript"), "{start}");
    assert!(sc.about.is_some_and(|a| a.contains("not a miniscript")));
    // a recognized miniscript gets its witness, no such note
    let sc = ok("script", "<pk(A)> OP_CHECKSIG", None);
    assert!(!sc.traces[0].steps[0].note.contains("not a miniscript"));
}

const UNCOMPRESSED: &str = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

#[test]
fn an_uncompressed_key_is_refused_in_segwit() {
    // it was built as a (compressed) test key, so the run passed and the descriptor came out
    // "importable", though no node relays a segwit spend with an uncompressed key
    for (kind, text, wrap) in [
        ("descriptor", format!("wsh(pk({UNCOMPRESSED}))"), None),
        ("descriptor", format!("wpkh({UNCOMPRESSED})"), None),
        ("policy", format!("pk({UNCOMPRESSED})"), Some("wpkh")),
        ("miniscript", format!("pk({UNCOMPRESSED})"), Some("wsh")),
    ] {
        let err = run(kind, &text, wrap).unwrap_err();
        assert!(err.contains("uncompressed"), "{kind} {text} {wrap:?}: {err}");
    }
    // legacy outputs take them
    let sc = ok("descriptor", &format!("pkh({UNCOMPRESSED})"), None);
    assert!(sc.importable);
    assert!(run("descriptor", &format!("sh(pk({UNCOMPRESSED}))"), None).is_ok());
}

#[test]
fn a_private_key_is_refused_and_not_repeated() {
    // a WIF key looked like a key name and compiled: it then sat in the page, the URL and history
    let wif = "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ";
    let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    for (kind, text) in [
        ("descriptor", format!("wsh(pk({wif}))")),
        ("policy", format!("pk({wif})")),
        ("descriptor", format!("wsh(pk({xprv}/0/*))")),
        ("script", format!("<{wif}> OP_CHECKSIG")),
    ] {
        let err = run(kind, &text, None).unwrap_err();
        assert!(err.contains("private key"), "{kind} {text}: {err}");
        assert!(!err.contains(&wif[..12]) && !err.contains(&xprv[..12]), "{err}");
    }
    // public keys and names still pass
    assert!(run("policy", "pk(Alice)", None).is_ok());
}

#[test]
fn a_run_too_big_to_show_is_refused() {
    // every push grows the stack, and every step carries the whole stack: quadratic
    let script = vec!["OP_1"; 800].join(" ");
    let err = run("script", &script, None).unwrap_err();
    assert!(err.contains("too big to show"), "{err}");
    assert!(run("script", &vec!["OP_1"; 100].join(" "), None).is_ok());
}
