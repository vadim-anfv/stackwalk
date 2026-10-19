use super::{MAX_POLICY_CONDITIONS, compile};
use crate::model::{CompileReq, Scenario};

/// Kind and wrap as the page sends them.
fn req(kind: &str, text: &str, wrap: Option<&str>) -> serde_json::Result<CompileReq> {
    serde_json::from_value(serde_json::json!({ "kind": kind, "text": text, "wrap": wrap }))
}

fn run(kind: &str, text: &str, wrap: Option<&str>) -> Result<Scenario, String> {
    compile(&req(kind, text, wrap).unwrap())
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
fn unknown_kind_or_wrap_is_refused() {
    assert!(req("policy", "pk(A)", Some("p2foo")).is_err());
    assert!(req("Policy", "pk(A)", None).is_err());
    // null, as absent, is the default (wsh)
    assert!(req("policy", "pk(A)", None).is_ok_and(|r| r.wrap.is_none()));
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
    for d in ["pk(A)", "multi(1,A,B)", "sh(multi(2,A,B))", "sh(pk(A))", "sh(pkh(A))", "pkh(A)", "wpkh(A)", "wsh(multi(2,A,B,C))"] {
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

#[test]
fn a_real_hash_is_run_as_a_named_one_and_said_so() {
    // a real sha256 was hashed again as if it were a preimage name, silently: the script did
    // not match the descriptor, and `keys` said nothing was swapped
    let h = "a".repeat(64);
    let sc = ok("descriptor", &format!("wsh(sha256({h}))"), None);
    assert_eq!(sc.descriptor.as_deref(), Some(format!("wsh(sha256({h}))").as_str()));
    let alias = sc.keys.iter().find(|k| k.key == h).expect("the hash is listed as swapped");
    assert!(sc.paths[0].name.contains(&alias.name), "{}", sc.paths[0].name);
    assert!(sc.importable, "a real hash and no keys: a wallet can watch it");
}

#[test]
fn importable_means_every_key_and_hash_is_real() {
    assert!(!ok("descriptor", "wsh(sha256(H))", None).importable, "a hash name");
    assert!(!ok("descriptor", &format!("wsh(and_v(v:pk({HEX}),sha256(H)))"), None).importable, "a real key next to a hash name");
    assert!(ok("descriptor", &format!("wsh(and_v(v:pk({HEX}),sha256({})))", "b".repeat(64)), None).importable);
    // no keys at all is a valid descriptor too
    assert!(ok("descriptor", "wsh(older(1))", None).importable);
}

#[test]
fn not_importable_says_why() {
    // the page said "the keys are made up" also when they were real
    let note = |text: &str| ok("descriptor", text, None).import_note;
    assert_eq!(note(&format!("wsh(and_v(v:pk({HEX}),sha256(H)))")).as_deref(), Some("test names, not real keys or hashes: H"));
    assert_eq!(note("wsh(multi(1,A,B))").as_deref(), Some("test names, not real keys or hashes: A, B"));
    assert_eq!(note(&format!("wsh(pk({HEX}))")), None);
    // real keys, but no wallet takes a non-standard bare miniscript
    let bare = ok("miniscript", &format!("and_v(v:pk({HEX}),pk({G}))"), Some("bare")).import_note.expect("not importable");
    assert!(bare.contains("standardness") && !bare.ends_with(['.', ' ', '\n']), "{bare:?}");
}

#[test]
fn the_same_real_hash_under_two_hash_functions_gets_two_names() {
    // one preimage "satisfied" sha256(h) and hash256(h): no x has both
    let h = "ab".repeat(32);
    let sc = ok("descriptor", &format!("wsh(and_v(v:sha256({h}),hash256({h})))"), None);
    assert_eq!(sc.keys.len(), 2, "{:?}", sc.keys.iter().map(|k| &k.name).collect::<Vec<_>>());
    assert_eq!(sc.descriptor.as_deref(), Some(format!("wsh(and_v(v:sha256({h}),hash256({h})))").as_str()));
}

const XONLY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
/// the generator: a second real key
const G: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

#[test]
fn an_x_only_key_is_refused_outside_taproot() {
    // it ran as a test key: "valid spend" for an output that cannot exist
    for (kind, text, wrap) in [
        ("descriptor", format!("wsh(pk({XONLY}))"), None),
        ("descriptor", format!("pkh({XONLY})"), None),
        ("miniscript", format!("pk({XONLY})"), Some("wsh")),
        ("policy", format!("pk({XONLY})"), Some("sh")),
    ] {
        let err = run(kind, &text, wrap).unwrap_err();
        assert!(err.contains("x-only"), "{kind} {text} {wrap:?}: {err}");
    }
}

#[test]
fn a_negative_timelock_note_says_so() {
    // the engine fails on the sign first; the note spoke of the disable flag / a compare
    for text in ["<-1> OP_CHECKSEQUENCEVERIFY", "<-1> OP_CHECKLOCKTIMEVERIFY"] {
        let sc = ok("script", text, None);
        let step = sc.traces[0].steps.iter().find(|s| s.error.is_some()).expect("it fails");
        assert!(step.note.contains("negative"), "{text}: {}", step.note);
    }
}

#[test]
fn pick_and_roll_past_the_stack_fail_the_script_not_the_server() {
    // `1 1 PICK`: n is popped first, then one item is left, so index 1 is out of range (Core:
    // INVALID_STACK_OPERATION); checking before the pop let it through to an unwrap
    for script in ["OP_1 OP_1 OP_PICK", "OP_1 OP_1 OP_ROLL"] {
        let sc = ok("script", script, None);
        let res = &sc.traces[0].result;
        assert!(!res.ok && res.message.contains("stack"), "{script}: {}", res.message);
    }
    // in range they work: 2 1 0 PICK leaves 2 1 1
    let sc = ok("script", "OP_2 OP_1 OP_0 OP_PICK OP_1 OP_EQUALVERIFY OP_DROP OP_2 OP_EQUAL", None);
    assert!(sc.traces[0].result.ok, "{}", sc.traces[0].result.message);
}

#[test]
fn failures_are_worded_and_policy_rules_say_so() {
    let msg = |script: &str| ok("script", script, None).traces[0].result.message.clone();
    // MINIMALIF and NULLFAIL are relay policy, not consensus: a learner must be told
    let m = msg("OP_2 OP_IF OP_1 OP_ENDIF");
    assert!(m.contains("MINIMALIF") && m.contains("policy"), "{m}");
    let sc = ok("policy", "pk(A)", None);
    let wrong = sc.paths.iter().position(|p| p.fails).unwrap();
    let m = &sc.traces[wrong].result.message;
    assert!(m.contains("NULLFAIL") && m.contains("policy"), "{m}");
    // but a wrong signature is not fine by consensus: CHECKSIG pushes false, VERIFY fails
    assert!(m.contains("push false"), "{m}");
    let sc = ok("miniscript", "and_v(v:pk(A),pk(B))", None);
    let m = &sc.traces[sc.paths.iter().position(|p| p.fails).unwrap()].result.message;
    assert!(m.contains("OP_CHECKSIGVERIFY") && m.contains("by consensus too"), "{m}");
}

#[test]
fn a_timelock_note_on_a_non_minimal_operand_does_not_guess() {
    // the engine fails on MINIMALDATA before the sign: the note said "negative locktime"
    for text in ["<0x0180> OP_CHECKSEQUENCEVERIFY", "<0x0180> OP_CHECKLOCKTIMEVERIFY"] {
        let sc = ok("script", text, None);
        let step = sc.traces[0].steps.iter().find(|s| s.error.is_some()).expect("it fails");
        assert!(step.error.as_deref().is_some_and(|e| e.contains("MINIMALDATA")), "{text}: {:?}", step.error);
        assert!(!step.note.contains("negative"), "{text}: {}", step.note);
    }
}

#[test]
fn digit_names_are_test_names_too() {
    // only multi's threshold is a number; `pk(1)` said "key too short"
    let note = |kind: &str, text: &str, wrap: Option<&str>| ok(kind, text, wrap).import_note;
    assert_eq!(note("miniscript", "pk(1)", Some("wsh")).as_deref(), Some("test names, not real keys or hashes: 1"));
    assert_eq!(note("descriptor", "wsh(and_v(v:pk(A),sha256(12)))", None).as_deref(), Some("test names, not real keys or hashes: A, 12"));
    assert_eq!(note("descriptor", "wsh(multi(2,A,3))", None).as_deref(), Some("test names, not real keys or hashes: A, 3"));
}

#[test]
fn op_reserved_fails_only_when_executed() {
    // as Core: a reserved opcode in a branch not taken is fine
    let sc = ok("script", "OP_0 OP_IF OP_RESERVED OP_ENDIF OP_1", None);
    assert!(sc.traces[0].result.ok, "{}", sc.traces[0].result.message);
    let sc = ok("script", "OP_RESERVED OP_1", None);
    assert!(!sc.traces[0].result.ok);
}

#[test]
fn small_pushes_are_written_as_the_minimal_opcodes() {
    // <0x81> is OP_1NEGATE and <0x05> is OP_5: the parser must not build pushes the
    // engine then refuses as non-minimal
    for script in ["<0x81> OP_1NEGATE OP_EQUAL", "<0x05> OP_5 OP_EQUAL", "<0x> OP_0 OP_EQUAL"] {
        let sc = ok("script", script, None);
        assert!(sc.traces[0].result.ok, "{script}: {}", sc.traces[0].result.message);
    }
}

#[test]
fn a_miniscript_mixing_height_and_time_locks_is_refused() {
    // no spend can meet both: its passing path was silently dropped, and the one failing
    // variant left lost the height lock from its name
    for (kind, text, wrap) in [
        ("descriptor", "wsh(and_v(v:after(1),after(500000001)))", None),
        ("miniscript", "and_v(v:pk(A),and_v(v:after(1),after(500000001)))", Some("wsh")),
        ("descriptor", "wsh(and_v(v:older(1),older(4194305)))", None),
    ] {
        let err = run(kind, text, wrap).unwrap_err();
        // the miniscript parser refuses the second one itself; the descriptors reach our check
        let want = if kind == "descriptor" { "no transaction can meet both" } else { "heightlock and timelock" };
        assert!(err.contains(want), "{text}: {err}");
    }
    // one kind of each is fine
    assert!(run("descriptor", "wsh(and_v(v:after(1),older(4194305)))", None).is_ok());
}

#[test]
fn a_timelock_note_gives_the_real_reason() {
    // the tx locktime is a height (0) and the script asks for a time: it fails on the kind,
    // not on "0 < 500000001"
    let sc = ok("script", "<500000001> OP_CHECKLOCKTIMEVERIFY", None);
    let step = sc.traces[0].steps.iter().find(|s| s.error.is_some()).expect("it fails");
    assert!(step.note.contains("kind"), "{}", step.note);
}

#[test]
fn script_numbers_are_bounded_as_core_parses_them() {
    // i64::MIN panicked inside rust-bitcoin's push_int; Core's ParseScript takes +-0xffffffff
    for text in ["-9223372036854775808", "<-9223372036854775808>", "4294967296", "<-4294967296>"] {
        let err = run("script", text, None).unwrap_err();
        assert!(err.contains("out of range"), "{text}: {err}");
    }
    assert!(run("script", "4294967295 OP_DROP OP_1", None).is_ok());
    assert!(run("script", "<-4294967295> OP_DROP OP_1", None).is_ok());
}

#[test]
fn a_bad_key_with_wide_characters_is_an_error_not_a_crash() {
    // shortening the key for the message cut it inside a character
    let err = run("policy", "pk([ééééééééééééééééééééé])", None).unwrap_err();
    assert!(err.contains("invalid key"), "{err}");
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
fn an_answer_too_many_bytes_is_refused() {
    // few items, each big: 200 copies of a 520-byte push stayed under the item limit and
    // made a 22 MB answer from a 2.4 KB request
    let script = format!("<0x{}>{}", "ab".repeat(520), " OP_DUP".repeat(200));
    let err = run("script", &script, None).unwrap_err();
    assert!(err.contains("too big to show"), "{err}");
    // the biggest example stays well below
    assert!(run("miniscript", "multi(2,A,B,C,D,E,F,G,H,I,J)", None).is_ok());
}

#[test]
fn a_run_too_big_to_show_is_refused() {
    // every push grows the stack, and every step carries the whole stack: quadratic
    let script = vec!["OP_1"; 800].join(" ");
    let err = run("script", &script, None).unwrap_err();
    assert!(err.contains("too big to show"), "{err}");
    assert!(run("script", &vec!["OP_1"; 100].join(" "), None).is_ok());
}
