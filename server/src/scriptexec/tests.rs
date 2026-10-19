//! Engine checks that Core's script_tests.json does not reach.
use bitcoin::hex::FromHex;

use super::*;

fn h(s: &str) -> Vec<u8> {
    Vec::from_hex(s).expect("hex")
}

/// Core's script_FindAndDelete unit test (src/test/script_tests.cpp, v31.1): (script, delete, expect).
#[test]
fn find_and_delete_matches_core() {
    let cases = [
        ("5152", "", "5152"),
        ("515253", "52", "5153"),
        ("535153535453", "53", "5154"),
        ("0302ff03", "0302ff03", ""),
        ("0302ff030302ff03", "0302ff03", ""),
        // whole opcodes only
        ("0302ff030302ff03", "02", "0302ff030302ff03"),
        ("0302ff030302ff03", "ff", "0302ff030302ff03"),
        // strips the push-3 prefixes, leaving two push-2s
        ("0302ff030302ff03", "03", "02ff0302ff03"),
        ("02feed5169", "feed51", "02feed5169"),
        ("02feed5169", "02feed51", "69"),
        ("516902feed5169", "feed51", "516902feed5169"),
        ("516902feed5169", "02feed51", "516969"),
        // single pass
        ("00005151", "0051", "0051"),
        ("000051005151", "0051", "0051"),
        // a truncated last push can be removed, and is kept as is otherwise
        ("0003feed", "03feed", "00"),
        ("0003feed", "00", "03feed"),
    ];
    for (script, del, want) in cases {
        assert_eq!(find_and_delete(&h(script), &h(del)), h(want), "FindAndDelete({script}, {del})");
    }
}

#[test]
fn a_signature_is_removed_as_a_push() {
    // <3001> CHECKSIG: the push goes
    assert_eq!(remove_sigs(&h("023001ac"), &[h("3001")]), h("ac"));
    // the same bytes inside another push are not a push of the signature
    assert_eq!(remove_sigs(&h("03ff3001ac"), &[h("3001")]), h("03ff3001ac"));
    // an empty signature is OP_0 pushed: every OP_0 goes
    assert_eq!(remove_sigs(&h("0051ac00"), &[vec![]]), h("51ac"));
}
