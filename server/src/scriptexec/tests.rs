//! Engine checks that Core's script_tests.json does not reach.
use bitcoin::hex::FromHex;

use super::*;

fn h(s: &str) -> Vec<u8> {
    Vec::from_hex(s).expect("hex")
}

/// One input spending `prevout`, one empty output.
fn tx(prevout: TxOut) -> TxTemplate {
    let tx = Transaction {
        version: transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn::default()],
        output: vec![TxOut { value: prevout.value, script_pubkey: ScriptBuf::new() }],
    };
    TxTemplate { tx, prevouts: vec![prevout], input_idx: 0, taproot_annex_scriptleaf: None }
}

fn run(ctx: ExecCtx, tmpl: TxTemplate, script: Vec<u8>, stack: Vec<Vec<u8>>) -> ExecutionResult {
    let ids = IdGen::new(0);
    let entries = stack.into_iter().map(|data| Entry { id: ids.next(), data }).collect();
    let script = ScriptBuf::from_bytes(script);
    let mut exec = Exec::new(ctx, Options::default(), tmpl, script, Stack::from_entries(entries, ids)).expect("parses");
    loop {
        if let Err(res) = exec.exec_next() {
            return res.clone();
        }
    }
}

#[test]
fn data_pushes_count_toward_the_stack_limit() {
    // 1001 pushes of 0xff: Core fails at the 1001st (STACK_SIZE is checked after every opcode)
    let script = h(&"01ff".repeat(1001));
    let res = run(ExecCtx::Legacy, tx(TxOut::NULL), script, vec![]);
    assert_eq!(res.error, Some(ExecError::StackSize));
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
