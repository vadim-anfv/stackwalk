//! Bitcoin Core's script test vectors run through our `Exec`.
//!
//! `data/script_tests.json` is Bitcoin Core v31.1's `src/test/data/script_tests.json`
//! (https://raw.githubusercontent.com/bitcoin/bitcoin/v31.1/src/test/data/script_tests.json, MIT).
//! The harness mirrors Core's `script_json_test` / `DoTest` (src/test/script_tests.cpp) and
//! `VerifyScript` (src/script/interpreter.cpp) for legacy, P2SH and segwit v0. Taproot is out of
//! scope. `cargo test core_vectors -- --nocapture` prints the summary.
use std::collections::BTreeMap;

use bitcoin::hashes::{Hash, sha256};
use bitcoin::opcodes::all::OP_RESERVED;
use bitcoin::opcodes::{Opcode, all::*};
use bitcoin::script::{Instruction, read_scriptbool};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute, transaction,
};
use serde_json::Value;

use crate::scriptexec::{Entry, Exec, ExecCtx, ExecError, IdGen, Options, Stack, TxTemplate, parse_opcode, scriptint_vec};

/// Vectors we knowingly disagree with: (index in the JSON array, why). Prefer fixing.
const KNOWN_GAPS: &[(usize, &str)] = &[];

/// Flags our engine or this harness implements; any other flag skips the vector.
const SUPPORTED: &[&str] = &[
    "",
    "NONE",
    "P2SH",
    "MINIMALDATA",
    "MINIMALIF",
    "NULLFAIL",
    "NULLDUMMY",
    "CHECKLOCKTIMEVERIFY",
    "CHECKSEQUENCEVERIFY",
    "WITNESS",
    "CLEANSTACK",
    "SIGPUSHONLY",
    "WITNESS_PUBKEYTYPE",
    "STRICTENC",
    "DERSIG",
    "LOW_S",
    "DISCOURAGE_UPGRADABLE_NOPS",
    "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
];

type Res<T> = Result<T, &'static str>;

/// Core's `CScript << vector`: the shortest push opcode for the length, never OP_N.
fn push_data(out: &mut Vec<u8>, d: &[u8]) {
    match d.len() {
        n if n < 0x4c => out.push(n as u8),
        n if n <= 0xff => out.extend([0x4c, n as u8]),
        n if n <= 0xffff => {
            out.push(0x4d);
            out.extend((n as u16).to_le_bytes());
        }
        n => {
            out.push(0x4e);
            out.extend((n as u32).to_le_bytes());
        }
    }
    out.extend(d);
}

/// Core's `CScript << int64`: OP_0, OP_1NEGATE, OP_1..OP_16, else a minimal number push.
fn push_int(out: &mut Vec<u8>, n: i64) {
    match n {
        0 => out.push(0),
        -1 => out.push(OP_PUSHNUM_NEG1.to_u8()),
        1..=16 => out.push(OP_PUSHNUM_1.to_u8() + n as u8 - 1),
        _ => push_data(out, &scriptint_vec(n)),
    }
}

fn hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// Core's `ParseScript` (src/core_read.cpp).
fn parse_script(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for w in s.split([' ', '\t', '\n']).filter(|w| !w.is_empty()) {
        let digits = |d: &str| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit());
        if digits(w) || w.strip_prefix('-').is_some_and(digits) {
            let n: i64 = w.parse().expect("decimal number");
            assert!(n.abs() <= 0xffff_ffff, "number out of range: {w}");
            push_int(&mut out, n);
        } else if let Some(h) = w.strip_prefix("0x").filter(|h| !h.is_empty()).and_then(hex) {
            out.extend(h);
        } else if w.len() >= 2 && w.starts_with('\'') && w.ends_with('\'') {
            push_data(&mut out, &w.as_bytes()[1..w.len() - 1]);
        } else {
            // Core names only OP_NOP and up, and OP_RESERVED
            let op = parse_opcode(w).unwrap_or_else(|_| panic!("unknown opcode {w}"));
            assert!(op == OP_RESERVED || op.to_u8() >= OP_NOP.to_u8(), "not a Core opcode name: {w}");
            out.push(op.to_u8());
        }
    }
    out
}

/// Core's `IsPushOnly`: every opcode parses and is at most OP_16.
fn push_only(script: &[u8]) -> bool {
    ScriptBuf::from_bytes(script.to_vec()).instructions().all(|i| match i {
        Ok(Instruction::PushBytes(_)) => true,
        Ok(Instruction::Op(op)) => op.to_u8() <= OP_PUSHNUM_16.to_u8(),
        Err(_) => false,
    })
}

fn is_p2sh(spk: &[u8]) -> bool {
    spk.len() == 23 && spk[0] == OP_HASH160.to_u8() && spk[1] == 0x14 && spk[22] == OP_EQUAL.to_u8()
}

/// Core's `IsWitnessProgram`: (version, program).
fn witness_program(spk: &[u8]) -> Option<(u8, &[u8])> {
    if spk.len() < 4 || spk.len() > 42 || usize::from(spk[1]) + 2 != spk.len() {
        return None;
    }
    match spk[0] {
        0 => Some((0, &spk[2..])),
        v @ 0x51..=0x60 => Some((v - 0x50, &spk[2..])),
        _ => None,
    }
}

struct Flags(Vec<String>);

impl Flags {
    fn parse(s: &str) -> Self {
        let mut f = Flags(s.split(',').filter(|f| !f.is_empty()).map(String::from).collect());
        // as DoTest: CLEANSTACK only makes sense with P2SH and WITNESS
        if f.has("CLEANSTACK") {
            f.0.extend(["P2SH".into(), "WITNESS".into()]);
        }
        f
    }

    fn has(&self, name: &str) -> bool {
        self.0.iter().any(|f| f == name)
    }

    fn unsupported(&self) -> Option<&str> {
        self.0.iter().map(String::as_str).find(|f| !SUPPORTED.contains(f))
    }

    fn options(&self) -> Options {
        Options {
            require_minimal: self.has("MINIMALDATA"),
            verify_cltv: self.has("CHECKLOCKTIMEVERIFY"),
            verify_csv: self.has("CHECKSEQUENCEVERIFY"),
            verify_minimal_if: self.has("MINIMALIF"),
            // consensus in Core, not a flag
            enforce_stack_limit: true,
            verify_nullfail: self.has("NULLFAIL"),
            verify_nulldummy: self.has("NULLDUMMY"),
            verify_witness_pubkeytype: self.has("WITNESS_PUBKEYTYPE"),
            verify_dersig: self.has("DERSIG"),
            verify_low_s: self.has("LOW_S"),
            verify_strictenc: self.has("STRICTENC"),
            verify_discourage_upgradable_nops: self.has("DISCOURAGE_UPGRADABLE_NOPS"),
        }
    }
}

/// Our error as Core's `ScriptError` name. `op` is set when an opcode failed (not a push).
fn core_err(e: &ExecError, op: Option<Opcode>, ctx: ExecCtx) -> &'static str {
    use ExecError::*;
    match e {
        DisabledOpcode => "DISABLED_OPCODE",
        BadOpcode => "BAD_OPCODE",
        OpCount => "OP_COUNT",
        PushSize => "PUSH_SIZE",
        // a number operand is a CScriptNum in Core: SCRIPTNUM, a push is MINIMALDATA
        MinimalData if op.is_some() => "SCRIPTNUM",
        MinimalData => "MINIMALDATA",
        InvalidStackOperation if op == Some(OP_FROMALTSTACK) => "INVALID_ALTSTACK_OPERATION",
        InvalidStackOperation => "INVALID_STACK_OPERATION",
        NegativeLocktime => "NEGATIVE_LOCKTIME",
        UnsatisfiedLocktime => "UNSATISFIED_LOCKTIME",
        UnbalancedConditional => "UNBALANCED_CONDITIONAL",
        TapscriptMinimalIf if ctx == ExecCtx::SegwitV0 => "MINIMALIF",
        TapscriptMinimalIf => "TAPSCRIPT_MINIMALIF",
        Verify => "VERIFY",
        OpReturn => "OP_RETURN",
        EqualVerify => "EQUALVERIFY",
        NumEqualVerify => "NUMEQUALVERIFY",
        CheckSigVerify => "CHECKSIGVERIFY",
        PubkeyCount => "PUBKEY_COUNT",
        StackSize => "STACK_SIZE",
        ScriptSize => "SCRIPT_SIZE",
        WitnessPubkeyType => "WITNESS_PUBKEYTYPE",
        SigDer => "SIG_DER",
        SigHighS => "SIG_HIGH_S",
        SigHashtype => "SIG_HASHTYPE",
        DiscourageUpgradableNops => "DISCOURAGE_UPGRADABLE_NOPS",
        SigCount => "SIG_COUNT",
        NullFail => "NULLFAIL",
        NullDummy => "SIG_NULLDUMMY",
        CheckMultiSigVerify => "CHECKMULTISIGVERIFY",
        ScriptIntNumericOverflow => "SCRIPTNUM",
        PubkeyType => "PUBKEYTYPE",
        TapscriptValidationWeight | SchnorrSigSize | SchnorrSigHashtype | SchnorrSig | TapscriptCheckMultiSig => {
            "TAPSCRIPT"
        }
    }
}

struct Ctx<'a> {
    flags: &'a Flags,
    opts: Options,
    tx: &'a Transaction,
    prevout: &'a TxOut,
}

impl Ctx<'_> {
    /// Core's `EvalScript`: the stack after running `script` on `stack`.
    fn eval(&self, ctx: ExecCtx, script: &[u8], stack: Vec<Vec<u8>>) -> Res<Vec<Vec<u8>>> {
        let ids = IdGen::new(0);
        let entries = stack.into_iter().map(|data| Entry { id: ids.next(), data }).collect();
        let tmpl = TxTemplate {
            tx: self.tx.clone(),
            prevouts: vec![self.prevout.clone()],
            input_idx: 0,
            taproot_annex_scriptleaf: None,
        };
        let script = ScriptBuf::from_bytes(script.to_vec());
        // Core runs up to the bad push and fails there with BAD_OPCODE
        let mut exec = Exec::new(ctx, self.opts.clone(), tmpl, script, Stack::from_entries(entries, ids))
            .map_err(|_| "BAD_OPCODE")?;
        loop {
            if let Err(res) = exec.exec_next() {
                return match &res.error {
                    Some(e) => Err(core_err(e, res.opcode, ctx)),
                    None => Ok(res.final_stack.as_v8_vec()),
                };
            }
        }
    }

    /// Core's `ExecuteWitnessScript` for segwit v0.
    fn exec_witness(&self, script: &[u8], stack: &[Vec<u8>]) -> Res<()> {
        if stack.iter().any(|e| e.len() > 520) {
            return Err("PUSH_SIZE");
        }
        let stack = self.eval(ExecCtx::SegwitV0, script, stack.to_vec())?;
        if stack.len() != 1 {
            return Err("CLEANSTACK");
        }
        if !read_scriptbool(&stack[0]) {
            return Err("EVAL_FALSE");
        }
        Ok(())
    }

    /// Core's `VerifyWitnessProgram`, without taproot (it is never enabled here).
    fn witness_program(&self, witness: &[Vec<u8>], version: u8, prog: &[u8], is_p2sh: bool) -> Res<()> {
        match (version, prog.len()) {
            (0, 32) => {
                let (script, rest) = witness.split_last().ok_or("WITNESS_PROGRAM_WITNESS_EMPTY")?;
                if sha256::Hash::hash(script).as_byte_array() != prog {
                    return Err("WITNESS_PROGRAM_MISMATCH");
                }
                self.exec_witness(script, rest)
            }
            (0, 20) => {
                if witness.len() != 2 {
                    return Err("WITNESS_PROGRAM_MISMATCH");
                }
                let mut script = vec![OP_DUP.to_u8(), OP_HASH160.to_u8()];
                push_data(&mut script, prog);
                script.extend([OP_EQUALVERIFY.to_u8(), OP_CHECKSIG.to_u8()]);
                self.exec_witness(&script, witness)
            }
            (0, _) => Err("WITNESS_PROGRAM_WRONG_LENGTH"),
            // taproot without the TAPROOT flag, and pay-to-anchor: anyone can spend
            (1, 32) if !is_p2sh => Ok(()),
            (1, 2) if !is_p2sh && prog == [0x4e, 0x73] => Ok(()),
            _ if self.flags.has("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM") => {
                Err("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM")
            }
            _ => Ok(()),
        }
    }

    /// Core's `VerifyScript`.
    fn verify(&self, sig: &[u8], spk: &[u8], witness: &[Vec<u8>]) -> Res<()> {
        let f = self.flags;
        if f.has("SIGPUSHONLY") && !push_only(sig) {
            return Err("SIG_PUSHONLY");
        }
        let stack = self.eval(ExecCtx::Legacy, sig, Vec::new())?;
        let copy = stack.clone();
        let mut stack = self.eval(ExecCtx::Legacy, spk, stack)?;
        if !stack.last().is_some_and(|t| read_scriptbool(t)) {
            return Err("EVAL_FALSE");
        }
        let mut had_witness = false;
        if f.has("WITNESS")
            && let Some((v, prog)) = witness_program(spk)
        {
            had_witness = true;
            if !sig.is_empty() {
                return Err("WITNESS_MALLEATED");
            }
            self.witness_program(witness, v, prog, false)?;
            stack.truncate(1);
        }
        if f.has("P2SH") && is_p2sh(spk) {
            if !push_only(sig) {
                return Err("SIG_PUSHONLY");
            }
            stack = copy;
            let rs = stack.pop().expect("P2SH spk ran on a non-empty stack");
            stack = self.eval(ExecCtx::Legacy, &rs, stack)?;
            if !stack.last().is_some_and(|t| read_scriptbool(t)) {
                return Err("EVAL_FALSE");
            }
            if f.has("WITNESS")
                && let Some((v, prog)) = witness_program(&rs)
            {
                had_witness = true;
                let mut single = Vec::new();
                push_data(&mut single, &rs);
                if sig != single {
                    return Err("WITNESS_MALLEATED_P2SH");
                }
                self.witness_program(witness, v, prog, true)?;
                stack.truncate(1);
            }
        }
        if f.has("CLEANSTACK") && stack.len() != 1 {
            return Err("CLEANSTACK");
        }
        if f.has("WITNESS") && !had_witness && !witness.is_empty() {
            return Err("WITNESS_UNEXPECTED");
        }
        Ok(())
    }
}

/// Core's `BuildCreditingTransaction` / `BuildSpendingTransaction`.
fn txs(spk: &[u8], sig: &[u8], witness: &[Vec<u8>], value: Amount) -> (Transaction, TxOut) {
    let credit = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            // CScript() << CScriptNum(0) << CScriptNum(0): two empty pushes
            script_sig: ScriptBuf::from_bytes(vec![0, 0]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value, script_pubkey: ScriptBuf::from_bytes(spk.to_vec()) }],
    };
    let spend = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: credit.compute_txid(), vout: 0 },
            script_sig: ScriptBuf::from_bytes(sig.to_vec()),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(witness),
        }],
        output: vec![TxOut { value, script_pubkey: ScriptBuf::new() }],
    };
    (spend, credit.output[0].clone())
}

enum Outcome {
    Skip(String),
    Pass,
    Mismatch(String),
}

fn run_vector(v: &[Value]) -> Outcome {
    let s = |i: usize| v[i].as_str().expect("string field");
    let (witness, value, pos) = match &v[0] {
        Value::Array(w) => {
            let (amount, items) = w.split_last().expect("witness has an amount");
            let items: Vec<&str> = items.iter().map(|e| e.as_str().expect("witness item")).collect();
            if items.iter().any(|e| e.starts_with('#')) {
                return Outcome::Skip("taproot".into());
            }
            let items = items.iter().map(|e| hex(e).expect("hex witness item")).collect();
            let sats = (amount.as_f64().expect("amount") * 1e8).round() as u64;
            (items, Amount::from_sat(sats), 1)
        }
        _ => (Vec::new(), Amount::ZERO, 0),
    };
    if s(pos + 1).contains("#TAPROOTOUTPUT#") {
        return Outcome::Skip("taproot".into());
    }
    let flags = Flags::parse(s(pos + 2));
    if let Some(f) = flags.unsupported() {
        return Outcome::Skip(format!("flag {f}"));
    }
    let (sig, spk) = (parse_script(s(pos)), parse_script(s(pos + 1)));
    let want = s(pos + 3);
    let (tx, prevout) = txs(&spk, &sig, &witness, value);
    let ctx = Ctx { flags: &flags, opts: flags.options(), tx: &tx, prevout: &prevout };
    let got = match ctx.verify(&sig, &spk, &witness) {
        Ok(()) => "OK",
        Err(e) => e,
    };
    if got == want { Outcome::Pass } else { Outcome::Mismatch(format!("got {got}, want {want}")) }
}

#[test]
fn core_script_vectors() {
    let all: Vec<Value> = serde_json::from_str(include_str!("data/script_tests.json")).expect("valid JSON");
    let (mut total, mut passed, mut gaps) = (0, 0, 0);
    let mut skipped: BTreeMap<String, usize> = BTreeMap::new();
    let mut failures = Vec::new();
    for (idx, v) in all.iter().enumerate() {
        let v = v.as_array().expect("vector is an array");
        let pos = usize::from(v.first().is_some_and(Value::is_array));
        // single strings are comments
        if v.len() < 4 + pos {
            continue;
        }
        total += 1;
        let gap = KNOWN_GAPS.iter().any(|(i, _)| *i == idx);
        match run_vector(v) {
            Outcome::Skip(why) => *skipped.entry(why).or_default() += 1,
            Outcome::Pass if gap => failures.push(format!("#{idx} passes now: drop it from KNOWN_GAPS")),
            Outcome::Pass => passed += 1,
            Outcome::Mismatch(_) if gap => gaps += 1,
            Outcome::Mismatch(m) => {
                let comment = v.get(4 + pos).and_then(Value::as_str).unwrap_or("");
                failures.push(format!("#{idx} {m}: {} | {} | {} ({comment})", v[pos], v[pos + 1], v[pos + 2]));
            }
        }
    }
    let skip_total: usize = skipped.values().sum();
    println!("Core script vectors: {total} total, {} run, {passed} passed, {gaps} known gaps, {} failed, {skip_total} skipped", total - skip_total, failures.len());
    for (why, n) in &skipped {
        println!("  skipped {n}: {why}");
    }
    for f in &failures {
        println!("  FAIL {f}");
    }
    assert!(failures.is_empty(), "{} vectors disagree with Core", failures.len());
}
