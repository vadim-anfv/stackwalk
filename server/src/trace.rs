//! Script -> `Ins` list / text, and step-by-step execution into a `Trace`.
use miniscript::bitcoin::opcodes::all::*;
use miniscript::bitcoin::opcodes::Opcode;
use miniscript::bitcoin::relative;
use miniscript::bitcoin::script::Instruction;
use miniscript::bitcoin::{ScriptBuf, Transaction, TxOut};

use crate::keys::KeyRing;
use crate::model::{Ins, Item, Step, Trace, TraceResult};
use crate::scriptexec::{Entry, Exec, ExecCtx, ExecError, IdGen, Options, Stack, TxTemplate, read_scriptint};

pub fn op_name(op: Opcode) -> String {
    match op {
        OP_CSV => "OP_CHECKSEQUENCEVERIFY".into(),
        OP_CLTV => "OP_CHECKLOCKTIMEVERIFY".into(),
        _ => op.to_string(),
    }
}

/// Small-number opcodes are pushes: OP_1NEGATE, OP_1..OP_16.
fn pushnum(op: Opcode) -> Option<i64> {
    let b = op.to_u8();
    if b == OP_PUSHNUM_NEG1.to_u8() {
        Some(-1)
    } else if (OP_PUSHNUM_1.to_u8()..=OP_PUSHNUM_16.to_u8()).contains(&b) {
        Some((b - OP_PUSHNUM_1.to_u8() + 1) as i64)
    } else {
        None
    }
}

fn num_bytes(n: i64) -> Vec<u8> {
    crate::scriptexec::scriptint_vec(n)
}

pub fn ins_list(ring: &KeyRing, script: &ScriptBuf, ids: &mut u64) -> Vec<Ins> {
    let mut out = Vec::new();
    for ins in script.instructions() {
        let mut next = || {
            *ids += 1;
            *ids - 1
        };
        match ins {
            Ok(Instruction::PushBytes(p)) => {
                out.push(Ins { op: "PUSH".into(), item: Some(ring.item(next(), p.as_bytes())), label: None })
            }
            Ok(Instruction::Op(op)) => match pushnum(op) {
                Some(n) => out.push(Ins { op: "PUSH".into(), item: Some(ring.item(next(), &num_bytes(n))), label: None }),
                None => out.push(Ins { op: op_name(op), item: None, label: None }),
            },
            Err(_) => out.push(Ins { op: "INVALID".into(), item: None, label: None }),
        }
    }
    out
}

pub fn ins_text(i: &Ins) -> String {
    match &i.item {
        Some(it) if it.kind == "num" && matches!(it.value, Some(0..=16)) => format!("OP_{}", it.value.unwrap()),
        Some(it) => format!("<{}>", it.label),
        None => i.op.clone(),
    }
}

pub fn script_text(ring: &KeyRing, script: &ScriptBuf) -> String {
    let mut ids = 0;
    ins_list(ring, script, &mut ids).iter().map(ins_text).collect::<Vec<_>>().join(" ")
}

fn err_text(e: &ExecError, op: Option<Opcode>) -> String {
    use ExecError::*;
    match e {
        CheckSigVerify => "signature check failed".into(),
        CheckMultiSigVerify => "multisig check failed".into(),
        NullFail => "signature check failed (NULLFAIL: a failing signature must be empty)".into(),
        NullDummy => "the CHECKMULTISIG dummy element must be empty (NULLDUMMY)".into(),
        EqualVerify => "values are not equal".into(),
        NumEqualVerify => "numbers are not equal".into(),
        Verify => "top of the stack is false".into(),
        UnsatisfiedLocktime if op == Some(OP_CSV) => "relative timelock not reached".into(),
        UnsatisfiedLocktime => "absolute timelock not reached".into(),
        NegativeLocktime => "negative locktime".into(),
        InvalidStackOperation => "not enough elements on the stack".into(),
        UnbalancedConditional => "unbalanced IF / ELSE / ENDIF".into(),
        TapscriptMinimalIf => "IF argument must be empty or exactly 0x01 (MINIMALIF)".into(),
        OpReturn => "OP_RETURN always fails".into(),
        DisabledOpcode => "disabled opcode".into(),
        BadOpcode => "bad opcode".into(),
        MinimalData => "non-minimal number encoding".into(),
        PubkeyCount => "bad public key count".into(),
        SigCount => "bad signature count".into(),
        WitnessPubkeyType => "uncompressed public key in segwit".into(),
        OpCount => "too many opcodes".into(),
        StackSize => "stack too large".into(),
        PushSize => "push too large".into(),
        ScriptIntNumericOverflow => "number out of range".into(),
        other => format!("{other:?}"),
    }
}

pub struct Runner<'a> {
    pub ring: &'a KeyRing,
    pub ins: &'a [Ins],
    pub tx: Transaction,
    pub prevouts: Vec<TxOut>,
    steps: Vec<Step>,
    prev_main: Vec<Item>,
    prev_alt: Vec<Item>,
    /// opcode count toward the 201 limit, the larger of the phases
    ops: usize,
}

enum Phase {
    Done,
    Failed(String),
}

/// Where the initial stack comes from, for the note of step 0.
#[derive(Clone, Copy)]
pub enum Initial {
    /// legacy: the result of running the scriptSig (push-only here)
    ScriptSig,
    /// P2WPKH: the witness items as they are
    Witness,
    /// P2WSH: the last witness item is the witnessScript, it is run, not pushed
    WitnessBody,
    /// a bare script: no transaction, no spending data
    Empty,
}

impl Initial {
    fn note(self, labels: &[String]) -> String {
        let src = match self {
            Self::ScriptSig => "scriptSig",
            Self::Witness => "witness",
            Self::WitnessBody => "witness without its last item (witnessScript)",
            Self::Empty => return "Initial stack: empty".into(),
        };
        format!("Initial stack = {src}: [{}]", labels.join(", "))
    }
}

impl<'a> Runner<'a> {
    pub fn new(ring: &'a KeyRing, ins: &'a [Ins], tx: Transaction, prevouts: Vec<TxOut>) -> Self {
        Runner { ring, ins, tx, prevouts, steps: Vec::new(), prev_main: Vec::new(), prev_alt: Vec::new(), ops: 0 }
    }

    fn items(&self, s: &[Entry]) -> Vec<Item> {
        s.iter().map(|e| self.ring.item(e.id, &e.data)).collect()
    }

    fn push_step(&mut self, pc: i64, main: &[Entry], alt: &[Entry], executed: bool, note: String, error: Option<String>) {
        let stack = self.items(main);
        let alt = self.items(alt);
        let common = self.prev_main.iter().zip(&stack).take_while(|(a, b)| a.id == b.id).count();
        let mut popped: Vec<Item> = self.prev_main[common..].to_vec();
        popped.reverse();
        let pushed = stack[common..].to_vec();
        let to_alt = alt.last().filter(|a| !self.prev_alt.iter().any(|p| p.id == a.id)).cloned();
        self.steps.push(Step { pc, stack: stack.clone(), alt: alt.clone(), popped, pushed, executed, note, error, to_alt });
        self.prev_main = stack;
        self.prev_alt = alt;
    }

    fn initial(&mut self, entries: &[Entry], from: Initial) {
        let labels: Vec<String> = entries.iter().map(|e| self.ring.text(&e.data)).collect();
        let note = from.note(&labels);
        self.push_step(-1, entries, &[], true, note, None);
    }

    fn finish(self, res: Result<(), String>) -> Trace {
        let result = match res {
            Ok(()) => TraceResult { ok: true, message: "valid spend".into() },
            Err(m) => TraceResult { ok: false, message: m },
        };
        Trace { steps: self.steps, result, ops: self.ops }
    }

    /// One script run as legacy / segwit v0 with `initial` (bottom first) as the stack.
    pub fn run_simple(mut self, ctx: ExecCtx, script: &ScriptBuf, initial: Vec<Vec<u8>>, from: Initial) -> Trace {
        let ids = IdGen::new(self.ins.len() as u64);
        let entries: Vec<Entry> = initial.into_iter().map(|data| Entry { id: ids.next(), data }).collect();
        self.initial(&entries, from);
        let res = match self.run_phase(ctx, script, Stack::from_entries(entries, ids), 0) {
            Phase::Done => Ok(()),
            Phase::Failed(m) => Err(m),
        };
        self.finish(res)
    }

    /// P2SH: scriptSig pushes (last = redeemScript), spk phase, PHASE step, redeemScript phase.
    pub fn run_p2sh(mut self, spk: &ScriptBuf, rs: &ScriptBuf, initial: Vec<Vec<u8>>, phase_pc: usize) -> Trace {
        let ids = IdGen::new(self.ins.len() as u64);
        let entries: Vec<Entry> = initial.into_iter().map(|data| Entry { id: ids.next(), data }).collect();
        self.initial(&entries, Initial::ScriptSig);
        if let Phase::Failed(m) = self.run_phase(ExecCtx::Legacy, spk, Stack::from_entries(entries.clone(), ids.clone()), 0) {
            return self.finish(Err(m));
        }
        let rest = entries[..entries.len() - 1].to_vec();
        let note = "redeemScript matches the hash: it now runs on the remaining stack".to_string();
        self.push_step(phase_pc as i64, &rest, &[], true, note, None);
        let res = match self.run_phase(ExecCtx::Legacy, rs, Stack::from_entries(rest, ids), phase_pc + 1) {
            Phase::Done => Ok(()),
            Phase::Failed(m) => Err(m),
        };
        self.finish(res)
    }

    fn run_phase(&mut self, ctx: ExecCtx, script: &ScriptBuf, stack: Stack, offset: usize) -> Phase {
        let positions: Vec<(usize, Option<Opcode>)> = script
            .instruction_indices()
            .filter_map(|r| r.ok())
            .map(|(p, i)| (p, if let Instruction::Op(op) = i { Some(op) } else { None }))
            .collect();
        let tmpl = TxTemplate { tx: self.tx.clone(), prevouts: self.prevouts.clone(), input_idx: 0, taproot_annex_scriptleaf: None };
        let mut exec = match Exec::new(ctx, Options::default(), tmpl, script.clone(), stack) {
            Ok(e) => e,
            Err(e) => return Phase::Failed(format!("invalid script: {e:?}")),
        };
        loop {
            let pos = exec.script_position();
            let idx = positions.iter().position(|(p, _)| *p == pos);
            let before = exec.cond_stack().all_true();
            let prev: Vec<Entry> = exec.stack().items().to_vec();
            let res = exec.exec_next().err().cloned();
            self.ops = self.ops.max(exec.opcode_count());
            let after = exec.cond_stack().all_true();
            let op = idx.and_then(|i| positions[i].1);
            let executed = match op {
                Some(OP_ELSE) | Some(OP_ENDIF) => before || after,
                _ => before,
            };
            match (idx, res) {
                (Some(i), None) => {
                    let note = self.note(op, executed, &prev, &exec, None);
                    let (m, a) = (exec.stack().items().to_vec(), exec.altstack().items().to_vec());
                    self.push_step((offset + i) as i64, &m, &a, executed, note, None);
                }
                (Some(i), Some(r)) => {
                    let pc = offset + i;
                    let err = r.error.as_ref().map(|e| err_text(e, op)).unwrap_or_else(|| "failed".into());
                    let opname = crate::trace::ins_text(&self.ins[pc]);
                    let note = self.note(op, executed, &prev, &exec, r.error.as_ref());
                    let (m, a) = (exec.stack().items().to_vec(), exec.altstack().items().to_vec());
                    self.push_step(pc as i64, &m, &a, executed, note, Some(format!("{opname}: {err}")));
                    return Phase::Failed(format!("fails at #{pc} {opname}: {err}"));
                }
                (None, Some(r)) => {
                    if let Some(e) = &r.error {
                        return Phase::Failed(format!("fails at the end of the script: {}", err_text(e, None)));
                    }
                    if r.success {
                        return Phase::Done;
                    }
                    let st = exec.stack().items();
                    let msg = match ctx {
                        ExecCtx::Legacy if st.is_empty() => "fails: the final stack is empty".to_string(),
                        ExecCtx::Legacy => "fails: the top of the final stack is false".to_string(),
                        _ if st.len() != 1 => format!(
                            "fails: clean stack rule, the final stack must be exactly one true element but it has {} elements",
                            st.len()
                        ),
                        _ => "fails: the final stack element is false".to_string(),
                    };
                    return Phase::Failed(msg);
                }
                (None, None) => return Phase::Failed("internal error: engine stepped past the script".into()),
            }
        }
    }

    fn note(&self, op: Option<Opcode>, executed: bool, prev: &[Entry], exec: &Exec, err: Option<&ExecError>) -> String {
        if !executed {
            return "Skipped: inside a branch that is not taken.".into();
        }
        let Some(op) = op else { return String::new() };
        let t = |k: usize| prev.len().checked_sub(k).map(|i| self.ring.text(&prev[i].data)).unwrap_or_else(|| "?".into());
        let top_true = prev.last().map(|e| miniscript::bitcoin::script::read_scriptbool(&e.data)).unwrap_or(false);
        let num = |k: usize| prev.len().checked_sub(k).and_then(|i| read_scriptint(&prev[i].data, 5, false).ok());
        match op {
            OP_CHECKSIG | OP_CHECKSIGVERIFY | OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                let parts: Vec<String> = exec
                    .last_checks
                    .iter()
                    .map(|c| {
                        let pk = self.ring.text(&c.pk);
                        if c.sig.is_empty() {
                            format!("empty signature for {pk}")
                        } else if c.ok {
                            format!("{} is valid for {pk}", self.ring.text(&c.sig))
                        } else {
                            format!("{} does not match {pk}", self.ring.text(&c.sig))
                        }
                    })
                    .collect();
                if parts.is_empty() && matches!(op, OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY) && err.is_none() {
                    "no signatures required".into()
                } else {
                    parts.join("; ")
                }
            }
            OP_EQUAL | OP_EQUALVERIFY => {
                let eq = prev.len() >= 2 && prev[prev.len() - 1].data == prev[prev.len() - 2].data;
                format!("{} {} {}", t(2), if eq { "==" } else { "!=" }, t(1))
            }
            OP_NUMEQUAL | OP_NUMEQUALVERIFY => {
                let eq = num(2).is_some() && num(2) == num(1);
                format!("{} {} {}", t(2), if eq { "==" } else { "!=" }, t(1))
            }
            OP_VERIFY => if top_true { "top is true: continue" } else { "top is false: fail" }.into(),
            OP_IF => if top_true { "top is true: run the IF branch" } else { "top is false: skip to ELSE" }.into(),
            OP_NOTIF => if top_true { "top is true: skip to ELSE" } else { "top is false: run the NOTIF branch" }.into(),
            OP_ELSE => "switch to the other branch".into(),
            OP_ENDIF => "end of the IF block".into(),
            OP_IFDUP => if top_true { "top is true: duplicate it" } else { "top is false: no copy" }.into(),
            OP_SIZE => format!("size of {} is {} bytes", t(1), prev.last().map(|e| e.data.len()).unwrap_or(0)),
            OP_HASH160 | OP_HASH256 | OP_SHA256 | OP_RIPEMD160 | OP_SHA1 => {
                format!("{} of {}", op_name(op).trim_start_matches("OP_").to_lowercase(), t(1))
            }
            OP_TOALTSTACK => format!("move {} to the alt stack", t(1)),
            OP_FROMALTSTACK => "move the top of the alt stack back".into(),
            OP_CSV => {
                let n = num(1).unwrap_or(0);
                let seq = self.tx.input[0].sequence;
                let req = relative::LockTime::from_consensus(n as u32).ok();
                match (seq.to_relative_lock_time(), req) {
                    (_, _) if n & (1 << 31) != 0 => "disable flag set: CSV acts as a NOP".into(),
                    (None, _) => "input nSequence disables relative timelocks".into(),
                    (Some(have), Some(want)) => {
                        let rel = if err.is_none() { ">=" } else { "<" };
                        format!("input age {} {rel} {}", rel_text(have, false), rel_text(want, true))
                    }
                    _ => String::new(),
                }
            }
            OP_CLTV => {
                let n = num(1).unwrap_or(0);
                let lt = self.tx.lock_time.to_consensus_u32();
                let rel = if err.is_none() { ">=" } else { "<" };
                format!("tx locktime {lt} {rel} {n}")
            }
            _ => String::new(),
        }
    }
}

fn rel_text(l: relative::LockTime, unit: bool) -> String {
    match l {
        relative::LockTime::Blocks(h) if unit => format!("{} blocks", h.value()),
        relative::LockTime::Blocks(h) => h.value().to_string(),
        relative::LockTime::Time(t) if unit => format!("{} x 512 seconds", t.value()),
        relative::LockTime::Time(t) => t.value().to_string(),
    }
}
