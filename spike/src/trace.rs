//! Q5: step-by-step execution with bitcoin-scriptexec, printing stacks with semantic labels.
use bitcoin_scriptexec::{Exec, ExecCtx, Options, Stack, TxTemplate};
use miniscript::bitcoin::opcodes::all::{OP_ELSE, OP_ENDIF, OP_IF, OP_NOTIF};
use miniscript::bitcoin::script::Instruction;
use miniscript::bitcoin::taproot::TapLeafHash;
use miniscript::bitcoin::{ScriptBuf, Transaction, TxOut};

use crate::keys::{KeyRing, hex};
use crate::layout::{NodeRange, innermost};

fn render(ring: &KeyRing, st: &Stack) -> String {
    let items: Vec<String> = st
        .iter_str()
        .map(|b| match ring.label_of(&b) {
            Some(l) => l.to_string(),
            None if b.is_empty() => "<>".into(),
            None if b.len() <= 4 => format!("0x{}", hex(&b)),
            None => format!("{}..({}B)", &hex(&b)[..8], b.len()),
        })
        .collect();
    format!("[{}]", items.join(", "))
}

pub fn run(
    ring: &KeyRing,
    ctx: ExecCtx,
    script: &ScriptBuf,
    witness_stack: Vec<Vec<u8>>,
    tx: &Transaction,
    prevouts: &[TxOut],
    leaf: Option<TapLeafHash>,
    ranges: &[NodeRange],
) {
    let tmpl = TxTemplate {
        tx: tx.clone(),
        prevouts: prevouts.to_vec(),
        input_idx: 0,
        taproot_annex_scriptleaf: leaf.map(|l| (l, None)),
    };
    // byte offset -> (instruction index, instruction text)
    let instrs: Vec<(usize, String, bool)> = script
        .instruction_indices()
        .map(|r| {
            let (pos, ins) = r.unwrap();
            let (txt, is_cond) = match ins {
                Instruction::Op(op) => (format!("{op:?}"), [OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF].contains(&op)),
                Instruction::PushBytes(p) => {
                    let b = p.as_bytes();
                    (format!("PUSH {}", ring.label_of(b).map(str::to_string).unwrap_or_else(|| format!("0x{}", hex(b)))), false)
                }
            };
            (pos, txt, is_cond)
        })
        .collect();

    let mut exec = Exec::new(ctx, Options::default(), tmpl, script.clone(), witness_stack).expect("exec init");
    println!("  init  stack={}", render(ring, exec.stack()));
    loop {
        let pos = exec.script_position();
        let executing = exec.cond_stack().all_true();
        let idx = instrs.iter().position(|(p, ..)| *p == pos);
        match exec.exec_next() {
            Ok(()) => {
                let i = idx.unwrap();
                let (_, txt, is_cond) = &instrs[i];
                let mark = if executing { "  " } else if *is_cond { "c " } else { "SKIP" };
                let frag = innermost(ranges, i).map(|r| r.fragment.as_str()).unwrap_or("-");
                println!(
                    "  #{i:<2} {mark:4} {txt:<28} main={} alt={}   <- {frag}",
                    render(ring, exec.stack()),
                    render(ring, exec.altstack())
                );
            }
            Err(res) => {
                if let (Some(i), false) = (idx, res.success) {
                    println!("  #{i:<2} FAIL {}", instrs[i].1);
                }
                println!(
                    "  RESULT success={} error={:?} opcode={:?} final_stack={}",
                    res.success,
                    res.error,
                    res.opcode,
                    render(ring, &res.final_stack)
                );
                break;
            }
        }
    }
}
