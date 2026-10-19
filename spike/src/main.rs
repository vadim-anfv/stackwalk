mod consensus;
mod keys;
mod layout;
mod paths;
mod sat;
mod trace;

use std::str::FromStr;

use bitcoin_scriptexec::ExecCtx;
use miniscript::bitcoin::taproot::{LeafVersion, TapLeafHash};
use miniscript::bitcoin::{PublicKey, ScriptBuf, Sequence, absolute};
use miniscript::policy::Concrete;
use miniscript::{Descriptor, Miniscript, Segwitv0};

use keys::{KeyRing, NameTranslator};
use sat::{Have, Sat, dummy_tx};

fn have(signers: &[&str], preimages: &[&str], lie: bool) -> Have {
    Have {
        signers: signers.iter().map(|s| s.to_string()).collect(),
        preimages: preimages.iter().map(|s| s.to_string()).collect(),
        lie_about_older: lie,
    }
}

fn show_layout(ranges: &[layout::NodeRange], script: &ScriptBuf) {
    let instrs: Vec<String> = script.instructions().map(|i| format!("{:?}", i.unwrap())).collect();
    println!("  instructions:");
    for (i, s) in instrs.iter().enumerate() {
        println!("    #{i:<2} {s}");
    }
    println!("  node -> instruction range:");
    for r in ranges {
        println!(
            "    {:indent$}[{:>2}..{:>2}) {}{}",
            "",
            r.start,
            r.end,
            r.fragment,
            if r.merged_verify { "   (VERIFY merged into child's last op)" } else { "" },
            indent = r.depth * 2
        );
    }
}

fn wsh_demo(ring: &mut KeyRing, policy: &str, cases: &[(&str, Have, u32)]) {
    println!("\n================ WSH: {policy}");
    let pol = Concrete::<String>::from_str(policy).unwrap();
    let ms_s: Miniscript<String, Segwitv0> = pol.compile().unwrap();
    let desc_s = Descriptor::new_wsh(ms_s.clone()).unwrap();
    println!("miniscript : {ms_s}\ndescriptor : {desc_s}");

    // Q2: translate names -> real keys/hashes
    let desc: Descriptor<PublicKey> = desc_s.translate_pk(&mut NameTranslator(ring)).unwrap();
    let ms: Miniscript<PublicKey, Segwitv0> = ms_s.translate_pk(&mut NameTranslator(ring)).unwrap();
    let ws = desc.explicit_script().unwrap();
    assert_eq!(ws, ms.encode());
    println!("descriptor(pk): {desc}");
    println!("script_pubkey : {}", desc.script_pubkey().to_asm_string());
    println!("witnessScript : {}", ws.to_asm_string());
    let ranges = layout::layout(&ms, &ms_s);
    show_layout(&ranges, &ws);

    println!("  spend paths (auto, via build_template over asset subsets):");
    for (set, tmpl) in paths::enumerate(&ms) {
        let names: Vec<String> = set.iter().map(|a| paths::atom_label(ring, a)).collect();
        let t: Vec<String> = tmpl.iter().map(|p| paths::placeholder_label(ring, p)).collect();
        println!("    assets={names:?}  witness template={t:?}");
    }

    for (title, h, seq) in cases {
        println!("\n--- case: {title} (nSequence={seq})");
        let (tx, prevouts) = dummy_tx(&desc.script_pubkey(), Sequence(*seq), absolute::LockTime::ZERO);
        let sat = Sat::segwit_v0(ring, h, &tx, &ws);
        match desc.get_satisfaction(&sat) {
            Ok((witness, script_sig)) => {
                assert!(script_sig.is_empty());
                let pretty: Vec<String> = witness
                    .iter()
                    .map(|w| ring.label_of(w).map(str::to_string).unwrap_or_else(|| format!("{}B:{}", w.len(), keys::hex(w))))
                    .collect();
                println!("  witness ({} items, last = witnessScript): {pretty:?}", witness.len());
                // scriptexec takes the witness stack WITHOUT the witnessScript
                let stack = witness[..witness.len() - 1].to_vec();
                trace::run(ring, ExecCtx::SegwitV0, &ws, stack, &tx, &prevouts, None, &ranges);
                println!("  libbitcoinconsensus (Core 26): {:?}", consensus::verify(&tx, &witness, &prevouts));
            }
            Err(e) => println!("  get_satisfaction failed: {e}"),
        }
    }
}

fn tr_demo(ring: &mut KeyRing) {
    let d = "tr(NUMS,{pk(A),and_v(v:pk(B),older(144))})";
    println!("\n================ TR script path: {d}");
    let desc_s = Descriptor::<String>::from_str(d).unwrap();
    let desc: Descriptor<PublicKey> = desc_s.translate_pk(&mut NameTranslator(ring)).unwrap();
    println!("descriptor(pk): {desc}\nscript_pubkey : {}", desc.script_pubkey().to_asm_string());
    let Descriptor::Tr(tr) = &desc else { unreachable!() };
    let Descriptor::Tr(tr_s) = &desc_s else { unreachable!() };
    let leaves: Vec<(ScriptBuf, Miniscript<PublicKey, miniscript::Tap>, Miniscript<String, miniscript::Tap>)> = tr
        .leaves()
        .zip(tr_s.leaves())
        .map(|(l, ls)| (l.compute_script(), (**l.miniscript()).clone(), (**ls.miniscript()).clone()))
        .collect();
    for (title, h, seq) in [("A signs", have(&["A"], &[], false), 0xffff_fffd), ("B after 144", have(&["B"], &[], false), 144)] {
        println!("\n--- case: {title} (nSequence={seq})");
        let (tx, prevouts) = dummy_tx(&desc.script_pubkey(), Sequence(seq), absolute::LockTime::ZERO);
        let scripts: Vec<ScriptBuf> = leaves.iter().map(|(s, ..)| s.clone()).collect();
        let sat = Sat::tapscript(ring, &h, &tx, &prevouts, &scripts);
        let (witness, _) = desc.get_satisfaction(&sat).unwrap();
        let n = witness.len();
        let leaf_script = ScriptBuf::from_bytes(witness[n - 2].clone());
        println!("  witness: {} stack items + leaf script + control block ({}B)", n - 2, witness[n - 1].len());
        println!("  leaf script: {}", leaf_script.to_asm_string());
        let (_, ms, ms_named) = leaves.iter().find(|(s, ..)| *s == leaf_script).unwrap();
        let ranges = layout::layout(ms, ms_named);
        let lh = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);
        trace::run(ring, ExecCtx::Tapscript, &leaf_script, witness[..n - 2].to_vec(), &tx, &prevouts, Some(lh), &ranges);
        println!("  libbitcoinconsensus (Core 26): {:?}", consensus::verify(&tx, &witness, &prevouts));
        if seq == 144 {
            println!("--- negative: same witness, executed against tx with nSequence=145 (sighash differs)");
            let (tx2, _) = dummy_tx(&desc.script_pubkey(), Sequence(145), absolute::LockTime::ZERO);
            trace::run(ring, ExecCtx::Tapscript, &leaf_script, witness[..n - 2].to_vec(), &tx2, &prevouts, Some(lh), &ranges);
        }
    }
}

fn main() {
    let mut ring = KeyRing::new();
    wsh_demo(
        &mut ring,
        "or(pk(A),and(pk(B),older(144)))",
        &[
            ("A signs", have(&["A"], &[], false), 0xffff_fffd),
            ("B signs, older(144) satisfied", have(&["B"], &[], false), 144),
            ("B signs, sequence too low (honest satisfier)", have(&["B"], &[], false), 10),
            ("B signs, sequence too low, satisfier LIES about older", have(&["B"], &[], true), 10),
            ("B signs, wrong key path: B signs but A expected? (A and B both)", have(&["A", "B"], &[], false), 144),
        ],
    );
    wsh_demo(
        &mut ring,
        "or(and(pk(A),sha256(H)),and(pk(B),hash160(G)))",
        &[
            ("A + preimage(H)", have(&["A"], &["H"], false), 0xffff_fffd),
            ("B + preimage(G)", have(&["B"], &["G"], false), 0xffff_fffd),
        ],
    );
    tr_demo(&mut ring);
    negative(&mut ring);
    layout_coverage(&mut ring);
}

/// Q4: the layout walker asserts that per-node ranges add up for every wrapper/combinator.
fn layout_coverage(ring: &mut KeyRing) {
    println!("\n================ LAYOUT COVERAGE");
    for s in [
        "thresh(2,pk(A),s:pk(B),sln:older(10))",
        "or_i(and_v(v:pkh(A),hash256(H)),or_b(pk(B),a:pk(C)))",
        "andor(pk(A),and_v(or_c(pk(B),v:sha256(H)),pk(D)),and_b(pk(C),a:after(500)))",
        "or_d(multi(2,A,B,C),and_v(v:ripemd160(R),j:pk(D)))",
        "and_v(v:pk(A),c:pk_h(B))",
        "and_b(pk(A),adv:older(5))",
        "and_b(n:pk(A),s:pk(B))",
    ] {
        let ms_s = Miniscript::<String, Segwitv0>::from_str(s).unwrap();
        let ms: Miniscript<PublicKey, Segwitv0> = ms_s.translate_pk(&mut NameTranslator(ring)).unwrap();
        let ranges = layout::layout(&ms, &ms_s);
        let n = ms.encode().instructions().count();
        println!("  OK {s}: {n} instructions, {} nodes", ranges.len());
    }
}

/// Prove that scriptexec really verifies signatures, and check CHECKMULTISIG.
fn negative(ring: &mut KeyRing) {
    println!("\n================ NEGATIVE / LIMITS");
    let ms_s = Miniscript::<String, Segwitv0>::from_str("or_d(pk(A),and_v(v:pk(B),older(144)))").unwrap();
    let ms: Miniscript<PublicKey, Segwitv0> = ms_s.translate_pk(&mut NameTranslator(ring)).unwrap();
    let ws = ms.encode();
    let spk = ScriptBuf::new_p2wsh(&ws.wscript_hash());
    let ranges = layout::layout(&ms, &ms_s);

    // (a) signature made for a DIFFERENT tx (sequence changed after signing)
    let (tx_signed, _) = dummy_tx(&spk, Sequence(0xffff_fffd), absolute::LockTime::ZERO);
    let sat = Sat::segwit_v0(ring, &have(&["A"], &[], false), &tx_signed, &ws);
    let wit = ms.satisfy(&sat).unwrap();
    let (tx_other, prevouts) = dummy_tx(&spk, Sequence(0xffff_fffe), absolute::LockTime::ZERO);
    println!("--- (a) sig(A) over a different tx -> CHECKSIG must push 0");
    // NB: Miniscript::satisfy returns only the stack, no witnessScript
    trace::run(ring, ExecCtx::SegwitV0, &ws, wit, &tx_other, &prevouts, None, &ranges);

    // (b) multi(2,A,B) in wsh -> OP_CHECKMULTISIG
    let ms2_s = Miniscript::<String, Segwitv0>::from_str("multi(2,A,B)").unwrap();
    let ms2: Miniscript<PublicKey, Segwitv0> = ms2_s.translate_pk(&mut NameTranslator(ring)).unwrap();
    let ws2 = ms2.encode();
    let spk2 = ScriptBuf::new_p2wsh(&ws2.wscript_hash());
    let (tx2, prevouts2) = dummy_tx(&spk2, Sequence(0xffff_fffd), absolute::LockTime::ZERO);
    let sat2 = Sat::segwit_v0(ring, &have(&["A", "B"], &[], false), &tx2, &ws2);
    let wit2 = ms2.satisfy(&sat2).unwrap();
    let ranges2 = layout::layout(&ms2, &ms2_s);
    println!("--- (b) multi(2,A,B): {}", ws2.to_asm_string());
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        trace::run(ring, ExecCtx::SegwitV0, &ws2, wit2.clone(), &tx2, &prevouts2, None, &ranges2);
    }));
    println!("  catch_unwind result is_err (panicked) = {}", r.is_err());
    let mut full = wit2.clone();
    full.push(ws2.to_bytes());
    println!("  libbitcoinconsensus (Core 26) on same witness: {:?}", consensus::verify(&tx2, &full, &prevouts2));
}
