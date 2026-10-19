//! Request -> Scenario: parse input, build scripts, enumerate paths, sign, trace.
use std::str::FromStr;

use miniscript::bitcoin::{PublicKey, ScriptBuf, Sequence, absolute};
use miniscript::descriptor::{ShInner, WshInner, checksum};
use miniscript::policy::Concrete;
use miniscript::{BareCtx, Descriptor, DescriptorPublicKey, ForEachKey, Legacy, Miniscript, MiniscriptKey, ScriptContext, Segwitv0, Terminal};

use crate::keys::{KeyRing, NameTranslator};
use crate::model::{CompileReq, Ins, KeyAlias, PathInfo, Scenario, Trace};
use crate::real_keys;
use crate::paths::{self, PathSpec};
use crate::sat::{Sat, SigCtx, dummy_tx};
use crate::scriptexec::ExecCtx;
use crate::script_parse;
use crate::spend::{Field, spend_data};
use crate::trace::{Initial, NO_WITNESS, Runner, ins_list, script_text};
use crate::tree;

/// Keys, hashes and timelocks in a policy. The compiler is exponential in the size of an
/// or-chain: 10 conditions compile in about a second, 12 in several.
pub const MAX_POLICY_CONDITIONS: usize = 10;

/// Stack items over all steps of all paths: every step carries its whole stack, so a long
/// run of pushes grows the answer quadratically (800 pushes: 320 000 items, 18 MB).
pub const MAX_TRACE_ITEMS: usize = 30_000;

pub fn compile(req: &CompileReq) -> Result<Scenario, String> {
    // never echoed back, and never built into anything shown or linked
    if real_keys::has_private_key(&req.text) {
        return Err("this is a private key (WIF or xprv): it is never needed here, and should not be pasted into any website. Use the public key".into());
    }
    let mut text = req.text.trim();
    if req.kind == "script" {
        let sc = build(req, text)?;
        check_size(&sc)?;
        return Ok(sc);
    }
    if req.kind == "descriptor" {
        // a pasted checksum is verified against the text as typed (real keys included)
        text = checksum::verify_checksum(text).map_err(|e| match e {
            checksum::Error::InvalidChecksum { actual, expected } => format!(
                "checksum mismatch: got #{}, expected #{} (a typo in the descriptor?)",
                String::from_iter(actual),
                String::from_iter(expected)
            ),
            e => format!("descriptor: {e}"),
        })?;
    }
    // real keys are built as test keys under free names, and shown as themselves again
    let (aliased, aliases) = real_keys::alias(text)?;
    let mut sc = build(req, &aliased)?;
    check_size(&sc)?;
    // a descriptor that does not parse back (non-standard bare miniscript) is no wallet's either
    sc.importable = sc.descriptor.as_deref().and_then(|d| Descriptor::<String>::from_str(d).ok())
        .is_some_and(|d| d.for_each_key(|k| aliases.iter().any(|(name, _)| name == k)));
    for s in [&mut sc.policy, &mut sc.miniscript, &mut sc.descriptor].into_iter().flatten() {
        *s = real_keys::restore(s, &aliases);
    }
    // the run used (compressed) test keys: a real uncompressed key would have passed it, in an
    // output no node relays a spend of
    if matches!(sc.wrap, "wsh" | "wpkh")
        && let Some((_, key)) = aliases.iter().find(|(_, k)| DescriptorPublicKey::from_str(k).is_ok_and(|k| k.is_uncompressed()))
    {
        return Err(format!("uncompressed keys are not allowed in segwit ({}): {}", sc.wrap, real_keys::short(key)));
    }
    if let Some(d) = &sc.descriptor {
        let mut eng = checksum::Engine::new();
        eng.input(d).map_err(|e| format!("descriptor: {e}"))?;
        sc.checksum = Some(eng.checksum());
    }
    sc.keys = aliases.into_iter().map(|(name, key)| KeyAlias { name, key }).collect();
    Ok(sc)
}

fn check_size(sc: &Scenario) -> Result<(), String> {
    let items: usize = sc.traces.iter().flat_map(|t| &t.steps).map(|s| s.stack.len() + s.alt.len()).sum();
    if items > MAX_TRACE_ITEMS {
        return Err(format!("the run is too big to show: {items} stack items over all its steps (max {MAX_TRACE_ITEMS})"));
    }
    Ok(())
}

fn build(req: &CompileReq, text: &str) -> Result<Scenario, String> {
    let mut ring = KeyRing::new();
    match req.kind.as_str() {
        kind @ ("policy" | "miniscript") => match target(req.wrap.as_deref())? {
            Target::Ms(Wrap::Wsh) => build_in::<Segwitv0>(&mut ring, Wrap::Wsh, kind, text),
            Target::Ms(Wrap::Sh) => build_in::<Legacy>(&mut ring, Wrap::Sh, kind, text),
            Target::Ms(Wrap::Bare) => build_in::<BareCtx>(&mut ring, Wrap::Bare, kind, text),
            Target::Pkh { segwit } => {
                let key = if kind == "policy" {
                    match Concrete::<String>::from_str(text).map_err(|e| format!("policy: {e}"))? {
                        Concrete::Key(k) => Some(k),
                        _ => None,
                    }
                } else {
                    let ms = Miniscript::<String, Segwitv0>::from_str(text).map_err(|e| format!("miniscript: {e}"))?;
                    single_key(&ms).cloned()
                };
                let key = key.ok_or("pkh / wpkh take a single key, e.g. pk(A)")?;
                let mut sc = build_pkh(&mut ring, &key, segwit);
                if kind == "policy" {
                    sc.policy = Some(text.to_string());
                }
                Ok(sc)
            }
        },
        "descriptor" => descriptor(&mut ring, text),
        "script" => {
            let script = script_parse::parse(&mut ring, text)?;
            match script_parse::as_miniscript(&ring, &script) {
                Some(ms) => build_ms(&mut ring, Wrap::Wsh, &ms, None),
                None => Ok(build_raw(&mut ring, script)),
            }
        }
        k => Err(format!("unknown kind {k:?}: expected policy, miniscript, descriptor or script")),
    }
}

fn descriptor(ring: &mut KeyRing, text: &str) -> Result<Scenario, String> {
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("tr(") || lower.starts_with("rawtr(") {
        return Err("taproot is not supported yet".into());
    }
    let d = Descriptor::<String>::from_str(text).map_err(|e| format!("descriptor: {e}"))?;
    match d {
        Descriptor::Bare(b) => build_ms::<BareCtx>(ring, Wrap::Bare, b.as_inner(), None),
        Descriptor::Pkh(p) => Ok(build_pkh(ring, p.as_inner(), false)),
        Descriptor::Wpkh(w) => Ok(build_pkh(ring, w.as_inner(), true)),
        Descriptor::Sh(sh) => match sh.as_inner() {
            ShInner::Ms(ms) => build_ms::<Legacy>(ring, Wrap::Sh, ms, None),
            ShInner::Wsh(_) | ShInner::Wpkh(_) => Err("nested sh(wsh(...)) / sh(wpkh(...)) is not supported yet".into()),
            ShInner::SortedMulti(_) => Err("sortedmulti is not supported yet".into()),
        },
        Descriptor::Wsh(w) => match w.as_inner() {
            WshInner::Ms(ms) => build_ms(ring, Wrap::Wsh, ms, None),
            WshInner::SortedMulti(_) => Err("sortedmulti is not supported yet".into()),
        },
        Descriptor::Tr(_) => Err("taproot is not supported yet".into()),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Wrap {
    Bare,
    Sh,
    Wsh,
}

impl Wrap {
    fn name(self) -> &'static str {
        match self {
            Wrap::Bare => "bare",
            Wrap::Sh => "sh",
            Wrap::Wsh => "wsh",
        }
    }
}

/// Output type a policy / miniscript is built for (the request's `wrap`).
enum Target {
    Ms(Wrap),
    /// the pkh / wpkh templates: a single key, no miniscript of its own
    Pkh { segwit: bool },
}

fn target(wrap: Option<&str>) -> Result<Target, String> {
    match wrap.unwrap_or("wsh") {
        "bare" => Ok(Target::Ms(Wrap::Bare)),
        "sh" => Ok(Target::Ms(Wrap::Sh)),
        "wsh" => Ok(Target::Ms(Wrap::Wsh)),
        "pkh" => Ok(Target::Pkh { segwit: false }),
        "wpkh" => Ok(Target::Pkh { segwit: true }),
        "tr" => Err("taproot is not supported yet".into()),
        w => Err(format!("unknown wrap {w:?}: expected bare, sh, wsh, pkh, wpkh or tr")),
    }
}

/// Keys, hashes and timelocks of a policy, repeats included.
fn conditions(pol: &Concrete<String>) -> usize {
    use miniscript::iter::TreeLike;
    pol.pre_order_iter()
        .filter(|p| !matches!(p, Concrete::Unsatisfiable | Concrete::Trivial | Concrete::And(_) | Concrete::Or(_) | Concrete::Thresh(_)))
        .count()
}

/// Compile the policy, or parse the miniscript, in the script context of `wrap`.
fn build_in<Ctx: ScriptContext>(ring: &mut KeyRing, wrap: Wrap, kind: &str, text: &str) -> Result<Scenario, String> {
    let (ms, policy) = if kind == "policy" {
        let pol = Concrete::<String>::from_str(text).map_err(|e| format!("policy: {e}"))?;
        let n = conditions(&pol);
        if n > MAX_POLICY_CONDITIONS {
            return Err(format!(
                "too many conditions to compile here: {n} keys, hashes and timelocks (max {MAX_POLICY_CONDITIONS}); write it as miniscript instead"
            ));
        }
        let ms: Miniscript<String, Ctx> = pol.compile().map_err(|e| format!("compile: {e}"))?;
        // Display of Concrete shows weights (`1@pk(A)`), so echo the input text instead
        (ms, Some(text.split_whitespace().collect()))
    } else {
        (Miniscript::<String, Ctx>::from_str(text).map_err(|e| format!("miniscript: {e}"))?, None)
    };
    build_ms(ring, wrap, &ms, policy)
}

/// `pk(X)`
fn is_pk<Ctx: ScriptContext>(ms: &Miniscript<String, Ctx>) -> bool {
    matches!(ms.as_inner(), Terminal::Check(c) if matches!(c.as_inner(), Terminal::PkK(_)))
}

/// The key of `pk(X)` / `pkh(X)`.
fn single_key<Ctx: ScriptContext>(ms: &Miniscript<String, Ctx>) -> Option<&String> {
    match ms.as_inner() {
        Terminal::Check(c) => match c.as_inner() {
            Terminal::PkK(k) | Terminal::PkH(k) => Some(k),
            _ => None,
        },
        _ => None,
    }
}

/// One concrete attempt to spend.
#[derive(Clone)]
struct Spend {
    name: String,
    fails: bool,
    spec: PathSpec,
    sequence: Sequence,
    lock_time: absolute::LockTime,
    lie: bool,
    /// (victim, impostor): the victim's signature is made by the impostor key instead
    wrong: Option<(String, String)>,
    reverse_sigs: bool,
}

impl Spend {
    fn pass(spec: PathSpec) -> Self {
        let sequence = spec.older.map(Sequence).unwrap_or(Sequence::ENABLE_RBF_NO_LOCKTIME);
        let lock_time = spec.after.map(absolute::LockTime::from_consensus).unwrap_or(absolute::LockTime::ZERO);
        Spend { name: spec.name(), fails: false, spec, sequence, lock_time, lie: false, wrong: None, reverse_sigs: false }
    }

    fn variant(&self, suffix: &str) -> Self {
        let mut s = self.clone();
        s.name = format!("{}: {suffix}", self.name);
        s.fails = true;
        s
    }

    fn timelock_variant(&self) -> Option<Self> {
        if self.spec.older.is_none() && self.spec.after.is_none() {
            return None;
        }
        let mut s = self.variant("timelock not reached");
        if let Some(n) = self.spec.older {
            s.sequence = Sequence(n.saturating_sub(1));
        }
        if let Some(n) = self.spec.after {
            s.lock_time = absolute::LockTime::from_consensus(n.saturating_sub(1));
        }
        s.lie = true;
        Some(s)
    }

    /// The first signature is made by `impostor` instead.
    fn wrong_signer(&self, impostor: String) -> Option<Self> {
        let victim = self.spec.signers.first()?.clone();
        let mut s = self.variant("wrong signer");
        s.wrong = Some((victim, impostor));
        Some(s)
    }

    fn wrong_order(&self) -> Self {
        let mut s = self.variant("wrong order");
        s.reverse_sigs = true;
        s
    }
}

/// A key name not in `used`: X, Y, Z, W, V, then X0, X1, ...
fn fresh_name(used: &[String]) -> String {
    ["X", "Y", "Z", "W", "V"]
        .iter()
        .map(|s| s.to_string())
        .find(|n| !used.contains(n))
        .unwrap_or_else(|| (0..).map(|i| format!("X{i}")).find(|n| !used.contains(n)).unwrap())
}

/// For the pk / pkh / wpkh templates the other signer is "B" (or "A" if the key is B).
fn template_impostor(used: &[String]) -> String {
    ["B", "A", "C"].iter().map(|s| s.to_string()).find(|n| !used.contains(n)).unwrap_or_else(|| fresh_name(used))
}

/// Spends that should pass, each followed by its failing variants.
fn spend_variants<Ctx: ScriptContext>(named: &Miniscript<String, Ctx>, wrap: Wrap, passing: Vec<Spend>, policy_keys: &[String]) -> Vec<Spend> {
    let mut spends = Vec::new();
    if let Terminal::Multi(t) = named.as_inner() {
        // the paths differ only in who signs: one failing variant for all. Another key of a
        // 1-of-n would pass, so the impostor is outside the policy
        let bad = passing.first().and_then(|p| if t.k() >= 2 { Some(p.wrong_order()) } else { p.wrong_signer(fresh_name(policy_keys)) });
        spends.extend(passing);
        spends.extend(bad);
    } else if wrap == Wrap::Bare && is_pk(named) {
        let imp = template_impostor(policy_keys);
        for p in passing {
            let bad = p.wrong_signer(imp.clone()).map(|v| Spend { name: format!("{imp} tries"), ..v });
            spends.push(p);
            spends.extend(bad);
        }
    } else {
        for p in passing {
            let imp = policy_keys.iter().find(|k| !p.spec.signers.contains(k)).cloned().unwrap_or_else(|| fresh_name(policy_keys));
            let (late, bad) = (p.timelock_variant(), p.wrong_signer(imp));
            spends.push(p);
            spends.extend(late);
            spends.extend(bad);
        }
    }
    spends
}

/// P2WSH of `script`, both labeled for the items that show them.
fn wsh_spk(ring: &mut KeyRing, script: &ScriptBuf) -> ScriptBuf {
    ring.label(script.as_bytes(), "script", "witnessScript".into(), None);
    let spk = ScriptBuf::new_p2wsh(&script.wscript_hash());
    ring.label(&spk.as_bytes()[2..], "hash", "sha256(witnessScript)".into(), None);
    spk
}

impl Scenario {
    /// What every builder states; checksum, importable and keys are `compile`'s.
    fn new(wrap: &'static str, spk: String, script: Vec<Ins>, script_bytes: usize, paths: Vec<PathInfo>, traces: Vec<Trace>) -> Self {
        Scenario {
            policy: None,
            miniscript: None,
            descriptor: None,
            checksum: None,
            importable: false,
            wrap,
            outside_bip379: false,
            keys: Vec::new(),
            spk,
            about: None,
            tree: None,
            script,
            script_bytes,
            paths,
            traces,
        }
    }
}

/// Sign, satisfy and replace / reorder signatures for the variant. Returns the stack (bottom first).
fn witness<Ctx: ScriptContext>(
    ring: &mut KeyRing,
    ms: &Miniscript<PublicKey, Ctx>,
    sp: &Spend,
    sigctx: &SigCtx,
    tx: &miniscript::bitcoin::Transaction,
) -> Option<Vec<Vec<u8>>> {
    let msg = sigctx.message(tx);
    let mut sat = Sat::new(sp.sequence, sp.lock_time, sp.lie);
    for s in &sp.spec.signers {
        let sig = ring.sign(s, &msg);
        sat.ecdsa.insert(ring.pubkey(s), sig);
    }
    for h in &sp.spec.preimages {
        let p = ring.preimage(h);
        sat.add_preimage(p);
    }
    let mut stack = ms.satisfy(&sat).ok()?;
    let sig_bytes: Vec<Vec<u8>> = sat.ecdsa.values().map(|s| s.to_vec()).collect();
    if let Some((victim, impostor)) = &sp.wrong {
        let good = sat.ecdsa.get(&ring.pubkey(victim))?.to_vec();
        let bad = ring.sign(impostor, &msg).to_vec();
        let pos = stack.iter().position(|e| *e == good)?;
        stack[pos] = bad;
    }
    if sp.reverse_sigs {
        let idx: Vec<usize> = (0..stack.len()).filter(|i| sig_bytes.contains(&stack[*i])).collect();
        let vals: Vec<Vec<u8>> = idx.iter().rev().map(|i| stack[*i].clone()).collect();
        for (i, v) in idx.iter().zip(vals) {
            stack[*i] = v;
        }
    }
    Some(stack)
}

/// `pk(X)` as bare is the P2PK template, its paths named like pkh ("A signs", "B tries").
fn build_ms<Ctx: ScriptContext>(ring: &mut KeyRing, wrap: Wrap, named: &Miniscript<String, Ctx>, policy: Option<String>) -> Result<Scenario, String> {
    let ms: Miniscript<PublicKey, Ctx> =
        named.translate_pk(&mut NameTranslator(ring)).map_err(|e| format!("key translation: {e:?}"))?;
    let inner = ms.encode();
    let (spk, sigctx) = match wrap {
        Wrap::Wsh => (wsh_spk(ring, &inner), SigCtx::SegwitV0(inner.clone())),
        Wrap::Sh => {
            ring.label(inner.as_bytes(), "script", "redeemScript".into(), None);
            let spk = ScriptBuf::new_p2sh(&inner.script_hash());
            ring.label(&spk.as_bytes()[2..22], "hash", "hash160(redeemScript)".into(), None);
            (spk, SigCtx::Legacy(inner.clone()))
        }
        Wrap::Bare => (inner.clone(), SigCtx::Legacy(inner.clone())),
    };
    let mut ids = 0u64;
    let (script, offset): (Vec<Ins>, usize) = match wrap {
        Wrap::Wsh => (ins_list(ring, &inner, &mut ids), 0),
        Wrap::Bare => (ins_list(ring, &spk, &mut ids), 0),
        Wrap::Sh => {
            let mut v = ins_list(ring, &spk, &mut ids);
            v.push(Ins { op: "PHASE".into(), item: None, label: Some("redeemScript".into()) });
            let off = v.len();
            v.extend(ins_list(ring, &inner, &mut ids));
            (v, off)
        }
    };
    let node = tree::build(&ms, named, offset);
    let policy_keys: Vec<String> = {
        let mut v: Vec<String> = Vec::new();
        for k in named.iter_pk() {
            if !v.contains(&k) {
                v.push(k);
            }
        }
        v
    };

    // paths
    let sets = paths::enumerate(&ms)?;
    let mut specs: Vec<PathSpec> = sets.iter().map(|s| PathSpec::from_atoms(ring, s)).collect();
    // smallest first, then by key order of the policy
    let rank = |n: &String| policy_keys.iter().position(|k| k == n).unwrap_or(usize::MAX);
    specs.sort_by_key(|p| {
        (p.signers.len() + p.preimages.len() + p.older.is_some() as usize + p.after.is_some() as usize, p.signers.iter().map(rank).collect::<Vec<_>>())
    });
    let spends = spend_variants(named, wrap, specs.into_iter().map(Spend::pass).collect(), &policy_keys);

    let mut path_infos = Vec::new();
    let mut traces = Vec::new();
    for sp in &spends {
        let (tx, prevouts) = dummy_tx(&spk, sp.sequence, sp.lock_time);
        let Some(stack) = witness(ring, &ms, sp, &sigctx, &tx) else { continue };
        // as sent: the witnessScript / redeemScript follows the stack items
        let with_script = || stack.iter().cloned().chain([inner.to_bytes()]).collect::<Vec<_>>();
        let spend = match wrap {
            Wrap::Wsh => spend_data(ring, Field::Witness, &with_script(), true),
            Wrap::Sh => spend_data(ring, Field::ScriptSig, &with_script(), true),
            Wrap::Bare => spend_data(ring, Field::ScriptSig, &stack, false),
        };
        let runner = Runner::new(ring, &script, tx, prevouts);
        let trace: Trace = match wrap {
            Wrap::Wsh => runner.run_simple(ExecCtx::SegwitV0, &inner, stack, Initial::WitnessBody),
            Wrap::Bare => runner.run_simple(ExecCtx::Legacy, &spk, stack, Initial::ScriptSig),
            Wrap::Sh => runner.run_p2sh(&spk, &inner, with_script(), offset - 1),
        };
        // a "failing" variant that actually passes is not a useful example: drop it
        if sp.fails && trace.result.ok {
            continue;
        }
        path_infos.push(PathInfo { name: sp.name.clone(), fails: sp.fails, spend });
        traces.push(trace);
    }

    let ms_text = named.to_string();
    let descriptor = match wrap {
        Wrap::Bare => ms_text.clone(),
        Wrap::Sh => format!("sh({ms_text})"),
        Wrap::Wsh => format!("wsh({ms_text})"),
    };
    Ok(Scenario {
        policy,
        miniscript: Some(ms_text),
        descriptor: Some(descriptor),
        // BIP-379 excludes P2SH and bare; pk() (BIP-381) and multi() (BIP-383) are plain descriptors there
        outside_bip379: wrap != Wrap::Wsh && !(is_pk(named) || matches!(named.as_inner(), Terminal::Multi(_))),
        tree: Some(node),
        ..Scenario::new(wrap.name(), script_text(ring, &spk), script, inner.len(), path_infos, traces)
    })
}

fn build_pkh(ring: &mut KeyRing, name: &str, segwit: bool) -> Scenario {
    let pk = ring.pubkey(name);
    let p2pkh = ScriptBuf::new_p2pkh(&pk.pubkey_hash());
    let spk = if segwit { ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().expect("compressed")) } else { p2pkh.clone() };
    let sigctx = if segwit { SigCtx::SegwitV0(p2pkh.clone()) } else { SigCtx::Legacy(p2pkh.clone()) };
    let mut ids = 0u64;
    let script = ins_list(ring, &p2pkh, &mut ids);
    let other = template_impostor(&[name.to_string()]);
    let mut path_infos = Vec::new();
    let mut traces = Vec::new();
    for (pname, signer, fails) in [(format!("{name} signs"), name.to_string(), false), (format!("{other} tries"), other.clone(), true)] {
        let (tx, prevouts) = dummy_tx(&spk, Sequence::ENABLE_RBF_NO_LOCKTIME, absolute::LockTime::ZERO);
        let msg = sigctx.message(&tx);
        let sig = ring.sign(&signer, &msg).to_vec();
        let stack = vec![sig, pk.to_bytes()];
        let spend = spend_data(ring, if segwit { Field::Witness } else { Field::ScriptSig }, &stack, false);
        let runner = Runner::new(ring, &script, tx, prevouts);
        let trace = if segwit {
            runner.run_simple(ExecCtx::SegwitV0, &p2pkh, stack, Initial::Witness)
        } else {
            runner.run_simple(ExecCtx::Legacy, &p2pkh, stack, Initial::ScriptSig)
        };
        path_infos.push(PathInfo { name: pname, fails, spend });
        traces.push(trace);
    }
    let wrap = if segwit { "wpkh" } else { "pkh" };
    Scenario {
        descriptor: Some(format!("{wrap}({name})")),
        // the script code that runs is the P2PKH template, also for wpkh
        ..Scenario::new(wrap, script_text(ring, &spk), script, p2pkh.len(), path_infos, traces)
    }
}

fn build_raw(ring: &mut KeyRing, script_buf: ScriptBuf) -> Scenario {
    let spk = wsh_spk(ring, &script_buf);
    let mut ids = 0u64;
    let script = ins_list(ring, &script_buf, &mut ids);
    let (tx, prevouts) = dummy_tx(&spk, Sequence::ENABLE_RBF_NO_LOCKTIME, absolute::LockTime::ZERO);
    let trace = Runner::new(ring, &script, tx, prevouts).run_simple(ExecCtx::SegwitV0, &script_buf, vec![], Initial::Empty);
    let spend = spend_data(ring, Field::Witness, &[script_buf.to_bytes()], true);
    let path = PathInfo { name: "empty witness".into(), fails: false, spend };
    Scenario { about: Some(NO_WITNESS.into()), ..Scenario::new("wsh", script_text(ring, &spk), script, script_buf.len(), vec![path], vec![trace]) }
}

#[cfg(test)]
#[path = "scenario_tests.rs"]
mod tests;
