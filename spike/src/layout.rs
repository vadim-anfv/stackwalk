//! Q4: map each miniscript AST node to the range of instruction indices it emits.
//! Mirrors the order in `Terminal::encode` (miniscript 13.2 astelem.rs).
use miniscript::bitcoin::PublicKey;
use miniscript::miniscript::decode::Terminal;
use miniscript::{Miniscript, ScriptContext};

#[derive(Debug, Clone)]
pub struct NodeRange {
    pub depth: usize,
    /// instruction indices [start, end)
    pub start: usize,
    pub end: usize,
    pub fragment: String,
    /// for `v:` wrappers whose VERIFY got merged into the child's last opcode
    pub merged_verify: bool,
}

enum Seg {
    Own(usize),
    Child(usize),
}

fn n_instr<Ctx: ScriptContext>(ms: &Miniscript<PublicKey, Ctx>) -> usize {
    ms.encode().instructions().count()
}

/// `named` is the same tree with String keys (pre-translation), used for display.
pub fn layout<Ctx: ScriptContext>(ms: &Miniscript<PublicKey, Ctx>, named: &Miniscript<String, Ctx>) -> Vec<NodeRange> {
    let mut out = Vec::new();
    walk(ms, named, 0, 0, &mut out);
    out
}

fn walk<Ctx: ScriptContext>(
    ms: &Miniscript<PublicKey, Ctx>,
    named: &Miniscript<String, Ctx>,
    start: usize,
    depth: usize,
    out: &mut Vec<NodeRange>,
) -> usize {
    use Seg::*;
    let total = n_instr(ms);
    let kids = ms.branches();
    let named_kids = named.branches();
    let segs: Vec<Seg> = match ms.as_inner() {
        Terminal::Alt(_) => vec![Own(1), Child(0), Own(1)],
        Terminal::Swap(_) => vec![Own(1), Child(0)],
        Terminal::Check(_) | Terminal::ZeroNotEqual(_) => vec![Child(0), Own(1)],
        Terminal::DupIf(_) => vec![Own(2), Child(0), Own(1)],
        Terminal::NonZero(_) => vec![Own(3), Child(0), Own(1)],
        // VERIFY may be merged into child's last op (CHECKSIG -> CHECKSIGVERIFY etc.)
        Terminal::Verify(c) => vec![Child(0), Own(total - n_instr(c))],
        Terminal::AndV(..) => vec![Child(0), Child(1)],
        Terminal::AndB(..) | Terminal::OrB(..) => vec![Child(0), Child(1), Own(1)],
        Terminal::AndOr(..) => vec![Child(0), Own(1), Child(2), Own(1), Child(1), Own(1)],
        Terminal::OrD(..) => vec![Child(0), Own(2), Child(1), Own(1)],
        Terminal::OrC(..) => vec![Child(0), Own(1), Child(1), Own(1)],
        Terminal::OrI(..) => vec![Own(1), Child(0), Own(1), Child(1), Own(1)],
        Terminal::Thresh(t) => {
            let mut v = vec![Child(0)];
            for i in 1..t.n() {
                v.push(Child(i));
                v.push(Own(1));
            }
            v.push(Own(2));
            v
        }
        _ => vec![Own(total)], // leaves
    };
    let idx = out.len();
    out.push(NodeRange {
        depth,
        start,
        end: start + total,
        fragment: named.to_string(),
        merged_verify: matches!(ms.as_inner(), Terminal::Verify(c) if total == n_instr(c)),
    });
    let mut pos = start;
    for s in segs {
        pos += match s {
            Own(n) => n,
            Child(i) => walk(kids[i], named_kids[i], pos, depth + 1, out),
        };
    }
    assert_eq!(pos, start + total, "layout mismatch for {}", out[idx].fragment);
    total
}

/// innermost node containing instruction `i`
pub fn innermost(ranges: &[NodeRange], i: usize) -> Option<&NodeRange> {
    ranges.iter().filter(|r| r.start <= i && i < r.end).max_by_key(|r| r.depth)
}
