//! Miniscript AST -> UI `Node` tree. Mirrors miniscript 13.2 `Display` (display.rs) for the
//! text split and `Terminal::encode` (astelem.rs) for the instruction layout.
use miniscript::bitcoin::PublicKey;
use miniscript::miniscript::decode::Terminal;
use miniscript::{Miniscript, ScriptContext};

use crate::model::Node;

enum Seg {
    Own(usize),
    Child(usize),
}

fn n_instr<Ctx: ScriptContext>(ms: &Miniscript<PublicKey, Ctx>) -> usize {
    ms.encode().instructions().count()
}

/// Display-level classification of a node.
enum Shape {
    Leaf,
    /// wrapper letter and index of the displayed child in `branches()`
    Wrap(&'static str, usize),
    /// head name and displayed child indices
    Head(&'static str, Vec<usize>),
}

fn shape<Pk: miniscript::MiniscriptKey, Ctx: ScriptContext>(t: &Terminal<Pk, Ctx>) -> Shape {
    use Terminal::*;
    match t {
        Check(sub) if matches!(sub.as_inner(), PkK(_) | PkH(_) | RawPkH(_)) => Shape::Leaf,
        Alt(_) => Shape::Wrap("a", 0),
        Swap(_) => Shape::Wrap("s", 0),
        Check(_) => Shape::Wrap("c", 0),
        DupIf(_) => Shape::Wrap("d", 0),
        Verify(_) => Shape::Wrap("v", 0),
        NonZero(_) => Shape::Wrap("j", 0),
        ZeroNotEqual(_) => Shape::Wrap("n", 0),
        AndV(_, r) if matches!(r.as_inner(), True) => Shape::Wrap("t", 0),
        OrI(_, r) if matches!(r.as_inner(), False) => Shape::Wrap("u", 0),
        OrI(l, _) if matches!(l.as_inner(), False) => Shape::Wrap("l", 1),
        AndV(..) => Shape::Head("and_v", vec![0, 1]),
        AndB(..) => Shape::Head("and_b", vec![0, 1]),
        OrB(..) => Shape::Head("or_b", vec![0, 1]),
        OrD(..) => Shape::Head("or_d", vec![0, 1]),
        OrC(..) => Shape::Head("or_c", vec![0, 1]),
        OrI(..) => Shape::Head("or_i", vec![0, 1]),
        AndOr(_, _, c) if matches!(c.as_inner(), False) => Shape::Head("and_n", vec![0, 1]),
        AndOr(..) => Shape::Head("andor", vec![0, 1, 2]),
        Thresh(th) => Shape::Head("thresh", (0..th.n()).collect()),
        _ => Shape::Leaf,
    }
}

fn is_wrapper<Pk: miniscript::MiniscriptKey, Ctx: ScriptContext>(t: &Terminal<Pk, Ctx>) -> bool {
    matches!(shape(t), Shape::Wrap(..))
}

/// Build the tree. `offset` is the index in `script` of the first instruction of `ms`.
pub fn build<Ctx: ScriptContext>(ms: &Miniscript<PublicKey, Ctx>, named: &Miniscript<String, Ctx>, offset: usize) -> Node {
    walk(ms, named, offset).0
}

/// Returns the node and the number of instructions it spans.
fn walk<Ctx: ScriptContext>(ms: &Miniscript<PublicKey, Ctx>, named: &Miniscript<String, Ctx>, start: usize) -> (Node, usize) {
    use Seg::*;
    use Terminal::*;
    let total = n_instr(ms);
    let kids = ms.branches();
    let nkids = named.branches();
    let segs: Vec<Seg> = match ms.as_inner() {
        Check(sub) if matches!(sub.as_inner(), PkK(_) | PkH(_) | RawPkH(_)) => vec![Own(total)],
        Alt(_) => vec![Own(1), Child(0), Own(1)],
        Swap(_) => vec![Own(1), Child(0)],
        Check(_) | ZeroNotEqual(_) => vec![Child(0), Own(1)],
        DupIf(_) => vec![Own(2), Child(0), Own(1)],
        NonZero(_) => vec![Own(3), Child(0), Own(1)],
        // VERIFY may be merged into the child's last op (CHECKSIG -> CHECKSIGVERIFY etc.)
        Verify(c) => vec![Child(0), Own(total - n_instr(c))],
        // t:X = and_v(X,1): the `1` belongs to the wrapper
        AndV(_, r) if matches!(r.as_inner(), True) => vec![Child(0), Own(1)],
        AndV(..) => vec![Child(0), Child(1)],
        AndB(..) | OrB(..) => vec![Child(0), Child(1), Own(1)],
        // [X] NOTIF [Z] ELSE [Y] ENDIF; for and_n Z = 0 is part of the node itself
        AndOr(_, _, c) if matches!(c.as_inner(), False) => vec![Child(0), Own(3), Child(1), Own(1)],
        AndOr(..) => vec![Child(0), Own(1), Child(2), Own(1), Child(1), Own(1)],
        OrD(..) => vec![Child(0), Own(2), Child(1), Own(1)],
        OrC(..) => vec![Child(0), Own(1), Child(1), Own(1)],
        // u:X = or_i(X,0), l:X = or_i(0,X)
        OrI(_, r) if matches!(r.as_inner(), False) => vec![Own(1), Child(0), Own(3)],
        OrI(l, _) if matches!(l.as_inner(), False) => vec![Own(3), Child(1), Own(1)],
        OrI(..) => vec![Own(1), Child(0), Own(1), Child(1), Own(1)],
        Thresh(t) => {
            let mut v = vec![Child(0)];
            for i in 1..t.n() {
                v.push(Child(i));
                v.push(Own(1));
            }
            v.push(Own(2));
            v
        }
        _ => vec![Own(total)],
    };
    let mut own = Vec::new();
    let mut children: Vec<Option<Node>> = (0..kids.len()).map(|_| None).collect();
    let mut pos = start;
    for s in segs {
        match s {
            Own(n) => {
                own.extend(pos..pos + n);
                pos += n;
            }
            Child(i) => {
                let (node, n) = walk(kids[i], nkids[i], pos);
                children[i] = Some(node);
                pos += n;
            }
        }
    }
    assert_eq!(pos, start + total, "layout mismatch for {named}");
    let node = match shape(ms.as_inner()) {
        Shape::Leaf => Node { text: Some(named.to_string()), ops: own, ..Default::default() },
        Shape::Wrap(w, ci) => {
            let colon = if is_wrapper(nkids[ci].as_inner()) { "" } else { ":" };
            Node {
                wrap: Some(format!("{w}{colon}")),
                ops: own,
                child: children[ci].take().map(Box::new),
                ..Default::default()
            }
        }
        Shape::Head(h, idx) => {
            let mut ch: Vec<Node> = Vec::new();
            if let Thresh(t) = ms.as_inner() {
                // keep `head(` + children joined by `,` + `)` == Display: k is a pseudo leaf
                ch.push(Node { text: Some(t.k().to_string()), ops: vec![], ..Default::default() });
            }
            ch.extend(idx.into_iter().map(|i| children[i].take().expect("child laid out")));
            Node { head: Some(h.to_string()), ops: own, children: Some(ch), ..Default::default() }
        }
    };
    (node, total)
}
