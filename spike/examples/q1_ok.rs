// Q1: what compiles and prints with String keys.
use std::str::FromStr;

use miniscript::policy::{Concrete, Liftable};
use miniscript::{Descriptor, Miniscript, Segwitv0, Tap};

fn main() {
    let src = "or(pk(A),and(pk(B),older(144)))";
    let pol = Concrete::<String>::from_str(src).unwrap();
    let ms: Miniscript<String, Segwitv0> = pol.compile().unwrap();
    println!("policy            : {pol}");
    println!("ms<String,Segwitv0>: {ms}");
    println!("ms debug          : {ms:?}");
    let tap: Miniscript<String, Tap> = pol.compile().unwrap();
    println!("ms<String,Tap>    : {tap}");
    let wsh = Descriptor::new_wsh(ms.clone()).unwrap();
    println!("Descriptor wsh    : {wsh}");
    let tr = pol.compile_tr(Some("UNSPENDABLE".to_string())).unwrap();
    println!("Descriptor tr     : {tr}");
    let tr2 = pol.compile_tr(None);
    println!("compile_tr(None)  : {tr2:?}");
    println!("lift(ms)          : {}", ms.lift().unwrap());
    // Parsing a miniscript directly with String keys also works:
    let parsed = Miniscript::<String, Segwitv0>::from_str("or_d(pk(A),and_v(v:pk(B),older(144)))").unwrap();
    println!("parsed ms         : {parsed} sat_size? script_size={}", parsed.script_size());
    // with hash fragments
    let ph = Concrete::<String>::from_str("or(and(pk(A),sha256(H)),and(pk(B),hash160(G)))").unwrap();
    println!("hash policy ms    : {}", ph.compile::<Segwitv0>().unwrap());
}
