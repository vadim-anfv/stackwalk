// Q1: try to get a ScriptBuf out of String-keyed miniscript/descriptor.
// Expected to FAIL to compile; compile with `cargo build --example q1_fail`.
use std::str::FromStr;

use miniscript::policy::Concrete;
use miniscript::{Descriptor, Miniscript, Segwitv0};

fn main() {
    let pol = Concrete::<String>::from_str("or(pk(A),and(pk(B),older(144)))").unwrap();
    let ms: Miniscript<String, Segwitv0> = pol.compile().unwrap();
    let _s1 = ms.encode();
    let desc = Descriptor::new_wsh(ms).unwrap();
    let _s2 = desc.script_pubkey();
    let _s3 = desc.explicit_script();
}
