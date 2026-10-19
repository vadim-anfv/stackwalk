//! Embeds the deploy build of `../web` (see `build/web.rs`) in the binary: writes the
//! files to OUT_DIR and generates `assets.rs`, a table of them for `include_bytes!`.
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::Path;
use std::{env, fs};

#[path = "build/web.rs"]
mod web;

/// Features cut out of the deploy build.
const CUT: &[&str] = &["train"];

fn content_type(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

fn main() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../web");
    // a directory: cargo reruns on any change below it
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed=build/web.rs");

    let mut files = Vec::new();
    for entry in fs::read_dir(&src).expect("read web/") {
        let path = entry.expect("web/ entry").path();
        if path.is_file() {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            files.push((name, fs::read(&path).expect("read a web/ file")));
        }
    }
    let out = web::build(files, CUT).unwrap_or_else(|e| panic!("web build: {e}"));

    let out_dir = Path::new(&env::var("OUT_DIR").unwrap()).join("web");
    let _ = fs::remove_dir_all(&out_dir);
    fs::create_dir_all(&out_dir).unwrap();
    // one ETag for the whole build: the page and its modules only change together
    let mut hash = DefaultHasher::new();
    let mut table = String::from("pub static FILES: &[(&str, &str, &[u8])] = &[\n");
    for (name, bytes) in &out {
        fs::write(out_dir.join(name), bytes).unwrap();
        (name, bytes).hash(&mut hash);
        let path = out_dir.join(name);
        table += &format!("    ({name:?}, {:?}, include_bytes!({:?})),\n", content_type(name), path.display().to_string());
    }
    table += "];\n";
    table += &format!("pub const ETAG: &str = \"\\\"{:016x}\\\"\";\n", hash.finish());
    fs::write(Path::new(&env::var("OUT_DIR").unwrap()).join("assets.rs"), table).unwrap();
}
