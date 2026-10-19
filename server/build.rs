//! Embeds `../web` in the binary: generates `assets.rs`, a table of its files for
//! `include_bytes!`, with one ETag for the whole set.
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::Path;
use std::{env, fs};

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

    let mut files: Vec<_> = fs::read_dir(&src)
        .expect("read web/")
        .map(|entry| entry.expect("web/ entry").path())
        .filter(|path| path.is_file())
        .collect();
    files.sort();

    // one ETag for the whole build: the page and its modules only change together
    let mut hash = DefaultHasher::new();
    let mut table = String::from("pub static FILES: &[(&str, &str, &[u8])] = &[\n");
    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy();
        (&name, fs::read(path).expect("read a web/ file")).hash(&mut hash);
        let path = path.canonicalize().unwrap();
        table += &format!("    ({name:?}, {:?}, include_bytes!({:?})),\n", content_type(&name), path.display().to_string());
    }
    table += "];\n";
    table += &format!("pub const ETAG: &str = \"\\\"{:016x}\\\"\";\n", hash.finish());
    fs::write(Path::new(&env::var("OUT_DIR").unwrap()).join("assets.rs"), table).unwrap();
}
