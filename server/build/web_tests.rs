use super::*;

#[test]
fn cut_regions_go_with_their_markers() {
    let src = "a\n<!-- flag:train -->\nb\n<!-- /flag:train -->\nc\n  // flag:train\nd\n  // /flag:train\n/* flag:train */\ne\n/* /flag:train */\nf\n";
    assert_eq!(strip("x", src, &["train"]).unwrap(), "a\nc\nf\n");
}

#[test]
fn other_flags_stay() {
    let src = "// flag:leaderboard\nx\n// /flag:leaderboard\n";
    assert_eq!(strip("x", src, &["train"]).unwrap(), src);
}

#[test]
fn a_marker_must_be_alone_on_its_line() {
    // code next to a marker is not a marker: nothing is cut
    let src = "x = 1; // flag:train\n";
    assert_eq!(strip("x", src, &["train"]).unwrap(), src);
}

#[test]
fn unbalanced_markers_fail() {
    assert!(strip("x", "// flag:train\nx\n", &["train"]).unwrap_err().contains("never closed"));
    assert!(strip("x", "x\n// /flag:train\n", &["train"]).unwrap_err().contains("without its opening"));
}

#[test]
fn page_scripts_and_imports() {
    let html = r#"<script type="module" src="app.js"></script><script src='b.js' defer></script>"#;
    assert_eq!(scripts(html), ["app.js", "b.js"]);
    let js = "import { a } from './cost.js';\nimport './side.js';\nconst s = 'from ./no.js';\n  } from \"./opinfo.js\";\n";
    assert_eq!(imports(js), ["cost.js", "side.js", "opinfo.js"]);
}

#[test]
fn whole_word_any_case() {
    assert!(has_word("let Train = 1", "train"));
    assert!(has_word("#train", "train"));
    assert!(!has_word("trainer, strain", "train"));
}

#[test]
fn only_reachable_modules_are_kept() {
    let files = vec![
        ("index.html".to_string(), b"<script type=\"module\" src=\"app.js\"></script>".to_vec()),
        ("app.js".to_string(), b"import './a.js';\n// flag:train\nimport './train.js';\n// /flag:train\n".to_vec()),
        ("a.js".to_string(), b"export const a = 1;\n".to_vec()),
        ("train.js".to_string(), b"import './ops.js';\n".to_vec()),
        ("ops.js".to_string(), b"".to_vec()),
        ("icon.png".to_string(), vec![0x89, b'P', b'N', b'G']),
    ];
    let out = build(files, &["train"]).unwrap();
    let names: Vec<&str> = out.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["a.js", "app.js", "icon.png", "index.html"]);
}

#[test]
fn a_leftover_name_fails_the_build() {
    let files = vec![
        ("index.html".to_string(), b"<p>train</p>".to_vec()),
    ];
    assert!(build(files, &["train"]).unwrap_err().contains("'train' is still there"));
}
