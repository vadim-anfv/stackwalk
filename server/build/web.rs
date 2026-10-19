//! The deploy build of `web/`, shared by `build.rs` (which embeds the result in the
//! release binary) and the crate's tests. No dependencies.
//!
//! Features in the cut list are removed from the code, not just hidden: every region
//! between markers on their own lines is dropped, marker lines included:
//!
//!   <!-- flag:train --> ... <!-- /flag:train -->   (HTML)
//!   // flag:train ... // /flag:train                (JS)
//!   /* flag:train */ ... /* /flag:train */          (CSS)
//!
//! Then only the JS modules still reachable by imports from index.html are kept
//! (train.js and its ops.js drop out). The build fails if a cut feature's name is
//! still found in the output, or if markers are unbalanced.

/// `Some((closing, name))` for a line that is only a feature marker.
fn marker(line: &str) -> Option<(bool, &str)> {
    let t = line.trim();
    let t = ["<!--", "//", "/*"].iter().find_map(|p| t.strip_prefix(p))?;
    let t = ["-->", "*/"].iter().find_map(|s| t.strip_suffix(s)).unwrap_or(t).trim();
    let (closing, t) = match t.strip_prefix('/') {
        Some(rest) => (true, rest),
        None => (false, t),
    };
    let name = t.trim_start().strip_prefix("flag:")?;
    (!name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_')).then_some((closing, name))
}

/// The text without the regions of the `cut` features.
pub fn strip(file: &str, text: &str, cut: &[&str]) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let mut inside: Vec<&str> = Vec::new();
    for (n, line) in text.split_inclusive('\n').enumerate() {
        if let Some((closing, name)) = marker(line).filter(|(_, name)| cut.contains(name)) {
            if !closing {
                inside.push(name);
            } else if inside.pop() != Some(name) {
                return Err(format!("{file}:{}: /flag:{name} without its opening marker", n + 1));
            }
            continue;
        }
        if inside.is_empty() {
            out.push_str(line);
        }
    }
    match inside.last() {
        Some(name) => Err(format!("{file}: flag:{name} is never closed")),
        None => Ok(out),
    }
}

fn is_name(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')
}

/// `src` of the `<script>` tags of a page.
pub fn scripts(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    for tag in html.split("<script").skip(1) {
        let tag = &tag[..tag.find('>').unwrap_or(tag.len())];
        let Some(at) = tag.find("src=") else { continue };
        let rest = &tag[at + 4..];
        let Some(q) = rest.chars().next().filter(|c| *c == '"' || *c == '\'') else { continue };
        let name: String = rest[1..].chars().take_while(|c| *c != q).collect();
        if name.ends_with(".js") && name.chars().all(is_name) {
            out.push(name);
        }
    }
    out
}

/// Local modules a JS file imports: `import ... from './x.js'` and `import './x.js'`.
pub fn imports(js: &str) -> Vec<String> {
    let mut out = Vec::new();
    for q in ['\'', '"'] {
        let open = format!("{q}./");
        let mut from = 0;
        while let Some(at) = js[from..].find(&open).map(|i| from + i) {
            from = at + open.len();
            let name: String = js[from..].chars().take_while(|c| is_name(*c)).collect();
            let closed = js[from + name.len()..].starts_with(q);
            // the keyword right before the quote (after whitespace) makes it an import
            let before = js[..at].trim_end();
            let keyword = ["import", "from"].iter().any(|k| {
                before.strip_suffix(k).is_some_and(|b| !b.ends_with(|c: char| c.is_alphanumeric() || c == '_' || c == '.'))
            });
            if keyword && closed && name.ends_with(".js") {
                out.push((at, name));
            }
        }
    }
    out.sort();
    out.into_iter().map(|(_, n)| n).collect()
}

/// `word` as a whole word in `line`, any case.
pub fn has_word(line: &str, word: &str) -> bool {
    let (line, word) = (line.to_lowercase(), word.to_lowercase());
    let word_char = |c: char| c.is_alphanumeric() || c == '_';
    line.match_indices(&word).any(|(i, _)| {
        !line[..i].ends_with(word_char) && !line[i + word.len()..].starts_with(word_char)
    })
}

/// `files` (name, bytes) of `web/` -> the deploy set, sorted by name.
pub fn build(files: Vec<(String, Vec<u8>)>, cut: &[&str]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let text_file = |n: &str| [".html", ".js", ".css"].iter().any(|e| n.ends_with(e));
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    let mut texts: Vec<(String, String)> = Vec::new();
    for (name, bytes) in files {
        if text_file(&name) {
            let text = String::from_utf8(bytes).map_err(|_| format!("{name}: not UTF-8"))?;
            texts.push((name.clone(), strip(&name, &text, cut)?));
        } else {
            // images, fonts...: as they are
            out.push((name, bytes));
        }
    }
    let text = |n: &str| texts.iter().find(|(name, _)| name == n).map(|(_, t)| t.as_str());

    // JS modules reachable from the page, after the cut
    let mut todo = scripts(text("index.html").ok_or("web/index.html is missing")?);
    let mut js: Vec<String> = Vec::new();
    while let Some(name) = todo.pop() {
        if js.contains(&name) {
            continue;
        }
        todo.extend(imports(text(&name).ok_or(format!("missing module {name}"))?));
        js.push(name);
    }

    for (name, t) in &texts {
        if name.ends_with(".js") && !js.contains(name) {
            continue;
        }
        for feature in cut {
            if let Some((n, line)) = t.lines().enumerate().find(|(_, l)| has_word(l, feature)) {
                return Err(format!("{name}:{}: '{feature}' is still there: {}", n + 1, line.trim()));
            }
        }
        out.push((name.clone(), t.clone().into_bytes()));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

#[cfg(test)]
#[path = "web_tests.rs"]
mod tests;
