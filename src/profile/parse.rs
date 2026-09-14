//! MIT util/profile/prof_parse.c grammar: sections, relations, subsections,
//! final markers, quoted strings, include/includedir, and the prof_tree.c
//! add_node merge/final semantics.

use std::path::Path;

use super::ProfileError;

/// A profile tree node.  `value.is_none()` marks a section/subsection.
#[derive(Debug)]
pub(crate) struct Node {
    pub name: String,
    pub value: Option<String>,
    pub is_final: bool,
    pub children: Vec<Node>,
}

impl Node {
    fn new(name: &str, value: Option<String>) -> Node {
        Node {
            name: name.to_string(),
            value,
            is_final: false,
            children: Vec::new(),
        }
    }
}

/// profile_add_node (prof_tree.c:196-249).  Children are kept sorted by name,
/// new same-named nodes inserted after the last match.  Subsections merge
/// into an existing same-named subsection; `check_final` suppresses a new
/// relation when a final same-named node exists.  Returns the index of the
/// node to use, or None if suppressed.
fn add_node(
    section: &mut Node,
    name: &str,
    value: Option<String>,
    check_final: bool,
) -> Option<usize> {
    let mut insert_at = section.children.len();
    for (i, p) in section.children.iter().enumerate() {
        match p.name.as_str().cmp(name) {
            std::cmp::Ordering::Greater => {
                insert_at = i;
                break;
            }
            std::cmp::Ordering::Equal => {
                if value.is_none() && p.value.is_none() {
                    // Duplicate subsection: merge.
                    return Some(i);
                }
                if check_final && p.is_final {
                    return None;
                }
            }
            std::cmp::Ordering::Less => {}
        }
    }
    section.children.insert(insert_at, Node::new(name, value));
    Some(insert_at)
}

fn skip_blanks(s: &str) -> &str {
    s.trim_start_matches([' ', '\t'])
}

/// parse_quoted_string (prof_parse.c:47-72): decode escapes in place,
/// stopping at the first unescaped '"'.  Text after the closing quote is
/// ignored, matching MIT (the caller never checks it).
fn parse_quoted_string(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => break,
            '\\' => match chars.next() {
                None => break,
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('b') => out.push('\u{8}'),
                Some(c) => out.push(c),
            },
            c => out.push(c),
        }
    }
    out
}

fn strip_trailing_ws(s: &str) -> &str {
    s.trim_end_matches(|c: char| c.is_whitespace())
}

#[derive(Clone, Copy, PartialEq)]
enum State {
    Init,
    Std,
    GetObrace,
}

struct ParseState<'a> {
    root: &'a mut Node,
    /// Index path from root to the current section.
    path: Vec<usize>,
    state: State,
    group_level: usize,
    discard: usize,
}

impl<'a> ParseState<'a> {
    fn current(&mut self) -> &mut Node {
        let mut n = &mut *self.root;
        for &i in &self.path {
            n = &mut n.children[i];
        }
        n
    }
}

fn parse_std_line(line: &str, st: &mut ParseState, lineno: usize) -> Result<(), ProfileError> {
    let syntax = |msg: &str| ProfileError::Syntax {
        line: lineno,
        msg: msg.to_string(),
    };
    let cp = skip_blanks(line);
    let ch = cp.chars().next().unwrap_or('\0');
    if ch == '\0' || ch == ';' || ch == '#' {
        return Ok(());
    }
    if ch == '[' {
        if st.group_level > 1 {
            return Err(syntax("section header must be at top level"));
        }
        let after = &cp[1..];
        let close = after
            .find(']')
            .ok_or_else(|| syntax("syntax error in section header"))?;
        let name = &after[..close];
        // Sections merge by name (add_node with value None).
        let idx = add_node(st.root, name, None, false).expect("root add");
        st.path.clear();
        st.path.push(idx);
        st.group_level = 1;
        st.discard = if st.root.children[idx].is_final { 1 } else { 0 };
        let mut rest = &after[close + 1..];
        if rest.starts_with('*') {
            st.root.children[idx].is_final = true;
            rest = &rest[1..];
        }
        let rest = skip_blanks(rest);
        if !rest.is_empty() {
            return Err(syntax("syntax error in section header"));
        }
        return Ok(());
    }
    if ch == '}' {
        if st.group_level < 2 {
            return Err(syntax("extraneous close brace"));
        }
        if cp[1..].starts_with('*') {
            st.current().is_final = true;
        }
        st.group_level -= 1;
        if st.group_level < st.discard {
            st.discard = 0;
        }
        if st.discard == 0 {
            st.path.pop();
        }
        return Ok(());
    }

    // Relations.
    let eq = match cp.find('=') {
        Some(e) if e > 0 => e,
        _ => return Err(syntax("syntax error in relations line")),
    };
    let mut tag = &cp[..eq];
    // Whitespace inside the tag: anything after must be whitespace only.
    if let Some(w) = tag.find([' ', '\t']) {
        if tag[w..].trim().is_empty() {
            tag = &tag[..w];
        } else {
            return Err(syntax("syntax error in relations line"));
        }
    }
    let value = skip_blanks(&cp[eq + 1..]);
    if let Some(quoted) = value.strip_prefix('"') {
        let decoded = parse_quoted_string(quoted);
        return add_relation(st, tag, decoded);
    }
    if !value.is_empty()
        && !value
            .strip_prefix('{')
            .is_some_and(|rest| skip_blanks(rest).is_empty())
    {
        let v = strip_trailing_ws(value).to_string();
        return add_relation(st, tag, v);
    }
    // Subsection: `key = {` on this line, or `key =` awaiting '{'.
    if value.is_empty() {
        st.state = State::GetObrace;
    }
    let (tag, mark_final) = match tag.find('*') {
        Some(p) => (&tag[..p], true),
        None => (tag, false),
    };
    st.group_level += 1;
    if st.discard == 0 {
        let idx = add_node(st.current(), tag, None, false).expect("subsection add");
        st.path.push(idx);
        let level = st.group_level;
        let was_final = st.current().is_final;
        if was_final {
            st.discard = level;
        }
        if mark_final {
            st.current().is_final = true;
        }
    }
    Ok(())
}

fn add_relation(st: &mut ParseState, tag: &str, value: String) -> Result<(), ProfileError> {
    let (tag, mark_final) = match tag.find('*') {
        Some(p) => (&tag[..p], true),
        None => (tag, false),
    };
    if st.discard == 0 {
        if let Some(idx) = add_node(st.current(), tag, Some(value), true) {
            if mark_final {
                st.current().children[idx].is_final = true;
            }
        }
    }
    Ok(())
}

/// valid_name (prof_parse.c:237-256): dotfiles excluded; otherwise all
/// alnum/'-'/'_', or anything ending in ".conf".
fn valid_name(name: &str) -> bool {
    if name.starts_with('.') {
        return false;
    }
    if name.ends_with(".conf") && name.len() >= 5 {
        return true;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn parse_include_dir(dir: &str, root: &mut Node) -> Result<(), ProfileError> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| ProfileError::Syntax {
            line: 0,
            msg: format!("couldn't open includedir {dir}: {e}"),
        })?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| valid_name(n))
        .collect();
    names.sort();
    for n in names {
        parse_file(&Path::new(dir).join(n), root)?;
    }
    Ok(())
}

fn parse_file(path: &Path, root: &mut Node) -> Result<(), ProfileError> {
    let text = std::fs::read_to_string(path).map_err(ProfileError::Io)?;
    parse_text_into(&text, root)
}

fn parse_line(line: &str, st: &mut ParseState, lineno: usize) -> Result<(), ProfileError> {
    // include/includedir are column-0 directives honored in any state
    // (prof_parse.c:295-306).
    if line.starts_with("include") && line[7..].starts_with([' ', '\t']) {
        let name = strip_trailing_ws(skip_blanks(&line[7..]));
        return parse_file(Path::new(name), st.root).map_err(|e| match e {
            ProfileError::Io(io) => ProfileError::Syntax {
                line: lineno,
                msg: format!("couldn't open include file {name}: {io}"),
            },
            e => e,
        });
    }
    if line.starts_with("includedir") && line[10..].starts_with([' ', '\t']) {
        let name = strip_trailing_ws(skip_blanks(&line[10..]));
        return parse_include_dir(name, st.root);
    }
    match st.state {
        State::Init => {
            // Anything other than a section header is ignored
            // (prof_parse.c:326-327).
            if !line.starts_with('[') {
                return Ok(());
            }
            st.state = State::Std;
            parse_std_line(line, st, lineno)
        }
        State::Std => parse_std_line(line, st, lineno),
        State::GetObrace => {
            let cp = skip_blanks(line);
            if !cp.starts_with('{') {
                return Err(ProfileError::Syntax {
                    line: lineno,
                    msg: "profile_parse(): missing '{'".to_string(),
                });
            }
            st.state = State::Std;
            Ok(())
        }
    }
}

/// Parse `text` into `root` (shared across included files).
pub(crate) fn parse_text_into(text: &str, root: &mut Node) -> Result<(), ProfileError> {
    let mut st = ParseState {
        root,
        path: Vec::new(),
        state: State::Init,
        group_level: 0,
        discard: 0,
    };
    for (i, raw) in text.split('\n').enumerate() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        parse_line(line, &mut st, i + 1)?;
    }
    Ok(())
}

pub(crate) fn load_file(path: &Path) -> Result<Node, ProfileError> {
    let mut root = Node::new("(root)", None);
    parse_file(path, &mut root)?;
    Ok(root)
}

pub(crate) fn parse_text(text: &str) -> Result<Node, ProfileError> {
    let mut root = Node::new("(root)", None);
    parse_text_into(text, &mut root)?;
    Ok(root)
}
