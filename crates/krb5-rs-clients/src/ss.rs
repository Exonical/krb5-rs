//! A port of MIT's `ss` subsystem library (`src/util/ss`): the request
//! table, line parser and listen loop behind `ktutil` and `kadmin`.

use std::io::{BufRead, Write};

/// One request (`ss_request_entry`).
pub struct Request<T> {
    /// Command names; the first is the canonical one.
    pub names: &'static [&'static str],
    /// The `list_requests` help text.
    pub info: &'static str,
    /// The handler, called with argv (argv\[0\] is the name typed).
    pub func: fn(&mut T, &[String]),
}

/// What a line did (`ss_execute_line`).
#[derive(Debug, PartialEq, Eq)]
pub enum Exec {
    /// Ran, or was empty.
    Done,
    /// `quit`.
    Quit,
    /// No such request (`SS_ET_COMMAND_NOT_FOUND`).
    NotFound,
}

/// `ss_parse`: split on blanks and tabs; `"..."` quotes with `""` for a
/// literal quote. `None` for unbalanced quotes.
pub fn parse(line: &str) -> Option<Vec<String>> {
    let mut argv = Vec::new();
    let mut cur: Option<String> = None;
    let mut quoted = false;
    let mut it = line.chars().peekable();
    while let Some(c) = it.next() {
        if quoted {
            if c == '"' {
                if it.peek() == Some(&'"') {
                    it.next();
                    cur.get_or_insert_with(String::new).push('"');
                } else {
                    quoted = false;
                }
            } else {
                cur.get_or_insert_with(String::new).push(c);
            }
        } else if c == ' ' || c == '\t' {
            if let Some(a) = cur.take() {
                argv.push(a);
            }
        } else if c == '"' {
            quoted = true;
            cur.get_or_insert_with(String::new);
        } else {
            cur.get_or_insert_with(String::new).push(c);
        }
    }
    if quoted {
        return None;
    }
    argv.extend(cur);
    Some(argv)
}

/// The `ss_list_requests` listing for `subsystem`.
pub fn list_requests<T>(subsystem: &str, table: &[Request<T>]) -> String {
    let mut out = format!("Available {subsystem} requests:\n\n");
    for r in table {
        let names = r.names.join(", ");
        let spacing = r.names.iter().map(|n| n.len() + 2).sum::<usize>() - 2;
        if spacing > 23 {
            out.push_str(&names);
            out.push('\n');
            out.push_str(&" ".repeat(25));
        } else {
            out.push_str(&format!("{names:<25}"));
        }
        out.push_str(r.info);
        out.push('\n');
    }
    out
}

/// A subsystem invocation (`ss_create_invocation`).
pub struct Subsystem<T: 'static> {
    /// The subsystem name, used in the prompt and errors.
    pub name: &'static str,
    /// Requests; `list_requests` and `quit` are appended like MIT's
    /// `ss_std_requests` entries in the `.ct` tables.
    pub table: &'static [Request<T>],
}

const LIST_NAMES: &[&str] = &["list_requests", "lr", "?"];
const QUIT_NAMES: &[&str] = &["quit", "exit", "q"];

impl<T> Subsystem<T> {
    fn listing(&self) -> String {
        let mut s = list_requests::<T>(self.name, self.table);
        for (names, info) in [
            (LIST_NAMES, "List available requests."),
            (QUIT_NAMES, "Exit program."),
        ] {
            let tmp = [Request::<()> { names, info, func: |_, _| {} }];
            let l = list_requests(self.name, &tmp);
            s.push_str(l.split_once("\n\n").map_or("", |(_, r)| r));
        }
        s
    }

    /// `ss_execute_line`.
    pub fn execute_line(&self, state: &mut T, line: &str) -> Exec {
        let line = line.trim_start_matches([' ', '\t']);
        if let Some(cmd) = line.strip_prefix('!') {
            let _ = std::process::Command::new("/bin/sh").arg("-c").arg(cmd).status();
            return Exec::Done;
        }
        let Some(argv) = parse(line) else {
            crate::com_err_as(self.name, "Unbalanced quotes in command line");
            return Exec::Done;
        };
        let Some(cmd) = argv.first() else {
            return Exec::Done;
        };
        if LIST_NAMES.contains(&cmd.as_str()) {
            print!("{}", self.listing());
            return Exec::Done;
        }
        if QUIT_NAMES.contains(&cmd.as_str()) {
            return Exec::Quit;
        }
        match self.table.iter().find(|r| r.names.contains(&cmd.as_str())) {
            Some(r) => {
                (r.func)(state, &argv);
                Exec::Done
            }
            None => Exec::NotFound,
        }
    }

    /// `ss_listen`: prompt `"<name>:  "`, run lines until EOF or `quit`.
    pub fn listen(&self, state: &mut T) {
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        loop {
            print!("{}:  ", self.name);
            let _ = std::io::stdout().flush();
            let mut line = String::new();
            match input.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            let line = line.trim_end_matches(['\n', '\r']);
            match self.execute_line(state, line) {
                Exec::Quit => return,
                Exec::NotFound => {
                    let c = line
                        .trim_start_matches([' ', '\t'])
                        .split([' ', '\t'])
                        .next()
                        .unwrap_or("");
                    crate::com_err_as(
                        self.name,
                        format!("Unknown request \"{c}\".  Type \"?\" for a request list."),
                    );
                }
                Exec::Done => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_like_ss() {
        assert_eq!(parse("  a\tb  ").unwrap(), ["a", "b"]);
        assert_eq!(parse("\"a b\" c\"d\"e").unwrap(), ["a b", "cde"]);
        assert_eq!(parse("\"say \"\"hi\"\"\"").unwrap(), ["say \"hi\""]);
        assert_eq!(parse("\"\"").unwrap(), [""]);
        assert!(parse("\"open").is_none());
        assert!(parse("").unwrap().is_empty());
    }

    #[test]
    fn list_requests_layout() {
        let t = [
            Request::<()> { names: &["list", "l"], info: "List the current keylist.", func: |_, _| {} },
            Request::<()> {
                names: &["get_principals", "getprincs", "listprincs"],
                info: "List principals",
                func: |_, _| {},
            },
        ];
        assert_eq!(
            list_requests("ktutil", &t),
            "Available ktutil requests:\n\n\
             list, l                  List the current keylist.\n\
             get_principals, getprincs, listprincs\n                         List principals\n"
        );
    }
}
