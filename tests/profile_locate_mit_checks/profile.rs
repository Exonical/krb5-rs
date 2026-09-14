// ---------------------------------------------------------------------------
// Section 1: profile parser (util/profile/test.ini verbatim + prof_parse.c)
// ---------------------------------------------------------------------------

#[test]
fn profile_test_ini_values() {
    let p = Profile::parse(TEST_INI).expect("test.ini parses");
    // Merged [test section 1] relations in file order; quoted "bar " keeps
    // its trailing space, unquoted values are trimmed (prof_parse.c:89-124).
    assert_eq!(
        p.get_values(&["test section 1", "foo"]),
        vec!["bar ", "bar2", "bar3"]
    );
    assert_eq!(p.get_string(&["test section 2", "child_section2", "child"]), Some("slick".to_string()));
    assert_eq!(
        p.get_values(&["test section 2", "child_section2", "child"]),
        vec!["slick", "harry", "john\tb ", "ron"]
    );
    assert_eq!(
        p.get_values(&["realms", "ATHENA.MIT.EDU", "server"]),
        vec!["KERBEROS.MIT.EDU:88", "KERBEROS1.MIT.EDU", "KERBEROS2.MIT.EDU"]
    );
    assert_eq!(p.subsection_names(&["realms"]), vec!["ATHENA.MIT.EDU"]);
    assert_eq!(
        p.get_string(&["test section 2", "test_child"]),
        Some("foo\nbar".to_string())
    );
    // Absent path -> empty.
    assert!(p.get_values(&["no", "such", "section"]).is_empty());
    assert_eq!(p.get_string(&["no", "such", "section"]), None);
}

#[test]
fn profile_final_markers() {
    // }* marks the subsection final: later same-named definitions are
    // discarded (prof_parse.c group_level/discard + prof_tree.c:225-230).
    let text = "[a]\nx = {\ny = 1\n}*\n[a]\nx = {\ny = 2\n}\n";
    let p = Profile::parse(text).unwrap();
    assert_eq!(p.get_values(&["a", "x", "y"]), vec!["1"]);

    // [section]* final: later relations under the merged section discarded.
    let text = "[a]*\nk = 1\n[a]\nk = 2\n";
    let p = Profile::parse(text).unwrap();
    assert_eq!(p.get_values(&["a", "k"]), vec!["1"]);

    // key* = v final relation: later same-name values suppressed
    // (prof_tree.c profile_add_node check_final, prof_parse.c:469-478).
    let text = "[a]\nk* = 1\nk = 2\n";
    let p = Profile::parse(text).unwrap();
    assert_eq!(p.get_values(&["a", "k"]), vec!["1"]);
}

#[test]
fn profile_comments_and_preamble() {
    let text = "preamble ignored\nkey = ignored_too\n  ; semicolon comment\n  # hash comment\n[a]\nk = a#b\n";
    let p = Profile::parse(text).unwrap();
    // '#' mid-value is literal (prof_parse.c:39-41 checks first non-ws char).
    assert_eq!(p.get_values(&["a", "k"]), vec!["a#b"]);
    assert_eq!(p.get_values(&["key"]), Vec::<String>::new());
}

#[test]
fn profile_quoted_escapes() {
    let text = "[a]\nk1 = \"x\\ny\\tt\\bb\\\\c\\\"d\"\nk2 = unquoted  \n";
    let p = Profile::parse(text).unwrap();
    assert_eq!(
        p.get_string(&["a", "k1"]).as_deref(),
        Some("x\ny\tt\u{8}b\\c\"d")
    );
    // Trailing whitespace stripped from unquoted values (prof_parse.c:347-349).
    assert_eq!(p.get_string(&["a", "k2"]).as_deref(), Some("unquoted"));
}

#[test]
fn profile_syntax_errors() {
    // Missing ']' (PROF_SECTION_SYNTAX).
    assert!(matches!(
        Profile::parse("[sec\nk = 1"),
        Err(ProfileError::Syntax { line: 1, .. })
    ));
    // '}' with no open subsection (PROF_EXTRA_CBRACE).
    assert!(matches!(
        Profile::parse("[a]\nk = 1\n}\n"),
        Err(ProfileError::Syntax { line: 3, .. })
    ));
    // Relation with no '=' (PROF_RELATION_SYNTAX).
    assert!(matches!(
        Profile::parse("[a]\nkey value\n"),
        Err(ProfileError::Syntax { line: 2, .. })
    ));
    // 'key =' then next line isn't '{' (PROF_MISSING_OBRACE).
    assert!(matches!(
        Profile::parse("[a]\nk =\nnot a brace\n"),
        Err(ProfileError::Syntax { line: 3, .. })
    ));
    // '[' inside a group (PROF_SECTION_NOTOP).
    assert!(matches!(
        Profile::parse("[a]\nsub = {\n[inner]\n}"),
        Err(ProfileError::Syntax { line: 3, .. })
    ));
    // Junk after ']' (PROF_SECTION_SYNTAX).
    assert!(matches!(
        Profile::parse("[a] junk\n"),
        Err(ProfileError::Syntax { line: 1, .. })
    ));
}

#[test]
fn profile_boolean_and_integer() {
    // libdef_parse.c:37-45 lists, case-insensitive (prof_get.c:356-369).
    for s in ["y", "YES", "True", "t", "1", "ON"] {
        assert_eq!(conf_boolean(s), Some(true), "{s}");
    }
    for s in ["n", "NO", "False", "nil", "0", "off"] {
        assert_eq!(conf_boolean(s), Some(false), "{s}");
    }
    assert_eq!(conf_boolean("maybe"), None);

    let p = Profile::parse("[a]\nb = maybe\ni = 12x\nj = 42\n").unwrap();
    assert!(matches!(
        p.get_boolean(&["a", "b"], false),
        Err(ProfileError::BadBoolean(_))
    ));
    assert!(p.get_boolean(&["a", "absent"], true).unwrap());
    assert!(matches!(
        p.get_integer(&["a", "i"], 7),
        Err(ProfileError::BadInteger(_))
    ));
    assert_eq!(p.get_integer(&["a", "absent"], 7).unwrap(), 7);
    assert_eq!(p.get_integer(&["a", "j"], 7).unwrap(), 42);
    // Empty value fails strict strtol (prof_get.c:287-288).
    let p = Profile::parse("[a]\ne = \"\"\n").unwrap();
    assert!(matches!(
        p.get_integer(&["a", "e"], 7),
        Err(ProfileError::BadInteger(_))
    ));
}

#[test]
fn profile_include_and_includedir() {
    let dir = tmpdir();
    let sub = dir.join("incdir");
    std::fs::create_dir_all(&sub).unwrap();
    let other = dir.join("other.conf");
    std::fs::write(&other, "[s]\nv = other\n").unwrap();
    std::fs::write(sub.join("a.conf"), "[s]\nv = a\n").unwrap();
    std::fs::write(sub.join("b-1.conf"), "[s]\nv = b-1\n").unwrap();
    // Excluded: names not alnum/-/_ with optional .conf (prof_file.c
    // good_file_pattern) or with ~ suffix, or hidden dotfiles.
    std::fs::write(sub.join("c.conf~"), "[s]\nv = ctilde\n").unwrap();
    std::fs::write(sub.join(".hidden"), "[s]\nv = hidden\n").unwrap();
    let main = dir.join("main.conf");
    std::fs::write(
        &main,
        format!(
            "[s]\nv = main\ninclude {}\nincludedir {}\n",
            other.display(),
            sub.display()
        ),
    )
    .unwrap();
    let p = Profile::load(&main).expect("load with includes");
    assert_eq!(
        p.get_values(&["s", "v"]),
        vec!["main", "other", "a", "b-1"]
    );
}
