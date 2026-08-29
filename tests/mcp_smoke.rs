use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn mcp_initialize_and_tools_list_are_machine_readable() {
    let state_dir =
        std::env::temp_dir().join(format!("codex-secret-handoff-smoke-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state_dir);
    let mut child = Command::new(env!("CARGO_BIN_EXE_codex-secret-handoff-mcp"))
        .env("CODEX_SECRET_HANDOFF_STATE_DIR", &state_dir)
        .arg("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn MCP server");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stdout = BufReader::new(stdout);
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-06-18","capabilities":{{}},"clientInfo":{{"name":"smoke","version":"0.1"}}}}}}"#).expect("initialize write");
    stdin.flush().expect("flush");

    let mut line = String::new();
    stdout.read_line(&mut line).expect("initialize response");
    let initialize: serde_json::Value = serde_json::from_str(&line).expect("valid initialize JSON");
    assert_eq!(initialize["id"], 1);
    assert_eq!(initialize["result"]["serverInfo"]["name"], "codex-secret-handoff-mcp");

    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{{}}}}"#)
        .expect("tools/list write");
    stdin.flush().expect("tools/list flush");
    line.clear();
    stdout.read_line(&mut line).expect("tools/list response");
    let tools: serde_json::Value = serde_json::from_str(&line).expect("valid tools/list JSON");
    let rendered = tools.to_string();
    assert!(rendered.contains("secret_handoff_capture"));
    assert!(rendered.contains("trusted GUI prompt"));
    assert!(!rendered.contains("TTY"));
    assert!(!rendered.contains("secret_value"));
    assert!(!rendered.contains("plaintext_value"));

    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"secret_handoff_status","arguments":{{}}}}}}"#
    )
    .expect("tools/call write");
    stdin.flush().expect("tools/call flush");
    line.clear();
    stdout.read_line(&mut line).expect("tools/call response");
    let status_call: serde_json::Value =
        serde_json::from_str(&line).expect("valid tools/call JSON");
    assert_eq!(status_call["id"], 3);
    assert!(status_call["result"]["structuredContent"]["records"].is_array());

    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"secret_handoff_capture","arguments":{{"target":"ok","label":"ok","ttl_seconds":"SENSITIVE_TEST"}}}}}}"#
    )
    .expect("invalid capture write");
    stdin.flush().expect("invalid capture flush");
    line.clear();
    stdout.read_line(&mut line).expect("invalid capture response");
    let invalid_capture: serde_json::Value =
        serde_json::from_str(&line).expect("valid invalid capture JSON");
    let invalid_rendered = invalid_capture.to_string();
    assert_eq!(invalid_capture["id"], 4);
    assert!(invalid_rendered.contains("invalid capture arguments"));
    assert!(!invalid_rendered.contains("SENSITIVE_TEST"));

    drop(stdin);
    let status = child.wait().expect("MCP server exit");
    assert!(status.success());
    let _ = std::fs::remove_dir_all(state_dir);
}
