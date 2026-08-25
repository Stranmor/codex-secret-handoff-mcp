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
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-06-18"}}}}"#).expect("initialize write");
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{{}}}}"#)
        .expect("tools/list write");
    stdin.flush().expect("flush");
    drop(stdin);

    let mut line = String::new();
    stdout.read_line(&mut line).expect("initialize response");
    let initialize: serde_json::Value = serde_json::from_str(&line).expect("valid initialize JSON");
    assert_eq!(initialize["id"], 1);
    assert_eq!(initialize["result"]["serverInfo"]["name"], "codex-secret-handoff-mcp");

    line.clear();
    stdout.read_line(&mut line).expect("tools/list response");
    let tools: serde_json::Value = serde_json::from_str(&line).expect("valid tools/list JSON");
    let rendered = tools.to_string();
    assert!(rendered.contains("secret_handoff_capture"));
    assert!(!rendered.contains("secret_value"));
    assert!(!rendered.contains("plaintext_value"));
    let status = child.wait().expect("MCP server exit");
    assert!(status.success());
    let _ = std::fs::remove_dir_all(state_dir);
}
