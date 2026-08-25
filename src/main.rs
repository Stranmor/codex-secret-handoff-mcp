use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroizing;

const SERVICE: &str = "codex-secret-handoff";
const PROTOCOL_VERSION: &str = "2025-06-18";
const MAX_TTL_SECONDS: u64 = 86_400;
const DEFAULT_TTL_SECONDS: u64 = 900;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SecretRecord {
    handle: String,
    target: String,
    label: String,
    created_at: u64,
    expires_at: u64,
    single_use: bool,
    status: String,
    keyring_account: String,
    consumed_at: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct State {
    schema_version: u32,
    records: BTreeMap<String, SecretRecord>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct OperationsFile {
    operations: BTreeMap<String, Operation>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Operation {
    command: String,
    args: Vec<String>,
    secret_env: String,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn state_dir() -> PathBuf {
    if let Ok(path) = env::var("CODEX_SECRET_HANDOFF_STATE_DIR")
        && !path.trim().is_empty()
    {
        return PathBuf::from(path);
    }
    if let Ok(path) = env::var("XDG_STATE_HOME")
        && !path.trim().is_empty()
    {
        return PathBuf::from(path).join("codex-secret-handoff");
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local/state/codex-secret-handoff")
}

fn config_file() -> PathBuf {
    if let Ok(path) = env::var("CODEX_SECRET_HANDOFF_CONFIG")
        && !path.trim().is_empty()
    {
        return PathBuf::from(path);
    }
    if let Ok(path) = env::var("XDG_CONFIG_HOME")
        && !path.trim().is_empty()
    {
        return PathBuf::from(path).join("codex-secret-handoff/operations.json");
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config/codex-secret-handoff/operations.json")
}

fn ensure_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn read_state(dir: &Path) -> Result<State, String> {
    let path = dir.join("state.json");
    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| "state file is invalid".into()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            Ok(State { schema_version: 1, records: BTreeMap::new() })
        },
        Err(_) => Err("state file cannot be read".into()),
    }
}

fn write_state(dir: &Path, state: &State) -> Result<(), String> {
    ensure_private_dir(dir).map_err(|_| "state directory cannot be created")?;
    let payload = serde_json::to_vec_pretty(state).map_err(|_| "state cannot be serialized")?;
    let tmp = dir.join(format!("state.json.{}.tmp", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|_| "temporary state file cannot be created")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| "state permissions cannot be set")?;
    }
    file.write_all(&payload)
        .and_then(|_| file.sync_all())
        .map_err(|_| "state cannot be written")?;
    fs::rename(tmp, dir.join("state.json")).map_err(|_| "state cannot be committed".into())
}

fn with_state<F, R>(mutator: F) -> Result<R, String>
where
    F: FnOnce(&mut State) -> Result<R, String>,
{
    let dir = state_dir();
    ensure_private_dir(&dir).map_err(|_| "state directory cannot be created")?;
    let lock_path = dir.join("state.lock");
    let lock = OpenOptions::new()
        .create(true)
        .append(true)
        .open(lock_path)
        .map_err(|_| "state lock cannot be opened")?;
    lock.lock_exclusive().map_err(|_| "state lock cannot be acquired")?;
    let mut state = read_state(&dir)?;
    let result = mutator(&mut state)?;
    write_state(&dir, &state)?;
    lock.unlock().map_err(|_| "state lock cannot be released")?;
    Ok(result)
}

fn with_state_read<F, R>(reader: F) -> Result<R, String>
where
    F: FnOnce(&State) -> Result<R, String>,
{
    let dir = state_dir();
    ensure_private_dir(&dir).map_err(|_| "state directory cannot be created")?;
    let lock = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("state.lock"))
        .map_err(|_| "state lock cannot be opened")?;
    lock.lock_shared().map_err(|_| "state lock cannot be acquired")?;
    let state = read_state(&dir)?;
    let result = reader(&state);
    let _ = lock.unlock();
    result
}

fn read_record(handle: &str) -> Result<SecretRecord, String> {
    let dir = state_dir();
    let state = read_state(&dir)?;
    state.records.get(handle).cloned().ok_or_else(|| "unknown handle".into())
}

fn secret_tool_store(
    account: &str,
    target: &str,
    label: &str,
    secret: &[u8],
) -> Result<(), String> {
    let mut child = Command::new("/usr/bin/secret-tool")
        .args(["store", "--label", label, "service", SERVICE, "account", account, "target", target])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "OS keyring is unavailable")?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(secret).map_err(|_| "OS keyring rejected the secret")?;
    }
    let status = child.wait().map_err(|_| "OS keyring operation failed")?;
    if status.success() { Ok(()) } else { Err("OS keyring rejected the secret".into()) }
}

fn secret_tool_lookup(account: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let output = Command::new("/usr/bin/secret-tool")
        .args(["lookup", "service", SERVICE, "account", account])
        .output()
        .map_err(|_| "OS keyring is unavailable")?;
    if !output.status.success() {
        return Err("secret is not available in OS keyring".into());
    }
    let mut value = output.stdout;
    if value.last() == Some(&b'\n') {
        value.pop();
        if value.last() == Some(&b'\r') {
            value.pop();
        }
    }
    Ok(Zeroizing::new(value))
}

fn secret_tool_clear(account: &str) -> Result<(), String> {
    let status = Command::new("/usr/bin/secret-tool")
        .args(["clear", "service", SERVICE, "account", account])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "OS keyring is unavailable")?;
    if status.success() { Ok(()) } else { Err("OS keyring entry could not be removed".into()) }
}

fn validate_text(value: &str, field: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 160 || trimmed.chars().any(|c| c.is_control()) {
        return Err(format!("invalid {field}"));
    }
    Ok(())
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
}

fn gui_prompt(target: &str, label: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let title = format!("Enter secret — {label}");
    let message =
        format!("Enter the secret for {target}.\nIt will be stored only in the local OS keyring.");
    let (program, args): (PathBuf, Vec<String>) = if let Some(path) = find_executable("zenity") {
        (
            path,
            vec![
                "--password".into(),
                "--hide-text".into(),
                "--title".into(),
                title,
                "--text".into(),
                message,
            ],
        )
    } else if let Some(path) = find_executable("kdialog") {
        (path, vec!["--title".into(), title, "--password".into(), message])
    } else {
        return Err("no supported GUI prompt found; install zenity or kdialog".into());
    };

    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| "the local GUI prompt could not be opened".to_string())?;
    if !output.status.success() {
        return Err("secret entry was cancelled or the local GUI prompt failed".into());
    }
    let mut secret = output.stdout;
    while matches!(secret.last(), Some(b'\n' | b'\r')) {
        secret.pop();
    }
    if secret.is_empty() {
        return Err("empty secret is not accepted".into());
    }
    Ok(Zeroizing::new(secret))
}

fn capture(target: &str, label: &str, ttl_seconds: u64, single_use: bool) -> Result<Value, String> {
    validate_text(target, "target")?;
    validate_text(label, "label")?;
    let ttl = ttl_seconds.clamp(1, MAX_TTL_SECONDS);
    let secret = gui_prompt(target.trim(), label.trim())?;
    let handle = format!("sh_{}", Uuid::new_v4().simple());
    let account = format!("handoff:{handle}");
    secret_tool_store(&account, target, label, secret.as_slice())?;
    let record = SecretRecord {
        handle: handle.clone(),
        target: target.trim().to_owned(),
        label: label.trim().to_owned(),
        created_at: now(),
        expires_at: now().saturating_add(ttl),
        single_use,
        status: "active".into(),
        keyring_account: account,
        consumed_at: None,
    };
    let result = with_state(|state| {
        state.records.insert(handle.clone(), record.clone());
        Ok(
            json!({"handle": handle, "target": record.target, "label": record.label, "expires_at": record.expires_at, "single_use": record.single_use, "status": "active"}),
        )
    });
    if result.is_err() {
        let _ = secret_tool_clear(&record.keyring_account);
    }
    result
}

fn public_record(record: &SecretRecord) -> Value {
    let status = if record.status == "active" && now() >= record.expires_at {
        "expired"
    } else {
        record.status.as_str()
    };
    json!({"handle": record.handle, "target": record.target, "label": record.label, "created_at": record.created_at, "expires_at": record.expires_at, "single_use": record.single_use, "status": status})
}

fn list_status(handle: Option<&str>) -> Result<Value, String> {
    with_state_read(|state| {
        if let Some(handle) = handle {
            return state
                .records
                .get(handle)
                .map(public_record)
                .ok_or_else(|| "unknown handle".into());
        }
        let records = state.records.values().map(public_record).collect::<Vec<_>>();
        Ok(json!({"records": records}))
    })
}

fn delete(handle: &str) -> Result<Value, String> {
    let record = read_record(handle)?;
    let clear_result = secret_tool_clear(&record.keyring_account);
    with_state(|state| {
        if let Some(entry) = state.records.get_mut(handle) {
            entry.status = "deleted".into();
        }
        Ok(())
    })?;
    clear_result?;
    Ok(json!({"handle": handle, "status": "deleted"}))
}

fn claim_for_run(handle: &str) -> Result<SecretRecord, String> {
    with_state(|state| {
        let record = state.records.get_mut(handle).ok_or_else(|| "unknown handle".to_string())?;
        if record.status != "active" || now() >= record.expires_at {
            return Err("handle is not active".into());
        }
        let claimed = record.clone();
        if record.single_use {
            record.status = "consuming".into();
        }
        Ok(claimed)
    })
}

fn operations() -> Result<OperationsFile, String> {
    let path = config_file();
    let bytes = fs::read(path).map_err(|_| "operation allowlist is unavailable")?;
    serde_json::from_slice(&bytes).map_err(|_| "operation allowlist is invalid".into())
}

fn run_operation(handle: &str, operation_name: &str) -> Result<Value, String> {
    validate_text(operation_name, "operation")?;
    let record = claim_for_run(handle)?;
    let operation = operations()?
        .operations
        .get(operation_name)
        .cloned()
        .ok_or_else(|| "operation is not allowlisted".to_string())?;
    if !Path::new(&operation.command).is_absolute()
        || operation.secret_env.is_empty()
        || operation.secret_env.contains('=')
        || operation.secret_env.chars().any(|c| c.is_control())
        || matches!(
            operation.secret_env.as_str(),
            "PATH" | "LD_PRELOAD" | "LD_LIBRARY_PATH" | "BASH_ENV" | "ENV" | "PYTHONINSPECT"
        )
        || !Path::new(&operation.command).is_file()
    {
        return Err("operation allowlist entry is invalid".into());
    }
    let secret = match secret_tool_lookup(&record.keyring_account) {
        Ok(secret) => secret,
        Err(error) => {
            if record.single_use {
                let _ = with_state(|state| {
                    if let Some(entry) = state.records.get_mut(handle) {
                        entry.status = "consumed".into();
                        entry.consumed_at = Some(now());
                    }
                    Ok(())
                });
            }
            return Err(error);
        },
    };
    if record.single_use {
        with_state(|state| {
            if let Some(entry) = state.records.get_mut(handle) {
                entry.status = "consumed".into();
                entry.consumed_at = Some(now());
            }
            Ok(())
        })?;
        secret_tool_clear(&record.keyring_account)?;
    }
    let started = std::time::Instant::now();
    let secret_value =
        std::str::from_utf8(secret.as_slice()).map_err(|_| "secret is not valid UTF-8")?;
    let mut child = Command::new(&operation.command)
        .args(&operation.args)
        .env(&operation.secret_env, secret_value)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "allowlisted operation could not start")?;
    let deadline = started + Duration::from_secs(120);
    let exit_code = loop {
        if let Some(status) = child.try_wait().map_err(|_| "allowlisted operation status failed")? {
            break status.code();
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("allowlisted operation timed out".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Ok(
        json!({"handle": handle, "operation": operation_name, "status": if exit_code == Some(0) { "succeeded" } else { "failed" }, "exit_code": exit_code, "duration_ms": started.elapsed().as_millis()}),
    )
}

fn text_result(value: Value) -> Value {
    json!({"content":[{"type":"text","text":serde_json::to_string(&value).unwrap_or_else(|_| "{}".into())}],"structuredContent":value})
}

fn error_result(message: &str) -> Value {
    json!({"isError":true,"content":[{"type":"text","text":message}]})
}

fn tools_list() -> Value {
    json!({"tools":[
      {"name":"secret_handoff_capture","description":"Open a local GUI prompt, store the entered secret in the OS keyring, and return only an opaque handle; the secret is never an MCP argument or response.","inputSchema":{"type":"object","properties":{"target":{"type":"string"},"label":{"type":"string"},"ttl_seconds":{"type":"integer","minimum":1,"maximum":86400},"single_use":{"type":"boolean"}},"required":["target","label"]},"annotations":{"readOnlyHint":false,"destructiveHint":false}},
      {"name":"secret_handoff_status","description":"Read redacted handles and lifecycle metadata; never returns secret material.","inputSchema":{"type":"object","properties":{"handle":{"type":"string"}}},"annotations":{"readOnlyHint":true}},
      {"name":"secret_handoff_delete","description":"Delete one exact handle from the OS keyring and mark it deleted.","inputSchema":{"type":"object","properties":{"handle":{"type":"string"}},"required":["handle"]},"annotations":{"readOnlyHint":false,"destructiveHint":true}},
      {"name":"secret_handoff_run","description":"Run one locally configured absolute command with a handle injected into its configured environment variable; command and args are never supplied by the model.","inputSchema":{"type":"object","properties":{"handle":{"type":"string"},"operation":{"type":"string"}},"required":["handle","operation"]},"annotations":{"readOnlyHint":false,"destructiveHint":false}}
    ]})
}

fn request_response(id: Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}

fn handle_request(request: &Value) -> Option<Value> {
    let method = request.get("method")?.as_str()?;
    let id = request.get("id").cloned();
    if method.starts_with("notifications/") {
        return None;
    }
    let id = id.unwrap_or(Value::Null);
    let result = match method {
        "initialize" => {
            json!({"protocolVersion":PROTOCOL_VERSION,"capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"codex-secret-handoff-mcp","version":env!("CARGO_PKG_VERSION")}})
        },
        "ping" => json!({}),
        "tools/list" => tools_list(),
        "tools/call" => {
            let params = request.get("params").and_then(|v| v.as_object());
            let name = params.and_then(|p| p.get("name")).and_then(Value::as_str);
            let args =
                params.and_then(|p| p.get("arguments")).cloned().unwrap_or_else(|| json!({}));
            let outcome = match (name, args) {
                (Some("secret_handoff_capture"), args) => capture(
                    args.get("target").and_then(Value::as_str).unwrap_or(""),
                    args.get("label").and_then(Value::as_str).unwrap_or(""),
                    args.get("ttl_seconds").and_then(Value::as_u64).unwrap_or(DEFAULT_TTL_SECONDS),
                    args.get("single_use").and_then(Value::as_bool).unwrap_or(true),
                ),
                (Some("secret_handoff_status"), args) => {
                    list_status(args.get("handle").and_then(Value::as_str))
                },
                (Some("secret_handoff_delete"), args) => args
                    .get("handle")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "handle is required".into())
                    .and_then(delete),
                (Some("secret_handoff_run"), args) => match (
                    args.get("handle").and_then(Value::as_str),
                    args.get("operation").and_then(Value::as_str),
                ) {
                    (Some(handle), Some(operation)) => run_operation(handle, operation),
                    _ => Err("handle and operation are required".into()),
                },
                (Some(_), _) => Err("unknown tool".into()),
                (None, _) => Err("tool name is required".into()),
            };
            match outcome {
                Ok(value) => text_result(value),
                Err(message) => error_result(&message),
            }
        },
        _ => error_result("method not found"),
    };
    Some(request_response(id, result))
}

fn serve() -> Result<(), String> {
    let stdin = io::stdin();
    let mut stdout = BufWriter::new(io::stdout());
    for line in BufReader::new(stdin.lock()).lines() {
        let line = line.map_err(|_| "stdio read failed")?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(request) => handle_request(&request),
            Err(_) => Some(
                json!({"jsonrpc":"2.0","id":Value::Null,"error":{"code":-32700,"message":"invalid JSON"}}),
            ),
        };
        if let Some(response) = response {
            serde_json::to_writer(&mut stdout, &response).map_err(|_| "stdio write failed")?;
            stdout.write_all(b"\n").map_err(|_| "stdio write failed")?;
            stdout.flush().map_err(|_| "stdio flush failed")?;
        }
    }
    Ok(())
}

fn print_json(value: Value) {
    println!("{}", serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".into()));
}

fn cli(args: &[String]) -> Result<(), String> {
    match args.get(1).map(String::as_str).unwrap_or("serve") {
        "serve" => serve(),
        "capture" => {
            let mut target = None;
            let mut label = None;
            let mut ttl = DEFAULT_TTL_SECONDS;
            let mut single_use = true;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--target" => {
                        i += 1;
                        target = args.get(i).cloned();
                    },
                    "--label" => {
                        i += 1;
                        label = args.get(i).cloned();
                    },
                    "--ttl-seconds" => {
                        i += 1;
                        ttl = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(0);
                    },
                    "--reusable" => single_use = false,
                    _ => return Err("unknown capture argument".into()),
                }
                i += 1;
            }
            print_json(capture(
                target.as_deref().unwrap_or(""),
                label.as_deref().unwrap_or(""),
                ttl,
                single_use,
            )?);
            Ok(())
        },
        "status" => {
            print_json(list_status(args.get(2).map(String::as_str))?);
            Ok(())
        },
        "delete" => {
            let handle = args.get(2).ok_or_else(|| "handle is required".to_string())?;
            print_json(delete(handle)?);
            Ok(())
        },
        "run" => {
            let handle = args
                .iter()
                .position(|a| a == "--handle")
                .and_then(|i| args.get(i + 1))
                .ok_or_else(|| "handle is required".to_string())?;
            let operation = args
                .iter()
                .position(|a| a == "--operation")
                .and_then(|i| args.get(i + 1))
                .ok_or_else(|| "operation is required".to_string())?;
            print_json(run_operation(handle, operation)?);
            Ok(())
        },
        _ => Err("commands: serve, capture, status, delete, run".into()),
    }
}

fn main() {
    if let Err(message) = cli(&env::args().collect::<Vec<_>>()) {
        eprintln!("codex-secret-handoff: {message}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_record_contains_no_secret_field() {
        let record = SecretRecord {
            handle: "sh_test".into(),
            target: "test".into(),
            label: "unit".into(),
            created_at: 1,
            expires_at: u64::MAX,
            single_use: true,
            status: "active".into(),
            keyring_account: "handoff:sh_test".into(),
            consumed_at: None,
        };
        let rendered = serde_json::to_string(&public_record(&record)).unwrap();
        assert!(!rendered.contains("keyring_account"));
        assert!(!rendered.contains("plaintext"));
        assert!(rendered.contains("sh_test"));
    }

    #[test]
    fn tool_catalog_has_no_secret_argument() {
        let rendered = tools_list().to_string();
        assert!(!rendered.contains("secret_value"));
        assert!(!rendered.contains("password"));
        assert!(rendered.contains("secret_handoff_capture"));
    }
}
