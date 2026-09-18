#[cfg(not(target_os = "linux"))]
compile_error!("codex-secret-handoff-mcp currently supports Linux only");

use fs2::FileExt;
use rmcp::{
    ErrorData, RoleServer, ServerHandler, ServiceExt,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, Implementation, ListToolsResult,
        PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool, ToolAnnotations,
    },
    service::RequestContext,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    env,
    ffi::{CStr, CString},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::fd::{AsRawFd, FromRawFd, RawFd},
    path::{Component, Path, PathBuf},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    sync::{Arc, OnceLock},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::Semaphore;
use tokio::task;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

const SERVICE: &str = "codex-secret-handoff";
const DEFAULT_TTL_SECONDS: u64 = 900;
const MAX_TTL_SECONDS: u64 = 86_400;
const KEYRING_TIMEOUT: Duration = Duration::from_secs(10);
const GUI_TIMEOUT: Duration = Duration::from_secs(60);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
const LEASE_TIMEOUT: Duration = Duration::from_secs(180);
const RECONCILE_TIMEOUT: Duration = Duration::from_secs(15);
const STATE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SECRET_BYTES: usize = 64 * 1024;
const MAX_CHILD_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_PROVIDER_OUTPUT_BYTES: usize = MAX_SECRET_BYTES + 1;
const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_OPERATION_FILE_BYTES: u64 = 256 * 1024;
const MAX_TOOL_ARGUMENT_BYTES: usize = 64 * 1024;
const MAX_MCP_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECORDS: usize = 1024;
const MAX_OPERATIONS: usize = 256;
const MAX_OPERATION_ARGS: usize = 64;
const MAX_CONCURRENT_OPERATIONS: usize = 4;
const MAX_CONCURRENT_CONTROL_OPERATIONS: usize = 2;
const MAX_OPERATION_CGROUPS: usize = 1024;
const OPERATION_CGROUP_LEASE: Duration = Duration::from_secs(120);
const OPERATION_CGROUP_ORPHAN_GRACE: Duration = Duration::from_secs(30);
const OPERATION_LEASE_GRACE: Duration = Duration::from_secs(30);
const CURRENT_STATE_SCHEMA_VERSION: u32 = 4;
const SAFE_LOCAL_ENVIRONMENT: &[&str] = &[
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_RUNTIME_DIR",
    "GDK_BACKEND",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct CgroupIdentity {
    dev: u64,
    ino: u64,
}

#[cfg(unix)]
#[derive(Debug)]
struct SecureFile {
    file: File,
    identity: CgroupIdentity,
}

#[cfg(unix)]
impl SecureFile {
    fn verify_identity(&self) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        let metadata = self.file.metadata().map_err(|_| "secure file cannot be inspected")?;
        if metadata.dev() != self.identity.dev || metadata.ino() != self.identity.ino {
            return Err("secure file identity changed".into());
        }
        Ok(())
    }

    fn exec_path(&self) -> Result<PathBuf, String> {
        self.verify_identity()?;
        Ok(PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd())))
    }

    fn read_bytes(&self, limit: u64) -> Result<Vec<u8>, String> {
        self.verify_identity()?;
        let file = self.file.try_clone().map_err(|_| "secure file cannot be read")?;
        let mut bytes = Vec::new();
        file.take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| "secure file cannot be read")?;
        if bytes.len() as u64 > limit {
            return Err("secure file exceeds the configured limit".into());
        }
        Ok(bytes)
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct OperationCgroup {
    path: PathBuf,
    identity: CgroupIdentity,
    file: File,
    parent: File,
    name: CString,
}

static PROCESS_OWNER: OnceLock<String> = OnceLock::new();

fn process_owner() -> &'static str {
    PROCESS_OWNER.get_or_init(process_identity).as_str()
}

fn process_identity() -> String {
    let pid = unsafe { libc::getpid() } as u32;
    let start_ticks = process_start_ticks(pid).ok().flatten().unwrap_or_default();
    let boot = boot_id().unwrap_or_default();
    format!("{pid}:{start_ticks}:{boot}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessLiveness {
    Alive,
    Dead,
    Unknown,
}

fn process_identity_liveness(identity: &str) -> ProcessLiveness {
    let mut parts = identity.splitn(3, ':');
    let (Some(pid), Some(start_ticks), Some(expected_boot)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return ProcessLiveness::Unknown;
    };
    let (Ok(pid), Ok(start_ticks)) = (pid.parse::<u32>(), start_ticks.parse::<u64>()) else {
        return ProcessLiveness::Unknown;
    };
    if pid == 0 || start_ticks == 0 || expected_boot.is_empty() {
        return ProcessLiveness::Unknown;
    }
    match boot_id() {
        Some(current_boot) if current_boot != expected_boot => ProcessLiveness::Dead,
        Some(_) => match process_start_ticks(pid) {
            Ok(Some(current_ticks)) if current_ticks == start_ticks => ProcessLiveness::Alive,
            Ok(Some(_)) | Ok(None) => ProcessLiveness::Dead,
            Err(_) => ProcessLiveness::Unknown,
        },
        None => ProcessLiveness::Unknown,
    }
}

#[cfg(test)]
fn process_identity_is_alive(identity: &str) -> bool {
    matches!(process_identity_liveness(identity), ProcessLiveness::Alive)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum LifecycleStatus {
    Provisioning,
    #[default]
    Active,
    Claimed,
    Running,
    CleanupPending,
    Consumed,
    Deleted,
    Expired,
    Revoked,
}

impl<'de> Deserialize<'de> for LifecycleStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "provisioning" => Ok(Self::Provisioning),
            "active" => Ok(Self::Active),
            "claimed" => Ok(Self::Claimed),
            "running" => Ok(Self::Running),
            "consuming" | "cleanup_pending" => Ok(Self::CleanupPending),
            "consumed" => Ok(Self::Consumed),
            "deleted" => Ok(Self::Deleted),
            "expired" => Ok(Self::Expired),
            "revoked" => Ok(Self::Revoked),
            _ => Err(serde::de::Error::custom("unknown lifecycle status")),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SecretRecord {
    handle: String,
    target: String,
    label: String,
    created_at: u64,
    expires_at: u64,
    single_use: bool,
    #[serde(default)]
    status: LifecycleStatus,
    keyring_account: String,
    consumed_at: Option<u64>,
    #[serde(default)]
    claim_id: Option<String>,
    #[serde(default)]
    cleanup_target: Option<LifecycleStatus>,
    #[serde(default)]
    last_error: Option<String>,
    #[serde(default)]
    generation: u64,
    #[serde(default)]
    lease_owner: Option<String>,
    #[serde(default)]
    lease_expires_at: Option<u64>,
    #[serde(default)]
    lease_expires_mono: Option<u64>,
    #[serde(default)]
    lease_boot_id: Option<String>,
    #[serde(default)]
    expires_mono: Option<u64>,
    #[serde(default)]
    expires_boot_id: Option<String>,
    #[serde(default)]
    helper_pid: Option<u32>,
    #[serde(default)]
    helper_pgid: Option<i32>,
    #[serde(default)]
    helper_start_ticks: Option<u64>,
    #[serde(default)]
    helper_boot_id: Option<String>,
    #[serde(default)]
    helper_kind: Option<String>,
    #[serde(default)]
    helper_cgroup: Option<String>,
    #[serde(default)]
    helper_cgroup_identity: Option<CgroupIdentity>,
    #[serde(default)]
    cleanup_keyring_done: bool,
    #[serde(default)]
    helper_descendants_unknown: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct State {
    #[serde(default = "legacy_state_schema_version")]
    schema_version: u32,
    records: BTreeMap<String, SecretRecord>,
    #[serde(default)]
    operation_cgroups: BTreeMap<String, OperationCgroupFence>,
    #[serde(default)]
    recovery_mode: bool,
}

impl Default for State {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_STATE_SCHEMA_VERSION,
            records: BTreeMap::new(),
            operation_cgroups: BTreeMap::new(),
            recovery_mode: false,
        }
    }
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
struct OperationCgroupFence {
    owner: String,
    expires_at: u64,
    expires_mono: Option<u64>,
    boot_id: Option<String>,
    #[serde(default)]
    identity: Option<CgroupIdentity>,
}

impl<'de> Deserialize<'de> for OperationCgroupFence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Current {
            owner: String,
            expires_at: u64,
            #[serde(default)]
            expires_mono: Option<u64>,
            #[serde(default)]
            boot_id: Option<String>,
            #[serde(default)]
            identity: Option<CgroupIdentity>,
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Input {
            Current(Current),
            Legacy(String),
        }

        match Input::deserialize(deserializer)? {
            Input::Current(current) => Ok(Self {
                owner: current.owner,
                expires_at: current.expires_at,
                expires_mono: current.expires_mono,
                boot_id: current.boot_id,
                identity: current.identity,
            }),
            Input::Legacy(owner) => {
                Ok(Self { owner, expires_at: 0, expires_mono: None, boot_id: None, identity: None })
            },
        }
    }
}

fn legacy_state_schema_version() -> u32 {
    1
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

#[derive(Debug, Clone)]
struct RunClaim {
    handle: String,
    account: String,
    claim_id: String,
    single_use: bool,
    generation: u64,
}

#[derive(Debug, Clone)]
struct CleanupAction {
    handle: String,
    account: String,
    target: LifecycleStatus,
    generation: u64,
    helper_pid: Option<u32>,
    helper_pgid: Option<i32>,
    helper_start_ticks: Option<u64>,
    helper_boot_id: Option<String>,
    helper_cgroup: Option<String>,
    helper_cgroup_identity: Option<CgroupIdentity>,
    cleanup_keyring_done: bool,
    helper_descendants_unknown: bool,
}

fn cleanup_action_for(record: &SecretRecord, target: LifecycleStatus) -> CleanupAction {
    CleanupAction {
        handle: record.handle.clone(),
        account: record.keyring_account.clone(),
        target,
        generation: record.generation,
        helper_pid: record.helper_pid,
        helper_pgid: record.helper_pgid,
        helper_start_ticks: record.helper_start_ticks,
        helper_boot_id: record.helper_boot_id.clone(),
        helper_cgroup: record.helper_cgroup.clone(),
        helper_cgroup_identity: record.helper_cgroup_identity,
        cleanup_keyring_done: record.cleanup_keyring_done,
        helper_descendants_unknown: record.helper_descendants_unknown,
    }
}

fn cleanup_action_for_helper(helper: &HelperFence, target: LifecycleStatus) -> CleanupAction {
    CleanupAction {
        handle: helper.handle.clone(),
        account: String::new(),
        target,
        generation: helper.generation,
        helper_pid: Some(helper.pid),
        helper_pgid: Some(helper.pgid),
        helper_start_ticks: Some(helper.start_ticks),
        helper_boot_id: Some(helper.boot_id.clone()),
        helper_cgroup: helper.cgroup.clone(),
        helper_cgroup_identity: helper.cgroup_identity,
        cleanup_keyring_done: true,
        helper_descendants_unknown: false,
    }
}

#[derive(Debug, Clone)]
struct HelperFence {
    handle: String,
    pid: u32,
    pgid: i32,
    start_ticks: u64,
    boot_id: String,
    generation: u64,
    cgroup: Option<String>,
    cgroup_identity: Option<CgroupIdentity>,
    #[cfg(target_os = "linux")]
    live_cgroup: Option<Arc<OperationCgroup>>,
}

#[derive(Debug, Clone)]
struct CaptureFence {
    handle: String,
    generation: u64,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn boot_id() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn monotonic_seconds() -> Option<u64> {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|value| value.split_whitespace().next()?.parse::<f64>().ok())
        .map(|value| value.floor() as u64)
}

fn monotonic_pair() -> (Option<u64>, Option<String>) {
    match (monotonic_seconds(), boot_id()) {
        (Some(current), Some(current_boot)) => (Some(current), Some(current_boot)),
        _ => (None, None),
    }
}

fn operation_cgroup_fence(identity: CgroupIdentity) -> OperationCgroupFence {
    let (expires_mono_base, boot_id) = monotonic_pair();
    OperationCgroupFence {
        owner: process_identity(),
        expires_at: now().saturating_add(OPERATION_CGROUP_LEASE.as_secs()),
        expires_mono: expires_mono_base
            .map(|value| value.saturating_add(OPERATION_CGROUP_LEASE.as_secs())),
        boot_id,
        identity: Some(identity),
    }
}

fn operation_cgroup_fence_for_owner(owner: &str, identity: CgroupIdentity) -> OperationCgroupFence {
    let (expires_mono_base, boot_id) = monotonic_pair();
    OperationCgroupFence {
        owner: owner.to_owned(),
        expires_at: now(),
        expires_mono: expires_mono_base,
        boot_id,
        identity: Some(identity),
    }
}

fn operation_cgroup_expired(fence: &OperationCgroupFence) -> bool {
    match (fence.expires_mono, fence.boot_id.as_deref(), monotonic_seconds(), boot_id()) {
        (Some(expires), Some(expected_boot), Some(current), Some(current_boot)) => {
            expected_boot != current_boot || current >= expires
        },
        _ => now() >= fence.expires_at,
    }
}

fn operation_cgroup_owner_liveness(fence: &OperationCgroupFence) -> ProcessLiveness {
    if fence.owner == process_owner() {
        ProcessLiveness::Alive
    } else {
        process_identity_liveness(&fence.owner)
    }
}

#[cfg(test)]
fn operation_cgroup_owner_live(fence: &OperationCgroupFence) -> bool {
    matches!(operation_cgroup_owner_liveness(fence), ProcessLiveness::Alive)
}

fn record_expired(record: &SecretRecord) -> bool {
    match (record.expires_mono, record.expires_boot_id.as_deref(), monotonic_seconds(), boot_id()) {
        (Some(expires), Some(expected_boot), Some(current), Some(current_boot)) => {
            expected_boot != current_boot || current >= expires
        },
        _ => now() >= record.expires_at,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaseLiveness {
    Live,
    Expired,
    Unknown,
}

fn lease_liveness(record: &SecretRecord) -> LeaseLiveness {
    let Some(owner) = record.lease_owner.as_deref() else {
        return LeaseLiveness::Expired;
    };
    match if owner == process_owner() {
        ProcessLiveness::Alive
    } else {
        process_identity_liveness(owner)
    } {
        ProcessLiveness::Dead => return LeaseLiveness::Expired,
        ProcessLiveness::Unknown => return LeaseLiveness::Unknown,
        ProcessLiveness::Alive => {},
    }
    let current_boot = boot_id();
    lease_deadline_liveness(record, monotonic_seconds(), current_boot.as_deref(), now())
}

fn lease_deadline_liveness(
    record: &SecretRecord,
    current_mono: Option<u64>,
    current_boot: Option<&str>,
    current_wall: u64,
) -> LeaseLiveness {
    match (record.lease_expires_mono, record.lease_boot_id.as_deref()) {
        (Some(expires), Some(expected_boot)) => match (current_mono, current_boot) {
            (Some(current), Some(observed_boot)) => {
                if expected_boot == observed_boot && current < expires {
                    LeaseLiveness::Live
                } else {
                    LeaseLiveness::Expired
                }
            },
            _ => LeaseLiveness::Unknown,
        },
        (None, None) => match record.lease_expires_at {
            Some(expires_at) if expires_at > current_wall => LeaseLiveness::Live,
            Some(_) => LeaseLiveness::Expired,
            None => LeaseLiveness::Unknown,
        },
        _ => LeaseLiveness::Unknown,
    }
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

fn canonical_state_dir() -> Result<PathBuf, String> {
    let raw = state_dir();
    if !raw.is_absolute() {
        return Err("state directory must be an absolute path".into());
    }
    let mut existing = raw.clone();
    let mut suffix = Vec::new();
    loop {
        match fs::symlink_metadata(&existing) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err("state directory cannot contain symlink components".into());
                }
                break;
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let component = existing
                    .file_name()
                    .ok_or_else(|| "state directory has no valid name".to_string())?
                    .to_owned();
                suffix.push(component);
                existing.pop();
            },
            Err(_) => return Err("state directory cannot be inspected".into()),
        }
    }
    let mut canonical =
        fs::canonicalize(existing).map_err(|_| "state directory parent cannot be canonicalized")?;
    for component in suffix.iter().rev() {
        canonical.push(component);
    }
    Ok(canonical)
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

#[cfg(unix)]
fn open_private_directory(path: &Path) -> Result<File, String> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err("private directory must be an absolute path without dot components".into());
    }
    let uid = unsafe { libc::geteuid() };
    let system_owner = trusted_system_owner();
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|_| "private directory cannot be opened")?;
    for component in path.components().skip(1) {
        let name = CString::new(component.as_os_str().as_bytes())
            .map_err(|_| "private directory contains an invalid component")?;
        let next = match unsafe {
            libc::openat(
                current.as_raw_fd(),
                name.as_ptr(),
                libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            )
        } {
            fd if fd >= 0 => unsafe { File::from_raw_fd(fd) },
            _ if io::Error::last_os_error().kind() == io::ErrorKind::NotFound => {
                let result = unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o700) };
                if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                    return Err("private directory cannot be created".into());
                }
                let fd = unsafe {
                    libc::openat(
                        current.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        0,
                    )
                };
                if fd < 0 {
                    return Err("private directory cannot be opened".into());
                }
                unsafe { File::from_raw_fd(fd) }
            },
            _ => return Err("private directory cannot be opened".into()),
        };
        let metadata = next.metadata().map_err(|_| "private directory cannot be inspected")?;
        let mode = metadata.permissions().mode();
        let sticky_shared_directory = mode & 0o1000 != 0 && mode & 0o002 != 0;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("private path contains a non-directory component".into());
        }
        if metadata.uid() != uid
            && metadata.uid() != 0
            && system_owner != Some(metadata.uid())
            && !sticky_shared_directory
        {
            return Err("private path contains an unexpected owner".into());
        }
        if mode & 0o022 != 0 && !sticky_shared_directory {
            return Err("private path contains a writable directory".into());
        }
        current = next;
    }
    let metadata = current.metadata().map_err(|_| "private directory cannot be inspected")?;
    if metadata.uid() != uid && metadata.uid() != 0 {
        return Err("private directory has an unexpected owner".into());
    }
    if metadata.uid() == uid {
        current
            .set_permissions(fs::Permissions::from_mode(0o700))
            .map_err(|_| "private directory permissions cannot be set")?;
    }
    Ok(current)
}

#[cfg(not(unix))]
fn open_private_directory(path: &Path) -> Result<File, String> {
    if !path.is_absolute() {
        return Err("private directory must be absolute".into());
    }
    fs::create_dir_all(path).map_err(|_| "private directory cannot be created".to_string())?;
    File::open(path).map_err(|_| "private directory cannot be opened".into())
}

#[cfg(unix)]
fn trusted_system_owner() -> Option<u32> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let root = fs::symlink_metadata("/").ok()?;
    let usr = fs::symlink_metadata("/usr").ok()?;
    let uid = unsafe { libc::geteuid() };
    (root.is_dir()
        && usr.is_dir()
        && root.uid() == usr.uid()
        && root.uid() != uid
        && root.permissions().mode() & 0o022 == 0
        && usr.permissions().mode() & 0o022 == 0)
        .then_some(root.uid())
}

#[cfg(not(unix))]
fn trusted_system_owner() -> Option<u32> {
    None
}

#[cfg(test)]
fn read_state(dir: &Path) -> Result<State, String> {
    let directory = open_private_directory(dir)?;
    read_state_at(&directory)
}

fn read_state_at(directory: &File) -> Result<State, String> {
    let name = CString::new("state.json").expect("static state filename");
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    let bytes = if fd < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            let mut state = State::default();
            migrate_legacy_state(&mut state);
            return Ok(state);
        }
        return Err("state file cannot be opened".into());
    } else {
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|_| "state file cannot be inspected")?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("state file must be a regular non-symlink file".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let uid = unsafe { libc::geteuid() };
            if metadata.uid() != uid && metadata.uid() != 0 {
                return Err("state file has an unexpected owner".into());
            }
            if metadata.permissions().mode() & 0o022 != 0 {
                return Err("state file is writable by group or other users".into());
            }
        }
        let mut bytes = Vec::new();
        file.take(MAX_STATE_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| "state file cannot be read")?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err("state file exceeds the configured limit".into());
        }
        bytes
    };
    let mut state: State = serde_json::from_slice(&bytes).map_err(|_| "state file is invalid")?;
    if state.schema_version > CURRENT_STATE_SCHEMA_VERSION {
        return Err("state file uses a newer unsupported schema version".into());
    }
    migrate_legacy_state(&mut state);
    if state.recovery_mode && state.records.len() <= MAX_RECORDS {
        return Err("state recovery mode is invalid below the record capacity".into());
    }
    if state.records.len() > MAX_RECORDS && !state.recovery_mode {
        return Err("state record capacity has been reached".into());
    }
    if state.operation_cgroups.len() > MAX_OPERATION_CGROUPS {
        return Err("state operation cgroup capacity has been reached".into());
    }
    for (path, fence) in &state.operation_cgroups {
        if path.len() > 512
            || !Path::new(path).is_absolute()
            || Path::new(path)
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
            || path.chars().any(char::is_control)
            || fence.owner.is_empty()
            || fence.owner.len() > 128
            || fence.owner.chars().any(char::is_control)
            || fence.identity.is_none()
            || fence.identity.is_some_and(|identity| identity.dev == 0 || identity.ino == 0)
            || fence.boot_id.as_ref().is_some_and(|value| {
                value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
            })
            || fence.expires_mono.is_some() != fence.boot_id.is_some()
        {
            return Err("state operation cgroup fence is invalid".into());
        }
    }
    for (map_handle, record) in &state.records {
        if record.handle.len() > 160
            || record.target.len() > 160
            || record.label.len() > 160
            || record.keyring_account.len() > 256
            || record.claim_id.as_ref().is_some_and(|value| value.len() > 128)
            || record.lease_owner.as_ref().is_some_and(|value| value.len() > 128)
            || record.lease_boot_id.as_ref().is_some_and(|value| value.len() > 128)
            || record.expires_boot_id.as_ref().is_some_and(|value| value.len() > 128)
            || record.helper_boot_id.as_ref().is_some_and(|value| value.len() > 128)
            || record.helper_kind.as_ref().is_some_and(|value| value.len() > 128)
            || record.last_error.as_ref().is_some_and(|value| value.len() > 2048)
            || record.helper_cgroup.as_ref().is_some_and(|path| {
                path.len() > 512
                    || !Path::new(path).is_absolute()
                    || Path::new(path).components().any(|component| {
                        matches!(component, Component::ParentDir | Component::CurDir)
                    })
                    || path.chars().any(char::is_control)
            })
            || record
                .helper_cgroup_identity
                .is_some_and(|identity| identity.dev == 0 || identity.ino == 0)
            || map_handle != &record.handle
            || record.keyring_account != format!("handoff:{}", record.handle)
            || record.handle.trim().is_empty()
            || record.handle.chars().any(|value| value.is_control())
            || record.target.trim().is_empty()
            || record.label.trim().is_empty()
            || record.target.chars().any(|value| value.is_control())
            || record.label.chars().any(|value| value.is_control())
            || record.claim_id.as_ref().is_some_and(|value| value.chars().any(char::is_control))
            || record.lease_owner.as_ref().is_some_and(|value| value.chars().any(char::is_control))
            || record
                .lease_boot_id
                .as_ref()
                .is_some_and(|value| value.chars().any(char::is_control))
            || record
                .expires_boot_id
                .as_ref()
                .is_some_and(|value| value.chars().any(char::is_control))
            || record
                .helper_boot_id
                .as_ref()
                .is_some_and(|value| value.chars().any(char::is_control))
            || record.helper_kind.as_ref().is_some_and(|value| value.chars().any(char::is_control))
            || record.last_error.as_ref().is_some_and(|value| value.chars().any(char::is_control))
        {
            return Err("state record exceeds the configured limit".into());
        }
        if record.lease_owner.is_some() != record.lease_expires_at.is_some()
            || record.lease_expires_mono.is_some() != record.lease_boot_id.is_some()
            || record.expires_mono.is_some() != record.expires_boot_id.is_some()
            || record.helper_pid.is_some() != record.helper_pgid.is_some()
            || record.helper_pid.is_some() != record.helper_start_ticks.is_some()
            || record.helper_pid.is_some() != record.helper_boot_id.is_some()
            || record.helper_pid.is_some() != record.helper_kind.is_some()
            || (record.helper_cgroup.is_some() != record.helper_cgroup_identity.is_some()
                && !record.helper_descendants_unknown)
            || (record.helper_cgroup.is_some()
                && record.helper_pid.is_none()
                && !matches!(
                    record.status,
                    LifecycleStatus::Claimed | LifecycleStatus::CleanupPending
                ))
            || (record.helper_descendants_unknown
                && !matches!(
                    record.status,
                    LifecycleStatus::CleanupPending | LifecycleStatus::Revoked
                ))
        {
            return Err("state record lifecycle fence is invalid".into());
        }
        if let (Some(pid), Some(pgid), Some(start_ticks)) =
            (record.helper_pid, record.helper_pgid, record.helper_start_ticks)
            && (pid == 0 || pgid <= 1 || pgid != pid as i32 || start_ticks == 0)
        {
            return Err("state record helper identity is invalid".into());
        }
        if record.cleanup_target.is_some_and(|target| {
            !matches!(
                target,
                LifecycleStatus::Consumed | LifecycleStatus::Deleted | LifecycleStatus::Expired
            )
        }) {
            return Err("state record cleanup target is invalid".into());
        }
        match record.status {
            LifecycleStatus::Provisioning => {
                if record.claim_id.is_some() || record.lease_owner.is_none() {
                    return Err("provisioning record lifecycle is invalid".into());
                }
            },
            LifecycleStatus::Active => {
                if record.claim_id.is_some()
                    || record.lease_owner.is_some()
                    || record.helper_pid.is_some()
                    || record.cleanup_target.is_some()
                {
                    return Err("active record lifecycle is invalid".into());
                }
            },
            LifecycleStatus::Claimed => {
                if record.claim_id.is_none() || record.lease_owner.is_none() {
                    return Err("claimed record lifecycle is invalid".into());
                }
            },
            LifecycleStatus::Running => {
                if record.claim_id.is_none()
                    || record.lease_owner.is_none()
                    || record.helper_pid.is_none()
                {
                    return Err("running record lifecycle is invalid".into());
                }
            },
            LifecycleStatus::CleanupPending | LifecycleStatus::Revoked => {},
            LifecycleStatus::Consumed | LifecycleStatus::Deleted | LifecycleStatus::Expired => {
                if record.claim_id.is_some()
                    || record.lease_owner.is_some()
                    || record.helper_pid.is_some()
                    || record.cleanup_target.is_some()
                    || record.cleanup_keyring_done
                    || record.helper_descendants_unknown
                {
                    return Err("terminal record lifecycle is invalid".into());
                }
            },
        }
    }
    for record in state.records.values() {
        if record.status == LifecycleStatus::CleanupPending && record.cleanup_target.is_none() {
            return Err("cleanup-pending record has no target".into());
        }
    }
    Ok(state)
}

fn migrate_legacy_state(state: &mut State) {
    let needs_schema_migration = state.schema_version != CURRENT_STATE_SCHEMA_VERSION;
    for record in state.records.values_mut() {
        if record.helper_cgroup.is_some() && record.helper_cgroup_identity.is_none() {
            record.helper_descendants_unknown = true;
            record.status = LifecycleStatus::CleanupPending;
            if record.cleanup_target.is_none() {
                record.cleanup_target = Some(LifecycleStatus::Deleted);
            }
            record.claim_id = None;
            record.lease_owner = None;
            record.lease_expires_at = None;
            record.lease_expires_mono = None;
            record.lease_boot_id = None;
            record.helper_cgroup = None;
            record.helper_cgroup_identity = None;
            record.generation = record.generation.saturating_add(1);
        }
        if needs_schema_migration {
            match record.status {
                LifecycleStatus::Consumed | LifecycleStatus::Deleted | LifecycleStatus::Expired => {
                    let target = record.status;
                    record.status = LifecycleStatus::CleanupPending;
                    record.cleanup_target = Some(target);
                    record.generation = record.generation.saturating_add(1);
                },
                LifecycleStatus::CleanupPending if record.cleanup_target.is_none() => {
                    record.cleanup_target = Some(LifecycleStatus::Consumed);
                },
                _ => {},
            }
        }
    }
    state.operation_cgroups.retain(|_, fence| fence.identity.is_some());
    if needs_schema_migration {
        state.schema_version = CURRENT_STATE_SCHEMA_VERSION;
        prune_terminal_records(state);
        state.recovery_mode = state.records.len() > MAX_RECORDS;
    }
}

/// Removes abandoned `state.json.<uuid>.tmp` files left behind by an interrupted
/// commit (process death between create and rename) or by a failed commit.
/// Only files older than `STALE_STATE_TMP_AGE` are removed so that the in-flight
/// temporary file of a concurrent writer is never touched. Best effort: callers
/// ignore failures, a dirty directory must not block state commits.
const STALE_STATE_TMP_AGE: Duration = Duration::from_secs(600);

fn sweep_stale_state_tmp(directory: &File) -> Result<(), String> {
    let dir_fd = directory.as_raw_fd();
    let dup = unsafe { libc::fcntl(dir_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return Err("state directory cannot be inspected".into());
    }
    let stream = unsafe { libc::fdopendir(dup) };
    if stream.is_null() {
        unsafe {
            libc::close(dup);
        }
        return Err("state directory cannot be read".into());
    }
    let mut candidates: Vec<CString> = Vec::new();
    loop {
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let bytes = name.to_bytes();
        if bytes.starts_with(b"state.json.") && bytes.ends_with(b".tmp") {
            candidates.push(name.to_owned());
        }
    }
    unsafe {
        libc::closedir(stream);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);
    for name in candidates {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(dir_fd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) }
            != 0
        {
            continue;
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            continue;
        }
        if now - (stat.st_mtime as i64) < STALE_STATE_TMP_AGE.as_secs() as i64 {
            continue;
        }
        unsafe {
            libc::unlinkat(dir_fd, name.as_ptr(), 0);
        }
    }
    Ok(())
}

/// Temporary state file that removes itself unless its rename committed, so a
/// failed or aborted commit cannot leave `state.json.<uuid>.tmp` behind.
struct PendingStateTmp<'a> {
    directory: &'a File,
    name: CString,
    committed: bool,
}

impl Drop for PendingStateTmp<'_> {
    fn drop(&mut self) {
        if !self.committed {
            unsafe {
                libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0);
            }
        }
    }
}

fn write_state_at(directory: &File, state: &mut State) -> Result<(), String> {
    let _ = sweep_stale_state_tmp(directory);
    prune_terminal_records(state);
    if state.records.len() > MAX_RECORDS {
        if !state.recovery_mode {
            return Err("state record capacity has been reached".into());
        }
    } else {
        state.recovery_mode = false;
    }
    if state.operation_cgroups.len() > MAX_OPERATION_CGROUPS {
        return Err("state operation cgroup capacity has been reached".into());
    }
    let payload = serde_json::to_vec_pretty(state).map_err(|_| "state cannot be serialized")?;
    let tmp_name = CString::new(format!("state.json.{}.tmp", Uuid::new_v4()))
        .map_err(|_| "temporary state filename is invalid")?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            tmp_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err("temporary state file cannot be created".into());
    }
    let mut temporary = PendingStateTmp { directory, name: tmp_name, committed: false };
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(&payload)
        .and_then(|_| file.sync_all())
        .map_err(|_| "state cannot be written")?;
    let state_name = CString::new("state.json").expect("static state filename");
    let rename_result = unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            temporary.name.as_ptr(),
            directory.as_raw_fd(),
            state_name.as_ptr(),
        )
    };
    if rename_result < 0 {
        return Err("state cannot be committed".into());
    }
    temporary.committed = true;
    directory.sync_all().map_err(|_| "state directory cannot be synchronized")?;
    Ok(())
}

fn register_operation_cgroup(raw: &str, identity: CgroupIdentity) -> Result<(), String> {
    if register_operation_cgroup_with_owner(raw, identity, process_owner())? {
        Ok(())
    } else {
        Err("operation cgroup is already registered".into())
    }
}

fn register_operation_cgroup_with_owner(
    raw: &str,
    identity: CgroupIdentity,
    owner: &str,
) -> Result<bool, String> {
    with_state(|state| {
        if state.operation_cgroups.len() >= MAX_OPERATION_CGROUPS
            && !state.operation_cgroups.contains_key(raw)
        {
            return Err("operation cgroup capacity has been reached".into());
        }
        if state.operation_cgroups.contains_key(raw) {
            return Ok(false);
        }
        let fence = if owner == process_owner() {
            operation_cgroup_fence(identity)
        } else {
            operation_cgroup_fence_for_owner(owner, identity)
        };
        state.operation_cgroups.insert(raw.to_owned(), fence);
        Ok(true)
    })
}

fn register_operation_cgroup_replacing_identity(
    raw: &str,
    expected_existing: Option<CgroupIdentity>,
    identity: CgroupIdentity,
    owner: &str,
) -> Result<bool, String> {
    with_state(|state| {
        if let Some(existing) = state.operation_cgroups.get(raw) {
            if existing.identity == Some(identity) {
                return Ok(false);
            }
            match expected_existing {
                Some(expected) if existing.identity == Some(expected) => {
                    state.operation_cgroups.remove(raw);
                },
                _ => return Ok(false),
            }
        }
        if state.operation_cgroups.len() >= MAX_OPERATION_CGROUPS
            && !state.operation_cgroups.contains_key(raw)
        {
            return Err("operation cgroup capacity has been reached".into());
        }
        let fence = if owner == process_owner() {
            operation_cgroup_fence(identity)
        } else {
            operation_cgroup_fence_for_owner(owner, identity)
        };
        state.operation_cgroups.insert(raw.to_owned(), fence);
        Ok(true)
    })
}

fn unregister_operation_cgroup_if_identity(
    raw: &str,
    identity: CgroupIdentity,
) -> Result<(), String> {
    with_state(|state| {
        if let Some(existing) = state.operation_cgroups.get(raw)
            && existing.identity == Some(identity)
        {
            state.operation_cgroups.remove(raw);
        }
        Ok(())
    })
}

fn forget_operation_cgroup_if_absent(raw: &str, identity: CgroupIdentity) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        if open_cgroup_dir(raw, Some(identity))?.is_none() {
            unregister_operation_cgroup_if_identity(raw, identity)?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = identity;
        with_state(|state| {
            state.operation_cgroups.remove(raw);
            Ok(())
        })?;
    }
    Ok(())
}

fn open_state_lock_at(directory: &File, exclusive: bool) -> Result<File, String> {
    let name = CString::new("state.lock").expect("static state lock filename");
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_APPEND | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err("state lock cannot be opened".into());
    }
    let lock = unsafe { File::from_raw_fd(fd) };
    let metadata = lock.metadata().map_err(|_| "state lock cannot be inspected")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("state lock must be a regular non-symlink file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid && metadata.uid() != 0 {
            return Err("state lock has an unexpected owner".into());
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err("state lock is writable by group or other users".into());
        }
    }
    let deadline = Instant::now() + STATE_LOCK_TIMEOUT;
    loop {
        if exclusive {
            match lock.try_lock_exclusive() {
                Ok(()) => return Ok(lock),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {},
                Err(_) => return Err("state lock cannot be acquired".into()),
            }
        } else {
            match lock.try_lock_shared() {
                Ok(()) => return Ok(lock),
                Err(std::fs::TryLockError::WouldBlock) => {},
                Err(std::fs::TryLockError::Error(_)) => {
                    return Err("state lock cannot be acquired".into());
                },
            }
        }
        if Instant::now() >= deadline {
            return Err("state lock acquisition timed out".into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn with_state<F, R>(mutator: F) -> Result<R, String>
where
    F: FnOnce(&mut State) -> Result<R, String>,
{
    let dir = canonical_state_dir()?;
    let directory = open_private_directory(&dir)?;
    let lock = open_state_lock_at(&directory, true)?;
    let mut state = read_state_at(&directory)?;
    let result = mutator(&mut state);
    if let Err(error) = &result {
        let _ = lock.unlock();
        return Err(error.clone());
    }
    if let Err(error) = write_state_at(&directory, &mut state) {
        let _ = lock.unlock();
        return Err(error);
    }
    lock.unlock().map_err(|_| "state lock cannot be released".to_string())?;
    result
}

fn with_state_read<F, R>(reader: F) -> Result<R, String>
where
    F: FnOnce(&State) -> Result<R, String>,
{
    let dir = canonical_state_dir()?;
    if !dir.exists() {
        return reader(&State::default());
    }
    let directory = open_private_directory(&dir)?;
    let lock = open_state_lock_at(&directory, false)?;
    let state = read_state_at(&directory)?;
    let result = reader(&state);
    let _ = lock.unlock();
    result
}

#[cfg(unix)]
fn secure_open_file_with_options(
    path: &Path,
    allow_root: bool,
    executable: bool,
    allow_non_user_ancestors: bool,
) -> Result<SecureFile, String> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    if !path.is_absolute() {
        return Err("secure paths must be absolute".into());
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err("secure paths cannot contain dot components".into());
    }
    let uid = unsafe { libc::geteuid() };
    let trusted_system_path = path.starts_with("/usr/");
    let owner_allowed = |owner: u32| {
        if trusted_system_path { owner == 0 } else { owner == uid || (allow_root && owner == 0) }
    };
    let trusted_ancestor_owner = if trusted_system_path { Some(0) } else { trusted_system_owner() };
    fn validate_directory(
        metadata: &std::fs::Metadata,
        owner_allowed: &impl Fn(u32) -> bool,
        trusted_ancestor_owner: Option<u32>,
        allow_non_user_ancestors: bool,
    ) -> Result<(), String> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("secure path contains a non-directory component".into());
        }
        let mode = metadata.permissions().mode();
        let sticky_shared_directory = mode & 0o1000 != 0 && mode & 0o002 != 0;
        let ancestor_owner_allowed = owner_allowed(metadata.uid())
            || (trusted_ancestor_owner == Some(metadata.uid()) && mode & 0o022 == 0)
            || (allow_non_user_ancestors && metadata.uid() == 0 && mode & 0o022 == 0)
            || sticky_shared_directory;
        if !ancestor_owner_allowed {
            return Err("secure path contains an unexpected owner".into());
        }
        if mode & 0o022 != 0 && !sticky_shared_directory {
            return Err("secure path contains a writable directory".into());
        }
        Ok(())
    }

    fn open_at(parent: RawFd, component: &CStr, flags: i32) -> Result<File, String> {
        let fd = unsafe { libc::openat(parent, component.as_ptr(), flags, 0) };
        if fd < 0 {
            return Err("secure path cannot be opened".into());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err("secure paths must be absolute".into());
    }
    let components = components.collect::<Vec<_>>();
    let final_component =
        components.last().ok_or_else(|| "secure file is unavailable".to_string())?;
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|_| "secure path cannot be opened")?;
    validate_directory(
        &current.metadata().map_err(|_| "secure path cannot be inspected")?,
        &owner_allowed,
        trusted_ancestor_owner,
        allow_non_user_ancestors,
    )?;
    for component in components.iter().take(components.len().saturating_sub(1)) {
        let name = CString::new(component.as_os_str().as_bytes())
            .map_err(|_| "secure path contains an invalid component")?;
        let next = open_at(
            current.as_raw_fd(),
            &name,
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )?;
        validate_directory(
            &next.metadata().map_err(|_| "secure path cannot be inspected")?,
            &owner_allowed,
            trusted_ancestor_owner,
            allow_non_user_ancestors,
        )?;
        current = next;
    }
    let final_name = CString::new(final_component.as_os_str().as_bytes())
        .map_err(|_| "secure path contains an invalid component")?;
    let file = open_at(
        current.as_raw_fd(),
        &final_name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?;
    let metadata = file.metadata().map_err(|_| "secure file cannot be inspected")?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err("secure file must be a regular non-symlink file".into());
    }
    if !owner_allowed(metadata.uid()) {
        return Err("secure file has an unexpected owner".into());
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err("secure file is writable by group or other users".into());
    }
    if executable && metadata.permissions().mode() & 0o111 == 0 {
        return Err("configured executable is not executable".into());
    }
    let identity = CgroupIdentity { dev: metadata.dev(), ino: metadata.ino() };
    let path_metadata = fs::symlink_metadata(path).map_err(|_| "secure file is unavailable")?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.dev() != identity.dev
        || path_metadata.ino() != identity.ino
    {
        return Err("secure file changed during validation".into());
    }
    Ok(SecureFile { file, identity })
}

fn secret_tool_path() -> Result<SecureFile, String> {
    secure_open_file_with_options(Path::new("/usr/bin/secret-tool"), true, true, false)
}

fn trusted_gui_path(name: &str) -> Option<SecureFile> {
    secure_open_file_with_options(&Path::new("/usr/bin").join(name), true, true, false).ok()
}

fn prepare_local_command(command: &mut Command) {
    command.env_clear().env("PATH", "/usr/bin:/bin");
    for key in SAFE_LOCAL_ENVIRONMENT {
        if let Some(value) = env::var_os(key) {
            command.env(key, value);
        }
    }
}

#[cfg(target_os = "linux")]
fn cgroup_root() -> Result<PathBuf, String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let uid = unsafe { libc::geteuid() };
    let configured =
        env::var("CODEX_SECRET_HANDOFF_CGROUP_ROOT").ok().filter(|value| !value.trim().is_empty());
    let raw = configured.clone().unwrap_or_else(|| {
        fs::read_to_string("/proc/self/cgroup")
            .ok()
            .and_then(|value| {
                value.lines().find_map(|line| {
                    let (hierarchy, path) = line.split_once("::")?;
                    (hierarchy == "0" && path.starts_with('/'))
                        .then(|| format!("/sys/fs/cgroup{path}"))
                })
            })
            .unwrap_or_else(|| {
                format!("/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service")
            })
    });
    let mut path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err("cgroup root must be absolute".into());
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err("cgroup root cannot contain dot components".into());
    }
    let mut component_path = PathBuf::new();
    for component in path.components() {
        component_path.push(component.as_os_str());
        let component_metadata = fs::symlink_metadata(&component_path)
            .map_err(|_| "delegated cgroup root cannot be inspected")?;
        if component_metadata.file_type().is_symlink() {
            return Err("delegated cgroup root cannot contain symlink components".into());
        }
        if component_metadata.is_dir() && component_metadata.permissions().mode() & 0o022 != 0 {
            return Err("delegated cgroup root contains a writable directory".into());
        }
    }
    if configured.is_none() {
        let mut candidate = path.clone();
        let mut stable = None;
        loop {
            let metadata = fs::symlink_metadata(&candidate)
                .map_err(|_| "delegated cgroup root cannot be inspected")?;
            let kill = fs::symlink_metadata(candidate.join("cgroup.kill"));
            let procs = fs::symlink_metadata(candidate.join("cgroup.procs"));
            let delegated = metadata.is_dir()
                && metadata.uid() == uid
                && kill.as_ref().is_ok_and(|entry| {
                    entry.uid() == uid
                        && entry.permissions().mode() & 0o200 != 0
                        && !entry.file_type().is_symlink()
                })
                && procs.as_ref().is_ok_and(|entry| {
                    entry.uid() == uid
                        && entry.permissions().mode() & 0o200 != 0
                        && !entry.file_type().is_symlink()
                });
            if delegated {
                stable = Some(candidate.clone());
            }
            if candidate == Path::new("/sys/fs/cgroup") || !candidate.pop() {
                break;
            }
        }
        path = stable.ok_or_else(|| "no stable delegated cgroup root is available".to_string())?;
    }
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| "delegated cgroup root is unavailable")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != uid {
        return Err("delegated cgroup root is not owned by the current user".into());
    }
    fs::canonicalize(path).map_err(|_| "delegated cgroup root cannot be canonicalized".into())
}

#[cfg(target_os = "linux")]
fn cgroup_open_at(parent: RawFd, name: &CStr, flags: i32) -> io::Result<File> {
    let fd = unsafe { libc::openat(parent, name.as_ptr(), flags, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn cgroup_name(component: &std::ffi::OsStr) -> Result<CString, String> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(component.as_bytes()).map_err(|_| "cgroup name contains an invalid byte".into())
}

#[cfg(target_os = "linux")]
fn open_cgroup_directory_path(path: &Path) -> Result<File, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err("cgroup directory path is invalid".into());
    }
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err("cgroup directory path must be absolute".into());
    }
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|_| "cgroup directory cannot be opened")?;
    for component in components {
        let name = cgroup_name(component.as_os_str())?;
        let next = cgroup_open_at(
            current.as_raw_fd(),
            &name,
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
        .map_err(|_| "cgroup directory cannot be opened")?;
        let metadata = next.metadata().map_err(|_| "cgroup directory cannot be inspected")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("cgroup directory contains an unsafe component".into());
        }
        let uid = unsafe { libc::geteuid() };
        if (metadata.uid() != uid && metadata.uid() != 0)
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err("cgroup directory contains an unsafe owner".into());
        }
        current = next;
    }
    Ok(current)
}

#[cfg(target_os = "linux")]
fn open_cgroup_dir(
    raw: &str,
    expected: Option<CgroupIdentity>,
) -> Result<Option<OperationCgroup>, String> {
    use std::os::unix::fs::MetadataExt;
    let root = cgroup_root()?;
    let path = PathBuf::from(raw);
    if !path.is_absolute()
        || path == root
        || !path.starts_with(&root)
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err("recorded cgroup path is outside the delegated root".into());
    }
    let relative = path.strip_prefix(&root).map_err(|_| "recorded cgroup path is invalid")?;
    let mut components = relative.components().peekable();
    if components.peek().is_none() {
        return Err("recorded cgroup path is invalid".into());
    }
    let mut current = open_cgroup_directory_path(&root)?;
    while let Some(component) = components.next() {
        let name = cgroup_name(component.as_os_str())?;
        let next = match cgroup_open_at(
            current.as_raw_fd(),
            &name,
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        ) {
            Ok(next) => next,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("recorded cgroup path cannot be opened".into()),
        };
        let metadata = next.metadata().map_err(|_| "recorded cgroup path cannot be inspected")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("recorded cgroup path is not a regular directory".into());
        }
        if components.peek().is_some() {
            current = next;
            continue;
        }
        let identity = CgroupIdentity { dev: metadata.dev(), ino: metadata.ino() };
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid {
            return Err("recorded cgroup has an unexpected owner".into());
        }
        if expected.is_some_and(|value| value != identity) {
            return Err("recorded cgroup identity no longer matches".into());
        }
        let parent =
            current.try_clone().map_err(|_| "recorded cgroup parent cannot be retained")?;
        return Ok(Some(OperationCgroup { path, identity, file: next, parent, name }));
    }
    Err("recorded cgroup path is invalid".into())
}

#[cfg(target_os = "linux")]
fn cgroup_member(cgroup: &OperationCgroup, name: &CStr, flags: i32) -> Result<File, String> {
    cgroup_open_at(cgroup.file.as_raw_fd(), name, flags)
        .map_err(|_| "operation cgroup member cannot be opened".into())
}

#[cfg(target_os = "linux")]
fn cgroup_populated(cgroup: &OperationCgroup) -> Result<bool, String> {
    let name = CString::new("cgroup.events").expect("static cgroup member name");
    let mut file =
        cgroup_member(cgroup, &name, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW)?;
    let mut bytes = Vec::with_capacity(256);
    std::io::Read::by_ref(&mut file)
        .take(4096)
        .read_to_end(&mut bytes)
        .map_err(|_| "operation cgroup state could not be read")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "operation cgroup state is invalid")?;
    text.lines()
        .find_map(|line| {
            let (key, value) = line.split_once(' ')?;
            (key == "populated").then(|| value.trim() == "1")
        })
        .ok_or_else(|| "operation cgroup state is invalid".into())
}

#[cfg(target_os = "linux")]
fn unlink_operation_cgroup(cgroup: &OperationCgroup) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let probe = cgroup_open_at(
        cgroup.parent.as_raw_fd(),
        &cgroup.name,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )
    .map_err(|_| "operation cgroup changed before removal")?;
    let metadata = probe.metadata().map_err(|_| "operation cgroup cannot be inspected")?;
    if metadata.dev() != cgroup.identity.dev || metadata.ino() != cgroup.identity.ino {
        return Err("operation cgroup changed before removal".into());
    }
    let result = unsafe {
        libc::unlinkat(cgroup.parent.as_raw_fd(), cgroup.name.as_ptr(), libc::AT_REMOVEDIR)
    };
    if result == -1 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err("operation cgroup could not be removed".into());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_empty_cgroup(cgroup: &OperationCgroup) -> Result<(), String> {
    if cgroup_populated(cgroup)? {
        return Err("operation cgroup is still populated".into());
    }
    unlink_operation_cgroup(cgroup)
}

#[cfg(target_os = "linux")]
fn kill_open_cgroup(cgroup: &OperationCgroup) -> Result<(), String> {
    let name = CString::new("cgroup.kill").expect("static cgroup member name");
    let mut kill_file =
        cgroup_member(cgroup, &name, libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW)?;
    kill_file.write_all(b"1").map_err(|_| "operation cgroup could not be terminated")?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if !cgroup_populated(cgroup)? {
            return unlink_operation_cgroup(cgroup);
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("operation cgroup did not empty after termination".into())
}

#[cfg(target_os = "linux")]
fn cgroup_age_seconds(cgroup: &OperationCgroup) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    let metadata = cgroup.file.metadata().ok()?;
    (metadata.ctime() >= 0).then(|| now().saturating_sub(metadata.ctime() as u64))
}

#[cfg(target_os = "linux")]
fn create_operation_cgroup() -> Result<OperationCgroup, String> {
    use std::os::unix::fs::MetadataExt;
    let root = cgroup_root()?;
    let parent = open_cgroup_directory_path(&root)?;
    let uid = unsafe { libc::geteuid() };
    if parent.metadata().map_err(|_| "delegated cgroup root cannot be inspected")?.uid() != uid {
        return Err("delegated cgroup root is not owned by the current user".into());
    }
    let name = CString::new(format!("codex-secret-handoff-{}", Uuid::new_v4().simple()))
        .map_err(|_| "dedicated operation cgroup name is invalid")?;
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if created == -1 {
        return Err("dedicated operation cgroup cannot be created".into());
    }
    let path = root.join(name.to_string_lossy().as_ref());
    let result = (|| {
        let file = cgroup_open_at(
            parent.as_raw_fd(),
            &name,
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
        .map_err(|_| "dedicated operation cgroup cannot be opened")?;
        let metadata =
            file.metadata().map_err(|_| "dedicated operation cgroup cannot be inspected")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != uid {
            return Err("dedicated operation cgroup has an unexpected owner".into());
        }
        let cgroup = OperationCgroup {
            path,
            identity: CgroupIdentity { dev: metadata.dev(), ino: metadata.ino() },
            file,
            parent: parent
                .try_clone()
                .map_err(|_| "dedicated operation cgroup parent cannot be retained")?,
            name: name.clone(),
        };
        let kill_name = CString::new("cgroup.kill").expect("static cgroup member name");
        let procs_name = CString::new("cgroup.procs").expect("static cgroup member name");
        cgroup_member(&cgroup, &kill_name, libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .map_err(|_| "dedicated operation cgroup cannot be terminated")?;
        cgroup_member(&cgroup, &procs_name, libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .map_err(|_| "dedicated operation cgroup cannot receive processes")?;
        Ok(cgroup)
    })();
    match result {
        Ok(cgroup) => Ok(cgroup),
        Err(error) => {
            let unlink_result =
                unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
            if unlink_result == -1 {
                let unlink_error = io::Error::last_os_error();
                if unlink_error.kind() != io::ErrorKind::NotFound {
                    return Err(format!("{error}; operation cgroup cleanup pending"));
                }
            }
            Err(error)
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn create_operation_cgroup() -> Result<OperationCgroup, String> {
    Err("dedicated operation cgroups require Linux".into())
}

#[cfg(target_os = "linux")]
fn kill_cgroup_path(raw: &str, expected: Option<CgroupIdentity>) -> Result<(), String> {
    let Some(expected) = expected else {
        return Err("recorded operation cgroup identity is unavailable".into());
    };
    let Some(cgroup) = open_cgroup_dir(raw, Some(expected))? else {
        return Ok(());
    };
    kill_open_cgroup(&cgroup)
}

#[cfg(not(target_os = "linux"))]
fn kill_cgroup_path(_raw: &str, _expected: Option<CgroupIdentity>) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn reconcile_unregistered_operation_cgroups(
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let root = cgroup_root()?;
    let tracked = with_state_read(|state| Ok(state.operation_cgroups.clone()))?;
    let uid = unsafe { libc::geteuid() };
    let mut first_cleanup_error = None;
    for entry in fs::read_dir(&root).map_err(|_| "delegated cgroup root cannot be listed")? {
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            break;
        }
        let entry = entry.map_err(|_| "delegated cgroup entry cannot be inspected")?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with("codex-secret-handoff-") {
            continue;
        }
        let path = entry.path();
        let raw = path.to_string_lossy().into_owned();
        let Some(cgroup) = open_cgroup_dir(&raw, None)? else {
            continue;
        };
        let expected_existing = tracked.get(&raw).and_then(|fence| fence.identity);
        if expected_existing == Some(cgroup.identity) {
            continue;
        }
        if cgroup
            .file
            .metadata()
            .map_err(|_| "unregistered operation cgroup cannot be inspected")?
            .uid()
            != uid
            || cgroup_age_seconds(&cgroup)
                .is_none_or(|age| age < OPERATION_CGROUP_ORPHAN_GRACE.as_secs())
        {
            continue;
        }
        let populated = cgroup_populated(&cgroup)?;
        if !populated {
            if let Err(error) = remove_empty_cgroup(&cgroup) {
                first_cleanup_error.get_or_insert(error);
            }
            continue;
        }
        let identity = cgroup.identity;
        if !register_operation_cgroup_replacing_identity(
            &raw,
            expected_existing,
            identity,
            "orphan-reconciler",
        )? {
            continue;
        }
        let result = match open_cgroup_dir(&raw, Some(identity))? {
            Some(current) => kill_open_cgroup(&current),
            None => Ok(()),
        };
        if result.is_ok() {
            unregister_operation_cgroup_if_identity(&raw, identity)?;
        } else if let Err(error) = result {
            first_cleanup_error.get_or_insert(error);
        }
    }
    first_cleanup_error.map_or(Ok(()), Err)
}

#[cfg(not(target_os = "linux"))]
fn reconcile_unregistered_operation_cgroups(
    _cancellation: &CancellationToken,
    _deadline: Instant,
) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn prepare_child(command: &mut Command, cgroup: Option<RawFd>) {
    use std::os::unix::process::CommandExt;
    let parent_pid = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            #[cfg(target_os = "linux")]
            {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != parent_pid {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "parent process exited before helper initialization",
                    ));
                }
            }
            if libc::setpgid(0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            if let Some(cgroup_fd) = cgroup {
                let name = b"cgroup.procs\0";
                let fd = libc::openat(
                    cgroup_fd,
                    name.as_ptr().cast(),
                    libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                );
                if fd == -1 {
                    return Err(io::Error::last_os_error());
                }
                let mut buffer = [0_u8; 32];
                let mut value = libc::getpid() as u32;
                let mut index = buffer.len();
                if value == 0 {
                    index -= 1;
                    buffer[index] = b'0';
                } else {
                    while value > 0 {
                        index -= 1;
                        buffer[index] = b'0' + (value % 10) as u8;
                        value /= 10;
                    }
                }
                index -= 1;
                buffer[index] = b'\n';
                let payload = &buffer[index..];
                let mut written_total = 0;
                while written_total < payload.len() {
                    let written = libc::write(
                        fd,
                        payload[written_total..].as_ptr().cast(),
                        payload.len() - written_total,
                    );
                    if written == -1 {
                        let error = io::Error::last_os_error();
                        if error.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        let _ = libc::close(fd);
                        return Err(error);
                    }
                    if written == 0 {
                        let _ = libc::close(fd);
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "cgroup process assignment was incomplete",
                        ));
                    }
                    written_total += written as usize;
                }
                let close_result = libc::close(fd);
                if close_result == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn prepare_child(_command: &mut Command, _cgroup: Option<RawFd>) {}

fn kill_child(child: &mut Child) -> Result<(), String> {
    match child.kill() {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("child could not be terminated".into()),
    }
}

#[cfg(unix)]
fn terminate_child(child: &mut Child, cgroup: Option<&OperationCgroup>) -> Option<String> {
    let cgroup_error = cgroup.and_then(|value| kill_open_cgroup(value).err());
    let child_error = kill_child(child).err();
    let reap_error = reap_bounded(child, Duration::from_secs(2)).err();
    let mut errors = Vec::new();
    if let Some(error) = cgroup_error {
        errors.push(format!("cgroup cleanup failed: {error}"));
    }
    if let Some(error) = child_error {
        errors.push(format!("child termination failed: {error}"));
    }
    if let Some(error) = reap_error {
        errors.push(format!("child cleanup failed: {error}"));
    }
    (!errors.is_empty()).then(|| errors.join("; "))
}

fn reap_bounded(child: &mut Child, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().map_err(|_| "child status failed")?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("child did not exit after termination".into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(unix)]
fn process_start_ticks(pid: u32) -> Result<Option<u64>, String> {
    let text = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("process identity could not be inspected".into()),
    };
    let end = text.rfind(") ").ok_or_else(|| "process identity is malformed".to_string())?;
    let value = text[end + 2..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| "process identity is incomplete".to_string())?;
    let start_ticks = value.parse().map_err(|_| "process identity is invalid".to_string())?;
    Ok(Some(start_ticks))
}

#[cfg(not(unix))]
fn process_start_ticks(_pid: u32) -> Result<Option<u64>, String> {
    Ok(None)
}

#[cfg(unix)]
fn process_group_matches(pid: u32, pgid: i32) -> bool {
    unsafe { libc::getpgid(pid as i32) == pgid }
}

#[cfg(not(unix))]
fn process_group_matches(_pid: u32, _pgid: i32) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn open_pidfd(pid: u32) -> Result<Option<File>, String> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_uint, 0) };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err("recorded helper pidfd could not be opened".into())
        };
    }
    Ok(Some(unsafe { File::from_raw_fd(fd as RawFd) }))
}

#[cfg(target_os = "linux")]
fn pidfd_kill(pidfd: &File) -> Result<(), String> {
    let result = unsafe {
        libc::syscall(libc::SYS_pidfd_send_signal, pidfd.as_raw_fd(), libc::SIGKILL, 0, 0)
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err("recorded helper could not be terminated".into());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn wait_pidfd(pidfd: &File, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("recorded helper did not exit after termination".into());
        }
        let milliseconds = remaining.as_millis().min(i32::MAX as u128) as i32;
        let mut pollfd = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut pollfd, 1, milliseconds.max(1)) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err("recorded helper exit could not be observed".into());
        }
        if pollfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Ok(());
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn open_pidfd(_pid: u32) -> Result<Option<File>, String> {
    Err("pidfd termination is unavailable".into())
}

#[cfg(unix)]
fn kill_recorded_helper(action: &CleanupAction) -> Result<(), String> {
    if action.helper_descendants_unknown {
        return Err("legacy helper descendants cannot be verified".into());
    }
    if let Some(cgroup) = action.helper_cgroup.as_deref() {
        let identity = action
            .helper_cgroup_identity
            .ok_or_else(|| "recorded helper cgroup identity is unavailable".to_string())?;
        return kill_cgroup_path(cgroup, Some(identity));
    }
    if action.helper_pid.is_none()
        && action.helper_pgid.is_none()
        && action.helper_start_ticks.is_none()
        && action.helper_boot_id.is_none()
    {
        return Ok(());
    }
    let (Some(pid), Some(_pgid), Some(start_ticks), Some(expected_boot)) = (
        action.helper_pid,
        action.helper_pgid,
        action.helper_start_ticks,
        action.helper_boot_id.as_deref(),
    ) else {
        return Err("recorded helper identity is incomplete".into());
    };
    match boot_id() {
        Some(current_boot) if current_boot == expected_boot => {},
        Some(_) => return Ok(()),
        None => return Err("current boot identity could not be verified".into()),
    }
    let Some(pidfd) = open_pidfd(pid)? else {
        return Err("recorded helper descendants cannot be verified without a pidfd".into());
    };
    match process_start_ticks(pid)? {
        Some(current_ticks) if current_ticks != start_ticks => {
            return Err("recorded helper identity no longer matches".into());
        },
        None => return Err("recorded helper descendants cannot be verified after pid exit".into()),
        Some(_) => {},
    }
    pidfd_kill(&pidfd)?;
    wait_pidfd(&pidfd, Duration::from_secs(2))
}

#[cfg(not(unix))]
fn kill_recorded_helper(_action: &CleanupAction) -> Result<(), String> {
    Ok(())
}

struct CommandOutput {
    status: ExitStatus,
    stdout: Zeroizing<Vec<u8>>,
    _stderr: Zeroizing<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminationReason {
    Cancelled,
    TimedOut,
}

impl TerminationReason {
    fn message(self) -> &'static str {
        match self {
            Self::Cancelled => "operation was cancelled",
            Self::TimedOut => "operation timed out",
        }
    }
}

#[cfg(unix)]
fn set_nonblocking(fd: std::os::unix::io::RawFd) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err("child pipe cannot be configured".into());
    }
    Ok(())
}

#[cfg(unix)]
fn write_secret_bounded(
    mut stdin: ChildStdin,
    secret: &[u8],
    timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<(), String> {
    use std::os::unix::io::AsRawFd;
    set_nonblocking(stdin.as_raw_fd())?;
    let deadline = Instant::now() + timeout;
    let mut written = 0;
    while written < secret.len() {
        if cancellation.is_cancelled() {
            return Err("operation was cancelled".into());
        }
        match stdin.write(&secret[written..]) {
            Ok(0) => return Err("OS keyring rejected the secret".into()),
            Ok(count) => written += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("OS keyring write timed out".into());
                }
                let mut pollfd =
                    libc::pollfd { fd: stdin.as_raw_fd(), events: libc::POLLOUT, revents: 0 };
                let poll_result = unsafe { libc::poll(&mut pollfd, 1, 50) };
                if poll_result < 0 {
                    let poll_error = io::Error::last_os_error();
                    if poll_error.kind() != io::ErrorKind::Interrupted {
                        return Err("OS keyring write could not be polled".into());
                    }
                } else if pollfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                    return Err("OS keyring rejected the secret".into());
                }
            },
            Err(_) => return Err("OS keyring rejected the secret".into()),
        }
    }
    drop(stdin);
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_bounded(
    mut stdin: ChildStdin,
    secret: &[u8],
    _timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<(), String> {
    if cancellation.is_cancelled() {
        return Err("operation was cancelled".into());
    }
    stdin.write_all(secret).map_err(|_| "OS keyring rejected the secret".into())
}

#[cfg(unix)]
fn drain_pipe<T>(
    stream: &mut Option<T>,
    output: &mut Zeroizing<Vec<u8>>,
    limit: usize,
) -> Result<(), String>
where
    T: Read + std::os::unix::io::AsRawFd,
{
    let Some(stream_ref) = stream.as_mut() else {
        return Ok(());
    };
    let mut buffer = Zeroizing::new([0_u8; 8192]);
    loop {
        match stream_ref.read(buffer.as_mut_slice()) {
            Ok(0) => {
                stream.take();
                return Ok(());
            },
            Ok(read) => {
                if output.len().saturating_add(read) > limit {
                    return Err("child output exceeded the configured limit".into());
                }
                output.extend_from_slice(&buffer[..read]);
            },
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(_) => return Err("child output could not be read".into()),
        }
    }
}

#[cfg(unix)]
fn wait_bounded(
    mut child: Child,
    timeout: Duration,
    cancellation: &CancellationToken,
    output_limit: usize,
    cgroup: Option<&OperationCgroup>,
) -> Result<CommandOutput, String> {
    use std::os::unix::io::AsRawFd;
    let mut stdout: Option<ChildStdout> = child.stdout.take();
    let mut stderr: Option<ChildStderr> = child.stderr.take();
    if let Some(stream) = stdout.as_ref()
        && let Err(error) = set_nonblocking(stream.as_raw_fd())
    {
        let cleanup_error = terminate_child(&mut child, cgroup);
        return Err(match cleanup_error {
            Some(cleanup_error) => format!("{error}; {cleanup_error}"),
            None => error,
        });
    }
    if let Some(stream) = stderr.as_ref()
        && let Err(error) = set_nonblocking(stream.as_raw_fd())
    {
        let cleanup_error = terminate_child(&mut child, cgroup);
        return Err(match cleanup_error {
            Some(cleanup_error) => format!("{error}; {cleanup_error}"),
            None => error,
        });
    }
    let deadline = Instant::now() + timeout;
    let mut termination_deadline = None;
    let mut termination_reason = None;
    let mut termination_cleanup_error = None;
    let mut post_exit_deadline = None;
    let mut status = None;
    let mut stdout_bytes = Zeroizing::new(Vec::new());
    let mut stderr_bytes = Zeroizing::new(Vec::new());
    loop {
        if let Err(error) = drain_pipe(&mut stdout, &mut stdout_bytes, output_limit) {
            let cleanup_error = terminate_child(&mut child, cgroup);
            return Err(match cleanup_error {
                Some(cleanup_error) => format!("{error}; {cleanup_error}"),
                None => error,
            });
        }
        if let Err(error) = drain_pipe(&mut stderr, &mut stderr_bytes, output_limit) {
            let cleanup_error = terminate_child(&mut child, cgroup);
            return Err(match cleanup_error {
                Some(cleanup_error) => format!("{error}; {cleanup_error}"),
                None => error,
            });
        }
        if cancellation.is_cancelled() && termination_deadline.is_none() {
            termination_cleanup_error = terminate_child(&mut child, cgroup);
            termination_reason = Some(TerminationReason::Cancelled);
            termination_deadline = Some(Instant::now() + Duration::from_secs(2));
        }
        if status.is_none() && termination_deadline.is_none() {
            match child.try_wait() {
                Ok(Some(child_status)) => status = Some(child_status),
                Ok(None) if Instant::now() >= deadline => {
                    termination_cleanup_error = terminate_child(&mut child, cgroup);
                    termination_reason = Some(TerminationReason::TimedOut);
                    termination_deadline = Some(Instant::now() + Duration::from_secs(2));
                },
                Ok(None) => {},
                Err(_) => {
                    let cleanup_error = terminate_child(&mut child, cgroup);
                    return Err(match cleanup_error {
                        Some(cleanup_error) => format!("child status failed; {cleanup_error}"),
                        None => "child status failed".into(),
                    });
                },
            }
        }
        if status.is_some() && post_exit_deadline.is_none() {
            post_exit_deadline = Some(Instant::now() + Duration::from_secs(2));
        }
        if termination_deadline.is_some_and(|limit| Instant::now() >= limit) {
            let mut message =
                termination_reason.unwrap_or(TerminationReason::TimedOut).message().to_owned();
            if let Some(error) = termination_cleanup_error.take() {
                message.push_str("; ");
                message.push_str(&error);
            }
            return Err(message);
        }
        if status.is_some() && stdout.is_none() && stderr.is_none() {
            let child_status = match child.wait() {
                Ok(status) => status,
                Err(_) => {
                    let cleanup_error = terminate_child(&mut child, cgroup);
                    return Err(match cleanup_error {
                        Some(cleanup_error) => format!("child wait failed; {cleanup_error}"),
                        None => "child wait failed".into(),
                    });
                },
            };
            let termination = termination_reason;
            if let Some(cgroup) = cgroup
                && let Err(error) = kill_open_cgroup(cgroup)
            {
                return Err(format!("child cgroup cleanup failed: {error}"));
            }
            if let Some(reason) = termination {
                let mut message = reason.message().to_owned();
                if let Some(error) = termination_cleanup_error {
                    message.push_str("; ");
                    message.push_str(&error);
                }
                return Err(message);
            }
            if cancellation.is_cancelled() {
                return Err("operation was cancelled".into());
            }
            if Instant::now() >= deadline {
                return Err("operation timed out".into());
            }
            return Ok(CommandOutput {
                status: child_status,
                stdout: stdout_bytes,
                _stderr: stderr_bytes,
            });
        }
        if post_exit_deadline.is_some_and(|limit| Instant::now() >= limit) {
            let cleanup_error = terminate_child(&mut child, cgroup);
            return Err(match cleanup_error {
                Some(cleanup_error) => {
                    format!("child pipes did not close after process exit; {cleanup_error}")
                },
                None => "child pipes did not close after process exit".into(),
            });
        }
        let mut pollfds = Vec::new();
        if let Some(stream) = stdout.as_ref() {
            pollfds.push(libc::pollfd { fd: stream.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        if let Some(stream) = stderr.as_ref() {
            pollfds.push(libc::pollfd { fd: stream.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        }
        if pollfds.is_empty() {
            thread::sleep(Duration::from_millis(10));
        } else {
            let poll_result =
                unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 50) };
            if poll_result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                let cleanup_error = terminate_child(&mut child, cgroup);
                return Err(match cleanup_error {
                    Some(cleanup_error) => format!("child pipe polling failed; {cleanup_error}"),
                    None => "child pipe polling failed".into(),
                });
            }
        }
    }
}

#[cfg(not(unix))]
fn wait_bounded(
    mut child: Child,
    timeout: Duration,
    cancellation: &CancellationToken,
    output_limit: usize,
    _cgroup: Option<&OperationCgroup>,
) -> Result<CommandOutput, String> {
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let reader = thread::spawn(move || {
        let mut stdout_bytes = Zeroizing::new(Vec::new());
        let mut stderr_bytes = Zeroizing::new(Vec::new());
        if let Some(stream) = stdout {
            let bytes = stream
                .take(output_limit.saturating_add(1) as u64)
                .read_to_end(&mut stdout_bytes)
                .map_err(|_| "child output could not be read")?;
            if bytes > output_limit {
                return Err("child output exceeded the configured limit".into());
            }
        }
        if let Some(stream) = stderr {
            let bytes = stream
                .take(output_limit.saturating_add(1) as u64)
                .read_to_end(&mut stderr_bytes)
                .map_err(|_| "child output could not be read")?;
            if bytes > output_limit {
                return Err("child output exceeded the configured limit".into());
            }
        }
        Ok((stdout_bytes, stderr_bytes))
    });
    let deadline = Instant::now() + timeout;
    let mut termination_reason = None;
    loop {
        if cancellation.is_cancelled() {
            let termination_error = kill_child(&mut child).err();
            termination_reason = Some(TerminationReason::Cancelled);
            let wait_error = child.wait().err().map(|_| "child cleanup failed".to_owned());
            return Err(match termination_error.or(wait_error) {
                Some(error) => format!("operation was cancelled; {error}"),
                None => "operation was cancelled".into(),
            });
        }
        if let Some(status) = child.try_wait().map_err(|_| "child status failed")? {
            let (stdout, stderr) = reader.join().map_err(|_| "child output reader failed")??;
            if let Some(reason) = termination_reason {
                return Err(reason.message().into());
            }
            return Ok(CommandOutput { status, stdout, _stderr: stderr });
        }
        if Instant::now() >= deadline {
            let termination_error = kill_child(&mut child).err();
            termination_reason = Some(TerminationReason::TimedOut);
            let wait_error = child.wait().err().map(|_| "child cleanup failed".to_owned());
            let reason = termination_reason.unwrap().message();
            return Err(match termination_error.or(wait_error) {
                Some(error) => format!("{reason}; {error}"),
                None => reason.into(),
            });
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn run_command(
    mut command: Command,
    timeout: Duration,
    cancellation: &CancellationToken,
    output_limit: usize,
) -> Result<CommandOutput, String> {
    prepare_local_command(&mut command);
    let cgroup = create_operation_cgroup()?;
    let cgroup_raw = cgroup.path.to_string_lossy().into_owned();
    let cgroup_identity = cgroup.identity;
    if let Err(error) = register_operation_cgroup(&cgroup_raw, cgroup_identity) {
        let cleanup = kill_open_cgroup(&cgroup).err();
        return Err(match cleanup {
            Some(cleanup) => format!("{error}; cgroup cleanup pending: {cleanup}"),
            None => error,
        });
    }
    prepare_child(&mut command, Some(cgroup.file.as_raw_fd()));
    let child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            let cleanup = kill_open_cgroup(&cgroup);
            let forget = forget_operation_cgroup_if_absent(&cgroup_raw, cgroup_identity);
            let mut message = match cleanup {
                Ok(()) => "local command could not be started".to_owned(),
                Err(error) => {
                    format!("local command could not be started; cgroup cleanup pending: {error}")
                },
            };
            if let Err(error) = forget {
                message.push_str("; cgroup metadata cleanup failed: ");
                message.push_str(&error);
            }
            return Err(message);
        },
    };
    let result = wait_bounded(child, timeout, cancellation, output_limit, Some(&cgroup));
    let forget = forget_operation_cgroup_if_absent(&cgroup_raw, cgroup_identity);
    if let Err(error) = forget {
        return Err(match result {
            Ok(_) => format!("operation cgroup metadata cleanup failed: {error}"),
            Err(result_error) => {
                format!("{result_error}; operation cgroup metadata cleanup failed: {error}")
            },
        });
    }
    result
}

fn normalize_provider_output(mut bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, String> {
    if bytes.pop() != Some(b'\n') {
        return Err("secret provider framing is invalid".into());
    }
    if bytes.is_empty() {
        return Err("empty secret is not accepted".into());
    }
    if matches!(bytes.last(), Some(b'\n' | b'\r')) {
        return Err("secrets ending in CR or LF are unsupported".into());
    }
    Ok(bytes)
}

fn normalize_keyring_output(mut bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, String> {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err("empty secret is not accepted".into());
    }
    if matches!(bytes.last(), Some(b'\n' | b'\r')) {
        return Err("secrets ending in CR or LF are unsupported".into());
    }
    Ok(bytes)
}

fn validate_secret_for_environment(secret: &[u8]) -> Result<(), String> {
    if secret.len() > MAX_SECRET_BYTES {
        return Err("secret exceeds the configured size limit".into());
    }
    let text = std::str::from_utf8(secret)
        .map_err(|_| "secret must be valid UTF-8 for environment handoff")?;
    if text.contains('\0') {
        return Err("secret must not contain NUL bytes".into());
    }
    Ok(())
}

fn secret_tool_store(
    fence: &CaptureFence,
    target: &str,
    label: &str,
    secret: &[u8],
    cancellation: &CancellationToken,
) -> Result<(), String> {
    validate_secret_for_environment(secret)?;
    let executable = secret_tool_path()?;
    let mut command = Command::new(executable.exec_path()?);
    command
        .args([
            "store",
            "--label",
            label,
            "service",
            SERVICE,
            "account",
            &format!("handoff:{}", fence.handle),
            "target",
            target,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    prepare_local_command(&mut command);
    let cgroup = create_operation_cgroup()?;
    let cgroup_raw = cgroup.path.to_string_lossy().into_owned();
    let cgroup_identity = cgroup.identity;
    if let Err(error) = register_operation_cgroup(&cgroup_raw, cgroup_identity) {
        let cleanup = kill_open_cgroup(&cgroup).err();
        return Err(match cleanup {
            Some(cleanup) => format!("{error}; cgroup cleanup pending: {cleanup}"),
            None => error,
        });
    }
    prepare_child(&mut command, Some(cgroup.file.as_raw_fd()));
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            let cleanup = kill_open_cgroup(&cgroup);
            let forget = forget_operation_cgroup_if_absent(&cgroup_raw, cgroup_identity);
            let mut message = match cleanup {
                Ok(()) => "OS keyring is unavailable".into(),
                Err(error) => format!("OS keyring is unavailable; cgroup cleanup pending: {error}"),
            };
            if let Err(error) = forget {
                message.push_str("; cgroup metadata cleanup failed: ");
                message.push_str(&error);
            }
            return Err(message);
        },
    };
    let pid = child.id();
    let helper = match register_helper(
        fence,
        pid,
        "secret-tool-store",
        Some(cgroup_raw.clone()),
        Some(cgroup_identity),
    ) {
        Ok(helper) => helper,
        Err(error) => {
            let cleanup = terminate_child(&mut child, Some(&cgroup));
            let forget = forget_operation_cgroup_if_absent(&cgroup_raw, cgroup_identity);
            let mut message = error;
            if let Some(cleanup_error) = cleanup {
                message.push_str("; helper cleanup pending: ");
                message.push_str(&cleanup_error);
            }
            if let Err(forget_error) = forget {
                message.push_str("; cgroup metadata cleanup failed: ");
                message.push_str(&forget_error);
            }
            return Err(message);
        },
    };
    let Some(stdin) = child.stdin.take() else {
        let cleanup = terminate_child(&mut child, Some(&cgroup));
        let clear = clear_helper(&helper);
        let forget = forget_operation_cgroup_if_absent(&cgroup_raw, cgroup_identity);
        let mut message = "OS keyring stdin is unavailable".to_owned();
        if let Some(cleanup_error) = cleanup {
            message.push_str("; helper cleanup pending: ");
            message.push_str(&cleanup_error);
        }
        if let Err(clear_error) = clear {
            message.push_str("; helper metadata cleanup failed: ");
            message.push_str(&clear_error);
        }
        if let Err(forget_error) = forget {
            message.push_str("; cgroup metadata cleanup failed: ");
            message.push_str(&forget_error);
        }
        return Err(message);
    };
    let write_result = write_secret_bounded(stdin, secret, KEYRING_TIMEOUT, cancellation);
    let output =
        wait_bounded(child, KEYRING_TIMEOUT, cancellation, MAX_CHILD_OUTPUT_BYTES, Some(&cgroup));
    let output = match output {
        Ok(output) => output,
        Err(wait_error) => {
            let write_error = write_result.err();
            let forget = forget_operation_cgroup_if_absent(&cgroup_raw, cgroup_identity);
            let mut message = match write_error {
                Some(write_error) => format!("{write_error}; {wait_error}; helper cleanup pending"),
                None => format!("{wait_error}; helper cleanup pending"),
            };
            if let Err(forget_error) = forget {
                message.push_str("; cgroup metadata cleanup failed: ");
                message.push_str(&forget_error);
            }
            return Err(message);
        },
    };
    if let Err(cleanup_error) = clear_helper(&helper) {
        let forget = forget_operation_cgroup_if_absent(&cgroup_raw, cgroup_identity);
        return Err(match forget {
            Ok(()) => format!("helper metadata cleanup failed: {cleanup_error}"),
            Err(forget_error) => format!(
                "helper metadata cleanup failed: {cleanup_error}; cgroup metadata cleanup failed: {forget_error}"
            ),
        });
    }
    forget_operation_cgroup_if_absent(&cgroup_raw, cgroup_identity)?;
    write_result?;
    if output.status.success() { Ok(()) } else { Err("OS keyring rejected the secret".into()) }
}

fn secret_tool_lookup(
    account: &str,
    cancellation: &CancellationToken,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let executable = secret_tool_path()?;
    let mut command = Command::new(executable.exec_path()?);
    command
        .args(["lookup", "service", SERVICE, "account", account])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let output = run_command(command, KEYRING_TIMEOUT, cancellation, MAX_PROVIDER_OUTPUT_BYTES)?;
    if !output.status.success() {
        return Err("secret is not available in OS keyring".into());
    }
    let secret = normalize_keyring_output(output.stdout)?;
    validate_secret_for_environment(&secret)?;
    Ok(secret)
}

fn secret_tool_clear(account: &str, cancellation: &CancellationToken) -> Result<(), String> {
    let executable = secret_tool_path()?;
    let mut command = Command::new(executable.exec_path()?);
    command
        .args(["clear", "service", SERVICE, "account", account])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let output = run_command(command, KEYRING_TIMEOUT, cancellation, MAX_CHILD_OUTPUT_BYTES)?;
    let mut clear_succeeded = output.status.success();
    for attempt in 0..2 {
        match secret_tool_entry_state(account, cancellation)? {
            KeyringEntryState::Missing => return Ok(()),
            KeyringEntryState::Unavailable => {
                return Err("OS keyring entry deletion could not be verified".into());
            },
            KeyringEntryState::Present if attempt == 0 => {
                let mut retry = Command::new(executable.exec_path()?);
                retry
                    .args(["clear", "service", SERVICE, "account", account])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                clear_succeeded =
                    run_command(retry, KEYRING_TIMEOUT, cancellation, MAX_CHILD_OUTPUT_BYTES)?
                        .status
                        .success();
            },
            KeyringEntryState::Present => break,
        }
    }
    let state = secret_tool_entry_state(account, cancellation)?;
    if state == KeyringEntryState::Missing {
        Ok(())
    } else if clear_succeeded {
        Err("OS keyring entry remains after deletion verification".into())
    } else {
        Err("OS keyring entry could not be removed".into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyringEntryState {
    Present,
    Missing,
    Unavailable,
}

fn classify_keyring_search_result(succeeded: bool, has_matches: bool) -> KeyringEntryState {
    if !succeeded {
        KeyringEntryState::Unavailable
    } else if has_matches {
        KeyringEntryState::Present
    } else {
        KeyringEntryState::Missing
    }
}

fn secret_tool_entry_state(
    account: &str,
    cancellation: &CancellationToken,
) -> Result<KeyringEntryState, String> {
    let executable = secret_tool_path()?;
    let mut command = Command::new(executable.exec_path()?);
    command
        .args(["search", "--all", "--unlock", "service", SERVICE, "account", account])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = run_command(command, KEYRING_TIMEOUT, cancellation, MAX_PROVIDER_OUTPUT_BYTES)?;
    Ok(classify_keyring_search_result(output.status.success(), !output.stdout.is_empty()))
}

fn cleanup_keyring(account: &str, cancellation: &CancellationToken) -> Result<(), String> {
    if account.is_empty() {
        return Ok(());
    }
    secret_tool_clear(account, cancellation)
}

fn register_helper(
    fence: &CaptureFence,
    pid: u32,
    kind: &str,
    cgroup: Option<String>,
    cgroup_identity: Option<CgroupIdentity>,
) -> Result<HelperFence, String> {
    let start_ticks = process_start_ticks(pid)?
        .ok_or_else(|| "helper identity could not be verified".to_string())?;
    let pgid = pid as i32;
    if !process_group_matches(pid, pgid) {
        return Err("helper process group could not be verified".into());
    }
    let helper_boot_id =
        boot_id().ok_or_else(|| "helper boot identity is unavailable".to_string())?;
    with_state(|state| {
        let record = state
            .records
            .get_mut(&fence.handle)
            .ok_or_else(|| "helper owner record is missing".to_string())?;
        if record.keyring_account != format!("handoff:{}", fence.handle)
            || record.status != LifecycleStatus::Provisioning
            || record.lease_owner.as_deref() != Some(process_owner())
            || record.generation != fence.generation
        {
            return Err("helper lifecycle fence was lost".into());
        }
        record.helper_pid = Some(pid);
        record.helper_pgid = Some(pgid);
        record.helper_start_ticks = Some(start_ticks);
        record.helper_boot_id = Some(helper_boot_id.clone());
        record.helper_kind = Some(kind.to_owned());
        record.helper_cgroup = cgroup.clone();
        record.helper_cgroup_identity = cgroup_identity;
        record.generation = record.generation.saturating_add(1);
        Ok(HelperFence {
            handle: fence.handle.clone(),
            pid,
            pgid,
            start_ticks,
            boot_id: helper_boot_id,
            generation: record.generation,
            cgroup,
            cgroup_identity,
            live_cgroup: None,
        })
    })
}

fn clear_helper(fence: &HelperFence) -> Result<(), String> {
    with_state(|state| {
        let record = state
            .records
            .get_mut(&fence.handle)
            .ok_or_else(|| "helper owner record is missing".to_string())?;
        let matching = record.generation == fence.generation
            && record.helper_pid == Some(fence.pid)
            && record.helper_pgid == Some(fence.pgid)
            && record.helper_start_ticks == Some(fence.start_ticks)
            && record.helper_boot_id.as_deref() == Some(fence.boot_id.as_str())
            && record.helper_cgroup.as_deref() == fence.cgroup.as_deref()
            && record.helper_cgroup_identity == fence.cgroup_identity;
        if matching {
            record.helper_pid = None;
            record.helper_pgid = None;
            record.helper_start_ticks = None;
            record.helper_boot_id = None;
            record.helper_kind = None;
            record.helper_cgroup = None;
            record.helper_cgroup_identity = None;
            record.helper_descendants_unknown = false;
            record.generation = record.generation.saturating_add(1);
            return Ok(());
        }
        if record.helper_pid.is_none()
            && matches!(
                record.status,
                LifecycleStatus::CleanupPending
                    | LifecycleStatus::Consumed
                    | LifecycleStatus::Deleted
                    | LifecycleStatus::Expired
            )
        {
            return Ok(());
        }
        Err("helper lifecycle fence was lost".into())
    })
}

fn validate_text(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > 160 || value.chars().any(|c| c.is_control()) {
        return Err(format!("invalid {field}"));
    }
    Ok(())
}

fn validate_ttl(ttl: u64) -> Result<u64, String> {
    if !(1..=MAX_TTL_SECONDS).contains(&ttl) {
        return Err(format!("ttl_seconds must be between 1 and {MAX_TTL_SECONDS}"));
    }
    Ok(ttl)
}

fn gui_prompt(
    target: &str,
    label: &str,
    cancellation: &CancellationToken,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let title = format!("Enter secret - {label}");
    let message = format!(
        "Enter the secret for {target}.\nIt stays in the local OS keyring and is never returned to the model."
    );
    let (program, args) = if let Some(path) = trusted_gui_path("zenity") {
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
    } else if let Some(path) = trusted_gui_path("kdialog") {
        (path, vec!["--title".into(), title, "--password".into(), message])
    } else {
        return Err("no supported trusted GUI prompt found".into());
    };
    let mut command = Command::new(program.exec_path()?);
    command.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    let output = run_command(command, GUI_TIMEOUT, cancellation, MAX_PROVIDER_OUTPUT_BYTES)?;
    if !output.status.success() {
        return Err("secret entry was cancelled or the GUI prompt failed".into());
    }
    normalize_provider_output(output.stdout)
}

fn public_record(record: &SecretRecord) -> Value {
    let status = if record.status == LifecycleStatus::Active && record_expired(record) {
        "expired"
    } else {
        match record.status {
            LifecycleStatus::Provisioning => "provisioning",
            LifecycleStatus::Active => "active",
            LifecycleStatus::Claimed => "claimed",
            LifecycleStatus::Running => "running",
            LifecycleStatus::CleanupPending => "cleanup_pending",
            LifecycleStatus::Consumed => "consumed",
            LifecycleStatus::Deleted => "deleted",
            LifecycleStatus::Expired => "expired",
            LifecycleStatus::Revoked => "revoked",
        }
    };
    json!({
        "handle": record.handle,
        "target": record.target,
        "label": record.label,
        "created_at": record.created_at,
        "expires_at": record.expires_at,
        "single_use": record.single_use,
        "status": status,
        "last_error": record.last_error,
    })
}

fn finalize_cleanup_parts(
    action: &CleanupAction,
    helper_result: &Result<(), String>,
    keyring_result: &Result<(), String>,
) -> Result<(), String> {
    with_state(|state| {
        let record =
            state.records.get_mut(&action.handle).ok_or_else(|| "unknown handle".to_string())?;
        if !matches!(record.status, LifecycleStatus::CleanupPending | LifecycleStatus::Revoked)
            || record.cleanup_target != Some(action.target)
            || record.generation != action.generation
        {
            return Ok(());
        }
        if helper_result.is_ok() {
            record.helper_pid = None;
            record.helper_pgid = None;
            record.helper_start_ticks = None;
            record.helper_boot_id = None;
            record.helper_kind = None;
            record.helper_cgroup = None;
            record.helper_cgroup_identity = None;
            record.helper_descendants_unknown = false;
        }
        if keyring_result.is_ok() {
            record.cleanup_keyring_done = true;
        }
        let helper_done = record.helper_pid.is_none()
            && record.helper_cgroup.is_none()
            && !record.helper_descendants_unknown;
        if helper_done && record.cleanup_keyring_done {
            record.status = action.target;
            record.cleanup_target = None;
            record.claim_id = None;
            record.lease_owner = None;
            record.lease_expires_at = None;
            record.lease_expires_mono = None;
            record.lease_boot_id = None;
            record.last_error = None;
            record.cleanup_keyring_done = false;
            record.helper_descendants_unknown = false;
            if action.target == LifecycleStatus::Consumed {
                record.consumed_at = Some(now());
            }
        } else {
            let mut errors = Vec::new();
            if let Err(error) = helper_result {
                errors.push(format!("helper cleanup failed: {error}"));
            }
            if let Err(error) = keyring_result {
                errors.push(format!("keyring cleanup failed: {error}"));
            }
            if errors.is_empty() {
                errors.push("cleanup remains incomplete".into());
            }
            record.last_error = Some(errors.join("; "));
        }
        record.generation = record.generation.saturating_add(1);
        Ok(())
    })
}

fn perform_cleanup(action: &CleanupAction, cancellation: &CancellationToken) -> Result<(), String> {
    let helper_result = if action.helper_descendants_unknown {
        Err("legacy helper descendants cannot be verified".to_owned())
    } else {
        kill_recorded_helper(action)
    };
    let keyring_result = if action.cleanup_keyring_done {
        Ok(())
    } else {
        cleanup_keyring(&action.account, cancellation)
    };
    finalize_cleanup_parts(action, &helper_result, &keyring_result)?;
    let mut errors = Vec::new();
    if let Err(error) = helper_result {
        errors.push(format!("helper cleanup failed: {error}"));
    }
    if let Err(error) = keyring_result {
        errors.push(format!("keyring cleanup failed: {error}"));
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}

fn reconcile_operation_cgroups(
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<(), String> {
    let stale = with_state(|state| {
        Ok(state
            .operation_cgroups
            .iter()
            .filter(|(_, fence)| {
                operation_cgroup_expired(fence)
                    || matches!(operation_cgroup_owner_liveness(fence), ProcessLiveness::Dead)
            })
            .map(|(path, fence)| (path.clone(), fence.clone()))
            .collect::<Vec<_>>())
    })?;
    let mut first_cleanup_error = None;
    for (path, fence) in stale {
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            break;
        }
        match kill_cgroup_path(&path, fence.identity) {
            Ok(()) => {
                with_state(|state| {
                    if state.operation_cgroups.get(&path) == Some(&fence) {
                        state.operation_cgroups.remove(&path);
                    }
                    Ok(())
                })?;
            },
            Err(error) => {
                first_cleanup_error.get_or_insert(error);
            },
        }
    }
    first_cleanup_error.map_or(Ok(()), Err)
}

fn reconcile(cancellation: &CancellationToken) -> Result<(), String> {
    let deadline = Instant::now() + RECONCILE_TIMEOUT;
    reconcile_unregistered_operation_cgroups(cancellation, deadline)?;
    reconcile_operation_cgroups(cancellation, deadline)?;
    let actions = with_state(|state| {
        let mut actions = Vec::new();
        for record in state.records.values_mut() {
            if cancellation.is_cancelled() || Instant::now() >= deadline {
                break;
            }
            let lease_state = lease_liveness(record);
            if matches!(lease_state, LeaseLiveness::Live | LeaseLiveness::Unknown)
                && matches!(
                    record.status,
                    LifecycleStatus::Provisioning
                        | LifecycleStatus::Claimed
                        | LifecycleStatus::Running
                )
            {
                continue;
            }
            let target = match record.status {
                LifecycleStatus::Provisioning
                | LifecycleStatus::Claimed
                | LifecycleStatus::Running
                | LifecycleStatus::Revoked => Some(LifecycleStatus::Deleted),
                LifecycleStatus::CleanupPending => {
                    record.cleanup_target.or(Some(LifecycleStatus::Deleted))
                },
                LifecycleStatus::Active if record_expired(record) => Some(LifecycleStatus::Expired),
                _ => None,
            };
            if let Some(target) = target {
                record.status = LifecycleStatus::CleanupPending;
                record.cleanup_target = Some(target);
                record.last_error = Some("cleanup scheduled during recovery".into());
                record.generation = record.generation.saturating_add(1);
                actions.push(cleanup_action_for(record, target));
            }
        }
        Ok(actions)
    })?;
    for action in actions {
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            break;
        }
        perform_cleanup(&action, cancellation)?;
    }
    Ok(())
}

fn capture(
    target: &str,
    label: &str,
    ttl_seconds: u64,
    single_use: bool,
    cancellation: &CancellationToken,
) -> Result<Value, String> {
    validate_text(target, "target")?;
    validate_text(label, "label")?;
    let ttl = validate_ttl(ttl_seconds)?;
    let target = target.trim().to_owned();
    let label = label.trim().to_owned();
    with_state(ensure_capture_capacity)?;
    let secret = gui_prompt(&target, &label, cancellation)?;
    validate_secret_for_environment(&secret)?;
    if cancellation.is_cancelled() {
        return Err("secret capture was cancelled".into());
    }
    let handle = format!("sh_{}", Uuid::new_v4().simple());
    let account = format!("handoff:{handle}");
    let created_at = now();
    let expires_at = created_at.saturating_add(ttl);
    let (current_mono, current_boot) = monotonic_pair();
    let record = SecretRecord {
        handle: handle.clone(),
        target: target.clone(),
        label: label.clone(),
        created_at,
        expires_at,
        single_use,
        status: LifecycleStatus::Provisioning,
        keyring_account: account.clone(),
        consumed_at: None,
        claim_id: None,
        cleanup_target: None,
        last_error: None,
        generation: 1,
        lease_owner: Some(process_owner().to_owned()),
        lease_expires_at: Some(created_at.saturating_add(LEASE_TIMEOUT.as_secs())),
        lease_expires_mono: current_mono.map(|value| value.saturating_add(LEASE_TIMEOUT.as_secs())),
        lease_boot_id: current_boot.clone(),
        expires_mono: current_mono.map(|value| value.saturating_add(ttl)),
        expires_boot_id: current_boot,
        helper_pid: None,
        helper_pgid: None,
        helper_start_ticks: None,
        helper_boot_id: None,
        helper_kind: None,
        helper_cgroup: None,
        helper_cgroup_identity: None,
        cleanup_keyring_done: false,
        helper_descendants_unknown: false,
    };
    with_state(|state| {
        ensure_capture_capacity(state)?;
        state.records.insert(handle.clone(), record.clone());
        Ok(())
    })?;
    let capture_fence = CaptureFence { handle: handle.clone(), generation: record.generation };
    if let Err(error) =
        secret_tool_store(&capture_fence, &target, &label, secret.as_slice(), cancellation)
    {
        if let Ok(action) = mark_cleanup_pending(&handle, LifecycleStatus::Deleted, &error) {
            if let Err(cleanup_error) = perform_cleanup(&action, cancellation) {
                return Err(format!("{error}; cleanup pending: {cleanup_error}"));
            }
        } else {
            return Err(format!("{error}; cleanup pending: state fence unavailable"));
        }
        return Err(error);
    }
    if cancellation.is_cancelled() {
        let action = mark_cleanup_pending(
            &handle,
            LifecycleStatus::Deleted,
            "capture was cancelled after keyring store",
        )?;
        if let Err(cleanup_error) = perform_cleanup(&action, cancellation) {
            return Err(format!("secret capture was cancelled; cleanup pending: {cleanup_error}"));
        }
        return Err("secret capture was cancelled".into());
    }
    if with_state(|state| {
        let record =
            state.records.get(&handle).ok_or_else(|| "capture state disappeared".to_string())?;
        Ok(record_expired(record))
    })? {
        let action = mark_cleanup_pending(
            &handle,
            LifecycleStatus::Expired,
            "capture expired before activation",
        )?;
        perform_cleanup(&action, cancellation)?;
        return Err("capture expired before activation".into());
    }
    let activate_result = with_state(|state| {
        let record = state
            .records
            .get_mut(&handle)
            .ok_or_else(|| "capture state disappeared".to_string())?;
        if record.status != LifecycleStatus::Provisioning {
            return Err("capture was revoked during provisioning".into());
        }
        if record_expired(record) {
            return Err("capture expired before activation".into());
        }
        record.status = LifecycleStatus::Active;
        record.lease_owner = None;
        record.lease_expires_at = None;
        record.lease_expires_mono = None;
        record.lease_boot_id = None;
        record.generation = record.generation.saturating_add(1);
        Ok(())
    });
    if let Err(error) = activate_result {
        let target = if error == "capture expired before activation" {
            LifecycleStatus::Expired
        } else {
            LifecycleStatus::Deleted
        };
        let action = mark_cleanup_pending(&handle, target, &error)?;
        if let Err(cleanup_error) = perform_cleanup(&action, cancellation) {
            return Err(format!("{error}; cleanup pending: {cleanup_error}"));
        }
        return Err(error);
    }
    if cancellation.is_cancelled() {
        let action = mark_cleanup_pending(
            &handle,
            LifecycleStatus::Deleted,
            "capture was cancelled before response",
        )?;
        if let Err(cleanup_error) = perform_cleanup(&action, cancellation) {
            return Err(format!("secret capture was cancelled; cleanup pending: {cleanup_error}"));
        }
        return Err("secret capture was cancelled".into());
    }
    Ok(json!({
        "handle": handle,
        "target": target,
        "label": label,
        "expires_at": record.expires_at,
        "single_use": single_use,
        "status": "active"
    }))
}

fn mark_cleanup_pending(
    handle: &str,
    target: LifecycleStatus,
    error: &str,
) -> Result<CleanupAction, String> {
    with_state(|state| {
        let record = state.records.get_mut(handle).ok_or_else(|| "unknown handle".to_string())?;
        if matches!(
            record.status,
            LifecycleStatus::Consumed | LifecycleStatus::Deleted | LifecycleStatus::Expired
        ) {
            return Err("cleanup was already finalized".into());
        }
        record.status = LifecycleStatus::CleanupPending;
        record.cleanup_target = Some(target);
        record.last_error = Some(error.to_owned());
        record.lease_owner = None;
        record.lease_expires_at = None;
        record.lease_expires_mono = None;
        record.lease_boot_id = None;
        record.generation = record.generation.saturating_add(1);
        Ok(cleanup_action_for(record, target))
    })
}

fn list_status(handle: Option<&str>) -> Result<Value, String> {
    with_state_read(|state| {
        if let Some(handle) = handle {
            validate_text(handle, "handle")?;
            return state
                .records
                .get(handle)
                .map(public_record)
                .ok_or_else(|| "unknown handle".into());
        }
        Ok(json!({
            "records": state.records.values().map(public_record).collect::<Vec<_>>()
        }))
    })
}

fn prune_terminal_records(state: &mut State) {
    if state.records.len() < MAX_RECORDS {
        return;
    }
    let excess = state.records.len().saturating_sub(MAX_RECORDS.saturating_sub(1));
    let mut removable = state
        .records
        .iter()
        .filter(|(_, record)| {
            matches!(
                record.status,
                LifecycleStatus::Consumed | LifecycleStatus::Deleted | LifecycleStatus::Expired
            ) && record.cleanup_target.is_none()
                && record.claim_id.is_none()
                && record.lease_owner.is_none()
                && record.helper_pid.is_none()
        })
        .map(|(handle, record)| (record.consumed_at.unwrap_or(record.created_at), handle.clone()))
        .collect::<Vec<_>>();
    removable.sort_by_key(|(timestamp, handle)| (*timestamp, handle.clone()));
    for (_, handle) in removable.into_iter().take(excess) {
        state.records.remove(&handle);
    }
}

fn ensure_capture_capacity(state: &mut State) -> Result<(), String> {
    prune_terminal_records(state);
    if state.records.len() >= MAX_RECORDS {
        return Err("secret handle capacity has been reached".into());
    }
    Ok(())
}

fn delete(handle: &str, cancellation: &CancellationToken) -> Result<Value, String> {
    validate_text(handle, "handle")?;
    if cancellation.is_cancelled() {
        return Err("operation was cancelled".into());
    }
    let action = with_state(|state| {
        let record = state.records.get_mut(handle).ok_or_else(|| "unknown handle".to_string())?;
        match record.status {
            LifecycleStatus::Deleted | LifecycleStatus::Consumed | LifecycleStatus::Expired => {
                Ok(None)
            },
            LifecycleStatus::CleanupPending => {
                record.cleanup_target = Some(LifecycleStatus::Deleted);
                record.generation = record.generation.saturating_add(1);
                Ok(Some(cleanup_action_for(record, LifecycleStatus::Deleted)))
            },
            LifecycleStatus::Claimed | LifecycleStatus::Running => {
                record.status = LifecycleStatus::Revoked;
                record.generation = record.generation.saturating_add(1);
                record.cleanup_target = Some(LifecycleStatus::Deleted);
                Ok(Some(cleanup_action_for(record, LifecycleStatus::Deleted)))
            },
            _ => {
                record.status = LifecycleStatus::CleanupPending;
                record.cleanup_target = Some(LifecycleStatus::Deleted);
                record.generation = record.generation.saturating_add(1);
                Ok(Some(cleanup_action_for(record, LifecycleStatus::Deleted)))
            },
        }
    })?;
    let Some(action) = action else {
        return list_status(Some(handle));
    };
    perform_cleanup(&action, cancellation)?;
    Ok(json!({"handle": handle, "status": "deleted"}))
}

fn claim_for_run(handle: &str, cancellation: &CancellationToken) -> Result<RunClaim, String> {
    validate_text(handle, "handle")?;
    let decision = with_state(|state| {
        let record = state.records.get_mut(handle).ok_or_else(|| "unknown handle".to_string())?;
        if record.status != LifecycleStatus::Active {
            return Ok(Err(None));
        }
        if record_expired(record) {
            record.status = LifecycleStatus::CleanupPending;
            record.cleanup_target = Some(LifecycleStatus::Expired);
            record.last_error = Some("handle expired before operation claim".into());
            record.generation = record.generation.saturating_add(1);
            return Ok(Err(Some(cleanup_action_for(record, LifecycleStatus::Expired))));
        }
        let claim_id = Uuid::new_v4().simple().to_string();
        record.status = LifecycleStatus::Claimed;
        record.claim_id = Some(claim_id.clone());
        record.lease_owner = Some(process_owner().to_owned());
        let current_now = now();
        let (current_mono, current_boot) = monotonic_pair();
        record.lease_expires_at = Some(current_now.saturating_add(LEASE_TIMEOUT.as_secs()));
        record.lease_expires_mono =
            current_mono.map(|value| value.saturating_add(LEASE_TIMEOUT.as_secs()));
        record.lease_boot_id = current_boot;
        record.generation = record.generation.saturating_add(1);
        let generation = record.generation;
        Ok(Ok(RunClaim {
            handle: handle.to_owned(),
            account: record.keyring_account.clone(),
            claim_id,
            single_use: record.single_use,
            generation,
        }))
    })?;
    match decision {
        Ok(claim) => Ok(claim),
        Err(Some(action)) => {
            perform_cleanup(&action, cancellation)?;
            Err("handle has expired".into())
        },
        Err(None) => Err("handle is not active".into()),
    }
}

fn restore_claim(claim: &RunClaim) -> Result<(), String> {
    with_state(|state| {
        if let Some(record) = state.records.get_mut(&claim.handle)
            && record.status == LifecycleStatus::Claimed
            && record.claim_id.as_deref() == Some(&claim.claim_id)
        {
            record.status = LifecycleStatus::Active;
            record.claim_id = None;
            record.lease_owner = None;
            record.lease_expires_at = None;
            record.lease_expires_mono = None;
            record.lease_boot_id = None;
            record.generation = record.generation.saturating_add(1);
        }
        Ok(())
    })
}

#[derive(Debug)]
struct LaunchError {
    message: String,
    uncertain: bool,
}

impl LaunchError {
    fn uncertain(message: impl Into<String>) -> Self {
        Self { message: message.into(), uncertain: true }
    }
}

impl From<String> for LaunchError {
    fn from(message: String) -> Self {
        Self { message, uncertain: false }
    }
}

impl From<&str> for LaunchError {
    fn from(message: &str) -> Self {
        Self { message: message.to_owned(), uncertain: false }
    }
}

fn mark_record_cleanup_pending(
    record: &mut SecretRecord,
    target: LifecycleStatus,
    error: impl Into<String>,
) {
    record.status = LifecycleStatus::CleanupPending;
    record.cleanup_target = Some(target);
    record.claim_id = None;
    record.lease_owner = None;
    record.lease_expires_at = None;
    record.lease_expires_mono = None;
    record.lease_boot_id = None;
    record.last_error = Some(error.into());
    record.generation = record.generation.saturating_add(1);
}

fn append_cleanup_error(mut message: String, cleanup: Result<(), String>) -> String {
    if let Err(error) = cleanup {
        message.push_str("; cgroup cleanup pending: ");
        message.push_str(&error);
    }
    message
}

fn launch_operation(
    claim: &RunClaim,
    command_path: &SecureFile,
    operation: &Operation,
    secret_value: &str,
    cancellation: &CancellationToken,
) -> Result<(Child, HelperFence), LaunchError> {
    if cancellation.is_cancelled() {
        return Err("operation was cancelled".into());
    }
    let dir = canonical_state_dir()?;
    let directory = open_private_directory(&dir)?;
    let lock = open_state_lock_at(&directory, true)?;
    let mut state = read_state_at(&directory)?;
    let (current_mono, current_boot) = monotonic_pair();
    let current_boot =
        current_boot.ok_or_else(|| "operation helper boot identity is unavailable".to_string())?;
    {
        let record =
            state.records.get(&claim.handle).ok_or_else(|| "unknown handle".to_string())?;
        if record.status != LifecycleStatus::Claimed
            || record.claim_id.as_deref() != Some(&claim.claim_id)
            || record.generation != claim.generation
        {
            let _ = lock.unlock();
            return Err("handle was revoked before operation start".into());
        }
    }
    let cgroup = Arc::new(create_operation_cgroup().map_err(LaunchError::from)?);
    let cgroup_raw = cgroup.path.to_string_lossy().into_owned();
    let cgroup_identity = cgroup.identity;
    if state.operation_cgroups.len() >= MAX_OPERATION_CGROUPS
        && !state.operation_cgroups.contains_key(&cgroup_raw)
    {
        let cleanup = kill_open_cgroup(&cgroup);
        let _ = lock.unlock();
        return Err(LaunchError::uncertain(append_cleanup_error(
            "operation cgroup capacity has been reached".to_owned(),
            cleanup,
        )));
    }
    state.operation_cgroups.insert(cgroup_raw.clone(), operation_cgroup_fence(cgroup_identity));
    {
        let record =
            state.records.get_mut(&claim.handle).ok_or_else(|| "unknown handle".to_string())?;
        record.helper_cgroup = Some(cgroup_raw.clone());
        record.helper_cgroup_identity = Some(cgroup_identity);
        record.generation = record.generation.saturating_add(1);
    }
    if let Err(error) = write_state_at(&directory, &mut state) {
        let message = append_cleanup_error(error, kill_open_cgroup(&cgroup));
        let _ = lock.unlock();
        return Err(LaunchError::uncertain(message));
    }
    let command_path = match command_path.exec_path() {
        Ok(path) => path,
        Err(error) => {
            let message = append_cleanup_error(error, kill_open_cgroup(&cgroup));
            let _ = lock.unlock();
            return Err(LaunchError::uncertain(message));
        },
    };
    let mut command = Command::new(command_path);
    command
        .args(&operation.args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env(&operation.secret_env, secret_value)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    prepare_child(&mut command, Some(cgroup.file.as_raw_fd()));
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            let cleanup = kill_open_cgroup(&cgroup);
            if let Some(record) = state.records.get_mut(&claim.handle) {
                let error = match &cleanup {
                    Ok(()) => "allowlisted operation could not be started".to_owned(),
                    Err(cleanup_error) => format!(
                        "allowlisted operation could not be started; cgroup cleanup pending: {cleanup_error}"
                    ),
                };
                mark_record_cleanup_pending(record, LifecycleStatus::Deleted, error);
                if cleanup.is_ok() {
                    record.helper_cgroup = None;
                    record.helper_cgroup_identity = None;
                }
            }
            if cleanup.is_ok() {
                state.operation_cgroups.remove(&cgroup_raw);
            }
            let state_write = write_state_at(&directory, &mut state);
            let _ = lock.unlock();
            let message = match state_write {
                Ok(()) => match cleanup {
                    Ok(()) => "allowlisted operation could not be started".to_owned(),
                    Err(error) => {
                        format!(
                            "allowlisted operation could not be started; cgroup cleanup pending: {error}"
                        )
                    },
                },
                Err(error) => format!(
                    "allowlisted operation could not be started; cleanup state could not be persisted: {error}"
                ),
            };
            return Err(LaunchError::uncertain(message));
        },
    };
    let pid = child.id();
    let start_ticks = match process_start_ticks(pid) {
        Ok(Some(start_ticks)) => start_ticks,
        Ok(None) | Err(_) => {
            let cleanup = terminate_child(&mut child, Some(&cgroup));
            if let Some(record) = state.records.get_mut(&claim.handle) {
                let error = match &cleanup {
                    Some(cleanup_error) => {
                        format!("operation helper identity could not be verified; {cleanup_error}")
                    },
                    None => "operation helper identity could not be verified".to_owned(),
                };
                mark_record_cleanup_pending(record, LifecycleStatus::Deleted, error);
            }
            let state_write = write_state_at(&directory, &mut state);
            let _ = lock.unlock();
            let message = match state_write {
                Ok(()) => match cleanup {
                    Some(error) => {
                        format!("operation helper identity could not be verified; {error}")
                    },
                    None => "operation helper identity could not be verified".to_owned(),
                },
                Err(error) => format!(
                    "operation helper identity could not be verified; cleanup state could not be persisted: {error}"
                ),
            };
            return Err(LaunchError::uncertain(message));
        },
    };
    let pgid = pid as i32;
    if !process_group_matches(pid, pgid) {
        let cleanup = terminate_child(&mut child, Some(&cgroup));
        if let Some(record) = state.records.get_mut(&claim.handle) {
            let error = match &cleanup {
                Some(cleanup_error) => {
                    format!("operation helper process group could not be verified; {cleanup_error}")
                },
                None => "operation helper process group could not be verified".to_owned(),
            };
            mark_record_cleanup_pending(record, LifecycleStatus::Deleted, error);
        }
        let state_write = write_state_at(&directory, &mut state);
        let _ = lock.unlock();
        let message = match state_write {
            Ok(()) => match cleanup {
                Some(error) => {
                    format!("operation helper process group could not be verified; {error}")
                },
                None => "operation helper process group could not be verified".to_owned(),
            },
            Err(error) => format!(
                "operation helper process group could not be verified; cleanup state could not be persisted: {error}"
            ),
        };
        return Err(LaunchError::uncertain(message));
    }
    let helper_generation;
    {
        let record =
            state.records.get_mut(&claim.handle).ok_or_else(|| "unknown handle".to_string())?;
        record.status = LifecycleStatus::Running;
        let current_now = now();
        let lease_seconds = OPERATION_TIMEOUT.saturating_add(OPERATION_LEASE_GRACE).as_secs();
        record.lease_expires_at = Some(current_now.saturating_add(lease_seconds));
        record.lease_expires_mono = current_mono.map(|value| value.saturating_add(lease_seconds));
        record.lease_boot_id = Some(current_boot.clone());
        record.helper_pid = Some(pid);
        record.helper_pgid = Some(pgid);
        record.helper_start_ticks = Some(start_ticks);
        record.helper_boot_id = Some(current_boot.clone());
        record.helper_kind = Some("allowlisted-operation".into());
        record.helper_cgroup = Some(cgroup_raw.clone());
        record.helper_cgroup_identity = Some(cgroup_identity);
        record.generation = record.generation.saturating_add(1);
        helper_generation = record.generation;
    }
    if let Err(error) = write_state_at(&directory, &mut state) {
        let cleanup = terminate_child(&mut child, Some(&cgroup));
        let message = match cleanup {
            Some(cleanup_error) => format!("{error}; {cleanup_error}"),
            None => error,
        };
        let _ = lock.unlock();
        return Err(LaunchError::uncertain(message));
    }
    let _ = lock.unlock();
    let helper = HelperFence {
        handle: claim.handle.clone(),
        pid,
        pgid,
        start_ticks,
        boot_id: current_boot,
        generation: helper_generation,
        cgroup: Some(cgroup_raw),
        cgroup_identity: Some(cgroup_identity),
        live_cgroup: Some(cgroup),
    };
    Ok((child, helper))
}

fn finish_run(
    claim: &RunClaim,
    helper: &HelperFence,
    outcome_uncertain: bool,
    cancellation: &CancellationToken,
) -> Result<(), String> {
    let mut outcome_uncertain = outcome_uncertain || cancellation.is_cancelled();
    let helper_cleanup_error =
        kill_recorded_helper(&cleanup_action_for_helper(helper, LifecycleStatus::Active)).err();
    if helper_cleanup_error.is_some() {
        outcome_uncertain = true;
    }
    let cgroup_forget_error = if let (Some(cgroup), Some(identity)) =
        (helper.cgroup.as_deref(), helper.cgroup_identity)
    {
        forget_operation_cgroup_if_absent(cgroup, identity).err()
    } else {
        None
    };
    if cgroup_forget_error.is_some() {
        outcome_uncertain = true;
    }
    let action = match with_state(|state| {
        let record =
            state.records.get_mut(&claim.handle).ok_or_else(|| "unknown handle".to_string())?;
        if record.status == LifecycleStatus::Revoked {
            record.status = LifecycleStatus::CleanupPending;
            record.cleanup_target = Some(LifecycleStatus::Deleted);
            return Ok(Some(cleanup_action_for(record, LifecycleStatus::Deleted)));
        }
        if record.status != LifecycleStatus::Running
            || record.claim_id.as_deref() != Some(&claim.claim_id)
            || record.generation != helper.generation
            || record.helper_pid != Some(helper.pid)
            || record.helper_pgid != Some(helper.pgid)
            || record.helper_start_ticks != Some(helper.start_ticks)
            || record.helper_boot_id.as_deref() != Some(helper.boot_id.as_str())
            || record.helper_cgroup.as_deref() != helper.cgroup.as_deref()
            || record.helper_cgroup_identity != helper.cgroup_identity
            || record.lease_owner.as_deref() != Some(process_owner())
        {
            return Err("operation lifecycle fence was lost".into());
        }
        if outcome_uncertain || cancellation.is_cancelled() {
            record.status = LifecycleStatus::CleanupPending;
            record.cleanup_target = Some(LifecycleStatus::Deleted);
            Ok(Some(cleanup_action_for(record, LifecycleStatus::Deleted)))
        } else if claim.single_use {
            record.status = LifecycleStatus::CleanupPending;
            record.cleanup_target = Some(LifecycleStatus::Consumed);
            Ok(Some(cleanup_action_for(record, LifecycleStatus::Consumed)))
        } else {
            record.status = LifecycleStatus::Active;
            record.claim_id = None;
            record.lease_owner = None;
            record.lease_expires_at = None;
            record.lease_expires_mono = None;
            record.lease_boot_id = None;
            record.helper_pid = None;
            record.helper_pgid = None;
            record.helper_start_ticks = None;
            record.helper_boot_id = None;
            record.helper_kind = None;
            record.helper_cgroup = None;
            record.helper_cgroup_identity = None;
            record.generation = record.generation.saturating_add(1);
            Ok(None)
        }
    }) {
        Ok(action) => action,
        Err(error) => {
            if (claim.single_use || outcome_uncertain || cancellation.is_cancelled())
                && let Err(cleanup_error) = cleanup_keyring(&claim.account, cancellation)
            {
                return Err(format!("{error}; cleanup pending: {cleanup_error}"));
            }
            return Err(error);
        },
    };
    if let Some(action) = action {
        let mut cleanup_error = perform_cleanup(&action, cancellation).err();
        if let Some(error) = helper_cleanup_error {
            cleanup_error = Some(match cleanup_error {
                Some(existing) => format!("{error}; {existing}"),
                None => error,
            });
        }
        if let Some(error) = cgroup_forget_error {
            cleanup_error = Some(match cleanup_error {
                Some(existing) => format!("{error}; {existing}"),
                None => error,
            });
        }
        if let Some(error) = cleanup_error {
            return Err(format!("cleanup pending: {error}"));
        }
    } else if cancellation.is_cancelled() {
        let action = mark_cleanup_pending(
            &claim.handle,
            LifecycleStatus::Deleted,
            "operation was cancelled before reusable handle restoration",
        )?;
        perform_cleanup(&action, cancellation)?;
        return Err("operation was cancelled".into());
    }
    Ok(())
}

fn load_operation(name: &str) -> Result<(SecureFile, Operation), String> {
    validate_text(name, "operation")?;
    let config = secure_open_file_with_options(&config_file(), false, false, true)?;
    let metadata = config.file.metadata().map_err(|_| "operation allowlist is unavailable")?;
    if metadata.len() > MAX_OPERATION_FILE_BYTES {
        return Err("operation allowlist exceeds the configured limit".into());
    }
    let bytes = config.read_bytes(MAX_OPERATION_FILE_BYTES)?;
    let file: OperationsFile =
        serde_json::from_slice(&bytes).map_err(|_| "operation allowlist is invalid")?;
    if file.operations.len() > MAX_OPERATIONS {
        return Err("operation allowlist exceeds the configured entry limit".into());
    }
    let operation = file
        .operations
        .get(name)
        .cloned()
        .ok_or_else(|| "operation is not allowlisted".to_string())?;
    if !Path::new(&operation.command).is_absolute()
        || operation.secret_env.is_empty()
        || operation.secret_env.len() > 128
        || operation.secret_env.chars().enumerate().any(|(index, c)| {
            !(c == '_' || c.is_ascii_alphanumeric()) || (index == 0 && c.is_ascii_digit())
        })
        || matches!(
            operation.secret_env.as_str(),
            "PATH" | "LD_PRELOAD" | "LD_LIBRARY_PATH" | "BASH_ENV" | "ENV" | "PYTHONINSPECT"
        )
    {
        return Err("operation allowlist entry is invalid".into());
    }
    for arg in &operation.args {
        if arg.len() > 4096 || arg.chars().any(|c| c.is_control()) {
            return Err("operation allowlist entry is invalid".into());
        }
    }
    if operation.args.len() > MAX_OPERATION_ARGS {
        return Err("operation allowlist entry has too many arguments".into());
    }
    let command = secure_open_file_with_options(Path::new(&operation.command), true, true, false)?;
    Ok((command, operation))
}

fn run_operation(
    handle: &str,
    operation_name: &str,
    cancellation: &CancellationToken,
) -> Result<Value, String> {
    let (command_path, operation) = load_operation(operation_name)?;
    let claim = claim_for_run(handle, cancellation)?;
    let secret = match secret_tool_lookup(&claim.account, cancellation) {
        Ok(secret) => secret,
        Err(error) => {
            return Err(match restore_claim(&claim) {
                Ok(()) => error,
                Err(restore_error) => {
                    format!("{error}; claim restoration failed: {restore_error}")
                },
            });
        },
    };
    let secret_value = match std::str::from_utf8(secret.as_slice()) {
        Ok(value) => value,
        Err(_) => {
            let error = "secret is not valid UTF-8 and cannot be placed in an environment variable";
            return Err(match restore_claim(&claim) {
                Ok(()) => error.into(),
                Err(restore_error) => format!("{error}; claim restoration failed: {restore_error}"),
            });
        },
    };
    let started = Instant::now();
    let (child, helper) =
        match launch_operation(&claim, &command_path, &operation, secret_value, cancellation) {
            Ok(launch) => launch,
            Err(error) => {
                if !error.uncertain {
                    let message = match restore_claim(&claim) {
                        Ok(()) => error.message,
                        Err(restore_error) => {
                            format!("{}; claim restoration failed: {restore_error}", error.message)
                        },
                    };
                    return Err(message);
                }
                return Err(error.message);
            },
        };
    let output = wait_bounded(
        child,
        OPERATION_TIMEOUT,
        cancellation,
        MAX_CHILD_OUTPUT_BYTES,
        helper.live_cgroup.as_deref(),
    );
    let outcome = match &output {
        Ok(output) => json!({
            "handle": handle,
            "operation": operation_name,
            "status": if output.status.success() { "succeeded" } else { "failed" },
            "exit_code": output.status.code(),
            "duration_ms": started.elapsed().as_millis()
        }),
        Err(error) => {
            return match finish_run(&claim, &helper, true, cancellation) {
                Ok(()) => Err(error.clone()),
                Err(cleanup_error) => Err(format!("{error}; cleanup pending: {cleanup_error}")),
            };
        },
    };
    finish_run(&claim, &helper, false, cancellation)?;
    Ok(outcome)
}

fn tool_schema<T: schemars::JsonSchema + 'static>() -> Arc<rmcp::model::JsonObject> {
    rmcp::handler::server::common::schema_for_input::<T>().expect("tool input schema must be valid")
}

#[derive(Debug, Deserialize, schemars::JsonSchema, Default)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
struct CaptureRequest {
    target: String,
    label: String,
    #[serde(default)]
    #[schemars(range(min = 1, max = 86400))]
    ttl_seconds: Option<u64>,
    #[serde(default)]
    single_use: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema, Default)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
struct StatusRequest {
    #[serde(default)]
    handle: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema, Default)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
struct DeleteRequest {
    handle: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema, Default)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
struct RunRequest {
    handle: String,
    operation: String,
}

fn tool_catalog() -> Vec<Tool> {
    vec![
        Tool::new(
            "secret_handoff_capture",
            "Open a local trusted GUI prompt, store the secret in the OS keyring, and return only an opaque handle.",
            tool_schema::<CaptureRequest>(),
        )
        .with_annotations(ToolAnnotations::from_raw(None, Some(false), Some(false), Some(false), Some(false))),
        Tool::new(
            "secret_handoff_status",
            "Read redacted handles and lifecycle metadata; never returns secret material.",
            tool_schema::<StatusRequest>(),
        )
        .with_annotations(ToolAnnotations::from_raw(None, Some(true), Some(false), Some(true), Some(false))),
        Tool::new(
            "secret_handoff_delete",
            "Revoke one exact handle and remove its keyring entry, retrying cleanup if the provider is temporarily unavailable.",
            tool_schema::<DeleteRequest>(),
        )
        .with_annotations(ToolAnnotations::from_raw(None, Some(false), Some(true), Some(true), Some(false))),
        Tool::new(
            "secret_handoff_run",
            "Run one locally configured trusted command with a handle injected into its configured environment variable.",
            tool_schema::<RunRequest>(),
        )
        .with_annotations(ToolAnnotations::from_raw(None, Some(false), Some(true), Some(false), Some(true))),
    ]
}

#[derive(Clone)]
struct SecretHandoffServer {
    tools: Arc<Vec<Tool>>,
    work_limiter: Arc<Semaphore>,
    control_limiter: Arc<Semaphore>,
}

impl Default for SecretHandoffServer {
    fn default() -> Self {
        Self {
            tools: Arc::new(tool_catalog()),
            work_limiter: Arc::new(Semaphore::new(MAX_CONCURRENT_OPERATIONS)),
            control_limiter: Arc::new(Semaphore::new(MAX_CONCURRENT_CONTROL_OPERATIONS)),
        }
    }
}

impl SecretHandoffServer {
    async fn dispatch(
        &self,
        request: CallToolRequestParams,
        cancellation: CancellationToken,
    ) -> Result<CallToolResponse, ErrorData> {
        let limiter = match request.name.as_ref() {
            "secret_handoff_status" | "secret_handoff_delete" => &self.control_limiter,
            "secret_handoff_capture" | "secret_handoff_run" => &self.work_limiter,
            _ => &self.control_limiter,
        };
        let _permit = limiter.clone().try_acquire_owned().map_err(|_| {
            ErrorData::internal_error("operation capacity is busy; retry later", None)
        })?;
        if cancellation.is_cancelled() {
            return Err(ErrorData::invalid_request("operation was cancelled", None));
        }
        let args = request.arguments.unwrap_or_default();
        let encoded_args = serde_json::to_vec(&args)
            .map_err(|_| ErrorData::invalid_params("tool arguments are not serializable", None))?;
        if encoded_args.len() > MAX_TOOL_ARGUMENT_BYTES {
            return Err(ErrorData::invalid_params(
                "tool arguments exceed the configured limit",
                None,
            ));
        }
        let result = match request.name.as_ref() {
            "secret_handoff_capture" => {
                let request: CaptureRequest =
                    serde_json::from_value(Value::Object(args)).map_err(|error| {
                        let _ = error;
                        ErrorData::invalid_params(
                            "invalid capture arguments; check documented field names and types",
                            None,
                        )
                    })?;
                let ttl = request.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
                let single_use = request.single_use.unwrap_or(true);
                task::spawn_blocking(move || {
                    reconcile(&cancellation)?;
                    capture(&request.target, &request.label, ttl, single_use, &cancellation)
                })
                .await
                .map_err(|_| ErrorData::internal_error("capture worker failed", None))?
            },
            "secret_handoff_status" => {
                let request: StatusRequest =
                    serde_json::from_value(Value::Object(args)).map_err(|error| {
                        let _ = error;
                        ErrorData::invalid_params(
                            "invalid status arguments; check documented field names and types",
                            None,
                        )
                    })?;
                task::spawn_blocking(move || list_status(request.handle.as_deref()))
                    .await
                    .map_err(|_| ErrorData::internal_error("status worker failed", None))?
            },
            "secret_handoff_delete" => {
                let request: DeleteRequest =
                    serde_json::from_value(Value::Object(args)).map_err(|error| {
                        let _ = error;
                        ErrorData::invalid_params(
                            "invalid delete arguments; check documented field names and types",
                            None,
                        )
                    })?;
                task::spawn_blocking(move || {
                    reconcile(&cancellation)?;
                    delete(&request.handle, &cancellation)
                })
                .await
                .map_err(|_| ErrorData::internal_error("delete worker failed", None))?
            },
            "secret_handoff_run" => {
                let request: RunRequest =
                    serde_json::from_value(Value::Object(args)).map_err(|error| {
                        let _ = error;
                        ErrorData::invalid_params(
                            "invalid run arguments; check documented field names and types",
                            None,
                        )
                    })?;
                task::spawn_blocking(move || {
                    reconcile(&cancellation)?;
                    run_operation(&request.handle, &request.operation, &cancellation)
                })
                .await
                .map_err(|_| ErrorData::internal_error("run worker failed", None))?
            },
            _ => return Err(ErrorData::invalid_params("unknown tool", None)),
        };
        match result {
            Ok(value) => Ok(CallToolResult::structured(value).into()),
            Err(error) => Ok(CallToolResult::structured_error(json!({"error": error})).into()),
        }
    }
}

impl ServerHandler for SecretHandoffServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("codex-secret-handoff-mcp", env!("CARGO_PKG_VERSION")))
            .with_instructions("Secrets are captured locally, stored in the OS keyring, and exposed only through opaque handles.")
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, ErrorData>> + Send + '_ {
        std::future::ready(Ok(ListToolsResult::with_all_items((*self.tools).clone())))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tools.iter().find(|tool| tool.name == name).cloned()
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResponse, ErrorData>> + Send + '_ {
        let server = self.clone();
        async move { server.dispatch(request, context.ct).await }
    }
}

struct BoundedLineReader<R> {
    inner: R,
    line_length: usize,
    max_line_length: usize,
    rejected: bool,
}

struct EofSignalReader<R> {
    inner: R,
    eof_signal: CancellationToken,
}

impl<R> EofSignalReader<R> {
    fn new(inner: R, eof_signal: CancellationToken) -> Self {
        Self { inner, eof_signal }
    }
}

impl<R> AsyncRead for EofSignalReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if matches!(&result, Poll::Ready(Ok(()))) && buffer.filled().len() == before {
            self.eof_signal.cancel();
        }
        result
    }
}

impl<R> BoundedLineReader<R> {
    fn new(inner: R, max_line_length: usize) -> Self {
        Self { inner, line_length: 0, max_line_length, rejected: false }
    }
}

impl<R> AsyncRead for BoundedLineReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.rejected {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MCP frame exceeds the configured limit",
            )));
        }
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(context, buffer);
        if matches!(&result, Poll::Ready(Ok(()))) {
            for byte in &buffer.filled()[before..] {
                if *byte == b'\n' {
                    this.line_length = 0;
                } else {
                    this.line_length = this.line_length.saturating_add(1);
                    if this.line_length > this.max_line_length {
                        this.rejected = true;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "MCP frame exceeds the configured limit",
                        )));
                    }
                }
            }
        }
        result
    }
}

async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    let reaper_cancel = CancellationToken::new();
    let reaper_signal = reaper_cancel.clone();
    let reaper = tokio::spawn(async move {
        loop {
            let cleanup_cancel = reaper_signal.child_token();
            let worker_cancel = cleanup_cancel.clone();
            let mut worker = task::spawn_blocking(move || reconcile(&worker_cancel));
            tokio::select! {
                _ = reaper_signal.cancelled() => {
                    cleanup_cancel.cancel();
                    let _ = worker.await;
                    break;
                },
                _ = &mut worker => {}
            }
            tokio::select! {
                _ = reaper_signal.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(30)) => {}
            }
        }
    });
    let eof_signal = CancellationToken::new();
    let transport = rmcp::transport::async_rw::AsyncRwTransport::<RoleServer, _, _>::new_server(
        EofSignalReader::new(
            BoundedLineReader::new(tokio::io::stdin(), MAX_MCP_FRAME_BYTES),
            eof_signal.clone(),
        ),
        tokio::io::stdout(),
    );
    let service_result = SecretHandoffServer::default().serve(transport).await;
    let result = match service_result {
        Ok(service) => {
            let service_cancel = service.cancellation_token();
            let waiting = service.waiting();
            tokio::pin!(waiting);
            tokio::select! {
                result = &mut waiting => result.map(|_| ()).map_err(|error| error.into()),
                _ = eof_signal.cancelled() => {
                    service_cancel.cancel();
                    waiting.await.map(|_| ()).map_err(|error| error.into())
                }
            }
        },
        Err(error) => Err(error.into()),
    };
    reaper_cancel.cancel();
    let _ = reaper.await;
    result
}

async fn cli(args: &[String]) -> Result<(), String> {
    match args.get(1).map(String::as_str).unwrap_or("serve") {
        "serve" => serve().await.map_err(|error| error.to_string()),
        "capture" => {
            let mut target = None;
            let mut label = None;
            let mut ttl = DEFAULT_TTL_SECONDS;
            let mut single_use = true;
            let mut index = 2;
            while index < args.len() {
                match args[index].as_str() {
                    "--target" => {
                        index += 1;
                        target = args.get(index).cloned();
                    },
                    "--label" => {
                        index += 1;
                        label = args.get(index).cloned();
                    },
                    "--ttl-seconds" => {
                        index += 1;
                        ttl = args
                            .get(index)
                            .ok_or_else(|| "ttl_seconds is required".to_string())?
                            .parse()
                            .map_err(|_| "ttl_seconds must be an integer".to_string())?;
                    },
                    "--reusable" => single_use = false,
                    _ => return Err("unknown capture argument".into()),
                }
                index += 1;
            }
            let target = target.ok_or_else(|| "target is required".to_string())?;
            let label = label.ok_or_else(|| "label is required".to_string())?;
            let cancellation = CancellationToken::new();
            let value = task::spawn_blocking(move || {
                reconcile(&cancellation)?;
                capture(&target, &label, ttl, single_use, &cancellation)
            })
            .await
            .map_err(|_| "capture worker failed".to_string())??;
            println!(
                "{}",
                serde_json::to_string_pretty(&value).map_err(|_| "result cannot be serialized")?
            );
            Ok(())
        },
        "status" => {
            let handle = args.get(2).map(String::to_owned);
            let value = task::spawn_blocking(move || list_status(handle.as_deref()))
                .await
                .map_err(|_| "status worker failed".to_string())??;
            println!(
                "{}",
                serde_json::to_string_pretty(&value).map_err(|_| "result cannot be serialized")?
            );
            Ok(())
        },
        "delete" => {
            let handle = args.get(2).ok_or_else(|| "handle is required".to_string())?.clone();
            let cancellation = CancellationToken::new();
            let value = task::spawn_blocking(move || {
                reconcile(&cancellation)?;
                delete(&handle, &cancellation)
            })
            .await
            .map_err(|_| "delete worker failed".to_string())??;
            println!(
                "{}",
                serde_json::to_string_pretty(&value).map_err(|_| "result cannot be serialized")?
            );
            Ok(())
        },
        "run" => {
            let handle_index = args
                .iter()
                .position(|value| value == "--handle")
                .ok_or_else(|| "handle is required".to_string())?;
            let operation_index = args
                .iter()
                .position(|value| value == "--operation")
                .ok_or_else(|| "operation is required".to_string())?;
            let handle =
                args.get(handle_index + 1).ok_or_else(|| "handle is required".to_string())?.clone();
            let operation = args
                .get(operation_index + 1)
                .ok_or_else(|| "operation is required".to_string())?
                .clone();
            let cancellation = CancellationToken::new();
            let value = task::spawn_blocking(move || {
                reconcile(&cancellation)?;
                run_operation(&handle, &operation, &cancellation)
            })
            .await
            .map_err(|_| "run worker failed".to_string())??;
            println!(
                "{}",
                serde_json::to_string_pretty(&value).map_err(|_| "result cannot be serialized")?
            );
            Ok(())
        },
        _ => Err("commands: serve, capture, status, delete, run".into()),
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(error) = cli(&env::args().collect::<Vec<_>>()).await {
        eprintln!("codex-secret-handoff: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease_test_record() -> SecretRecord {
        SecretRecord {
            handle: "sh_lease_test".into(),
            target: "test".into(),
            label: "lease".into(),
            created_at: 1,
            expires_at: u64::MAX,
            single_use: true,
            status: LifecycleStatus::Claimed,
            keyring_account: "handoff:sh_lease_test".into(),
            consumed_at: None,
            claim_id: Some("claim".into()),
            cleanup_target: None,
            last_error: None,
            generation: 1,
            lease_owner: Some(process_owner().to_owned()),
            lease_expires_at: Some(u64::MAX),
            lease_expires_mono: None,
            lease_boot_id: None,
            expires_mono: None,
            expires_boot_id: None,
            helper_pid: None,
            helper_pgid: None,
            helper_start_ticks: None,
            helper_boot_id: None,
            helper_kind: None,
            helper_cgroup: None,
            helper_cgroup_identity: None,
            cleanup_keyring_done: false,
            helper_descendants_unknown: false,
        }
    }

    fn scratch_state_dir(tag: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("codex-secret-handoff-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch state directory");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("scratch permissions");
        dir
    }

    fn temporary_state_files(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .expect("read scratch directory")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("state.json.") && name.ends_with(".tmp"))
            .collect()
    }

    #[test]
    fn state_commits_leave_no_temporary_files() {
        let dir = scratch_state_dir("tmpguard");
        let blocked = dir.join("state.json");
        fs::create_dir(&blocked).expect("blocking directory");
        let directory = open_private_directory(&dir).expect("private directory");
        let mut state = State::default();
        assert!(write_state_at(&directory, &mut state).is_err());
        assert!(
            temporary_state_files(&dir).is_empty(),
            "aborted state commit leaked a temporary file"
        );
        fs::remove_dir(&blocked).expect("remove blocking directory");
        let mut state = State::default();
        write_state_at(&directory, &mut state).expect("state commit");
        assert!(blocked.is_file());
        assert!(
            temporary_state_files(&dir).is_empty(),
            "successful state commit leaked a temporary file"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_removes_only_stale_temporary_state_files() {
        use std::os::unix::ffi::OsStrExt;
        let dir = scratch_state_dir("tmpsweep");
        let stale = dir.join("state.json.11111111-1111-1111-1111-111111111111.tmp");
        let fresh = dir.join("state.json.22222222-2222-2222-2222-222222222222.tmp");
        fs::write(&stale, b"{}").expect("stale temporary file");
        fs::write(&fresh, b"{}").expect("fresh temporary file");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock").as_secs();
        let aged = libc::timespec { tv_sec: (now - 3600) as libc::time_t, tv_nsec: 0 };
        let stale_path = CString::new(stale.as_os_str().as_bytes()).expect("stale path");
        let touched = unsafe {
            libc::utimensat(libc::AT_FDCWD, stale_path.as_ptr(), [aged, aged].as_ptr(), 0)
        };
        assert_eq!(touched, 0, "age the stale temporary file");
        let directory = open_private_directory(&dir).expect("private directory");
        sweep_stale_state_tmp(&directory).expect("sweep");
        assert!(!stale.exists(), "stale temporary state file was kept");
        assert!(fresh.exists(), "in-flight temporary state file was removed");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lifecycle_status_migrates_old_consuming_state() {
        let parsed: LifecycleStatus = serde_json::from_str("\"consuming\"").expect("status");
        assert_eq!(parsed, LifecycleStatus::CleanupPending);
    }

    #[test]
    fn process_owner_is_restart_detectable() {
        let owner = process_owner();
        assert!(process_identity_is_alive(owner));
        assert!(!process_identity_is_alive("owner_legacy"));
    }

    #[test]
    fn monotonic_lease_expiry_wins_over_wall_clock_rollback() {
        let mut record = lease_test_record();
        record.lease_expires_mono = Some(99);
        record.lease_boot_id = Some("boot".into());
        assert_eq!(
            lease_deadline_liveness(&record, Some(100), Some("boot"), 0),
            LeaseLiveness::Expired
        );
    }

    #[test]
    fn partial_or_unavailable_monotonic_lease_is_unknown() {
        let mut record = lease_test_record();
        record.lease_expires_mono = Some(200);
        assert_eq!(
            lease_deadline_liveness(&record, Some(100), Some("boot"), 0),
            LeaseLiveness::Unknown
        );

        record.lease_expires_mono = None;
        record.lease_boot_id = Some("boot".into());
        assert_eq!(
            lease_deadline_liveness(&record, Some(100), Some("boot"), 0),
            LeaseLiveness::Unknown
        );

        record.lease_expires_mono = Some(200);
        assert_eq!(lease_deadline_liveness(&record, None, Some("boot"), 0), LeaseLiveness::Unknown);
        assert_eq!(lease_deadline_liveness(&record, Some(100), None, 0), LeaseLiveness::Unknown);
    }

    #[test]
    fn legacy_lease_uses_wall_clock_only_without_monotonic_state() {
        let mut record = lease_test_record();
        record.lease_expires_at = Some(200);
        assert_eq!(lease_deadline_liveness(&record, None, None, 100), LeaseLiveness::Live);
        assert_eq!(lease_deadline_liveness(&record, None, None, 200), LeaseLiveness::Expired);
    }

    #[test]
    fn catalog_has_redacted_tool_contracts() {
        let rendered = serde_json::to_string(&tool_catalog()).expect("catalog JSON");
        assert!(rendered.contains("secret_handoff_capture"));
        assert!(rendered.contains("destructiveHint"));
        assert!(!rendered.contains("secret_value"));
        assert!(!rendered.contains("plaintext"));
    }

    #[test]
    fn request_contracts_reject_unknown_secret_fields() {
        let capture = serde_json::from_value::<CaptureRequest>(json!({
            "target": "github",
            "label": "publish",
            "secret_value": "plaintext"
        }));
        let run = serde_json::from_value::<RunRequest>(json!({
            "handle": "sh_test",
            "operation": "publish",
            "plaintext_value": "plaintext"
        }));
        assert!(capture.is_err());
        assert!(run.is_err());

        let rendered = serde_json::to_string(&tool_catalog()).expect("catalog JSON");
        assert!(rendered.contains("additionalProperties"));
    }

    #[test]
    fn provider_delimiter_is_removed_exactly_once() {
        let value = normalize_provider_output(b"secret\n".to_vec().into()).expect("secret");
        assert_eq!(value.as_slice(), b"secret");
        assert!(normalize_provider_output(b"secret\n\n".to_vec().into()).is_err());
        assert!(normalize_provider_output(b"secret\r\n".to_vec().into()).is_err());
        assert!(normalize_provider_output(b"secret".to_vec().into()).is_err());
    }

    #[test]
    fn keyring_output_does_not_require_tty_framing() {
        let value = normalize_keyring_output(b"secret\n".to_vec().into()).expect("secret");
        assert_eq!(value.as_slice(), b"secret");
        let value = normalize_keyring_output(b"secret".to_vec().into()).expect("raw secret");
        assert_eq!(value.as_slice(), b"secret");
        assert!(normalize_keyring_output(Vec::new().into()).is_err());
        assert!(normalize_keyring_output(b"secret\n\n".to_vec().into()).is_err());
        assert!(normalize_keyring_output(b"secret\r".to_vec().into()).is_err());
    }

    #[test]
    fn legacy_terminal_records_become_cleanup_pending() {
        let handle = "sh_legacy".to_string();
        let mut state = State {
            schema_version: 1,
            records: BTreeMap::from([(
                handle.clone(),
                SecretRecord {
                    handle: handle.clone(),
                    target: "test".into(),
                    label: "legacy".into(),
                    created_at: 1,
                    expires_at: u64::MAX,
                    single_use: true,
                    status: LifecycleStatus::Consumed,
                    keyring_account: format!("handoff:{handle}"),
                    consumed_at: Some(2),
                    claim_id: None,
                    cleanup_target: None,
                    last_error: None,
                    generation: 4,
                    lease_owner: None,
                    lease_expires_at: None,
                    lease_expires_mono: None,
                    lease_boot_id: None,
                    expires_mono: None,
                    expires_boot_id: None,
                    helper_pid: None,
                    helper_pgid: None,
                    helper_start_ticks: None,
                    helper_boot_id: None,
                    helper_kind: None,
                    helper_cgroup: None,
                    helper_cgroup_identity: None,
                    cleanup_keyring_done: false,
                    helper_descendants_unknown: false,
                },
            )]),
            operation_cgroups: BTreeMap::new(),
            recovery_mode: false,
        };

        migrate_legacy_state(&mut state);

        let record = state.records.get(&handle).expect("legacy record");
        assert_eq!(state.schema_version, CURRENT_STATE_SCHEMA_VERSION);
        assert_eq!(record.status, LifecycleStatus::CleanupPending);
        assert_eq!(record.cleanup_target, Some(LifecycleStatus::Consumed));
        assert_eq!(record.generation, 5);
    }

    #[test]
    fn oversized_legacy_state_enters_recovery_mode_before_capacity_rejection() {
        let dir =
            std::env::temp_dir().join(format!("codex-secret-handoff-over-cap-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("state directory");
        let mut records = BTreeMap::new();
        for index in 0..=MAX_RECORDS {
            let handle = format!("sh_legacy_{index}");
            records.insert(
                handle.clone(),
                SecretRecord {
                    handle: handle.clone(),
                    target: "test".into(),
                    label: "legacy".into(),
                    created_at: index as u64,
                    expires_at: u64::MAX,
                    single_use: true,
                    status: LifecycleStatus::Consumed,
                    keyring_account: format!("handoff:{handle}"),
                    consumed_at: Some(index as u64),
                    claim_id: None,
                    cleanup_target: None,
                    last_error: None,
                    generation: 1,
                    lease_owner: None,
                    lease_expires_at: None,
                    lease_expires_mono: None,
                    lease_boot_id: None,
                    expires_mono: None,
                    expires_boot_id: None,
                    helper_pid: None,
                    helper_pgid: None,
                    helper_start_ticks: None,
                    helper_boot_id: None,
                    helper_kind: None,
                    helper_cgroup: None,
                    helper_cgroup_identity: None,
                    cleanup_keyring_done: false,
                    helper_descendants_unknown: false,
                },
            );
        }
        let legacy = State {
            schema_version: 1,
            records,
            operation_cgroups: BTreeMap::new(),
            recovery_mode: false,
        };
        fs::write(dir.join("state.json"), serde_json::to_vec(&legacy).expect("state JSON"))
            .expect("legacy state");

        let state = read_state(&dir).expect("oversized legacy state is recoverable");
        assert!(state.recovery_mode);
        assert_eq!(state.records.len(), MAX_RECORDS + 1);
        assert!(
            state.records.values().all(|record| record.status == LifecycleStatus::CleanupPending)
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn legacy_operation_cgroup_fences_are_released_for_descriptor_rediscovery() {
        let dir = std::env::temp_dir()
            .join(format!("codex-secret-handoff-cgroup-schema-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("state directory");
        fs::write(
            dir.join("state.json"),
            br#"{"schema_version":2,"records":{},"operation_cgroups":{"/sys/fs/cgroup/user.slice/legacy":"legacy-owner"}}"#,
        )
        .expect("legacy state");

        let state = read_state(&dir).expect("legacy cgroup state");
        assert_eq!(state.schema_version, CURRENT_STATE_SCHEMA_VERSION);
        assert!(state.operation_cgroups.is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn legacy_record_without_cgroup_identity_uses_pidfd_recovery() {
        let handle = "sh_legacy_running".to_owned();
        let mut state = State {
            schema_version: 2,
            records: BTreeMap::from([(
                handle.clone(),
                SecretRecord {
                    handle: handle.clone(),
                    target: "test".into(),
                    label: "legacy".into(),
                    created_at: 1,
                    expires_at: u64::MAX,
                    single_use: true,
                    status: LifecycleStatus::Running,
                    keyring_account: format!("handoff:{handle}"),
                    consumed_at: None,
                    claim_id: Some("claim".into()),
                    cleanup_target: None,
                    last_error: None,
                    generation: 4,
                    lease_owner: Some("legacy-owner".into()),
                    lease_expires_at: Some(2),
                    lease_expires_mono: None,
                    lease_boot_id: None,
                    expires_mono: None,
                    expires_boot_id: None,
                    helper_pid: Some(42),
                    helper_pgid: Some(42),
                    helper_start_ticks: Some(7),
                    helper_boot_id: Some("boot".into()),
                    helper_kind: Some("legacy-helper".into()),
                    helper_cgroup: Some(
                        "/sys/fs/cgroup/user.slice/codex-secret-handoff-legacy".into(),
                    ),
                    helper_cgroup_identity: None,
                    cleanup_keyring_done: false,
                    helper_descendants_unknown: true,
                },
            )]),
            operation_cgroups: BTreeMap::new(),
            recovery_mode: false,
        };

        migrate_legacy_state(&mut state);

        let record = state.records.get(&handle).expect("legacy record");
        assert_eq!(record.status, LifecycleStatus::CleanupPending);
        assert_eq!(record.cleanup_target, Some(LifecycleStatus::Deleted));
        assert_eq!(record.helper_pid, Some(42));
        assert!(record.helper_cgroup.is_none());
        assert!(record.helper_cgroup_identity.is_none());
        assert_eq!(record.generation, 5);
    }

    #[test]
    fn current_schema_without_cgroup_identity_is_quarantined() {
        let handle = "sh_current_missing_identity".to_owned();
        let mut state = State {
            schema_version: CURRENT_STATE_SCHEMA_VERSION,
            records: BTreeMap::from([(
                handle.clone(),
                SecretRecord {
                    handle: handle.clone(),
                    target: "test".into(),
                    label: "current".into(),
                    created_at: 1,
                    expires_at: u64::MAX,
                    single_use: true,
                    status: LifecycleStatus::Running,
                    keyring_account: format!("handoff:{handle}"),
                    consumed_at: None,
                    claim_id: Some("claim".into()),
                    cleanup_target: None,
                    last_error: None,
                    generation: 8,
                    lease_owner: Some("owner".into()),
                    lease_expires_at: Some(2),
                    lease_expires_mono: None,
                    lease_boot_id: None,
                    expires_mono: None,
                    expires_boot_id: None,
                    helper_pid: Some(42),
                    helper_pgid: Some(42),
                    helper_start_ticks: Some(7),
                    helper_boot_id: Some("boot".into()),
                    helper_kind: Some("helper".into()),
                    helper_cgroup: Some(
                        "/sys/fs/cgroup/user.slice/codex-secret-handoff-current".into(),
                    ),
                    helper_cgroup_identity: None,
                    cleanup_keyring_done: false,
                    helper_descendants_unknown: false,
                },
            )]),
            operation_cgroups: BTreeMap::new(),
            recovery_mode: false,
        };

        migrate_legacy_state(&mut state);

        let record = state.records.get(&handle).expect("current record");
        assert_eq!(state.schema_version, CURRENT_STATE_SCHEMA_VERSION);
        assert_eq!(record.status, LifecycleStatus::CleanupPending);
        assert_eq!(record.cleanup_target, Some(LifecycleStatus::Deleted));
        assert_eq!(record.helper_pid, Some(42));
        assert!(record.helper_cgroup.is_none());
        assert!(record.helper_cgroup_identity.is_none());
        assert_eq!(record.generation, 9);
    }

    #[test]
    fn terminal_records_are_pruned_before_capacity_failure() {
        let mut state = State::default();
        for index in 0..MAX_RECORDS {
            let handle = format!("sh_{index}");
            state.records.insert(
                handle.clone(),
                SecretRecord {
                    handle: handle.clone(),
                    target: "test".into(),
                    label: "test".into(),
                    created_at: index as u64,
                    expires_at: u64::MAX,
                    single_use: true,
                    status: if index == MAX_RECORDS - 1 {
                        LifecycleStatus::Active
                    } else {
                        LifecycleStatus::Consumed
                    },
                    keyring_account: format!("handoff:{handle}"),
                    consumed_at: Some(index as u64),
                    claim_id: None,
                    cleanup_target: None,
                    last_error: None,
                    generation: 1,
                    lease_owner: None,
                    lease_expires_at: None,
                    lease_expires_mono: None,
                    lease_boot_id: None,
                    expires_mono: None,
                    expires_boot_id: None,
                    helper_pid: None,
                    helper_pgid: None,
                    helper_start_ticks: None,
                    helper_boot_id: None,
                    helper_kind: None,
                    helper_cgroup: None,
                    helper_cgroup_identity: None,
                    cleanup_keyring_done: false,
                    helper_descendants_unknown: false,
                },
            );
        }
        prune_terminal_records(&mut state);
        assert_eq!(state.records.len(), MAX_RECORDS - 1);
        assert!(state.records.contains_key(&format!("sh_{}", MAX_RECORDS - 1)));
    }

    #[test]
    fn environment_validation_rejects_unsupported_payloads_before_store() {
        assert!(validate_secret_for_environment(b"secret\0value").is_err());
        assert!(validate_secret_for_environment(&[b'a'; MAX_SECRET_BYTES + 1]).is_err());
        assert!(validate_secret_for_environment("token".as_bytes()).is_ok());
    }

    #[test]
    fn cleanup_action_carries_helper_fence() {
        let record = SecretRecord {
            handle: "sh_test".into(),
            target: "test".into(),
            label: "unit".into(),
            created_at: 1,
            expires_at: u64::MAX,
            single_use: true,
            status: LifecycleStatus::Provisioning,
            keyring_account: "handoff:sh_test".into(),
            consumed_at: None,
            claim_id: None,
            cleanup_target: None,
            last_error: None,
            generation: 1,
            lease_owner: None,
            lease_expires_at: None,
            lease_expires_mono: None,
            lease_boot_id: None,
            expires_mono: None,
            expires_boot_id: None,
            helper_pid: Some(42),
            helper_pgid: Some(42),
            helper_start_ticks: Some(7),
            helper_boot_id: Some("boot".into()),
            helper_kind: Some("secret-tool-store".into()),
            helper_cgroup: None,
            helper_cgroup_identity: None,
            cleanup_keyring_done: false,
            helper_descendants_unknown: false,
        };
        let action = cleanup_action_for(&record, LifecycleStatus::Deleted);
        assert_eq!(action.helper_pid, Some(42));
        assert_eq!(action.helper_start_ticks, Some(7));
    }

    #[test]
    fn cancellation_reason_wins_over_fast_child_exit() {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        prepare_child(&mut command, None);
        let child = command.spawn().expect("spawn child");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let result = wait_bounded(
            child,
            Duration::from_secs(5),
            &cancellation,
            MAX_CHILD_OUTPUT_BYTES,
            None,
        );
        assert_eq!(result.err().as_deref(), Some("operation was cancelled"));
    }

    #[test]
    fn future_state_schema_is_rejected_before_recovery() {
        let dir =
            std::env::temp_dir().join(format!("codex-secret-handoff-schema-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("state directory");
        fs::write(dir.join("state.json"), br#"{"schema_version":999,"records":{}}"#)
            .expect("future state");
        let error = read_state(&dir).expect_err("future schema must fail closed");
        assert!(error.contains("newer unsupported schema"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn invalid_helper_identity_is_rejected_before_kill() {
        let dir =
            std::env::temp_dir().join(format!("codex-secret-handoff-helper-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("state directory");
        let handle = "sh_invalid".to_string();
        let state = State {
            schema_version: CURRENT_STATE_SCHEMA_VERSION,
            records: BTreeMap::from([(
                handle.clone(),
                SecretRecord {
                    handle: handle.clone(),
                    target: "test".into(),
                    label: "invalid".into(),
                    created_at: 1,
                    expires_at: u64::MAX,
                    single_use: true,
                    status: LifecycleStatus::CleanupPending,
                    keyring_account: format!("handoff:{handle}"),
                    consumed_at: None,
                    claim_id: None,
                    cleanup_target: Some(LifecycleStatus::Deleted),
                    last_error: None,
                    generation: 1,
                    lease_owner: None,
                    lease_expires_at: None,
                    lease_expires_mono: None,
                    lease_boot_id: None,
                    expires_mono: None,
                    expires_boot_id: None,
                    helper_pid: Some(0),
                    helper_pgid: Some(0),
                    helper_start_ticks: Some(0),
                    helper_boot_id: Some("boot".into()),
                    helper_kind: Some("test".into()),
                    helper_cgroup: None,
                    helper_cgroup_identity: None,
                    cleanup_keyring_done: false,
                    helper_descendants_unknown: false,
                },
            )]),
            operation_cgroups: BTreeMap::new(),
            recovery_mode: false,
        };
        fs::write(dir.join("state.json"), serde_json::to_vec(&state).expect("state JSON"))
            .expect("write state");
        let error = read_state(&dir).expect_err("invalid helper identity must fail closed");
        assert!(error.contains("helper identity is invalid"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn delegated_cgroup_contains_and_terminates_descendants() {
        let Ok(cgroup) = create_operation_cgroup() else {
            return;
        };
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 30 & wait"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        prepare_child(&mut command, Some(cgroup.file.as_raw_fd()));
        let child = command.spawn().expect("spawn contained child");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let result = wait_bounded(
            child,
            Duration::from_secs(5),
            &cancellation,
            MAX_CHILD_OUTPUT_BYTES,
            Some(&cgroup),
        );
        assert_eq!(result.err().as_deref(), Some("operation was cancelled"));
        assert!(!cgroup.path.exists());
    }

    #[test]
    fn current_process_is_a_live_operation_cgroup_owner() {
        let identity = CgroupIdentity { dev: 1, ino: 1 };
        let fence = operation_cgroup_fence(identity);
        assert_eq!(fence.owner, process_owner());
        assert!(operation_cgroup_owner_live(&fence));
    }

    #[test]
    fn keyring_search_failures_are_unavailable_not_missing() {
        assert_eq!(classify_keyring_search_result(false, false), KeyringEntryState::Unavailable);
        assert_eq!(classify_keyring_search_result(true, false), KeyringEntryState::Missing);
        assert_eq!(classify_keyring_search_result(true, true), KeyringEntryState::Present);
    }

    #[test]
    fn empty_unregistered_operation_cgroups_are_reconciled() {
        let Ok(cgroup) = create_operation_cgroup() else {
            return;
        };
        assert!(cgroup.path.exists());
        let cancellation = CancellationToken::new();
        reconcile_unregistered_operation_cgroups(&cancellation, Instant::now() + RECONCILE_TIMEOUT)
            .expect("reconcile orphan cgroup");
        assert!(cgroup.path.exists());
        remove_empty_cgroup(&cgroup).expect("remove test cgroup");
        assert!(!cgroup.path.exists());
    }

    #[test]
    fn recorded_cgroup_identity_mismatch_fails_closed() {
        let Ok(cgroup) = create_operation_cgroup() else {
            return;
        };
        let wrong =
            CgroupIdentity { dev: cgroup.identity.dev, ino: cgroup.identity.ino.saturating_add(1) };
        assert!(kill_cgroup_path(&cgroup.path.to_string_lossy(), Some(wrong)).is_err());
        remove_empty_cgroup(&cgroup).expect("remove test cgroup");
    }

    #[test]
    fn secure_file_descriptor_remains_bound_after_path_replacement() {
        use std::os::unix::fs::PermissionsExt;

        // The bound-executable check needs real system binaries with opposite
        // exit statuses; hosts without them (nix environments) are not a
        // supported target for this assertion.
        if !Path::new("/bin/true").exists() || !Path::new("/bin/false").exists() {
            return;
        }
        let directory = std::env::current_dir()
            .expect("working directory")
            .join("target")
            .join(format!("secure-file-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).expect("test directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("permissions");
        let path = directory.join("payload");
        fs::copy("/bin/true", &path).expect("payload");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("payload permissions");
        let secure = secure_open_file_with_options(&path, false, true, false).expect("secure open");
        fs::rename(&path, directory.join("payload.old")).expect("rename payload");
        fs::copy("/bin/false", &path).expect("replacement payload");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("replacement permissions");
        let output = Command::new(secure.exec_path().expect("bound exec path"))
            .output()
            .expect("bound executable");
        assert!(output.status.success());
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn trusted_helpers_require_root_owned_system_files() {
        use std::os::unix::fs::MetadataExt;
        // The assertion is about how a real root-owned helper is vetted; hosts
        // without the helper (nix environments) have nothing to assert on.
        let Ok(metadata) = fs::symlink_metadata("/usr/bin/secret-tool") else {
            return;
        };
        if metadata.uid() == 0 {
            assert!(secure_open_file_with_options(
                Path::new("/usr/bin/secret-tool"),
                true,
                true,
                false,
            )
            .is_ok());
        } else {
            assert!(secure_open_file_with_options(
                Path::new("/usr/bin/secret-tool"),
                true,
                true,
                false,
            )
            .is_err());
        }
    }
}
