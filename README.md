# Codex Secret Handoff MCP

Local Rust MCP server for entering API keys in a trusted desktop prompt and
handing them to one explicitly allowlisted local operation without putting
plaintext into Codex context. The server uses the official Rust MCP SDK and
the standard stdio transport.

## Security properties

- `secret_handoff_capture` opens a local GUI prompt using `zenity` or `kdialog`.
- MCP arguments and responses contain only an opaque `handle` and metadata.
- Plaintext is never written to the state file, MCP stdout, stderr, logs, URLs,
  or command arguments.
- Secrets are stored in the operating-system Secret Service through
  `secret-tool`.
- External commands are executable only through a named local allowlist entry.
- Handles can expire and are single-use by default.
- Lifecycle transitions are durable and crash-recoverable: provisioning,
  claiming, running, cleanup-pending, consumed, deleted, and expired are
  persisted with a fencing generation and a process lease.
- Delete is a revocation boundary: it prevents future runs immediately and
  removes the keyring entry with retryable cleanup.
- If a run is cancelled or times out after launch, the handle is revoked even
  when it was reusable because the external side effect cannot be safely
  replayed.
- GUI, keyring, and allowlisted child processes have bounded waits; cancellation
  terminates the dedicated cgroup and direct child, then performs an independent
  bounded reap.
- Trusted GUI, keyring, and allowlisted operation helpers run inside dedicated
  delegated cgroup v2 boundaries with `cgroup.kill`, so forked or detached
  descendants remain inside the cleanup boundary. Cgroup paths are reopened
  through no-follow descriptors and checked against their recorded device/inode
  identity before termination or removal.
- A cgroup identity is persisted before a child is spawned. Startup recovery
  quarantines older populated cgroups that were created before a crash but not
  yet registered, then retries their termination through the same identity
  fence. A failed cleanup remains durable instead of being silently discarded.
- The allowlist and operation executable are required to be absolute,
  canonical, non-symlink paths owned by the current user or root and not
  writable by group or other users. Fixed helpers under `/usr/bin` additionally
  require a fully root-owned path.
- Trusted helpers receive a minimal environment containing only local display,
  session-bus, locale, and fixed `PATH` variables; unrelated process secrets are
  not inherited.
- A background reaper reconciles expired and stale records while the MCP
  process is alive; startup reconciliation resumes the same cleanup after a
  restart. Reaper cancellation is linked to service shutdown and reconciliation
  has a bounded shutdown window.
- An oversized legacy state enters bounded recovery mode: existing handles
  remain inspectable and cleanup continues, while new captures are refused
  until the record count returns below the configured limit.

If a secret has already been pasted into a model prompt or chat, this tool
cannot make that historical exposure disappear.

## Requirements

- Rust toolchain
- `secret-tool` and a running Secret Service provider
- One GUI prompt provider: `zenity` or `kdialog`
- Codex with MCP server support

All helper execution requires a writable user-owned cgroup v2 delegation with
`cgroup.kill`. By default the server derives the stable user-owned delegated
ancestor of the current process cgroup; set `CODEX_SECRET_HANDOFF_CGROUP_ROOT`
when the host exposes another delegated path. If no such boundary is available,
the server rejects the operation instead of falling back to an escapable
process-group-only route.

The current security boundary is Linux-only: trusted binaries are resolved from
`/usr/bin`, and the operation allowlist must be a private file owned by the
current user. GUI text is UTF-8, at most 64 KiB, must not contain NUL, and must
not end in CR or LF. The prompt provider's single trailing LF is framing and is
removed exactly once.

On a Debian/Ubuntu system, the GUI and keyring packages are typically provided
by `zenity` and `libsecret-tools`; use the equivalent packages for your system.

## Installation

```sh
cargo install --path . --locked
```

Add the server to `~/.codex/config.toml`:

```toml
[mcp_servers.secret-handoff]
command = "/home/USER/.cargo/bin/codex-secret-handoff-mcp"
default_tools_approval_mode = "approve"
startup_timeout_sec = 30
tool_timeout_sec = 120
```

After changing the configuration, use the supported Codex MCP autoreload path
or restart only the Codex App Server route that owns the configuration.

## Usage

Call `secret_handoff_capture` with a `target`, `label`, optional TTL, and
`single_use` flag. A local window opens on the desktop; type the key there and
confirm the dialog. The MCP stores the secret in the OS keyring and returns
only a handle. TTL is rejected when outside `1..86400`; it is never silently
clamped.

Call `secret_handoff_run` with that handle and an allowlisted operation name.
The operation configuration lives at
`${XDG_CONFIG_HOME:-~/.config}/codex-secret-handoff/operations.json`:

```json
{
  "operations": {
    "github-publish": {
      "command": "/usr/bin/gh",
      "args": ["api", "user"],
      "secret_env": "GH_TOKEN"
    }
  }
}
```

Commands must use an absolute executable path and fixed arguments. Shell
strings and model-supplied commands are rejected. Child stdout and stderr are
discarded; the result contains only status, exit code, and duration. The
`secret_handoff_run` tool is marked destructive because an allowlisted command
may publish or mutate an external system.

The binary also exposes a local CLI for environments that already have an
approved GUI session:

```sh
codex-secret-handoff-mcp capture --target github --label publish
codex-secret-handoff-mcp status
codex-secret-handoff-mcp delete <handle>
```

## Scope and limitations

This is a local security boundary, not an internet-facing secret manager.
Security still depends on the local OS, desktop session, Secret Service, and
the configured allowlist operation. The repository contains no credentials.
