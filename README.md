# Codex Secret Handoff MCP

Local Rust MCP server for entering API keys in a local desktop prompt and
handing them to one explicitly allowlisted local operation without putting
plaintext into Codex context.

## Security properties

- `secret_handoff_capture` opens a local GUI prompt using `zenity` or `kdialog`.
- MCP arguments and responses contain only an opaque `handle` and metadata.
- Plaintext is never written to the state file, MCP stdout, stderr, logs, URLs,
  or command arguments.
- Secrets are stored in the operating-system Secret Service through
  `secret-tool`.
- External commands are executable only through a named local allowlist entry.
- Handles can expire and are single-use by default.

If a secret has already been pasted into a model prompt or chat, this tool
cannot make that historical exposure disappear.

## Requirements

- Rust toolchain
- `secret-tool` and a running Secret Service provider
- One GUI prompt provider: `zenity` or `kdialog`
- Codex with MCP server support

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
confirm the dialog. The MCP stores the secret in the OS keyring and
returns only a handle.

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
discarded; the result contains only status, exit code, and duration.

The binary also exposes a local CLI for environments that already have an
approved GUI session:

```sh
codex-secret-handoff-mcp capture --target github --label publish --single-use
codex-secret-handoff-mcp status
codex-secret-handoff-mcp delete <handle>
```

## Scope and limitations

This is a local security boundary, not an internet-facing secret manager.
Security still depends on the local OS, desktop session, Secret Service, and
the configured allowlist operation. The repository contains no credentials.
