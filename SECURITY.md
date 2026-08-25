# Security policy

This project is designed so plaintext secrets do not enter Codex prompts,
MCP JSON-RPC arguments, MCP responses, command arguments, state files, or
logs. The secret is entered in a local GUI prompt and stored in the operating
system Secret Service keyring.

Do not add secrets, exported keyring data, local state, or personal Codex
configuration to issues, pull requests, or this repository. Report suspected
security problems privately to the repository owner.

The GUI prompt is local-only: the MCP starts `zenity` or `kdialog`, captures
its stdout in process memory, and never forwards the value to MCP output. If
the desktop prompt is cancelled, no handle is created.

The `secret_handoff_run` operation is intentionally allowlisted: it executes a
locally configured absolute command with fixed arguments and injects the secret
only into the configured child environment variable. It is not a general shell.
