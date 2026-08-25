# Security policy

This project is designed so plaintext secrets do not enter Codex prompts,
MCP JSON-RPC arguments, MCP responses, command arguments, state files, or
logs. The secret is entered locally through a hidden TTY prompt and stored in
the operating-system Secret Service keyring.

Do not add secrets, exported keyring data, local state, or personal Codex
configuration to issues, pull requests, or this repository. Report a suspected
security problem privately to the repository owner.

The `secret_handoff_run` operation is intentionally allowlisted: it executes a
locally configured absolute command with fixed arguments and injects the secret
only into the configured child environment variable. It is not a general shell.
