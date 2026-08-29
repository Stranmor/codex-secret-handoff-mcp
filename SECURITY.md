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

The current implementation is Linux-only. Only root-owned
`/usr/bin/zenity`, `/usr/bin/kdialog`, and `/usr/bin/secret-tool` paths are
accepted as trusted system helpers. Operation configuration and executables
are checked for absolute canonical paths, ownership, non-symlink status, and
absence of group/other write permissions before a handle is claimed.
Trusted helpers receive only the display/session-bus and locale variables they
need plus a fixed system `PATH`; unrelated server environment variables are
not inherited.

The state machine uses a durable claim fence and process lease. A server
restart recovers stale provisioning/running records into cleanup-pending and
retries keyring removal; cleanup is finalized only after the clear provider
returns success. Cleanup is attempted independently of a cancelled request so
cancellation cannot strand a keyring entry.

The live server runs a bounded background reaper and also reconciles on
startup. Expiration is closed atomically at claim time, while stale
provisioning or running records remain cleanup-pending until helper fencing and
keyring removal both succeed. Reaper cancellation is linked to service
shutdown, and reconciliation has a bounded shutdown window.

Legacy state that exceeds the record limit is opened only in an explicit
recovery mode; cleanup can drain it without permitting new captures, and the
normal capacity gate is restored after recovery.

The `secret_handoff_run` operation is intentionally allowlisted: it executes a
locally configured absolute command with fixed arguments and injects the secret
only into the configured child environment variable. It is not a general shell.
Every trusted child is placed in its own process group and a dedicated
delegated cgroup v2 with `cgroup.kill`; the recorded cgroup is rooted under a
stable delegated ancestor so restart reconciliation remains valid across new
transient service scopes. Cgroup directories and helper binaries are consumed
through no-follow descriptors with device/inode identity checks, preventing a
same-user pathname replacement from redirecting cleanup or execution. Bounded
execution terminates the cgroup and direct child, including forked
descendants; a pidfd with boot-id and start-tick fencing is used when recovery
has only a recorded process identity. If the delegated cgroup boundary is
unavailable, execution fails closed. Deletion prevents future runs, but cannot
retroactively erase a secret already handed to a child that is currently
running.

Before spawning, the cgroup identity is durably recorded. Startup recovery
quarantines older populated operation cgroups that exist outside the state
file, terminates them through a verified descriptor, and leaves a retryable
state fence when termination fails. No cleanup error is intentionally ignored.
If a reusable operation is cancelled or times out after launch, its handle is
also revoked to prevent replaying an outcome that may already have taken effect.
