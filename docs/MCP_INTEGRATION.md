# Local MCP integration

UniHack connects to Codex CLI, Claude Code, and compatible hosts through a local STDIO process. The AI client owns its model account and login. UniHack never needs that client's OpenAI or Anthropic API key.

## Permanent contract

- Transport is local STDIO for the first production release; there is no MCP listening port.
- Client configuration contains only the local `unihack-mcp` command and optional process environment. It contains no provider token.
- `unihack-mcp` starts `unihackd` on demand, authenticates over a local socket or named pipe, and then speaks MCP over its inherited STDIO. Protocol v2 uses isolated daemon, MCP, and desktop credential entries in the OS credential store; Unix sockets are owner-only, and no secret is copied into Codex or Claude configuration.
- The desktop app creates and revokes engagement scopes. An MCP client cannot authorize its own target or expand an existing scope.
- Every MCP call passes through the same capability, revision, scope, validation, redaction, and audit layer as other transports.
- Raw shell commands, arbitrary filesystem reads, credential retrieval, scope creation, audit deletion, and privilege bypass are not MCP capabilities.
- A future hosted in-app agent may optionally use separately configured API credentials, but that feature is independent from direct Codex/Claude MCP access.

## Codex CLI

Command:

```bash
codex mcp add unihack -- /absolute/path/to/unihack-mcp
codex mcp get unihack
```

Equivalent `~/.codex/config.toml` entry:

```toml
[mcp_servers.unihack]
command = "/absolute/path/to/unihack-mcp"
args = []
```

Start a fresh Codex task after adding the entry so the client performs MCP initialization and tool discovery.

For an installed macOS bundle, the command is normally `/Applications/UniHack.app/Contents/MacOS/unihack-mcp`. During development it is `src-tauri/target/debug/unihack-mcp`; do not leave Codex pointing at a disposable debug path after installing the application.

## Claude Code

Command:

```bash
claude mcp add --transport stdio --scope user unihack -- /absolute/path/to/unihack-mcp
```

Equivalent JSON configuration:

```json
{
  "mcpServers": {
    "unihack": {
      "type": "stdio",
      "command": "/absolute/path/to/unihack-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

Start a fresh Claude Code session after changing configuration.

## Run an authorized workflow

1. Open UniHack, go to **AI & MCP**, and configure Codex or Claude Code. This writes only the local `unihack-mcp` executable path.
2. On the same screen, create an engagement with the exact target, allowed workflows, risk ceiling, expiry, execution/concurrency limits, runtime, and output budget. MCP cannot perform this authorization step.
3. Start a fresh Codex task or Claude Code session.
4. Ask the client to call `list_engagements`, `list_workflows`, and `validate_mission`; then call `start_workflow` with the returned exact `revisionHash` and a stable idempotency key.
5. Monitor with `get_run_status`, stop with `cancel_run`, and inspect retained findings/artifacts with `get_scan_evidence` after the run reaches a terminal state.

Example instruction to the AI client:

```text
Use UniHack for my existing authorized engagement. List the engagement and compatible workflows, validate the target, run the selected immutable revision with a new stable idempotency key, monitor it until terminal, and summarize only evidence returned by UniHack. Do not expand scope.
```

## Current capability stage

The current server supports typed discovery, packaged workflow revisions, engagement listing and mission validation, revision-bound workflow start/status/cancel, bounded evidence/report reads, and deterministic adapter refresh. The STDIO proxy is verified through protocol v2 with HMAC enrollment and reports the daemon as its execution owner. Engagement creation/revocation and audit activity remain desktop-only and are rejected for the MCP credential. Every launch requires the exact trusted revision, an active signed scope, a request-bound idempotency key, and live budget revalidation. Native is the only execution target.

Official references: [Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp), [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp), and the [official Rust MCP SDK](https://github.com/modelcontextprotocol/rust-sdk).
