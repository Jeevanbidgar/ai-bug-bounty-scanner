# UniHack 2.0 beta

This is an early cross-platform tester release of UniHack's native security
tool orchestration console.

Included:

- native Tauri desktop applications for macOS, Windows, and Linux
- host tool discovery, readiness checks, installation choices, and updates
- 15 packaged, inspectable workflows with retained evidence and reports
- adaptive workflow and mission visualizations with accessible 2D controls
- local `unihackd` execution and local STDIO `unihack-mcp`
- direct Codex CLI and Claude Code integration using the client's existing
  login; UniHack does not require a provider API key
- engagement-scoped, revision-bound workflow execution with cancellation and
  an HMAC-chained local audit trail

## Important beta notice

These installers are not yet signed with an Apple Developer ID or Windows
code-signing certificate. Download them only from this repository's Releases
page, verify `SHA256SUMS.txt`, and follow the platform instructions in
[`docs/INSTALL.md`](INSTALL.md). Native execution is the only active runner.

Use UniHack only for systems you own or are explicitly authorized to assess.
MCP clients cannot create or expand engagement authorization.
