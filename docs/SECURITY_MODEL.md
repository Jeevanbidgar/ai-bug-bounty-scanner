# Security model

UniHack is designed for authorized testing. It is not a guardrail against a malicious local administrator or a compromised third-party scanner binary.

## Enforced controls

- Targets must be concrete hostnames, IP addresses, CIDR ranges, or HTTP(S) URLs. Option-like values, whitespace, embedded credentials, wildcards, unsupported schemes, invalid ports, and path-like non-URLs are rejected.
- Every scan requires an explicit authorization confirmation in both the UI contract and the Rust command boundary.
- Workflows name registered tools. Executable paths and templates cannot be supplied by workflow YAML.
- Scan execution fails before state changes when required tools are unavailable, and an existing scan cannot be run with a workflow other than its assigned workflow.
- Commands use direct argument vectors; no shell interprets targets or workflow values.
- Adapter previews are non-executing argument-vector inspection. Shared-pattern adapters use bundled, validated profiles rather than arbitrary user-supplied command definitions. Profiles bind targets and outputs as individual argv values or stdin, and active defaults stay detection-oriented: managed wordlists for content discovery, low level/risk plus batch mode for SQLMap, and machine-readable output without takeover, dump, password attack, or elevation flags.
- Auto-adapter discovery probes only catalog-resolved, installed security binaries with `--help`; runtime utilities and manually registered executables are excluded. Probes have a four-second timeout, kill-on-drop, hidden process configuration, bounded output, and no target or operational arguments.
- Auto-generated contracts become ready only for an explicit target flag at or above the confidence threshold. Ambiguous positional/stdin contracts are quarantined, cannot build commands, and cannot influence packaged workflow execution. Cached contracts are regenerated when the resolved path, binary fingerprint, or detected version changes.
- Environment, stdin, retry, timeout, output path, and template fields have parser-level validation and bounds.
- Only backend-approved installation methods for the current OS may run.
- The webview cannot submit arbitrary elevated commands; privilege prompts are reachable only through backend-owned, catalog-validated installer paths.
- Child stdout and stderr are drained independently and captured with configurable limits.
- Cancellation and timeout terminate descendant processes before final state is stored.
- Generated artifacts and reports must remain inside managed application directories.
- Tauri exposes only the main window's required core capability and uses a restrictive Content Security Policy.
- Browser development uses deterministic `MockBridge` fixtures that cannot launch tools. The desktop runtime selects `TauriBridge`; browser preview state is never treated as execution authority.
- Workflow Studio edits cannot execute. Only an unchanged packaged workflow ID can reach the existing execution command, and the UI disables that path whenever the current graph differs from its packaged baseline, including after a modified local draft is saved or restored.
- Notification history stores local operational summaries, timestamps, and internal routes. It does not copy scanner stdout or artifact contents; explicit copy/reveal actions may record the same managed path or scan/report label already shown on the owning page.
- The spatial preview is presentation only. 3D selection, physics, or animation never changes execution policy, argv, privileges, or scan state.
- Local MCP is STDIO-only and uses the calling Codex or Claude client's existing session. UniHack does not accept, retrieve, proxy, log, or store that client's model-provider credentials.
- MCP tools have explicit JSON schemas, bounded evidence/report previews, read/write/destructive annotations, capability checks, redacted audit arguments, and stable domain errors. Scanner output is treated as untrusted evidence rather than instructions.
- The `owner_automation` MCP profile is revocable. It cannot create or expand engagement scopes, retrieve credentials, suppress audit events, submit raw shell strings, or bypass privilege prompts.
- Packaged workflows are persisted as immutable SHA-256 revisions with packaged trust records before they are returned over MCP. Engagement grants are HMAC-signed using a secret stored by the OS credential service.
- The MCP proxy authenticates to `unihackd` over an owner-only Unix socket or local Windows named pipe using protocol v2's HMAC challenge. Daemon, MCP, and desktop pairing entries are isolated in the OS credential service, and development identities are separated from stable production identities so unsigned local builds cannot replace a release client's pairing entry. Codex/Claude configuration contains no reusable secret. Windows named-pipe ACL behavior remains a native release test gate.
- Engagement creation, revocation, and audit activity reads require the dedicated authenticated desktop credential at the daemon boundary and are not MCP tools. UI hiding is not the security boundary.
- MCP execution accepts only a high-level workflow request. The daemon atomically binds the run to an exact trusted immutable revision and active signed engagement, revalidates trust/scope/budgets before every step and during long-running tools, and owns process-tree cancellation. Request-bound idempotency prevents retries from launching a different mission. A transport client cannot submit a shell string or launch a scanner itself.
- Workflow events reach Tauri through a dedicated authenticated daemon stream. Audit appends are serialized and HMAC-chained with an OS-credential-backed key after credential-shaped arguments are redacted.

## Deliberate non-goals

- UniHack does not bypass tool licensing, authentication, rate limits, operating-system security, or package-manager elevation prompts.
- It does not make Linux kernel features available on Windows or macOS.
- It does not automatically route scans through Docker, WSL, a VM, or a remote machine.
- It does not guarantee that third-party tools are safe; installation metadata must remain auditable and users should verify upstream releases.
- It does not load unsigned or user-editable adapter profiles into the execution boundary. A dynamic catalog requires signing, versioning, quarantine, review, and revocation first.
- Internet search results and unverified documentation are not command authority. Future online adapter packs must verify signatures/provenance and expected producer identity before UniHack considers their metadata.
- It does not yet trust or execute imported/custom workflow revisions. That capability requires backend hashing, quarantine, executable/argv review, revocation, and immutable execution references.
- It does not treat Codex or Claude account login as authorization to scan a target. A deliberate desktop-created engagement scope is still required for execution.

## Reporting a security issue

Do not include live targets, credentials, tokens, customer data, or exploit output in a public issue. Provide the smallest reproducible description and redact managed artifact contents before sharing logs.
