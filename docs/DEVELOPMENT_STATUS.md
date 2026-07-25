# Development status

Updated: 2026-07-25

This is the canonical current plan. Older phase and completion notes under `info/` are historical and may describe removed Python services or unfinished behavior as complete.

## Product boundary

UniHack reduces the RAM and storage overhead of VM-based tool use by executing a certified tool set directly on macOS, Windows, or Linux. It is a native orchestration workbench, not a hardware or kernel virtualizer. Tools that require a different kernel, privileged lab network, or an unsupported runtime remain outside the native guarantee.

## Verified now

- Tauri 2 desktop application with React 19.2.7, Vite 8.1.5, and the Rust backend
- Responsive cyber-console from 800×600 through 4K with semantic tokens, keyboard command palette, route-level lazy loading, deterministic browser fixtures, reduced motion, high contrast, and consistent non-3D controls
- Functional local notification center with unread state, read/clear controls, compact-layout layering, and startup, scan, tool-installation, and mutation events
- Stable shared frontend cache contracts across Mission, Tools, and Adapters, including native route-transition regression coverage
- Compact, keyboard-accessible tool inventory cards with one status hierarchy, equal-height responsive layout, installation affordances, and detailed data kept in an accessible drill-down dialog
- Adaptive Mission Topology with WebGL fallback, 1.5 DPR cap, demand/visibility-aware rendering, optional High-only physics, and development-only scene tuning
- XYFlow Workflow Studio with DAG validation, undo/redo/reset, packaged workflow compatibility, local versioned drafts, and a read-only 3D preview; modified drafts cannot execute
- Outcome-oriented workflow catalog metadata for all fifteen packaged procedures, with activity level, target type, expected runtime, evidence, prerequisites, search, and direct links between Workflow Studio, scans, and adapters
- Guided scan launcher that shows workflow intent, tool-chain readiness, missing tools, managed prerequisites, target form, and authorization before execution; scan history has compact live progress, evidence access, safe rerun prefilling, and explicit start/delete confirmation
- Evidence-oriented Reports route with local export metrics, scan-source selection, explained HTML/JSON/SARIF formats, integrity metadata, preview, host file-manager reveal, path copy, and explicit managed-file deletion confirmation
- Live UniHack process CPU/RAM measurement plus a configurable, clearly labelled VM memory comparison
- Host readiness wizard covering native tools, package managers, workflow compatibility, and explicit runner availability; WSL, container, and remote targets cannot be selected
- Additive frontend contracts for workflow drafts/revisions/trust/validation and the future runner lifecycle
- SQLite persistence for scans, workflow executions, step executions, artifacts, findings, reports, and settings, with WAL and foreign-key enforcement on every pooled connection
- Explicit authorization confirmation and strict hostname, IP, CIDR, and HTTP(S) target validation
- Shell-free execution, verified executable resolution, bounded concurrency, timeouts, retry validation, stdin support, live output, process-tree cancellation, and interrupted-run recovery
- Fifteen packaged workflows; all YAML definitions load, every executable is catalog-registered with an installation path on each desktop OS, every declared file artifact is passed to its tool, and all fifteen core tools appear in at least one workflow
- Workflow pipeline contracts prevent JSONL, CSV, or enriched display output from being consumed as a plain one-target-per-line input list
- Host-specific target forms (`domain`, `host`, and `url`) and an application-managed web path wordlist
- Hybrid structured command adapters for all fifteen core tools: seven specialized typed adapters plus eight validated declarative profiles with inspectable argv/stdin, risk and authorization metadata, expected evidence, live installation readiness, and packaged-workflow usage; new shared-pattern tools need an audited profile rather than another command builder, and previews never execute from the adapter screen
- Automatic local adapter discovery for newly installed catalog security tools using bounded `--help` probing, explicit target/output capability inference, path/version/fingerprint evidence, persisted profiles, confidence scoring, and quarantine for ambiguous contracts; bundled adapters retain priority and internet content cannot silently become executable configuration
- Adaptive Tool Contracts UI showing ready support, installed coverage, auto-generated profiles, review-required profiles, origin, version evidence, and inference confidence
- OS-aware installation allowlists for macOS, Windows, and Linux; unsupported or client-invented methods are rejected by Rust
- Backend execution preflight rejects workflows with missing tools before scan state changes and prevents a request from substituting a workflow different from the one assigned to the scan
- Real tool test commands, scan history/details, safe system-file-manager access to managed artifacts/results, settings, and HTML/JSON/SARIF exports
- Structured finding normalization for Nuclei JSONL plus Nikto, WPScan, and Dalfox JSON; parser or finding-persistence failures fail the step instead of producing a false-clean scan
- Restrictive Tauri capability and Content Security Policy configuration
- Frontend lint/build, a high-severity production JavaScript dependency gate, 100 Playwright interaction checks on Linux plus four macOS visual baselines across 800×600, 1024×768, 1440×900, 1920×1080, and 4K (with six intentionally project-scoped visual skips), strict Rust Clippy with warnings denied, 172 deterministic Rust library tests, all-target test compilation/execution, and a four-target desktop packaging workflow. Development-only audit findings remain visible for compatible upstream upgrades rather than forcing breaking application changes into a release.
- Host- and registry-dependent package-manager probes are explicit ignored manual smoke tests instead of unreliable clean-runner gates
- Local `unihack-mcp` STDIO server built with the official Rust MCP SDK. It exposes typed status, tool, workflow, engagement, validation, revision-bound start/status/cancel, scan-evidence, report, and deterministic adapter-refresh operations with bounded output and accurate MCP annotations.
- Direct Codex CLI integration is verified without any provider API key: the local server was registered globally as `unihack`, MCP Inspector completed tool discovery, and `get_status` returned structured live UniHack state.
- `unihack-mcp` now starts and authenticates to `unihackd` through protocol v2's versioned, length-prefixed local frames. The macOS verification used an owner-only `0600` Unix socket, credential-isolated daemon, MCP, and desktop Keychain entries, HMAC challenge-response, daemon-owned SQLite access, and a live response reporting `executionOwner: unihackd` and `providerApiKeyRequired: false`.
- An AI & MCP screen detects Codex CLI and Claude Code, performs an explicit one-click local configuration, and provides copyable Codex TOML, Claude JSON, and CLI commands. Browser preview uses deterministic non-executing fixtures.
- Backend governance migration and contracts now cover immutable workflow revisions/trust, signed engagement scopes, revocable MCP profiles, request-bound idempotency records, provider-neutral audit events, and future agent records. The append-only MCP audit chain redacts credential-shaped arguments, serializes concurrent appends, and uses an OS-credential-backed HMAC so modification is detectable.
- Desktop and MCP launches now use the same daemon-owned workflow engine. Each run atomically binds its scan, exact immutable revision hash, trust record, signed engagement, principal, and request ID before child execution. Scope expiry/revocation, runtime/output limits, and revision/trust state are rechecked before every step and during long-running processes; revocation cancels active process trees.
- The desktop receives workflow and scan lifecycle updates from a dedicated authenticated daemon event stream and re-emits the established Tauri event names. MCP execution returns immediately with stable run/scan IDs and supports bounded status polling plus idempotent cancellation.
- The desktop Integrations screen now creates, lists, and deliberately revokes signed engagement scopes, exposes resource budgets and sanitized HMAC-chained activity, and keeps these authority-changing operations absent from MCP. The daemon also rejects them unless the authenticated credential is the dedicated desktop client.
- Tauri external-binary configuration and a target-aware locked build script stage `unihackd` and `unihack-mcp` for Linux x64, Windows x64, macOS Apple Silicon, and macOS Intel packaging jobs. All four native targets built successfully for `v2.0.0-beta.3`; the bundled Apple Silicon MCP/daemon pair also passed MCP Inspector with the desktop initially closed.
- The tagged beta-release workflow has published separately named Linux DEB/AppImage, Windows NSIS, macOS Apple Silicon DMG, and macOS Intel DMG assets plus SHA-256 checksums in a clearly labelled unsigned GitHub prerelease.

Core tools: Nmap, Subfinder, Nuclei, Naabu, Amass, HTTPX, FFUF, Gobuster, GAU, Waybackurls, SQLMap, Nikto, WPScan, Feroxbuster, and Dalfox.

## Remaining before a stable release

1. Finish the remaining daemon data migration: execution/status/cancel and live events are daemon-owned, but older Tauri history, report, settings, and tool-management commands still open the shared SQLite database directly. Move those commands behind `UniHackService`/protocol v2 so `unihackd` becomes the only process that opens SQLite.
2. Move Workflow Studio drafts from local UI snapshots to backend-owned `WorkflowDraft` and immutable `WorkflowRevision` records. Add validation, quarantine, reviewed executable/argv trust, revocation, and make every execution reference the immutable revision hash.
3. Smoke-test the newly bundled `unihackd` and `unihack-mcp` sidecars with real Codex and Claude Code clients on all four CI targets while the desktop window is closed.
4. Implement the backend `Runner` interface and authoritative probes behind the additive frontend contract. Native remains the only active runner until separately permissioned WSL, container, and remote implementations have platform tests and clear privilege/credential boundaries.
5. Add project workspaces, evidence vaulting, scan-to-scan diffing, and audit-trail exports. OS credential storage is already used for local daemon enrollment and scope signing; broader application credentials still need the same no-plaintext policy. A hosted in-app agent remains optional and separate; direct Codex/Claude MCP access never depends on provider API keys.
6. Add structured finding parsers for further machine-readable tools where their outputs represent actionable findings. Every tool still preserves its raw artifact.
7. Define a signed, versioned adapter-pack format and producer trust policy before any internet-delivered recipe can influence execution. Keep online documentation as non-authoritative enrichment until signature/provenance and revocation checks exist.
8. Exercise a harmless authorized smoke target on each OS with representative passive, network, and web workflows, including native WKWebView, WebView2, and WebKitGTK UI smoke checks.
9. Add application signing/notarization and a stable update channel. Current beta artifacts are deliberately unsigned.
10. Complete the React Router 7 migration for the upstream security fixes, then refresh development tooling as compatible releases remove its remaining transitive audit findings. Do not use forced dependency changes that break the locked build.

## Release gates

- All frontend lint/build and Rust tests pass from a clean clone using lockfiles.
- Strict Clippy passes for every Rust target with warnings denied.
- Linux, Windows, Apple Silicon macOS, and Intel macOS bundles build in CI.
- Cancellation leaves no child scanner process running.
- A scan cannot execute without current authorization confirmation.
- Artifacts and reports cannot escape the managed application data root.
- No report marks a tool failure as a clean scan, and no scanner finding exit code is treated as an infrastructure error.
- Every SQLite pool connection enforces foreign keys, and a running scan cannot be deleted before cancellation completes.
- Every packaged workflow uses catalog-supported tools and has executable artifact-output contracts.
- Custom workflow execution remains impossible until an immutable backend revision and active, non-revoked trust record are enforced at the Rust command boundary.
- MCP execution must always require an authenticated client, active signed engagement, exact trusted immutable revision, request-bound idempotency key, live budget checks, and cancellable daemon-owned process tree. These execution guards are implemented; sole SQLite ownership remains a stable-release gate for the older desktop data commands.
- Direct Codex and Claude Code integration must continue to work through local STDIO configuration without requesting a provider API key.
