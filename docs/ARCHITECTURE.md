# Architecture

## Native-first execution

```text
React UI
  -> AppBridge typed command/event boundary
  -> Tauri IPC in desktop builds or deterministic fixtures in browser tests
  -> typed Tauri command
  -> target and authorization validation
  -> workflow loader and DAG scheduler
  -> catalog-verified host executable plus argv and optional stdin
  -> bounded child process with timeout and cancellation
  -> managed artifacts and parser registry
  -> SQLite history, normalized findings, and report exports
```

The frontend never launches a process. Rust owns installation allowlists, executable discovery, command construction, process lifecycle, artifact paths, persistence, and report generation.

## Frontend console

The desktop UI uses React 19.2.7 and Vite 8.1.5. React Query owns Tauri/backend state; Zustand owns local high-frequency state such as selection, scene quality, editor history, and visual preferences. `AppBridge` selects the real Tauri implementation only inside the desktop runtime and a deterministic, non-executing mock implementation in normal browser development and Playwright.

Shared React Query keys have one stable data shape across every route. For example, `['tools']` always caches `Tool[]`; pages do not mix API envelopes and arrays under the same key. This keeps route transitions from reinterpreting cached native data.

The shell owns a persisted local notification center for startup state, scan lifecycle, tool installation, and safe frontend mutations. Native events enter through `AppBridge`; browser fixtures exercise the same controls without executing tools. Notification entries contain operational summaries and routes, never captured stdout or artifact contents.

All pages are route-lazy. The Mission Topology and Workflow Studio load Three.js, React Three Fiber, postprocessing, XYFlow, and Rapier only when their routes or quality modes require them. The base shell therefore does not preload the 3D or physics runtime. GSAP is reserved for coordinated page transitions; ordinary focus, hover, and reduced-motion states remain CSS-owned.

Operational controls remain accessible DOM elements. The Mission Topology has a structurally equivalent 2D view when immersive visuals are disabled or WebGL is unavailable. Rendering uses a maximum 1.5 device-pixel ratio, demand rendering while idle, explicit document-visibility suspension, and no physics, shadows, or postprocessing in Low Power mode. Rapier is restricted to explicit High quality. Leva is development-only and appears only with `?sceneControls=1`.

Workflow Studio uses XYFlow as the authoring surface and R3F only for a read-only spatial preview. Current drafts are local, versioned snapshots for interface development. Only unchanged packaged workflows can execute; backend-owned immutable revision hashing, quarantine, and revision trust must exist before custom draft execution is enabled.

The shared frontend workflow catalog adds product-facing intent, activity, target shape, time, evidence, and prerequisite metadata without replacing backend workflow YAML as execution truth. Workflow Studio, the guided scan launcher, and the adapter explorer consume the same metadata so a researcher can move from an outcome to host readiness, an authorized execution, and retained evidence without reinterpreting tool flags.

Packaged workflow handoffs keep machine-readable evidence separate from pipeline input. Files consumed as target lists must contain one target per line, so JSONL, CSV, or enriched display output cannot be passed directly to a downstream target-list flag. Loader regression tests enforce this contract across every packaged workflow.

The adapter registry exposes command and evidence contracts for all fifteen core workflow tools through a hybrid model. Seven tools retain specialized typed adapters where tool semantics justify dedicated code. The eight shared-pattern web tools use validated declarative `AdapterProfile` records that describe their executable, target transform and binding, subcommand/fixed arguments, output binding, risk, authorization, timeout, and expected evidence. The shared engine supports flag, positional, and stdin targets plus normal, prelude, and inline output flags without invoking a shell.

Adding another compatible tool therefore requires an audited profile record, catalog/install metadata, and any workflow or parser contract it needs—not a new adapter implementation or registry match arm. A specialized adapter is still required when a tool has conditional arguments, multiple execution modes, typed configuration beyond the profile schema, or output behavior that cannot be represented safely. The older `GenericAdapter` preset experiment remains source-compatible but is intentionally not registered because its loose flag model cannot enforce these distinctions.

Profiles are bundled application code and validated before command construction. They are not loaded from arbitrary user files. Adapter previews remain structured argv/stdin inspection only; actual workflows continue to use their packaged, validated argv and the Rust execution boundary. A future remotely updateable profile catalog must be signed, versioned, quarantined, and tied to the same immutable revision-trust model as custom workflows before it may influence execution.

### Automatic adapter discovery

The bundled profile engine is also the foundation for host-local auto-adapters. When catalog discovery finds a newly installed non-runtime security tool, UniHack executes only the resolved binary's standard `--help` probe with a four-second timeout, hidden process configuration, no-color environment, kill-on-drop, and a 64 KiB capture ceiling. It infers target and output capabilities from the installed CLI's own documentation, records the binary path/version/fingerprint and help-output hash, and persists the result under application data. Refresh, installation recheck, and the Adapters route all converge on this idempotent generation path.

An inferred adapter is `ready` only when the help contract contains an explicit target option and reaches the confidence threshold. Positional targets, stdin-only behavior, missing target semantics, and other ambiguous shapes remain `review_required`; quarantined profiles are visible but cannot construct commands. Runtime dependencies, general utility entries, and manually registered binaries are not probed automatically. Bundled and specialized adapters always take precedence over inferred profiles.

Internet documentation may later enrich descriptions and evidence, but it is not execution authority. UniHack does not scrape a web page and turn its contents into runnable arguments. A remotely distributed adapter pack must verify its signature/provenance against a configured trust root, match the installed binary/version, remain revocable, and pass the same local capability checks before activation.

The additive frontend contracts for `WorkflowDraft`, `WorkflowRevision`, `WorkflowTrust`, `WorkflowValidation`, `ExecutionTarget`, and `Runner` live under `frontend/src/types/`. They define the intended boundary without pretending an alternate runner exists. The Readiness route reports host tools, package managers, and workflow compatibility while visibly keeping WSL, container, and remote targets disabled or planned.

The GLB policy and license manifest live under `frontend/assets/models/` and `frontend/public/models/`. Dynamic workflow and scan structures remain procedural geometry.

## Important modules

- `src-tauri/src/commands/mod.rs`: typed desktop command boundary
- `src-tauri/src/security.rs`: executable target validation and tool-specific target forms
- `src-tauri/src/adapters/profile.rs`: validated declarative command-pattern engine
- `src-tauri/src/adapters/auto.rs`: local CLI probing, capability inference, quarantine, and persisted evidence
- `src-tauri/src/adapters/registry.rs`: specialized adapter routing and bundled profile catalog
- `src-tauri/src/tools/catalog.rs`: tool metadata and platform installation policy
- `src-tauri/src/tools/discovery.rs`: executable and dependency discovery
- `src-tauri/src/runtime/executor.rs`: argv/stdin execution, stream draining, timeout, cancellation, and artifact collection
- `src-tauri/src/workflow/loader.rs`: strict YAML parsing, template allowlist, retry bounds, DAG validation, and packaged workflow/catalog/artifact-contract tests
- `src-tauri/src/workflow/engine.rs`: durable execution state and DAG scheduling
- `src-tauri/src/database.rs`: SQLite ownership and migrations
- `src-tauri/src/reports.rs`: HTML, JSON, and SARIF rendering
- `frontend/src/bridge/appBridge.ts`: Tauri versus deterministic browser boundary
- `frontend/src/components/NotificationCenter.tsx`: persisted local operational event center
- `frontend/src/stores/notificationStore.ts`: bounded notification history and unread state
- `frontend/src/components/mission/`: adaptive 3D topology and accessible fallback
- `frontend/src/pages/WorkflowsPage.tsx`: visual DAG editor and packaged-workflow execution boundary
- `frontend/src/pages/ScansPage.tsx`: outcome-driven workflow launcher and retained execution operations
- `frontend/src/pages/ReportsPage.tsx`: local evidence export, preview, integrity metadata, and managed-file operations
- `frontend/src/components/AdapterExplorer.tsx`: tool readiness, workflow relationships, and non-executing command inspection
- `frontend/src/data/workflowCatalog.ts`: shared product metadata for packaged workflow selection
- `frontend/src/pages/ReadinessPage.tsx`: read-only host and runner readiness wizard
- `frontend/src/stores/`: local UI preferences and workflow editor history
- `app/workflows/`: packaged workflows bundled into the desktop application

## Cross-platform installation policy

The backend computes available methods for the current host. Preferred native methods are Homebrew on macOS, WinGet on Windows, and APT on Linux when an audited mapping exists. Go, Cargo, Gem, Pipx, and manual recipes are explicit fallbacks. The frontend can select only methods returned by the backend, and the install command validates the selection again.

Tool binaries are not bundled. This keeps UniHack small and lets researchers manage tool versions, but it means the first-run experience depends on host package managers and runtimes. Tool licensing remains the user's responsibility; WPScan vulnerability enrichment, for example, requires the user's own API configuration and may have separate licensing terms.

## Persistence and isolation

Application data, including the discovery cache, is rooted in the Tauri app-data directory for the established `com.aibugbountyscanner.app` identifier. Keeping this identifier stable preserves existing scan history across upgrades. Each scan receives its own working directory and support files. Output paths are template-validated, canonicalized, and checked against the scan root. Reports live under a managed reports directory and are recorded with size and SHA-256 metadata. Reveal commands resolve records by ID, canonicalize the stored path, and reject anything outside the managed results or reports root before invoking the host file manager.

SQLite is the source of truth for scan history and workflow state. WAL mode, a busy timeout, and foreign-key enforcement are configured on every pooled connection. Executions left running during an application shutdown are recovered as interrupted rather than silently reported as complete.

## Local AI and MCP boundary

Codex CLI, Claude Code, and compatible MCP hosts connect to the local `unihack-mcp` STDIO binary. The host uses its own signed-in model session; UniHack does not receive or require the host's OpenAI or Anthropic API key. There is no MCP HTTP listener, remote endpoint, or bearer token in the production design.

```text
Codex CLI / Claude Code
  -> launch local unihack-mcp over STDIO
  -> typed MCP schemas and capability check
  -> owner-only Unix socket or local Windows named pipe
  -> versioned JSON frames plus HMAC client enrollment
  -> unihackd and transport-neutral UniHackService
  -> immutable workflow revision + engagement-scope validation
  -> SQLite audit event with serialized HMAC chain
  -> bounded result returned over STDIO
```

The current MCP milestone exposes status, tools, packaged workflow revisions, approved engagement discovery, mission validation, revision-bound workflow start/status/cancel, bounded scan evidence, reports, and deterministic adapter refresh. The STDIO proxy never opens SQLite or spawns a scanner: it starts or reconnects to `unihackd`, authenticates with an OS-credential-backed HMAC challenge, and relays typed requests. Protocol v2 gives the desktop and MCP proxy distinct credential identities; authority-changing engagement creation, revocation, and activity reads are daemon-gated to the desktop credential and are not MCP tools. `unihackd` atomically binds every execution to the exact trusted revision and signed scope, applies request-bound idempotency and resource budgets, revalidates authority throughout the run, and owns cancellation. A separate authenticated daemon stream relays persisted execution events to Tauri without blocking commands.

`EngagementScope` canonicalizes hostnames, IPs, CIDRs, and URL origins/path boundaries and binds them to a principal, workflow set, risk ceiling, validity window, and resource budget. Scope signatures live in OS credential storage. MCP clients cannot create or expand a scope.

Important modules:

- `src-tauri/src/governance.rs`: capabilities, scope matching/signatures, immutable revision hashes, trust, and audit contracts
- `src-tauri/src/service.rs`: transport-neutral discovery/evidence/governance operations
- `src-tauri/src/mcp.rs`: bounded MCP schemas, annotations, and audited tool handlers
- `src-tauri/src/bin/unihack-mcp.rs`: zero-key STDIO server entry point
- `src-tauri/src/daemon.rs`: local authenticated protocol, daemon autostart, single-instance socket, and idle lifecycle
- `src-tauri/src/bin/unihackd.rs`: background service entry point
- `src-tauri/src/integrations.rs`: explicit Codex/Claude configuration helpers
- `scripts/prepare-sidecars.mjs`: locked release build and target-triple staging for Tauri external binaries
- `frontend/src/pages/IntegrationsPage.tsx`: local client detection, one-click setup, copyable configuration, and desktop engagement authority surface
- `frontend/src/components/EngagementAccessPanel.tsx`: scope boundaries, resource budgets, deliberate revocation, and sanitized activity

See [MCP Integration](MCP_INTEGRATION.md) for the supported client configuration and permanent no-provider-key contract.
