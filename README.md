# AI Bug Bounty Scanner

The AI Bug Bounty Scanner is a Tauri-based desktop application that orchestrates security tooling across platforms. All project documentation now lives in the `info/` directory to keep the repository root focused on source code.

## Documentation

- `info/README.md` – full product overview, architecture, and onboarding steps
- `info/IMPLEMENTATION_STATUS.md` – current delivery status and remaining tasks
- `info/READY_TO_USE.md` – latest verification checklist before releases

## Quick Start

Use the existing npm workspace scripts to run the application during development:

```bash
npm install
npm run tauri dev
```

Build distributable bundles with:

```bash
npm run tauri build
```

For additional operational guides, migration plans, and troubleshooting playbooks, inspect the specialized markdown files inside `info/`.
