# UniHack macOS beta installation

This beta package is for invited testers using an Apple-silicon Mac. It is not
yet Developer ID signed or notarized for public distribution.

## Install

1. Open the UniHack DMG.
2. Drag **UniHack** into **Applications**.
3. In Finder, open **Applications**.
4. Control-click **UniHack**, choose **Open**, then confirm **Open** if macOS
   shows the unidentified-developer warning.

Do not disable Gatekeeper and do not run Terminal commands that remove macOS
security protections.

## First run

1. Open **Readiness** and refresh local tool detection.
2. Install only tools you understand and need. Package-manager or operating
   system privilege prompts remain visible and must be approved by the tester.
3. Use **Workflows** to inspect the exact tools and arguments before starting.
4. Run security tools only against systems the tester owns or is explicitly
   authorized to assess.

## Connect Codex CLI or Claude Code

Open **AI & MCP** in UniHack and use the client setup action. The MCP
configuration contains only the local `unihack-mcp` executable path. UniHack
uses the AI client's existing login and does not need an OpenAI or Anthropic
API key.

Before an AI client may run a workflow, create a narrowly bounded engagement in
UniHack with the exact target, allowed workflows, expiry, and resource limits.
The AI client cannot create or expand that authorization.

## Send useful feedback

Include:

- Mac model and macOS version
- UniHack screen and action used
- Expected and actual result
- Whether a tool was installed, missing, or incompatible
- A screenshot with targets and private data redacted

Do not send API keys, passwords, session tokens, customer data, private target
details, or raw vulnerability evidence in ordinary chat or public issues.

## Current beta limitations

- This package supports Apple-silicon Macs only.
- Native is the only execution target.
- Some security tools are operating-system-specific.
- The package is ad-hoc signed for invited testing, not Developer ID signed or
  notarized.
- Windows, Linux, and Intel macOS installers require their own native builds.
