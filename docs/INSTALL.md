# Install UniHack beta

Download the installer for your computer from the repository's
[Releases page](https://github.com/Jeevanbidgar/UniHack-Cross-Platform-Tool-Orchestrator/releases).
Every tagged beta release includes `SHA256SUMS.txt`.

> Beta installers are currently unsigned. Download only from the official
> repository, verify the checksum, and do not disable operating-system security
> features globally.

## macOS

Choose:

- `UniHack-2.0.0-macos-arm64.dmg` for Apple Silicon (M1 or newer)
- `UniHack-2.0.0-macos-x86_64.dmg` for Intel Macs

Open the DMG and drag **UniHack** into **Applications**. On the first launch,
Control-click UniHack in Finder, choose **Open**, and confirm the
unidentified-developer warning. Do not disable Gatekeeper.

## Windows

Choose `UniHack-2.0.0-windows-x86_64-setup.exe`.

Run the installer. Because this beta is not code signed, Microsoft Defender
SmartScreen may show an unrecognized-app warning. Continue only if the file came
from the official release and its SHA-256 matches `SHA256SUMS.txt`.

## Linux

Choose one:

- `UniHack-2.0.0-linux-x86_64.deb` for Debian, Ubuntu, and compatible systems
- `UniHack-2.0.0-linux-x86_64.AppImage` for other x86_64 desktop distributions

Install the Debian package:

```bash
sudo apt install ./UniHack-2.0.0-linux-x86_64.deb
```

Or run the AppImage:

```bash
chmod +x UniHack-2.0.0-linux-x86_64.AppImage
./UniHack-2.0.0-linux-x86_64.AppImage
```

The AppImage still requires a working graphical Linux session and the host
libraries expected by Tauri/WebKitGTK.

## Verify a checksum

macOS or Linux:

```bash
sha256sum -c SHA256SUMS.txt
```

On macOS, use `shasum -a 256` if `sha256sum` is unavailable and compare the
printed value with the matching line in `SHA256SUMS.txt`.

Windows PowerShell:

```powershell
Get-FileHash .\UniHack-2.0.0-windows-x86_64-setup.exe -Algorithm SHA256
```

## First run

1. Open **Readiness** and refresh the host inventory.
2. Install only the security tools you understand and need.
3. Inspect a packaged procedure in **Workflows**.
4. Create a narrowly bounded authorized engagement before allowing an MCP
   client to execute anything.
5. Open **AI & MCP**, then connect Codex CLI or Claude Code. No model-provider
   API key is requested by UniHack.

See [MCP integration](MCP_INTEGRATION.md) for the complete client flow.
