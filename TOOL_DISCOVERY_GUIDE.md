# Tool Discovery System Guide

## Overview

The AI Bug Bounty Scanner uses a robust, cross-platform tool discovery service that automatically detects, verifies, and caches installed security tools. This system provides fast lookups with automatic background refresh to keep tool status up-to-date.

## Architecture

### Core Components

1. **ToolDiscoveryService** (`backend/tool_discovery.py`)

   - Main service coordinating tool discovery, caching, and refresh
   - Resolves executables using cross-platform methods
   - Verifies tool versions by executing `--version` commands
   - Checks OS-level dependencies (e.g., libpcap, Npcap)

2. **ToolDiscoveryCache** (`backend/tool_discovery.py`)

   - Async-friendly JSON-based cache stored at `data/tool_discovery_cache.json`
   - Persists tool records with paths, versions, and metadata
   - Thread-safe with asyncio locks

3. **Tool Records** (`ToolRecord` dataclass)
   - `name`: Tool identifier
   - `status`: "available", "degraded", "missing", or "error"
   - `installed`: Boolean indicating if tool was found
   - `version`: Normalized semantic version (e.g., "2.8.0")
   - `raw_version`: Full version output from tool
   - `path`: Absolute path to executable
   - `os_dependencies`: Required OS packages
   - `missing_dependencies`: Missing required packages
   - `last_checked`: Timestamp of last verification
   - `last_seen`: Last time tool was found installed

## Cross-Platform Resolution

### Resolution Strategy

The service uses a multi-tier approach to locate tools:

1. **Primary: `shutil.which()`**

   - Cross-platform Python utility
   - Searches PATH for executables

2. **Windows Fallbacks**

   - PowerShell `Get-Command`: `powershell -Command "Get-Command tool_name"`
   - CMD `where.exe`: For Windows-native resolution

3. **Linux/macOS Fallbacks**

   - Shell `which`: `/usr/bin/env which tool_name`

4. **Manual Search**
   - Common installation directories
   - User home directories (~/go/bin, ~/.cargo/bin, etc.)

### OS Dependency Checking

**Windows:**

- Checks for Npcap/WinPcap DLLs in System32 for network tools

**Linux:**

- Scans standard library paths for libpcap.so

**macOS:**

- Checks Homebrew and system lib paths for libpcap.dylib

## Usage

### Backend API

The tool discovery service is exposed through FastAPI endpoints:

```python
from fastapi import BackgroundTasks
from backend.tool_discovery import tool_discovery_service

# Get all tools (returns cached, schedules refresh if stale)
@router.get("/tools/")
async def get_tools(background_tasks: BackgroundTasks):
    records = await tool_discovery_service.list_tools(
        background_tasks=background_tasks
    )
    return [record.to_dict() for record in records]

# Get specific tool
@router.get("/tools/{tool_name}")
async def get_tool(tool_name: str, background_tasks: BackgroundTasks):
    record = await tool_discovery_service.get_tool(
        tool_name,
        background_tasks=background_tasks
    )
    return record.to_dict() if record else None

# Force refresh all tools
@router.post("/tools/refresh")
async def refresh_tools():
    refreshed = await tool_discovery_service.refresh_all(force=True)
    return {"refreshed": len(refreshed)}
```

### Frontend API

The frontend TypeScript interface matches the backend schema:

```typescript
interface Tool {
  name: string;
  description: string;
  category: string;
  status: string;
  installed: boolean;
  available: boolean;
  version: string | null;
  raw_version?: string | null;
  path?: string | null;
  command_template: string[];
  output_format: string;
  os_dependencies: string[];
  missing_dependencies: string[];
  last_check?: string | null;
  last_seen?: string | null;
  last_error?: string | null;
}

// Fetch tools from API
const response = await fetch("http://localhost:8000/api/tools/");
const tools: Tool[] = await response.json();
```

### Direct Service Usage

```python
from backend.tool_discovery import tool_discovery_service

# Ensure service is initialized
await tool_discovery_service.ensure_ready()

# List all tools (returns cached data)
tools = await tool_discovery_service.list_tools()

# Get specific tool with force refresh
tool = await tool_discovery_service.get_tool("nuclei", force_refresh=True)

# Refresh specific tools
refreshed = await tool_discovery_service.refresh_selection(
    ["nuclei", "subfinder", "nmap"],
    force=True
)

# Verify tool before execution (health check)
record = await tool_discovery_service.verify_tool_before_use("nuclei")
if not record.installed:
    raise RuntimeError(f"Tool {record.name} not available")
```

## Cache Behavior

### TTL (Time-To-Live)

- Default: **900 seconds (15 minutes)**
- Configurable via `TOOL_DISCOVERY_REFRESH_TTL` env var
- Tools older than TTL are refreshed in background

### Refresh Strategy

1. **Instant Response**: API endpoints return cached data immediately
2. **Background Refresh**: Stale tools are refreshed asynchronously
3. **Force Refresh**: `force=True` bypasses cache and re-scans

### Cache Location

- Path: `data/tool_discovery_cache.json`
- Configurable via `TOOL_DISCOVERY_CACHE_PATH` env var
- Auto-created on first run

## Configuration

Environment variables:

```bash
# Cache file location
TOOL_DISCOVERY_CACHE_PATH=data/tool_discovery_cache.json

# Cache TTL in seconds
TOOL_DISCOVERY_REFRESH_TTL=900

# Tool resolution timeout (seconds)
TOOL_DISCOVERY_RESOLUTION_TIMEOUT=4.0

# Version check timeout (seconds)
TOOL_DISCOVERY_VERSION_TIMEOUT=5.0
```

## Adding New Tools

### 1. Via Plugin System

Create a YAML plugin in `backend/plugins/`:

```yaml
name: custom_tool
description: My custom security tool
category: custom
risk_level: medium
command_template:
  - custom_tool
  - "-t"
  - "{target}"
parameters:
  - name: target
    type: string
    required: true
output_format: json
timeout: 300
tags:
  - custom
  - scanning
```

### 2. Via Code (Fallback Definitions)

Edit `backend/tool_discovery.py` → `_build_definitions()`:

```python
fallback_definitions = [
    {
        "name": "my_tool",
        "description": "My custom tool",
        "category": "custom",
        "commands": ["my_tool"],
    },
    # ... other tools
]
```

## Troubleshooting

### Tool Not Detected

1. **Check PATH**: Ensure tool is in system PATH

   ```bash
   # Windows
   where tool_name

   # Linux/macOS
   which tool_name
   ```

2. **Check Cache**: Delete cache to force re-scan

   ```bash
   rm data/tool_discovery_cache.json
   ```

3. **Check Logs**: Enable debug logging
   ```python
   import logging
   logging.getLogger('backend.tool_discovery').setLevel(logging.DEBUG)
   ```

### Missing Dependencies

If tool shows "degraded" status:

**Linux:**

```bash
sudo apt install libpcap-dev  # For naabu, nmap, masscan
```

**macOS:**

```bash
brew install libpcap
```

**Windows:**

- Download and install [Npcap](https://npcap.com/)

### Version Detection Fails

Some tools may not support `--version`:

- Check `raw_version` field for actual output
- Tool still works, just version is "unknown"

## Performance

- **First Load**: ~2-5 seconds (scans all tools)
- **Cached Load**: <10ms (reads from JSON cache)
- **Background Refresh**: Non-blocking, doesn't affect response time

## Security Considerations

1. **Path Validation**: Only executes tools with `--version` flag
2. **Timeout Protection**: All subprocesses have 5-second timeout
3. **Error Isolation**: Failed tool checks don't crash the service
4. **No Shell Injection**: Uses `asyncio.create_subprocess_exec` (no shell)

## Testing

Run integration tests:

```bash
# Test imports
python test_imports.py

# Test tool discovery
python test_tool_discovery.py

# Test with plugin loader
python test_tool_discovery_integration.py
```

Expected output:

```
[OK] Discovered 10 tools:
  - subfinder: INSTALLED (recon) v2.8.0
  - amass: INSTALLED (recon) v5.0.0
  - nuclei: INSTALLED (vulnerability) v3.4.10
  ...
[OK] Total installed tools: 10
```

## Migration from Old System

The new system automatically replaces the old `ToolRegistry` class. No manual migration needed.

**Old Code:**

```python
from backend.tool_discovery import ToolRegistry
registry = ToolRegistry()
tools = await registry.refresh_tools()
```

**New Code:**

```python
from backend.tool_discovery import tool_discovery_service
tools = await tool_discovery_service.list_tools()
```

## API Reference

See `/api/tools/` endpoint documentation:

- `GET /api/tools/` - List all tools
- `GET /api/tools/{name}` - Get specific tool
- `POST /api/tools/{name}/check` - Check tool availability
- `POST /api/tools/refresh` - Force refresh all tools
- `GET /api/tools/categories` - List categories
- `GET /api/tools/category/{category}` - Get tools by category

---

**Last Updated**: October 1, 2025  
**Version**: 2.0.0

