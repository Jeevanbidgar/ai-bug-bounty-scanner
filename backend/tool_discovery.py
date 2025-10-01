"""
Cross-platform tool discovery service with caching and background refresh.

This module discovers security tooling by resolving executables on PATH (with
platform-specific fallbacks), verifying versions, and caching results on disk
for fast subsequent lookups. The public service exposes async helpers that can
be used directly in FastAPI endpoints (with BackgroundTasks) as well as by
other backend components that need to validate tooling before execution.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import re
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - only for typing during development
    from fastapi import BackgroundTasks

logger = logging.getLogger(__name__)

WINDOWS = platform.system() == "Windows"

class ToolDiscoveryError(Exception):
    """Raised when tool discovery operations fail"""
    pass
CACHE_PATH = Path(os.getenv("TOOL_DISCOVERY_CACHE_PATH", Path("data/tool_discovery_cache.json")))
DEFAULT_REFRESH_TTL = int(os.getenv("TOOL_DISCOVERY_REFRESH_TTL", "900"))  # seconds
RESOLUTION_TIMEOUT = float(os.getenv("TOOL_DISCOVERY_RESOLUTION_TIMEOUT", "4.0"))
VERSION_TIMEOUT = float(os.getenv("TOOL_DISCOVERY_VERSION_TIMEOUT", "5.0"))
VERSION_REGEX = re.compile(r"v?(\d+\.\d+(?:\.\d+)*)")

TOOL_DEPENDENCY_MATRIX: Dict[str, Dict[str, List[str]]] = {
    "naabu": {
        "Linux": ["libpcap"],
        "Darwin": ["libpcap"],
        "Windows": ["Npcap", "WinPcap"],
    },
    "nmap": {
        "Linux": ["libpcap"],
        "Darwin": ["libpcap"],
        "Windows": [],  # Bundled with installers
    },
    "masscan": {
        "Linux": ["libpcap"],
        "Darwin": ["libpcap"],
        "Windows": ["Npcap", "WinPcap"],
    },
}


@dataclass
class ToolDefinition:
    """Static metadata describing how to locate and verify a tool."""

    name: str
    description: str
    category: str
    command_candidates: List[str]
    version_args: List[str] = field(default_factory=lambda: ["--version"])
    output_format: str = "text"
    os_dependencies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolRecord:
    """Cache entry for a discovered tool."""

    name: str
    description: str
    category: str
    status: str = "unknown"
    installed: bool = False
    command_template: List[str] = field(default_factory=list)
    output_format: str = "text"
    version: Optional[str] = None
    raw_version: Optional[str] = None
    path: Optional[str] = None
    os_dependencies: List[str] = field(default_factory=list)
    missing_dependencies: List[str] = field(default_factory=list)
    last_checked: Optional[str] = None
    last_seen: Optional[str] = None
    last_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolRecord":
        return cls(**data)


class ToolDiscoveryCache:
    """Simple async-friendly cache backed by a JSON file."""

    def __init__(self, cache_path: Path = CACHE_PATH) -> None:
        self.cache_path = cache_path
        self._records: Dict[str, ToolRecord] = {}
        self._loaded = False
        self._lock = asyncio.Lock()

    async def load(self) -> None:
        async with self._lock:
            if self._loaded:
                return
            if self.cache_path.exists():
                try:
                    raw = await asyncio.to_thread(self.cache_path.read_text, encoding="utf-8")
                    data = json.loads(raw)
                    for name, payload in data.items():
                        self._records[name] = ToolRecord.from_dict(payload)
                    logger.debug("Loaded %d tool cache entries", len(self._records))
                except Exception as exc:  # pragma: no cover - protective
                    logger.warning("Failed to read tool cache %s: %s", self.cache_path, exc)
            self._loaded = True

    async def save(self) -> None:
        async with self._lock:
            payload = {name: record.to_dict() for name, record in self._records.items()}

        def _write() -> None:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with self.cache_path.open("w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)

        await asyncio.to_thread(_write)

    async def set(self, name: str, record: ToolRecord) -> None:
        async with self._lock:
            self._records[name] = record

    async def get(self, name: str) -> Optional[ToolRecord]:
        async with self._lock:
            return self._records.get(name)

    async def snapshot(self) -> List[ToolRecord]:
        async with self._lock:
            return [record for record in self._records.values()]

    async def ensure_entry(self, name: str, record: ToolRecord) -> None:
        async with self._lock:
            self._records.setdefault(name, record)

    async def prune(self, valid_names: Iterable[str]) -> None:
        valid = set(valid_names)
        async with self._lock:
            removed = [name for name in self._records.keys() if name not in valid]
            for name in removed:
                self._records.pop(name, None)
            if removed:
                logger.debug("Pruned %d stale tool cache entries", len(removed))


class ToolDiscoveryService:
    """High-level service coordinating tool discovery, caching, and refresh."""

    def __init__(
        self,
        plugin_loader: Any = None,
        cache_path: Optional[Path] = None,
        refresh_ttl: Optional[int] = None,
    ) -> None:
        self.plugin_loader = plugin_loader
        self.cache = ToolDiscoveryCache(cache_path or CACHE_PATH)
        self.refresh_ttl = refresh_ttl or DEFAULT_REFRESH_TTL
        self.additional_search_paths = self._build_additional_search_paths()
        self.tool_definitions: Dict[str, ToolDefinition] = {}
        self._refresh_lock = asyncio.Lock()
        self._definitions_lock = asyncio.Lock()
        self._definitions_ready = asyncio.Event()
        self._initialised = False

    async def ensure_ready(self) -> None:
        if not self._initialised:
            await self.reload_definitions()
            await self.cache.load()
            await self._ensure_cache_entries()
            self._initialised = True

    async def reload_definitions(self, plugin_loader: Any = None) -> None:
        async with self._definitions_lock:
            if plugin_loader is not None:
                self.plugin_loader = plugin_loader
            definitions = await asyncio.to_thread(self._build_definitions)
            self.tool_definitions = definitions
            await self.cache.prune(definitions.keys())
            self._definitions_ready.set()
            logger.debug("Registered %d tool definitions", len(definitions))

    async def _ensure_cache_entries(self) -> None:
        await self._definitions_ready.wait()
        for definition in self.tool_definitions.values():
            placeholder = ToolRecord(
                name=definition.name,
                description=definition.description,
                category=definition.category,
                command_template=list(definition.command_candidates),
                output_format=definition.output_format,
            )
            await self.cache.ensure_entry(definition.name, placeholder)

    async def list_tools(
        self,
        background_tasks: Optional["BackgroundTasks"] = None,
        force_refresh: bool = False,
    ) -> List[ToolRecord]:
        await self.ensure_ready()
        records = await self.cache.snapshot()
        stale: List[str] = []
        for record in records:
            if force_refresh or self._is_stale(record):
                stale.append(record.name)
        if stale:
            self._schedule_refresh(stale, background_tasks, force=force_refresh)
        return sorted(records, key=lambda r: r.name)

    async def get_tool(
        self,
        tool_name: str,
        background_tasks: Optional["BackgroundTasks"] = None,
        force_refresh: bool = False,
    ) -> Optional[ToolRecord]:
        await self.ensure_ready()
        record = await self.cache.get(tool_name)
        if record is None:
            logger.debug("Tool %s not present in cache, refreshing definitions", tool_name)
            await self.reload_definitions()
            await self._ensure_cache_entries()
            record = await self.cache.get(tool_name)
        if record and (force_refresh or self._is_stale(record)):
            self._schedule_refresh([tool_name], background_tasks, force=True)
        return record

    async def refresh_all(self, force: bool = False) -> Dict[str, ToolRecord]:
        return await self.refresh_selection(list(self.tool_definitions.keys()), force=force)

    async def refresh_selection(
        self,
        tool_names: List[str],
        force: bool = False,
    ) -> Dict[str, ToolRecord]:
        await self.ensure_ready()
        async with self._refresh_lock:
            results: Dict[str, ToolRecord] = {}
            for name in tool_names:
                definition = self.tool_definitions.get(name)
                if not definition:
                    logger.debug("Skipping unknown tool %s during refresh", name)
                    continue
                record = await self._refresh_tool(definition, force=force)
                if record:
                    results[name] = record
            if results:
                await self.cache.save()
            return results

    async def verify_tool_before_use(self, tool_name: str) -> ToolRecord:
        await self.ensure_ready()
        definition = self.tool_definitions.get(tool_name)
        if not definition:
            raise ValueError(f"Unknown tool: {tool_name}")
        record = await self.cache.get(tool_name)
        needs_refresh = True
        if record and record.path:
            cached_path = Path(record.path)
            if cached_path.exists():
                resolved = shutil.which(cached_path.name)
                if resolved and Path(resolved).resolve() == cached_path.resolve():
                    needs_refresh = False
        if needs_refresh:
            logger.debug("Re-resolving tool %s before execution", tool_name)
            record = await self._refresh_tool(definition, force=True)
            await self.cache.save()
        return record

    def _schedule_refresh(
        self,
        tool_names: List[str],
        background_tasks: Optional["BackgroundTasks"],
        force: bool,
    ) -> None:
        if background_tasks is not None:
            background_tasks.add_task(self.refresh_selection, tool_names, force)
            return
        asyncio.create_task(self.refresh_selection(tool_names, force))

    async def _refresh_tool(self, definition: ToolDefinition, force: bool = False) -> ToolRecord:
        record = await self.cache.get(definition.name)
        if record and not force and not self._is_stale(record):
            return record

        logger.debug("Refreshing tool %s", definition.name)
        now = self._timestamp()
        status = "missing"
        path: Optional[str] = None
        version: Optional[str] = None
        raw_version: Optional[str] = None
        last_seen: Optional[str] = None
        last_error: Optional[str] = None
        installed = False

        try:
            path = await self._resolve_tool_path(definition.command_candidates)
            deps, missing = self._check_os_dependencies(definition)
            if path:
                installed = True
                status = "available"
                last_seen = now
                version, raw_version = await self._capture_tool_version(path, definition.version_args)
                if missing:
                    status = "degraded"
            else:
                missing = deps  # all deps considered missing when tool absent
            record = ToolRecord(
                name=definition.name,
                description=definition.description,
                category=definition.category,
                status=status,
                installed=installed,
                command_template=list(definition.command_candidates),
                output_format=definition.output_format,
                version=version,
                raw_version=raw_version,
                path=path,
                os_dependencies=list(sorted(set(deps))),
                missing_dependencies=list(sorted(set(missing))),
                last_checked=now,
                last_seen=last_seen,
                last_error=last_error,
            )
        except Exception as exc:  # pragma: no cover - protective
            logger.exception("Failed to refresh tool %s", definition.name)
            record = ToolRecord(
                name=definition.name,
                description=definition.description,
                category=definition.category,
                status="error",
                installed=False,
                command_template=list(definition.command_candidates),
                output_format=definition.output_format,
                last_checked=now,
                last_error=str(exc),
            )
        await self.cache.set(definition.name, record)
        return record

    async def _resolve_tool_path(self, candidates: Iterable[str]) -> Optional[str]:
        for command in candidates:
            if not command:
                continue

            # Try the command as-is first
            path = shutil.which(command)
            if path:
                return path

            # Try with .exe extension on Windows (handles case sensitivity)
            if WINDOWS:
                exe_command = f"{command}.exe"
                path = shutil.which(exe_command)
                if path:
                    return path

                # Try uppercase extension
                exe_command_upper = f"{command}.EXE"
                path = shutil.which(exe_command_upper)
                if path:
                    return path

            path = await self._resolve_with_system_command(command)
            if path:
                return path

            for search_dir in self.additional_search_paths:
                candidate_path = Path(search_dir) / command
                if WINDOWS and candidate_path.suffix == "":
                    # Try .exe extension
                    exe_candidate = candidate_path.with_suffix(".exe")
                    if exe_candidate.exists() and os.access(exe_candidate, os.X_OK):
                        return str(exe_candidate)

                    # Try .EXE extension
                    exe_candidate_upper = candidate_path.with_suffix(".EXE")
                    if exe_candidate_upper.exists() and os.access(exe_candidate_upper, os.X_OK):
                        return str(exe_candidate_upper)

                if candidate_path.exists() and os.access(candidate_path, os.X_OK):
                    return str(candidate_path)
        return None

    async def _resolve_with_system_command(self, command: str) -> Optional[str]:
        if WINDOWS:
            ps_script = (
                f"$cmd = Get-Command -Name '{command}' -ErrorAction SilentlyContinue | "
                "Select-Object -First 1 -ExpandProperty Source; if ($cmd) { $cmd }"
            )
            path = await self._run_command([
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script
            ])
            if path:
                path_obj = Path(path.strip())
                if path_obj.exists():
                    return str(path_obj)

            path = await self._run_command(["where.exe", command])
            if path:
                first = path.strip().splitlines()[0]
                path_obj = Path(first)
                if path_obj.exists():
                    return str(path_obj)
        else:
            path = await self._run_command(["/usr/bin/env", "which", command])
            if path:
                candidate = path.strip().splitlines()[0]
                candidate_path = Path(candidate)
                if candidate_path.exists():
                    return str(candidate_path)
        return None

    async def _capture_tool_version(
        self,
        tool_path: str,
        version_args: Iterable[str],
    ) -> Tuple[Optional[str], Optional[str]]:
        cmd = [tool_path, *(list(version_args) or ["--version"])]
        output = await self._run_command(cmd, timeout=VERSION_TIMEOUT, capture_stderr=True)
        if not output:
            return None, None
        normalized = self._normalize_version(output)
        return normalized, output.strip()

    async def _run_command(
        self,
        cmd: List[str],
        timeout: float = RESOLUTION_TIMEOUT,
        capture_stderr: bool = False,
    ) -> Optional[str]:
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE if capture_stderr else asyncio.subprocess.DEVNULL,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            if process.returncode != 0 and not capture_stderr:
                return None
            data = stdout or b""
            if capture_stderr and not data:
                data = stderr or b""
            return data.decode("utf-8", errors="ignore").strip()
        except (FileNotFoundError, asyncio.TimeoutError):
            return None

    def _normalize_version(self, output: str) -> Optional[str]:
        match = VERSION_REGEX.search(output)
        if match:
            version = match.group(1)
            return version
            return None

    def _check_os_dependencies(self, definition: ToolDefinition) -> Tuple[List[str], List[str]]:
        os_name = platform.system()
        required = list(definition.os_dependencies)
        matrix = TOOL_DEPENDENCY_MATRIX.get(definition.name, {}).get(os_name, [])
        for dep in matrix:
            if dep not in required:
                required.append(dep)

        missing: List[str] = []
        for dep in required:
            if os_name == "Linux" and dep == "libpcap":
                lib_paths = [
                    "/usr/lib",
                    "/usr/local/lib",
                    "/lib",
                    "/usr/lib/x86_64-linux-gnu",
                ]
                if not any(list(Path(path).glob("libpcap.so*")) for path in lib_paths if Path(path).exists()):
                    missing.append(dep)
            elif os_name == "Darwin" and dep == "libpcap":
                lib_paths = ["/usr/lib", "/usr/local/lib", "/opt/homebrew/lib"]
                if not any(list(Path(path).glob("libpcap*.dylib")) for path in lib_paths if Path(path).exists()):
                    missing.append(dep)
            elif os_name == "Windows" and dep in {"Npcap", "WinPcap"}:
                npcap_paths = [
                    Path(r"C:\\Windows\\System32\\Npcap"),
                    Path(r"C:\\Windows\\System32\\wpcap.dll"),
                    Path(r"C:\\Windows\\SysWOW64\\wpcap.dll"),
                ]
                if not any(path.exists() for path in npcap_paths):
                    missing.append(dep)
        return required, missing

    def _is_stale(self, record: ToolRecord) -> bool:
        if not record.last_checked:
            return True
        try:
            last = datetime.fromisoformat(record.last_checked)
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
        except ValueError:
            return True
        return datetime.now(timezone.utc) - last > timedelta(seconds=self.refresh_ttl)

    def _timestamp(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _build_definitions(self) -> Dict[str, ToolDefinition]:
        definitions: Dict[str, ToolDefinition] = {}

        # Prefer plugin-defined tools if available
        loader = self.plugin_loader
        if loader is not None:
            try:
                if not getattr(loader, "_loaded_tools", {}):
                    loader.load_tool_plugins()
            except Exception as exc:  # pragma: no cover - protective
                logger.warning("Failed to load tool plugins: %s", exc)
            for plugin in getattr(loader, "_loaded_tools", {}).values():
                primary = self._extract_primary_command(plugin.command_template, plugin.name)
                command_candidates = self._collect_candidates(plugin.name, primary)
                definition = ToolDefinition(
                    name=plugin.name,
                    description=plugin.description or plugin.name,
                    category=plugin.category or "general",
                    command_candidates=command_candidates,
                    version_args=self._extract_version_args(plugin),
                    output_format=getattr(plugin, "output_format", "text"),
                    os_dependencies=list(getattr(plugin, "dependencies", [])),
                    metadata={"source": "plugin"},
                )
                definitions[plugin.name] = definition

        # Fallback built-ins (ensures core tools are covered even without plugins)
        # Comprehensive list of security tools to discover
        # This list covers common tools found in Kali Linux and penetration testing environments
        fallback_definitions = [
            # Subdomain Enumeration & DNS
            {"name": "subfinder", "description": "Fast passive subdomain discovery tool", "category": "recon", "commands": ["subfinder"]},
            {"name": "amass", "description": "Comprehensive network reconnaissance tool", "category": "recon", "commands": ["amass"]},
            {"name": "assetfinder", "description": "Find domains and subdomains", "category": "recon", "commands": ["assetfinder", "assetfinder.exe"]},
            {"name": "knockpy", "description": "Subdomain scanner", "category": "recon", "commands": ["knockpy"]},
            {"name": "sublist3r", "description": "Fast subdomains enumeration tool", "category": "recon", "commands": ["sublist3r"]},
            {"name": "dnsrecon", "description": "DNS enumeration script", "category": "recon", "commands": ["dnsrecon"]},
            {"name": "fierce", "description": "DNS reconnaissance tool", "category": "recon", "commands": ["fierce"]},
            {"name": "dnsenum", "description": "DNS enumeration tool", "category": "recon", "commands": ["dnsenum"]},
            
            # Port Scanning
            {"name": "nmap", "description": "Network discovery and security auditing tool", "category": "network", "commands": ["nmap"]},
            {"name": "naabu", "description": "Fast port scanner", "category": "network", "commands": ["naabu"]},
            {"name": "masscan", "description": "TCP port scanner", "category": "network", "commands": ["masscan"]},
            {"name": "rustscan", "description": "Modern port scanner", "category": "network", "commands": ["rustscan"]},
            
            # HTTP Probing & Web Analysis
            {"name": "httpx", "description": "Fast HTTP probe", "category": "web", "commands": ["httpx", "httpx.exe"]},
            {"name": "httprobe", "description": "HTTP/HTTPS probe", "category": "web", "commands": ["httprobe"]},
            {"name": "meg", "description": "Fetch many paths for many hosts", "category": "web", "commands": ["meg"]},
            
            # Web Crawling & Spidering
            {"name": "katana", "description": "Web crawler from ProjectDiscovery", "category": "web", "commands": ["katana", "katana.exe"]},
            {"name": "gospider", "description": "Fast web spider", "category": "web", "commands": ["gospider"]},
            {"name": "hakrawler", "description": "Simple, fast web crawler", "category": "web", "commands": ["hakrawler"]},
            
            # URL Discovery
            {"name": "gau", "description": "Get all URLs from various sources", "category": "recon", "commands": ["gau"]},
            {"name": "waybackurls", "description": "Wayback Machine URL fetcher", "category": "recon", "commands": ["waybackurls"]},
            {"name": "gauplus", "description": "Modified GAU with additional features", "category": "recon", "commands": ["gauplus"]},
            
            # Vulnerability Scanning
            {"name": "nuclei", "description": "Fast and customizable vulnerability scanner", "category": "vulnerability", "commands": ["nuclei"]},
            {"name": "nikto", "description": "Web server scanner", "category": "vulnerability", "commands": ["nikto"]},
            {"name": "wpscan", "description": "WordPress vulnerability scanner", "category": "vulnerability", "commands": ["wpscan"]},
            {"name": "joomscan", "description": "Joomla vulnerability scanner", "category": "vulnerability", "commands": ["joomscan"]},
            
            # Directory & File Brute Forcing
            {"name": "ffuf", "description": "Fast web fuzzer", "category": "web", "commands": ["ffuf"]},
            {"name": "gobuster", "description": "Directory/DNS brute force tool", "category": "web", "commands": ["gobuster"]},
            {"name": "dirbuster", "description": "Web directory brute forcer", "category": "web", "commands": ["dirbuster"]},
            {"name": "feroxbuster", "description": "Fast content discovery tool", "category": "web", "commands": ["feroxbuster"]},
            {"name": "wfuzz", "description": "Web application fuzzer", "category": "web", "commands": ["wfuzz"]},
            
            # Parameter Discovery & Fuzzing
            {"name": "arjun", "description": "HTTP parameter discovery tool", "category": "web", "commands": ["arjun", "arjun.exe"]},
            {"name": "param-miner", "description": "Parameter mining tool", "category": "web", "commands": ["param-miner"]},
            
            # SQL Injection
            {"name": "sqlmap", "description": "Automatic SQL injection tool", "category": "web", "commands": ["sqlmap"]},
            
            # XSS Detection
            {"name": "dalfox", "description": "Fast XSS scanner", "category": "web", "commands": ["dalfox"]},
            {"name": "xsstrike", "description": "XSS detection suite", "category": "web", "commands": ["xsstrike"]},
            
            # Technology Detection
            {"name": "wappalyzer", "description": "Technology detection", "category": "recon", "commands": ["wappalyzer"]},
            {"name": "whatweb", "description": "Web technology identification", "category": "recon", "commands": ["whatweb"]},
            
            # Screenshot & Visual Recon
            {"name": "gowitness", "description": "Web screenshot utility", "category": "recon", "commands": ["gowitness"]},
            {"name": "aquatone", "description": "Domain flyover tool", "category": "recon", "commands": ["aquatone"]},
            {"name": "eyewitness", "description": "Website screenshot tool", "category": "recon", "commands": ["eyewitness"]},
            
            # JavaScript Analysis
            {"name": "linkfinder", "description": "Find endpoints in JS files", "category": "recon", "commands": ["linkfinder"]},
            {"name": "subjs", "description": "Find JavaScript files", "category": "recon", "commands": ["subjs"]},
            
            # SSRF & Testing
            {"name": "interactsh-client", "description": "OAST client", "category": "testing", "commands": ["interactsh-client"]},
            
            # Exploitation Frameworks
            {"name": "metasploit", "description": "Penetration testing framework", "category": "exploitation", "commands": ["msfconsole"]},
            {"name": "searchsploit", "description": "Exploit database search", "category": "exploitation", "commands": ["searchsploit"]},
            
            # Network Tools
            {"name": "netcat", "description": "Network utility", "category": "network", "commands": ["nc", "netcat"]},
            {"name": "socat", "description": "Multipurpose relay", "category": "network", "commands": ["socat"]},
            
            # Git Tools
            {"name": "git", "description": "Version control system", "category": "utility", "commands": ["git"]},
            {"name": "trufflehog", "description": "Find secrets in git repos", "category": "security", "commands": ["trufflehog"]},
            {"name": "gitleaks", "description": "Secret scanning tool", "category": "security", "commands": ["gitleaks"]},
            
            # Cloud Security
            {"name": "s3scanner", "description": "S3 bucket scanner", "category": "cloud", "commands": ["s3scanner"]},
            {"name": "cloudfail", "description": "Find origin servers", "category": "cloud", "commands": ["cloudfail"]},
            
            # Other Tools
            {"name": "curl", "description": "Transfer data with URLs", "category": "utility", "commands": ["curl"]},
            {"name": "wget", "description": "Network downloader", "category": "utility", "commands": ["wget"]},
            {"name": "jq", "description": "JSON processor", "category": "utility", "commands": ["jq"]},
            {"name": "python", "description": "Python interpreter", "category": "utility", "commands": ["python", "python3"]},
            {"name": "go", "description": "Go programming language", "category": "utility", "commands": ["go"]},
        ]

        for item in fallback_definitions:
            if item["name"] in definitions:
                continue
            # Include all commands from the definition
            all_commands = item.get("commands", [item["name"]])
            command_candidates = []
            for cmd in all_commands:
                if cmd and cmd not in command_candidates:
                    command_candidates.append(cmd)
            # Also include the name itself if not already included
            if item["name"] not in command_candidates:
                command_candidates.append(item["name"])

            definitions[item["name"]] = ToolDefinition(
                name=item["name"],
                description=item["description"],
                category=item["category"],
                command_candidates=command_candidates,
                metadata={"source": "fallback"},
            )

        return definitions

    def _extract_primary_command(self, template: Any, default: str) -> str:
        if isinstance(template, list) and template:
            return template[0]
        if isinstance(template, str) and template:
            return template.split()[0]
        return default

    def _collect_candidates(self, name: str, primary: str) -> List[str]:
        candidates = []
        for value in {name, primary}:
            if value and value not in candidates:
                candidates.append(value)
        return candidates

    def _extract_version_args(self, plugin: Any) -> List[str]:
        flag = getattr(plugin, "version_flag", None)
        if isinstance(flag, str) and flag.strip():
            return [flag.strip()]
        if isinstance(flag, (list, tuple)) and flag:
            return list(flag)
        return ["--version"]

    def _build_additional_search_paths(self) -> List[str]:
        paths: List[str] = []
        env_path = os.environ.get("PATH")
        if env_path:
            paths.extend(env_path.split(os.pathsep))

        home = Path.home()
        candidates = [
            Path("/usr/local/bin"),
            Path("/usr/bin"),
            Path("/bin"),
            Path("/opt"),
            home / ".local" / "bin",
            home / "go" / "bin",
            home / ".cargo" / "bin",
        ]

        if WINDOWS:
            program_files = Path(os.environ.get("PROGRAMFILES", r"C:\\Program Files"))
            program_files_x86 = Path(os.environ.get("PROGRAMFILES(X86)", r"C:\\Program Files (x86)"))
            candidates.extend(
                [
                    program_files / "Git" / "usr" / "bin",
                    program_files / "Git" / "bin",
                    program_files_x86 / "Git" / "usr" / "bin",
                    program_files_x86 / "Git" / "bin",
                    home / "scoop" / "shims",
                    home / "AppData" / "Local" / "Microsoft" / "WindowsApps",
                ]
            )

        candidates.extend(
            [
                Path("/usr/share/wordlists"),
                Path("/usr/share/seclists"),
            ]
        )

        for candidate in candidates:
            try:
                candidate = candidate.expanduser()
            except Exception:
                continue
            if str(candidate) not in paths and candidate.exists():
                paths.append(str(candidate))
        return paths

    def add_manual_tool(self, tool_name: str, tool_path: str, category: str = "custom") -> ToolRecord:
        """Manually add a tool with a custom path

        Args:
            tool_name: Name of the tool
            tool_path: Full path to the executable
            category: Category for the tool (default: "custom")

        Returns:
            ToolRecord for the added tool

        Raises:
            ToolDiscoveryError: If the path is invalid or tool can't be verified
        """
        import os
        import subprocess

        # Validate the path exists and is executable
        if not os.path.exists(tool_path):
            raise ToolDiscoveryError(f"Tool path does not exist: {tool_path}")

        if not os.access(tool_path, os.X_OK):
            raise ToolDiscoveryError(f"Tool path is not executable: {tool_path}")

        # Try to get version information
        version = None
        raw_version = None
        try:
            # Run the tool with --version or -V flag to verify it's the expected tool
            result = subprocess.run(
                [tool_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                raw_version = result.stdout.strip()
                version = self._normalize_version(result.stdout.strip())
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            # If --version fails, try -V
            try:
                result = subprocess.run(
                    [tool_path, "-V"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    raw_version = result.stdout.strip()
                    version = self._normalize_version(result.stdout.strip())
            except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
                # If version check fails, we'll still add it but without version info
                logger.warning(f"Could not determine version for manually added tool: {tool_name}")

        # Create a tool record for the manually added tool
        tool_record = ToolRecord(
            name=tool_name,
            description=f"Manually added tool: {tool_name}",
            category=category,
            status="available",
            installed=True,
            path=tool_path,
            version=version,
            raw_version=raw_version,
            last_checked=datetime.now(timezone.utc).isoformat(),
            last_seen=datetime.now(timezone.utc).isoformat()
        )

        # Update the cache to include this manually added tool
        self._update_tool_in_cache(tool_record)

        logger.info(f"Added manual tool: {tool_name} at {tool_path}")
        return tool_record

    def _update_tool_in_cache(self, tool_record: ToolRecord) -> None:
        """Update the cache to include a manually added tool"""
        try:
            # Load existing cache
            if self.cache_path.exists():
                with open(self.cache_path, 'r') as f:
                    cache_data = json.load(f)
            else:
                cache_data = {
                    'tools': {},
                    'last_refresh': None,
                    'manual_tools': []
                }

            # Add to cache
            cache_data['tools'][tool_record.name] = tool_record.to_dict()
            cache_data['manual_tools'] = cache_data.get('manual_tools', [])
            cache_data['manual_tools'].append(tool_record.name)

            # Save updated cache
            with open(self.cache_path, 'w') as f:
                json.dump(cache_data, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to update cache for manual tool {tool_record.name}: {e}")

    def list_manual_tools(self) -> List[str]:
        """Get list of manually added tools"""
        try:
            if self.cache_path.exists():
                with open(self.cache_path, 'r') as f:
                    cache_data = json.load(f)
                    return cache_data.get('manual_tools', [])
        except Exception as e:
            logger.error(f"Failed to load manual tools from cache: {e}")
            return []

    def remove_manual_tool(self, tool_name: str) -> bool:
        """Remove a manually added tool

        Args:
            tool_name: Name of the tool to remove

        Returns:
            True if successfully removed, False otherwise
        """
        try:
            if self.cache_path.exists():
                with open(self.cache_path, 'r') as f:
                    cache_data = json.load(f)

                # Check if it's a manual tool
                manual_tools = cache_data.get('manual_tools', [])
                if tool_name in manual_tools:
                    # Remove from tools dict
                    if tool_name in cache_data['tools']:
                        del cache_data['tools'][tool_name]

                    # Remove from manual tools list
                    cache_data['manual_tools'].remove(tool_name)

                    # Save updated cache
                    with open(self.cache_path, 'w') as f:
                        json.dump(cache_data, f, indent=2)

                    logger.info(f"Removed manual tool: {tool_name}")
                    return True

        except Exception as e:
            logger.error(f"Failed to remove manual tool {tool_name}: {e}")

        return False


def _create_service() -> ToolDiscoveryService:
    try:
        from backend.plugins.plugin_loader import plugin_loader
    except Exception:  # pragma: no cover - plugin loader optional during tests
        plugin_loader = None
    return ToolDiscoveryService(plugin_loader=plugin_loader)


tool_discovery_service = _create_service()

__all__ = ["ToolRecord", "ToolDefinition", "tool_discovery_service", "ToolDiscoveryService"]
