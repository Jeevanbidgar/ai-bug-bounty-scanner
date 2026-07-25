import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import type { AppCapabilities } from '../types/ui'

type EventHandler<T> = (payload: T) => void

export interface AppBridge {
  readonly capabilities: AppCapabilities
  invoke<T>(command: string, args?: Record<string, unknown>): Promise<T>
  listen<T>(event: string, handler: EventHandler<T>): Promise<UnlistenFn>
}

export const isTauriRuntime = () => {
  if (typeof window === 'undefined') return false
  if ('__TAURI_INTERNALS__' in window || '__TAURI__' in window) return true
  return window.location.protocol === 'tauri:' || window.location.hostname === 'tauri.localhost'
}

class TauriBridge implements AppBridge {
  readonly capabilities: AppCapabilities = {
    desktop: true,
    events: true,
    filesystem: true,
    mock: false,
  }

  invoke<T>(command: string, args: Record<string, unknown> = {}) {
    return invoke<T>(command, args)
  }

  listen<T>(event: string, handler: EventHandler<T>) {
    return listen<T>(event, ({ payload }) => handler(payload))
  }
}

const mockToolFixtures: Array<[string, string, string, boolean, string | null, string]> = [
  ['nmap', 'Network discovery and service enumeration', 'Network', true, '7.95', 'homebrew'],
  ['subfinder', 'Passive subdomain discovery', 'Reconnaissance', true, '2.6.8', 'go'],
  ['nuclei', 'Template-driven vulnerability detection', 'Vulnerability', true, '3.4.1', 'go'],
  ['httpx', 'HTTP service probing and metadata', 'Web', true, '1.7.1', 'go'],
  ['naabu', 'Fast port discovery', 'Network', false, null, 'homebrew'],
  ['ffuf', 'Web content discovery', 'Web', true, '2.1.0', 'homebrew'],
  ['rustscan', 'Fast adaptive port discovery', 'Network', true, '2.4.1', 'cargo'],
  ['masscan', 'High-speed network port scanner', 'Network', true, '1.3.2', 'homebrew'],
]

const mockTools = mockToolFixtures.map(([name, description, category, installed, version, installMethod]) => ({
  name,
  description,
  category,
  status: installed ? 'available' : 'missing',
  installed,
  command_template: [name],
  output_format: 'text',
  version,
  raw_version: version,
  path: installed ? `/usr/local/bin/${name}` : null,
  os_dependencies: [],
  missing_dependencies: [],
  last_checked: new Date().toISOString(),
  last_seen: installed ? new Date().toISOString() : null,
  last_error: null,
  install_method: installMethod,
  available_install_methods: installed ? [] : [installMethod, 'go'],
}))

const mockWorkflowDetails = [
  {
    id: 'quick-bug-bounty',
    name: 'Quick Bug Bounty',
    description: 'Fast passive discovery and focused vulnerability validation.',
    category: 'Web security',
    inputs: { target: 'Domain or URL' },
    steps: [
      { id: 'discover', name: 'Discover subdomains', description: 'Passive discovery with Subfinder', run: ['subfinder'], needs: [], timeout: 600 },
      { id: 'probe', name: 'Probe web services', description: 'Identify live HTTP services', run: ['httpx'], needs: ['discover'], timeout: 600 },
      { id: 'scan', name: 'Run Nuclei', description: 'Match verified vulnerability templates', run: ['nuclei'], needs: ['probe'], timeout: 1200 },
    ],
  },
  {
    id: 'network-recon',
    name: 'Network Recon',
    description: 'Port and service discovery for an authorized host or CIDR.',
    category: 'Network',
    inputs: { target: 'Host or CIDR' },
    steps: [
      { id: 'ports', name: 'Discover ports', description: 'Fast port discovery with Naabu', run: ['naabu'], needs: [], timeout: 900 },
      { id: 'services', name: 'Enumerate services', description: 'Nmap service detection', run: ['nmap'], needs: ['ports'], timeout: 1800 },
    ],
  },
  {
    id: 'passive-url-discovery',
    name: 'Passive URL Discovery',
    description: 'Collect historical URLs without active probing.',
    category: 'Passive',
    inputs: { target: 'Domain' },
    steps: [
      { id: 'gau', name: 'Collect URLs', description: 'Gather known URLs', run: ['gau'], needs: [], timeout: 600 },
      { id: 'archive', name: 'Query archives', description: 'Collect Wayback URLs', run: ['waybackurls'], needs: [], timeout: 600 },
    ],
  },
]

const mockWorkflows = mockWorkflowDetails.map((workflow) => ({
  ...workflow,
  steps_count: workflow.steps.length,
  compatibility: {
    compatible: workflow.id !== 'network-recon',
    required_tools: workflow.steps.map((step) => step.run[0]),
    available_tools: workflow.steps.map((step) => step.run[0]).filter((tool) => tool !== 'naabu'),
    missing_tools: workflow.id === 'network-recon' ? ['naabu'] : [],
    compatibility_percentage: workflow.id === 'network-recon' ? 50 : 100,
    warnings: [],
  },
}))

const mockAdapters = [
  ['Subfinder', 'subfinder', 'Passive subdomain discovery', 'recon', 'low', false, 300, ['text']],
  ['Amass', 'amass', 'Advanced subdomain discovery', 'recon', 'medium', true, 900, ['text']],
  ['Naabu', 'naabu', 'Fast network port discovery', 'network', 'high', true, 900, ['text']],
  ['Nmap', 'nmap', 'Network service enumeration', 'network', 'high', true, 1800, ['xml', 'text']],
  ['Nuclei', 'nuclei', 'Template-driven vulnerability detection', 'vulnerability', 'high', true, 1800, ['jsonl']],
  ['GAU', 'gau', 'Archived URL collection', 'url discovery', 'low', false, 600, ['text']],
  ['WaybackURLs', 'waybackurls', 'Wayback Machine URL collection', 'url discovery', 'low', false, 600, ['text']],
  ['HTTPX', 'httpx', 'HTTP service probing and metadata', 'http probe', 'medium', true, 600, ['jsonl']],
  ['FFUF', 'ffuf', 'Web content discovery with a managed wordlist', 'content discovery', 'high', true, 1800, ['json']],
  ['Gobuster', 'gobuster', 'Directory discovery with a managed wordlist', 'content discovery', 'high', true, 1800, ['text']],
  ['SQLMap', 'sqlmap', 'Conservative SQL injection detection', 'vulnerability', 'high', true, 2400, ['session directory']],
  ['Nikto', 'nikto', 'Web server exposure audit', 'web audit', 'high', true, 1800, ['json']],
  ['WPScan', 'wpscan', 'WordPress component and exposure assessment', 'cms audit', 'high', true, 1500, ['json']],
  ['Feroxbuster', 'feroxbuster', 'Recursive content discovery', 'content discovery', 'high', true, 1800, ['jsonl']],
  ['Dalfox', 'dalfox', 'Reflected and DOM XSS assessment', 'vulnerability', 'high', true, 1800, ['json']],
].map(([name, tool_name, description, category, risk_level, requires_authorization, timeout, expected_outputs], index) => ({
  name,
  tool_name,
  description,
  category,
  risk_level,
  requires_authorization,
  timeout,
  expected_outputs,
  origin: index < 7 ? 'specialized' : 'bundled_profile',
  status: 'ready',
  confidence: 1,
  generated_at: null,
  verified_version: null,
}))

mockAdapters.push(
  {
    name: 'Rustscan', tool_name: 'rustscan', description: 'Fast adaptive port discovery (adapter inferred from installed CLI help)', category: 'network', risk_level: 'high', requires_authorization: true, timeout: 1800, expected_outputs: ['text'],
    origin: 'auto_detected', status: 'ready', confidence: 0.85, generated_at: new Date().toISOString(), verified_version: '2.4.1',
  },
  {
    name: 'Masscan', tool_name: 'masscan', description: 'High-speed network port scanner (adapter inferred from installed CLI help)', category: 'network', risk_level: 'high', requires_authorization: true, timeout: 1800, expected_outputs: ['text'],
    origin: 'auto_detected', status: 'review_required', confidence: 0.55, generated_at: new Date().toISOString(), verified_version: '1.3.2',
  },
)

const mockScans = [
  {
    id: 'scan-demo-running', name: 'Acme perimeter review', target: 'example.com', status: 'running', scan_type: 'Web security', workflow_id: 'quick-bug-bounty',
    started: new Date(Date.now() - 480_000).toISOString(), progress: 62, current_test: 'nuclei', current_step: 'scan', total_steps: 3,
    target_validated: true, vulnerabilities: 3, critical: 0, high: 1, medium: 2, low: 0,
    created_at: new Date(Date.now() - 500_000).toISOString(), updated_at: new Date().toISOString(),
  },
  {
    id: 'scan-demo-complete', name: 'API evidence sweep', target: 'api.example.com', status: 'completed', scan_type: 'API', workflow_id: 'api-security-scan',
    started: new Date(Date.now() - 86_400_000).toISOString(), completed: new Date(Date.now() - 85_200_000).toISOString(), progress: 100,
    target_validated: true, vulnerabilities: 7, critical: 0, high: 2, medium: 3, low: 2,
    created_at: new Date(Date.now() - 86_400_000).toISOString(), updated_at: new Date(Date.now() - 85_200_000).toISOString(),
  },
]

class MockBridge implements AppBridge {
  readonly capabilities: AppCapabilities = {
    desktop: false,
    events: false,
    filesystem: false,
    mock: true,
  }

  private settings = {
    maxParallelSteps: 4,
    defaultStepTimeoutSeconds: 1800,
    maxOutputLinesPerStream: 5000,
  }

  private tools = mockTools.map((tool) => ({ ...tool, available_install_methods: [...tool.available_install_methods] }))
  private scans: Array<Record<string, any>> = mockScans.map((scan) => ({ ...scan }))
  private reports: Array<Record<string, any>> = []
  private manualTools: string[] = []
  private engagementScopes: Array<Record<string, any>> = [
    {
      id: 'scope-preview-authorized',
      revision: 1,
      name: 'Preview authorized assessment',
      principalId: 'local-owner-automation',
      targets: [
        { original: 'example.com', canonical: 'example.com', kind: 'hostname' },
        { original: 'https://api.example.com/v1', canonical: 'https://api.example.com/v1', kind: 'url' },
      ],
      workflowIds: ['discovery-only', 'quick-bug-bounty'],
      allowedRiskTier: 'active',
      startsAt: new Date(Date.now() - 60_000).toISOString(),
      expiresAt: new Date(Date.now() + 28_800_000).toISOString(),
      budget: { maxExecutions: 25, maxConcurrentProcesses: 4, maxRuntimeSeconds: 14_400, maxOutputBytes: 500_000_000 },
      createdAt: new Date(Date.now() - 60_000).toISOString(),
      revokedAt: null,
    },
  ]
  private mcpAuditActivity: Array<Record<string, any>> = [
    {
      id: 'audit-preview-status',
      principalId: 'local-owner-automation',
      capability: 'read_status',
      requestId: 'preview-request',
      scopeId: null,
      sanitizedArguments: {},
      outcome: 'success',
      correlationId: null,
      previousHash: null,
      eventHash: 'f0d578b54d6f6e02a16a57b911e53f86f218e576afba76f96fc8494d5b9ed287',
      createdAt: new Date(Date.now() - 30_000).toISOString(),
    },
  ]

  async invoke<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
    const fixtures: Record<string, unknown> = {
      get_system_info: { os: 'macOS', arch: 'aarch64', total_memory_mb: 16384, available_memory_mb: 11264, cpu_cores: 10, process_memory_mb: 186, process_cpu_percent: 1.8 },
      get_os_info: { os: 'macOS', arch: 'aarch64' },
      get_stats: { total_scans: 2, active_scans: 1, total_vulnerabilities: 10, critical_issues: 0, tools_available: 5, system_health: 'healthy' },
      get_system_metrics: { total_scans: 2, active_scans: 1, completed_scans: 1, total_vulnerabilities: 10, critical_issues: 0, tools_available: 5, tools_total: 6, tools_unavailable: 1, system_health: 'healthy', health_details: { scan_capacity: 'available', tool_availability: 'good', database: 'healthy' } },
      list_tools: this.tools,
      refresh_tools: Object.fromEntries(this.tools.map((tool) => [tool.name, tool])),
      get_tool_categories: [...new Set(this.tools.map((tool) => tool.category))],
      load_workflow_templates: mockWorkflows,
      list_vulnerabilities: [],
      list_adapters: mockAdapters,
      get_adapter_categories: [...new Set(mockAdapters.map((adapter) => adapter.category))],
      detect_package_managers: [
        { manager_type: 'homebrew', available: true, version: '4.6.0', path: '/opt/homebrew/bin/brew', error: null },
        { manager_type: 'go', available: true, version: '1.25.0', path: '/opt/homebrew/bin/go', error: null },
        { manager_type: 'cargo', available: true, version: '1.91.0', path: '/Users/researcher/.cargo/bin/cargo', error: null },
        { manager_type: 'pipx', available: false, version: null, path: null, error: null },
      ],
      get_settings: this.settings,
      get_mcp_integration_info: {
        transport: 'stdio',
        serverName: 'unihack',
        binaryPath: '/Applications/UniHack.app/Contents/MacOS/unihack-mcp',
        binaryAvailable: true,
        providerApiKeyRequired: false,
        codex: { installed: true, executablePath: '/opt/homebrew/bin/codex', configured: true },
        claudeCode: { installed: true, executablePath: '/opt/homebrew/bin/claude', configured: false },
        codexAddCommand: 'codex mcp add unihack -- /Applications/UniHack.app/Contents/MacOS/unihack-mcp',
        claudeAddCommand: 'claude mcp add --transport stdio --scope user unihack -- /Applications/UniHack.app/Contents/MacOS/unihack-mcp',
        codexToml: '[mcp_servers.unihack]\ncommand = "/Applications/UniHack.app/Contents/MacOS/unihack-mcp"\nargs = []',
        claudeJson: '{\n  "mcpServers": {\n    "unihack": {\n      "type": "stdio",\n      "command": "/Applications/UniHack.app/Contents/MacOS/unihack-mcp",\n      "args": [],\n      "env": {}\n    }\n  }\n}',
        restartNote: 'Start a fresh Codex task or Claude Code session after changing MCP configuration so the host can discover the UniHack tools.',
      },
    }

    if (command === 'list_scans') return this.scans.map((scan) => ({ ...scan })) as T
    if (command === 'list_reports') return this.reports.map((report) => ({ ...report })) as T
    if (command === 'list_manual_tools') return [...this.manualTools] as T
    if (command === 'list_engagement_scopes') return this.engagementScopes.map((scope) => ({ ...scope })) as T
    if (command === 'list_mcp_audit_activity') return this.mcpAuditActivity.map((event) => ({ ...event })) as T

    if (command === 'get_workflow_details') {
      const workflow = mockWorkflowDetails.find((candidate) => candidate.id === args.workflowId)
      if (!workflow) throw new Error(`Workflow '${String(args.workflowId)}' was not found`)
      const summary = mockWorkflows.find((candidate) => candidate.id === workflow.id)
      return { ...workflow, compatibility: summary?.compatibility } as T
    }
    if (command === 'get_tool') {
      return (this.tools.find((tool) => tool.name === args.toolName) ?? null) as T
    }
    if (command === 'get_tool_version') {
      const tool = this.tools.find((candidate) => candidate.name === args.toolName)
      return (tool?.version ?? null) as T
    }
    if (command === 'get_tool_installation_info') {
      const tool = this.tools.find((candidate) => candidate.name === args.toolName) ?? this.tools[0]
      const automatedMethods = tool.available_install_methods.length > 0
        ? tool.available_install_methods.filter((method) => method !== 'manual' && method !== 'runtime')
        : tool.install_method
          ? [tool.install_method]
          : []
      return {
        name: tool.name,
        platform: 'macOS',
        install_method: tool.install_method,
        recommended_install_method: tool.install_method,
        available_install_methods: automatedMethods,
        automated_install_methods: automatedMethods,
        go_module: null,
        pipx_package: null,
        apt_package: null,
        winget_id: null,
        description: tool.description,
        category: tool.category,
      } as T
    }
    if (command === 'check_tool_update') {
      const tool = this.tools.find((candidate) => candidate.name === args.toolName)
      return {
        has_update: false,
        current_version: tool?.version ?? null,
        latest_version: tool?.version ?? null,
        package_manager: tool?.install_method ?? 'unknown',
        error: null,
      } as T
    }
    if (command === 'get_tools_by_category') {
      return this.tools.filter((tool) => tool.category === args.category) as T
    }
    if (command === 'build_tool_command_with_defaults') {
      const target = String(args.target ?? 'example.com')
      const toolName = String(args.toolName ?? 'nmap')
      const adapter = mockAdapters.find((candidate) => candidate.tool_name === toolName)
      if (adapter?.status === 'review_required') {
        throw new Error(`Auto-adapter for '${toolName}' requires review before command previews are enabled`)
      }
      const url = target.startsWith('http') ? target : `https://${target}`
      const commands: Record<string, string[]> = {
        subfinder: ['subfinder', '-d', target, '-silent'],
        nmap: ['nmap', target, '-sV'],
        nuclei: ['nuclei', '-u', url, '-jsonl'],
        httpx: ['httpx', '-u', url, '-silent', '-json', '-status-code', '-title', '-tech-detect'],
        ffuf: ['ffuf', '-u', `${url.replace(/\/$/, '')}/FUZZ`, '-w', '<unihack-managed-web-wordlist>', '-of', 'json'],
        wpscan: ['wpscan', '--url', url, '--format', 'json', '--no-banner'],
        dalfox: ['dalfox', 'scan', url, '--format', 'json', '--no-color'],
        rustscan: ['rustscan', '--addresses', target],
      }
      return { argv: commands[toolName] ?? [toolName, target], stdin: null } as T
    }
    if (command === 'get_available_tools_count') return 5 as T
    if (command === 'update_settings') {
      this.settings = args.settings as typeof this.settings
      return this.settings as T
    }
    if (command === 'configure_mcp_client') {
      const client = String(args.client)
      return {
        client,
        configured: true,
        alreadyConfigured: false,
        message: `Preview configured ${client === 'codex' ? 'Codex CLI' : 'Claude Code'} for local STDIO MCP.`,
      } as T
    }
    if (command === 'create_engagement_scope') {
      const request = args.request as Record<string, any>
      const now = new Date()
      const scope = {
        id: `scope-preview-${Date.now()}`,
        revision: 1,
        name: String(request.name),
        principalId: 'local-owner-automation',
        targets: (request.targets as string[]).map((target) => ({
          original: target,
          canonical: target.toLowerCase(),
          kind: target.includes('://') ? 'url' : target.includes('/') ? 'cidr' : /^\d+\.\d+\.\d+\.\d+$/.test(target) ? 'ip' : 'hostname',
        })),
        workflowIds: request.workflowIds ?? [],
        allowedRiskTier: request.allowedRiskTier,
        startsAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + Number(request.durationMinutes) * 60_000).toISOString(),
        budget: request.budget,
        createdAt: now.toISOString(),
        revokedAt: null,
      }
      this.engagementScopes.unshift(scope)
      this.mcpAuditActivity.unshift({
        id: `audit-preview-${Date.now()}`,
        principalId: 'local-owner-automation',
        capability: 'manage_engagements',
        requestId: `preview-${Date.now()}`,
        scopeId: scope.id,
        sanitizedArguments: { action: 'create' },
        outcome: 'success',
        correlationId: null,
        previousHash: this.mcpAuditActivity[0]?.eventHash ?? null,
        eventHash: '6a40c4ed30cba3c23cf531b87917f95e82d70d4b07943a12a3c12329bb86d80e',
        createdAt: now.toISOString(),
      })
      return scope as T
    }
    if (command === 'revoke_engagement_scope') {
      const scope = this.engagementScopes.find((candidate) => candidate.id === args.scopeId)
      if (!scope) throw new Error(`Engagement '${String(args.scopeId)}' was not found`)
      scope.revokedAt = new Date().toISOString()
      scope.revision += 1
      return { ...scope } as T
    }
    if (command === 'execute_workflow') {
      const request = args.request as Record<string, any>
      const scanId = `mock-scan-${Date.now()}`
      const target = String((request.inputs as Record<string, unknown>)?.target ?? 'example.com')
      this.scans.unshift({
        id: scanId,
        name: request.scanName || mockWorkflows.find((workflow) => workflow.id === request.workflowId)?.name || 'Mock workflow',
        target,
        status: 'running',
        scan_type: 'Preview',
        workflow_id: request.workflowId,
        started: new Date().toISOString(),
        progress: 5,
        current_test: 'preview runner',
        target_validated: true,
        vulnerabilities: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        description: request.description,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      })
      return { execution_id: `mock-execution-${Date.now()}`, scan_id: scanId, status: 'running', message: 'Mock workflow started' } as T
    }
    if (command === 'create_scan') return mockScans[0] as T
    if (command === 'get_scan') return (this.scans.find((scan) => scan.id === args.scanId) ?? null) as T
    if (command === 'get_workflow_status') {
      const scan = this.scans.find((candidate) => candidate.id === args.executionId)
      if (!scan) throw new Error(`Execution or scan '${String(args.executionId)}' not found`)
      return {
        execution_id: `mock-execution-${scan.id}`,
        status: scan.status,
        progress: scan.progress ?? 0,
        current_step: scan.current_step ?? scan.current_test ?? null,
        logs: scan.status === 'completed'
          ? ['[STEP COMPLETED] Evidence collection', '[EXECUTION COMPLETED]']
          : [`[STEP RUNNING] ${scan.current_test ?? 'Preparing workflow'}`],
      } as T
    }
    if (command === 'start_scan') {
      const scan = this.scans.find((candidate) => candidate.id === args.scanId)
      if (!scan) throw new Error(`Scan '${String(args.scanId)}' was not found`)
      scan.status = 'running'
      scan.started = new Date().toISOString()
      scan.updated_at = new Date().toISOString()
      return { scan_id: scan.id, execution_id: `mock-execution-${Date.now()}`, status: 'running', message: 'Mock scan started' } as T
    }
    if (command === 'stop_scan' || command === 'stop_workflow_execution') {
      const scan = this.scans.find((candidate) => candidate.id === args.scanId)
      if (scan) {
        scan.status = 'cancelled'
        scan.updated_at = new Date().toISOString()
      }
      return true as T
    }
    if (command === 'delete_scan') {
      this.scans = this.scans.filter((scan) => scan.id !== args.scanId)
      return true as T
    }
    if (command === 'get_scan_vulnerabilities' || command === 'get_workflow_artifacts' || command === 'get_workflow_findings') return [] as T
    if (command === 'reveal_scan_results' || command === 'reveal_workflow_artifact' || command === 'reveal_report') return undefined as T
    if (command === 'create_report') {
      const reportData = args.reportData as Record<string, any>
      const scan = this.scans.find((candidate) => candidate.id === reportData.scan_id)
      if (!scan) throw new Error('Select an existing scan before generating a report')
      const report = {
        id: `mock-report-${Date.now()}`,
        scanId: scan.id,
        title: reportData.title || `${scan.name || scan.target} report`,
        createdAt: new Date().toISOString(),
        target: scan.target,
        vulnerabilityCount: scan.vulnerabilities ?? 0,
        format: reportData.format,
        severity: (scan.vulnerabilities ?? 0) > 0 ? 'high' : 'none',
        filePath: `/mock/reports/${scan.id}.${reportData.format}`,
        sizeBytes: 2048,
        sha256: '8db9f7f6a1b4df8e19f6f72369dc04d0a80fa32abfd15ab5d9f563c7bf1d4e83',
        content: `UniHack preview report\nTarget: ${scan.target}\nFindings: ${scan.vulnerabilities ?? 0}`,
      }
      this.reports.unshift(report)
      return report as T
    }
    if (command === 'get_report') return (this.reports.find((report) => report.id === args.reportId) ?? null) as T
    if (command === 'delete_report') {
      this.reports = this.reports.filter((report) => report.id !== args.reportId)
      return true as T
    }
    if (command === 'test_tool') {
      const tool = this.tools.find((candidate) => candidate.name === args.toolName)
      if (!tool?.installed) throw new Error(`${String(args.toolName)} is not installed`)
      return { toolName: tool.name, success: true, path: tool.path, output: `${tool.name} preview health check passed`, exitCode: 0, durationMs: 12 } as T
    }
    if (command === 'recheck_tool') {
      const tool = this.tools.find((candidate) => candidate.name === args.toolName)
      if (!tool) throw new Error(`Tool '${String(args.toolName)}' was not found`)
      return { ...tool } as T
    }
    if (command === 'add_manual_tool') {
      const name = String(args.toolName)
      if (!this.manualTools.includes(name)) this.manualTools.push(name)
      const tool = {
        name,
        description: 'Manually registered local tool',
        category: String(args.category),
        status: 'available',
        installed: true,
        command_template: [name],
        output_format: 'text',
        version: null,
        raw_version: null,
        path: String(args.toolPath),
        os_dependencies: [],
        missing_dependencies: [],
        last_checked: new Date().toISOString(),
        last_seen: new Date().toISOString(),
        last_error: null,
        install_method: 'manual',
        available_install_methods: [],
      }
      this.tools.push(tool)
      return tool as T
    }
    if (command === 'remove_manual_tool') {
      const name = String(args.toolName)
      this.manualTools = this.manualTools.filter((toolName) => toolName !== name)
      this.tools = this.tools.filter((tool) => tool.name !== name || tool.install_method !== 'manual')
      return true as T
    }
    if (command === 'install_tool' || command === 'install_tool_with_method' || command === 'update_tool') {
      return { success: true, message: `Preview completed for ${String(args.toolName)}`, steps: [], requires_restart: false } as T
    }
    if (command === 'uninstall_tool') return `Preview uninstalled ${String(args.toolName)}` as T
    if (command in fixtures) return fixtures[command] as T

    throw new Error(`Mock bridge has no fixture for '${command}'`)
  }

  async listen<T>(_event: string, _handler: EventHandler<T>): Promise<UnlistenFn> {
    return () => undefined
  }
}

export const appBridge: AppBridge = isTauriRuntime() ? new TauriBridge() : new MockBridge()
