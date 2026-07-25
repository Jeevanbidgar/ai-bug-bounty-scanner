/**
 * API service for Tauri commands to the Rust backend
 */

import { appBridge } from '../bridge/appBridge'

export interface ApiResponse<T = any> {
  data?: T
  error?: string
  message?: string
}

export interface Scan {
  id: string
  name: string
  target: string
  status: string
  scan_type: string
  workflow_id?: string
  started: string
  completed?: string
  progress: number
  current_test?: string
  current_step?: string
  total_steps?: number
  duration?: string
  estimated_time?: string
  description?: string
  tags?: string
  working_directory?: string
  agents?: string
  command_log?: string
  target_validated: boolean
  vulnerabilities?: number
  critical?: number
  high?: number
  medium?: number
  low?: number
  created_at: string
  updated_at: string
}

export interface Tool {
  name: string
  description: string
  category: string
  status: string // "available", "missing", "degraded", "error"
  installed: boolean
  command_template: string[]
  output_format: string
  version: string | null
  raw_version: string | null
  path: string | null
  os_dependencies: string[]
  missing_dependencies: string[]
  last_checked: string | null
  last_seen: string | null
  last_error: string | null
  install_method?: string // Primary installation method
  alternative_install_methods?: string[] // Alternative methods (e.g., ["pipx", "git-pip"])
  available_install_methods: string[]
}

export interface ToolInstallationInfo {
  name: string
  platform: string
  install_method: string | null
  recommended_install_method: string | null
  available_install_methods: string[]
  automated_install_methods: string[]
  go_module: string | null
  pipx_package: string | null
  apt_package: string | null
  winget_id: string | null
  description: string
  category: string
}

export interface ToolTestResult {
  toolName: string
  success: boolean
  path: string
  output: string
  exitCode: number | null
  durationMs: number
}

export interface Report {
  id: string
  scanId: string
  title: string
  createdAt: string
  target: string
  vulnerabilityCount: number
  format: string
  severity: string
  filePath?: string
  sizeBytes?: number
  sha256?: string
  content?: string
}

export interface AppSettings {
  maxParallelSteps: number
  defaultStepTimeoutSeconds: number
  maxOutputLinesPerStream: number
}

export interface SystemInfo {
  os: string
  arch: string
  total_memory_mb: number
  available_memory_mb: number
  cpu_cores: number
  process_memory_mb: number
  process_cpu_percent: number
}

export interface SystemStats {
  total_scans: number
  active_scans: number
  total_vulnerabilities: number
  critical_issues: number
  tools_available: number
  system_health: string
}

export interface WorkflowCompatibility {
  compatible: boolean
  required_tools: string[]
  available_tools: string[]
  missing_tools: string[]
  compatibility_percentage: number
  warnings?: string[]
}

export interface WorkflowTemplate {
  id: string
  name: string
  description: string
  category: string
  steps_count: number
  inputs: Record<string, string>
  steps?: WorkflowStep[]
  compatibility?: WorkflowCompatibility
}

export interface WorkflowStep {
  id: string
  name: string
  description: string
  needs?: string[]
  run: string[]
  stdin?: string
  timeout?: number
  success_exit_codes?: number[]
  env?: Record<string, string>
  working_directory?: string
  outputs?: WorkflowOutput[]
}

export interface WorkflowOutput {
  name: string
  type: string
  path: string
  description?: string
}

export interface WorkflowArtifact {
  id: string
  execution_id: string
  step_id: string
  name: string
  artifact_type: string
  file_path?: string
  content?: string
  metadata_?: string  // JSON string containing line_count, is_text, etc.
  size?: number       // File size in bytes (enriched by ArtifactManager)
  hash?: string       // SHA256 hash (enriched by ArtifactManager)
  created_at: string
}

export interface WorkflowExecution {
  id: string
  workflow_id: string
  workflow_name: string
  status: string
  started_at: string
  completed_at?: string
  inputs: Record<string, string>
  current_step?: string
  steps: Record<string, StepExecution>
  artifacts: Record<string, string>
  error_message?: string
}

export interface WorkflowStatus {
  execution_id: string
  status: string
  progress: number
  current_step?: string
  logs: string[]
}

export interface StepExecution {
  step_id: string
  status: string
  started_at?: string
  completed_at?: string
  exit_code?: number
  stdout: string
  stderr: string
  error_message?: string
  artifacts: string[]
  attempts: number
}

// Adapter Interfaces
export interface AdapterInfo {
  name: string
  tool_name: string
  description: string
  category: string
  risk_level: string
  requires_authorization: boolean
  timeout: number
  expected_outputs: string[]
  origin: 'specialized' | 'bundled_profile' | 'auto_detected'
  status: 'ready' | 'review_required'
  confidence: number
  generated_at?: string | null
  verified_version?: string | null
}

export interface CommandPreview {
  argv: string[]
  stdin?: string | null
}

export interface SubfinderConfig {
  target: string
  output_file?: string | null
  recursive?: boolean
  all_sources?: boolean
  silent?: boolean
  sources?: string[]
}

export interface AmassConfig {
  target: string
  output_file?: string | null
  passive?: boolean
  brute?: boolean
  active?: boolean
}

export interface NaabuConfig {
  target: string
  output_file?: string | null
  ports?: string | null
  rate?: number | null
  passive?: boolean
  verbose?: boolean
}

export interface NmapConfig {
  target: string
  output_file?: string | null
  service_scan?: boolean
  script_scan?: boolean
  os_detection?: boolean
  aggressive?: boolean
  fast?: boolean
}

export interface NucleiConfig {
  target: string
  output_file?: string | null
  severity?: string[]
  templates?: string[]
  exclude_templates?: string[]
}

export interface GAUConfig {
  target: string
  output_file?: string | null
  threads?: number | null
}

export interface WaybackURLsConfig {
  target: string
  output_file?: string | null
}

// Package Manager Interfaces
export interface PackageManagerInfo {
  manager_type: 'go' | 'pipx' | 'apt' | 'winget' | 'cargo' | 'npm' | 'gem' | 'homebrew'
  available: boolean
  version: string | null
  path: string | null
  error: string | null
}

export interface InstallationResult {
  success: boolean
  message: string
  steps: string[]
  requires_restart: boolean
}

export interface ElevationMethod {
  Sudo?: null
  RunAs?: null
  Pkexec?: null
  None?: null
}

export interface VersionCheckResult {
  has_update: boolean
  current_version: string | null
  latest_version: string | null
  package_manager: string
  error: string | null
}

// Enhanced update check result with additional metadata
export interface EnhancedVersionCheckResult {
  has_update: boolean
  current_version: string | null
  latest_version: string | null
  package_manager: string
  error: string | null
  error_code?: string
  source?: string
  update_type?: 'patch' | 'minor' | 'major' | 'prerelease' | 'unknown'
  diagnostic?: string
  checked_at?: string
  duration?: number
}

// Coordinated update result from multiple managers
export interface CoordinatedUpdateResult {
  package: string
  results: Record<string, EnhancedVersionCheckResult>
  best_result?: EnhancedVersionCheckResult
  has_update: boolean
  duration: number
  managers_checked: number
}

// Event Payloads
export interface ToolInstallationEvent {
  tool_name: string
  installation_method: string
  timestamp: string
}

export interface ToolInstallationCompleteEvent {
  tool_name: string
  success: boolean
  message: string
  timestamp: string
}

export interface ScanEvent {
  scan_id: string
  timestamp: string
}

export interface ScanProgressEvent {
  scan_id: string
  progress: number
  current_test: string | null
  status: string
  timestamp: string
}

export interface WorkflowStdoutEvent {
  execution_id: string
  step_id: string
  line: string
  timestamp: string
}

export interface WorkflowStderrEvent {
  execution_id: string
  step_id: string
  line: string
  timestamp: string
  threads?: number | null
}

export type AdapterConfig =
  | { type: 'Subfinder'; config: SubfinderConfig }
  | { type: 'Amass'; config: AmassConfig }
  | { type: 'Naabu'; config: NaabuConfig }
  | { type: 'Nmap'; config: NmapConfig }
  | { type: 'Nuclei'; config: NucleiConfig }
  | { type: 'GAU'; config: GAUConfig }
  | { type: 'WaybackURLs'; config: WaybackURLsConfig }

class ApiService {
  private async invokeCommand<T>(command: string, args: any = {}): Promise<T> {
    try {
      return await appBridge.invoke<T>(command, args)
    } catch (error) {
      // Only log errors that aren't expected/handled
      const errorMsg = String(error)
      const isExpectedError = errorMsg.includes('not supported') ||
        errorMsg.includes('is not installed') ||
        errorMsg.includes('not found')

      if (!isExpectedError) {
        console.error(`❌ Tauri command failed: ${command}`, error)
      }

      // Re-throw the error with better context
      throw new Error(`Failed to execute command '${command}': ${error}`)
    }
  }

  // Health endpoints - using Tauri commands
  async getHealth() {
    return { data: { status: 'healthy', backend: 'rust' } }
  }

  async getDetailedHealth() {
    try {
      // Get system stats from Tauri commands
      const stats = await this.invokeCommand<SystemStats>('get_stats')
      return { data: stats }
    } catch (error) {
      console.error('Failed to get detailed health:', error)
      // Fallback to computing stats manually
      try {
        const scans = await this.invokeCommand('list_scans')
        const toolsCount = await this.getAvailableToolsCount()

        const stats: SystemStats = {
          total_scans: Array.isArray(scans) ? scans.length : 0,
          active_scans: Array.isArray(scans) ? scans.filter((s: any) => s.status === 'running').length : 0,
          total_vulnerabilities: 0,
          critical_issues: 0,
          tools_available: toolsCount.data,
          system_health: 'healthy'
        }

        return { data: stats }
      } catch (fallbackError) {
        console.error('Failed to get stats:', fallbackError)
        return { error: 'Failed to get system health' }
      }
    }
  }

  // Scan endpoints - using Tauri commands
  async getScans() {
    const scans = await this.invokeCommand<Scan[]>('list_scans')
    return { data: Array.isArray(scans) ? scans : [] }
  }

  async getScan(scanId: string) {
    const scan = await this.invokeCommand('get_scan', { scanId })
    return { data: scan }
  }

  async createScan(scanData: {
    target: string
    scan_type?: string
    agents?: string[]
  }) {
    try {
      const scan = await this.invokeCommand('create_scan', { scanData })
      return { data: scan }
    } catch (error) {
      console.error('Failed to create scan:', error)
      throw error
    }
  }

  async runQuickScan(target: string) {
    try {
      const scan = await this.invokeCommand('create_scan', {
        scanData: { target, scan_type: 'Quick Scan' }
      })
      return { data: scan }
    } catch (error) {
      console.error('Failed to run quick scan:', error)
      throw error
    }
  }

  async startScan(scanId: string, authorizationConfirmed: boolean) {
    const result = await this.invokeCommand('start_scan', { scanId, authorizationConfirmed })
    return { data: result }
  }

  async deleteScan(scanId: string) {
    try {
      const result = await this.invokeCommand('delete_scan', { scanId })
      return { data: result }
    } catch (error) {
      console.error('Failed to delete scan:', error)
      throw error
    }
  }

  async getScanVulnerabilities(scanId: string) {
    try {
      const vulns = await this.invokeCommand('get_scan_vulnerabilities', { scanId })
      return vulns
    } catch (error) {
      console.error('Failed to get scan vulnerabilities:', error)
      return []
    }
  }

  async getScanReports(_scanId: string) {
    // For now, return empty array - reports will be handled by workflow findings
    return []
  }

  // Tool endpoints - using Tauri commands with enhanced tool discovery
  async getTools(forceRefresh = false): Promise<{ data: Tool[] }> {
    const tools = await this.invokeCommand('list_tools', { forceRefresh })
    return { data: Array.isArray(tools) ? tools : [] }
  }

  async getTool(toolName: string, forceRefresh = false): Promise<{ data: Tool | null }> {
    const tool = await this.invokeCommand('get_tool', {
      toolName,
      forceRefresh
    }) as Tool | null
    return { data: tool }
  }

  async checkToolAvailability(toolName: string): Promise<{ available: boolean }> {
    const tool = await this.invokeCommand('get_tool', {
      toolName,
      forceRefresh: false
    }) as Tool | null
    return { available: tool?.installed || false }
  }

  async refreshToolsStatus(): Promise<{ data: Record<string, Tool>; success: boolean }> {
    const result = await this.invokeCommand('refresh_tools') as Record<string, Tool>
    return { data: result, success: true }
  }

  async getToolCategories(): Promise<{ data: string[] }> {
    const categories = await this.invokeCommand('get_tool_categories')
    return { data: Array.isArray(categories) ? categories : [] }
  }

  async getToolsByCategory(category: string): Promise<{ data: Tool[] }> {
    const tools = await this.invokeCommand('get_tools_by_category', { category })
    return { data: Array.isArray(tools) ? tools : [] }
  }

  async addManualTool(data: { tool_name: string; tool_path: string; category: string }): Promise<{ data: Tool; success: boolean; message: string }> {
    try {
      const tool = await this.invokeCommand('add_manual_tool', {
        toolName: data.tool_name,
        toolPath: data.tool_path,
        category: data.category
      }) as Tool
      return { data: tool, success: true, message: 'Tool added successfully' }
    } catch (error) {
      console.error('Failed to add manual tool:', error)
      throw error
    }
  }

  async removeManualTool(toolName: string): Promise<{ success: boolean; message: string }> {
    try {
      const result = await this.invokeCommand('remove_manual_tool', { toolName }) as boolean
      return { success: result, message: result ? 'Tool removed successfully' : 'Tool not found' }
    } catch (error) {
      console.error('Failed to remove manual tool:', error)
      throw error
    }
  }

  async getManualTools(): Promise<{ data: { manual_tools: string[] } }> {
    const manualTools = await this.invokeCommand('list_manual_tools')
    return { data: { manual_tools: Array.isArray(manualTools) ? manualTools : [] } }
  }

  async getAvailableToolsCount(): Promise<{ data: number }> {
    try {
      const count = await this.invokeCommand('get_available_tools_count')
      return { data: typeof count === 'number' ? count : 0 }
    } catch (error) {
      console.error('Failed to get available tools count:', error)
      return { data: 0 }
    }
  }

  // Report endpoints - using Tauri commands
  async getReports(_params?: {
    skip?: number
    limit?: number
    scan_id?: string
  }) {
    const reports = await this.invokeCommand<Report[]>('list_reports')
    return Array.isArray(reports) ? reports : []
  }

  async getReport(reportId: string) {
    return this.invokeCommand<Report | null>('get_report', { reportId })
  }

  async createReport(reportData: {
    scanId: string
    title?: string
    format: string
  }) {
    try {
      return await this.invokeCommand<Report>('create_report', {
        reportData: {
          scan_id: reportData.scanId,
          title: reportData.title,
          format: reportData.format
        }
      })
    } catch (error) {
      console.error('Failed to create report:', error)
      throw error
    }
  }

  async downloadReport(_reportId: string) {
    // For now, throw error - download functionality needs to be implemented
    throw new Error('Download report not yet implemented in Rust backend')
  }

  async deleteReport(reportId: string) {
    try {
      await this.invokeCommand('delete_report', { reportId })
      return { success: true, message: 'Report deleted' }
    } catch (error) {
      console.error('Failed to delete report:', error)
      throw error
    }
  }

  async getSettings(): Promise<AppSettings> {
    return this.invokeCommand<AppSettings>('get_settings')
  }

  async updateSettings(settings: AppSettings): Promise<AppSettings> {
    return this.invokeCommand<AppSettings>('update_settings', { settings })
  }

  async getSystemInfo(): Promise<SystemInfo> {
    return this.invokeCommand<SystemInfo>('get_system_info')
  }

  // Recon endpoints - using Tauri commands
  async getReconPlans() {
    // For now, return empty array - recon will be handled by workflows
    return []
  }

  async getReconPlan(_planId: string) {
    // For now, return null - recon will be handled by workflows
    return null
  }

  async getReconTemplates() {
    // For now, return empty array - recon will be handled by workflows
    return []
  }

  async generateReconPlan(_target: string, _template: string = 'auto') {
    // For now, return success - recon will be handled by workflows
    return { success: true, message: 'Recon plan generated' }
  }

  async executeReconPlan(_planId: string, _target: string) {
    // For now, return success - recon will be handled by workflows
    return { success: true, message: 'Recon plan executed' }
  }

  // Workflow endpoints - using Tauri commands
  async getWorkflowTemplates(_checkCompatibility: boolean = true) {
    const templates = await this.invokeCommand<WorkflowTemplate[]>('load_workflow_templates')
    return { data: Array.isArray(templates) ? templates : [] }
  }

  async getWorkflowDetails(workflowId: string) {
    try {
      const details = await this.invokeCommand('get_workflow_details', { workflowId })
      return { data: details }
    } catch (error) {
      console.error('Failed to get workflow details:', error)
      throw error
    }
  }

  async executeWorkflow(
    workflowTemplateId: string,
    inputs: Record<string, string>,
    options: {
      workingDirectory?: string
      scanId?: string
      scanName?: string
      description?: string
      authorizationConfirmed?: boolean
    } = {}
  ) {
    try {
      const result = await this.invokeCommand('execute_workflow', {
        request: {
          workflowId: workflowTemplateId,
          inputs,
          workingDirectory: options.workingDirectory,
          scanId: options.scanId,
          scanName: options.scanName,
          description: options.description,
          authorizationConfirmed: options.authorizationConfirmed ?? false,
        }
      })
      return { data: result }
    } catch (error) {
      console.error('Failed to execute workflow:', error)
      throw error
    }
  }

  async getWorkflowStatus(executionId: string): Promise<WorkflowStatus> {
    return this.invokeCommand<WorkflowStatus>('get_workflow_status', { executionId })
  }

  async stopWorkflow(executionId: string) {
    try {
      const result = await this.invokeCommand('stop_workflow_execution', { executionId })
      return { data: result }
    } catch (error) {
      console.error('Failed to stop workflow:', error)
      throw error
    }
  }

  async stopScan(scanId: string) {
    const result = await this.invokeCommand('stop_scan', { scanId })
    return { data: result }
  }

  async getExecutionArtifacts(executionId: string): Promise<WorkflowArtifact[]> {
    const artifacts = await this.invokeCommand('get_workflow_artifacts', { executionId })
    return Array.isArray(artifacts) ? artifacts : []
  }

  async revealWorkflowArtifact(executionId: string, artifactId: string): Promise<void> {
    await this.invokeCommand('reveal_workflow_artifact', { executionId, artifactId })
  }

  async revealScanResults(scanId: string): Promise<void> {
    await this.invokeCommand('reveal_scan_results', { scanId })
  }

  async revealReport(reportId: string): Promise<void> {
    await this.invokeCommand('reveal_report', { reportId })
  }

  async getExecutionFindings(executionId: string): Promise<any[]> {
    const findings = await this.invokeCommand('get_workflow_findings', { executionId })
    return Array.isArray(findings) ? findings : []
  }

  async loadWorkflowTemplatesTauri() {
    try {
      const templates = await this.invokeCommand('load_workflow_templates')
      return { data: templates }
    } catch (error) {
      console.error('Failed to load workflow templates:', error)
      return { data: [] }
    }
  }

  async getSystemMetrics() {
    return { data: await this.invokeCommand('get_system_metrics') }
  }

  // Tool Installation Commands (Phase 8)

  async installTool(toolName: string): Promise<{ success: boolean; message: string; steps: any[]; requires_restart: boolean }> {
    try {
      const result = await this.invokeCommand('install_tool', { toolName }) as { success: boolean; message: string; steps: any[]; requires_restart: boolean }
      return result
    } catch (error) {
      console.error('Failed to install tool:', error)
      throw error
    }
  }

  async installToolWithMethod(toolName: string, installMethod: string): Promise<{ success: boolean; message: string; steps: any[]; requires_restart: boolean }> {
    try {
      const result = await this.invokeCommand('install_tool_with_method', { toolName, installMethod }) as { success: boolean; message: string; steps: any[]; requires_restart: boolean }
      return result
    } catch (error) {
      console.error('Failed to install tool with method:', error)
      throw error
    }
  }

  async updateTool(toolName: string): Promise<{ success: boolean; message: string; steps: any[]; requires_restart: boolean }> {
    try {
      const result = await this.invokeCommand('update_tool', { toolName }) as { success: boolean; message: string; steps: any[]; requires_restart: boolean }
      return result
    } catch (error) {
      console.error('Failed to update tool:', error)
      throw error
    }
  }

  async uninstallTool(toolName: string): Promise<string> {
    try {
      const message = await this.invokeCommand('uninstall_tool', { toolName }) as string
      return message
    } catch (error) {
      console.error('Failed to uninstall tool:', error)
      throw error
    }
  }

  async checkToolInstalled(toolName: string): Promise<boolean> {
    try {
      const result = await this.invokeCommand('check_tool_installed', { toolName }) as boolean
      return result
    } catch (error) {
      console.error('Failed to check tool installation:', error)
      return false
    }
  }

  async getToolVersion(toolName: string): Promise<string | null> {
    try {
      const version = await this.invokeCommand('get_tool_version', { toolName }) as string | null
      return version
    } catch (error) {
      console.error('Failed to get tool version:', error)
      return null
    }
  }

  async testTool(toolName: string): Promise<ToolTestResult> {
    return this.invokeCommand<ToolTestResult>('test_tool', { toolName })
  }

  async recheckTool(toolName: string): Promise<Tool> {
    return this.invokeCommand<Tool>('recheck_tool', { toolName })
  }

  async checkToolUpdate(toolName: string): Promise<{
    has_update: boolean
    current_version: string | null
    latest_version: string | null
    package_manager: string
    error: string | null
  }> {
    // Just invoke the command, error logging is handled in invokeCommand
    return await this.invokeCommand('check_tool_update', { toolName }) as {
      has_update: boolean
      current_version: string | null
      latest_version: string | null
      package_manager: string
      error: string | null
    }
  }

  // Enhanced update check with detailed results
  async checkToolUpdateEnhanced(toolName: string): Promise<CoordinatedUpdateResult> {
    return await this.invokeCommand('check_tool_update_enhanced', { toolName }) as CoordinatedUpdateResult
  }

  // Legacy update check for backward compatibility
  async checkToolUpdateLegacy(toolName: string): Promise<{
    has_update: boolean
    current_version: string | null
    latest_version: string | null
    package_manager: string
    error: string | null
  }> {
    return await this.invokeCommand('check_tool_update_legacy', { toolName }) as {
      has_update: boolean
      current_version: string | null
      latest_version: string | null
      package_manager: string
      error: string | null
    }
  }

  async getUpdateCheckerTelemetry(): Promise<any> {
    return await this.invokeCommand('get_update_checker_telemetry', {})
  }

  async clearUpdateCheckerTelemetry(): Promise<void> {
    return await this.invokeCommand('clear_update_checker_telemetry', {})
  }

  async getToolInstallationInfo(toolName: string): Promise<ToolInstallationInfo> {
    try {
      const info = await this.invokeCommand<ToolInstallationInfo>('get_tool_installation_info', { toolName })
      return info
    } catch (error) {
      console.error('Failed to get tool installation info:', error)
      throw error
    }
  }

  // Adapter Commands - Tool Command Builders

  async buildToolCommand(adapterConfig: AdapterConfig): Promise<CommandPreview> {
    try {
      const command = await this.invokeCommand('build_tool_command', { adapterType: adapterConfig }) as CommandPreview
      return command
    } catch (error) {
      console.error('Failed to build tool command:', error)
      throw error
    }
  }

  async buildToolCommandWithDefaults(
    toolName: string,
    target: string,
    outputFile?: string | null
  ): Promise<CommandPreview> {
    try {
      const command = await this.invokeCommand('build_tool_command_with_defaults', {
        toolName,
        target,
        outputFile: outputFile || null
      }) as CommandPreview
      return command
    } catch (error) {
      console.error('Failed to build tool command with defaults:', error)
      throw error
    }
  }

  async getAdapterInfo(toolName: string): Promise<AdapterInfo> {
    try {
      const info = await this.invokeCommand('get_adapter_info', { toolName }) as AdapterInfo
      return info
    } catch (error) {
      console.error('Failed to get adapter info:', error)
      throw error
    }
  }

  async listAdapters(): Promise<AdapterInfo[]> {
    return await this.invokeCommand('list_adapters') as AdapterInfo[]
  }

  async getAdaptersByCategory(category: string): Promise<AdapterInfo[]> {
    try {
      const adapters = await this.invokeCommand('get_adapters_by_category', { category }) as AdapterInfo[]
      return adapters
    } catch (error) {
      console.error('Failed to get adapters by category:', error)
      return []
    }
  }

  async getAdaptersByRiskLevel(riskLevel: string): Promise<AdapterInfo[]> {
    try {
      const adapters = await this.invokeCommand('get_adapters_by_risk_level', { riskLevel }) as AdapterInfo[]
      return adapters
    } catch (error) {
      console.error('Failed to get adapters by risk level:', error)
      return []
    }
  }

  async hasAdapter(toolName: string): Promise<boolean> {
    try {
      const result = await this.invokeCommand('has_adapter', { toolName }) as boolean
      return result
    } catch (error) {
      console.error('Failed to check adapter availability:', error)
      return false
    }
  }

  async getAdapterCategories(): Promise<string[]> {
    try {
      const categories = await this.invokeCommand('get_adapter_categories') as string[]
      return categories
    } catch (error) {
      console.error('Failed to get adapter categories:', error)
      return []
    }
  }

  // Package Manager Commands

  async detectPackageManagers(): Promise<PackageManagerInfo[]> {
    return await this.invokeCommand('detect_package_managers') as PackageManagerInfo[]
  }

  async checkPackageManager(managerName: string): Promise<PackageManagerInfo> {
    try {
      const info = await this.invokeCommand('check_package_manager', { managerName }) as PackageManagerInfo
      return info
    } catch (error) {
      console.error(`Failed to check package manager ${managerName}:`, error)
      throw error
    }
  }

  async installPackageManagerPipx(): Promise<InstallationResult> {
    try {
      const result = await this.invokeCommand('install_package_manager_pipx') as InstallationResult
      return result
    } catch (error) {
      console.error('Failed to install pipx:', error)
      throw error
    }
  }

  async installPackageManagerGo(): Promise<InstallationResult> {
    try {
      const result = await this.invokeCommand('install_package_manager_go') as InstallationResult
      return result
    } catch (error) {
      console.error('Failed to install Go:', error)
      throw error
    }
  }

  async installPackageManagerWinget(): Promise<InstallationResult> {
    try {
      const result = await this.invokeCommand('install_package_manager_winget') as InstallationResult
      return result
    } catch (error) {
      console.error('Failed to install WinGet:', error)
      throw error
    }
  }

  // Elevation Commands

  async checkElevationSupport(): Promise<ElevationMethod> {
    try {
      const method = await this.invokeCommand('check_elevation_support') as ElevationMethod
      return method
    } catch (error) {
      console.error('Failed to check elevation support:', error)
      throw error
    }
  }

  // Pipx Path Management (Windows)

  async checkPipxPath(): Promise<{
    in_path: boolean
    pipx_bin_path: string | null
    current_path: string
    platform: string
  }> {
    try {
      const result = await this.invokeCommand('check_pipx_path') as {
        in_path: boolean
        pipx_bin_path: string | null
        current_path: string
        platform: string
      }
      return result
    } catch (error) {
      console.error('Failed to check pipx path:', error)
      throw error
    }
  }

  async fixPipxPath(): Promise<string> {
    try {
      const message = await this.invokeCommand('fix_pipx_path') as string
      return message
    } catch (error) {
      console.error('Failed to fix pipx path:', error)
      throw error
    }
  }

  async cleanupOldPipx(): Promise<string> {
    try {
      const message = await this.invokeCommand('cleanup_old_pipx') as string
      return message
    } catch (error) {
      console.error('Failed to cleanup old pipx:', error)
      throw error
    }
  }
}

// Create singleton instance
export const apiService = new ApiService()

// React Query hooks
export const useApi = () => {
  return apiService
}

export default apiService
