/**
 * API service for Tauri commands to the Rust backend
 */

// Check if we're running in Tauri
const isTauriEnvironment = () => {
  // More robust Tauri detection
  if (typeof window === 'undefined') return false

  // Check for Tauri global object
  if ('__TAURI__' in window) return true

  // Check for Tauri protocol
  try {
    const loc = (window as any).location
    if (loc?.protocol === 'tauri:') return true

    // Check for Tauri origin
    if (loc?.origin.startsWith('tauri://')) return true
  } catch (e) {
    // window.location might not be available in some contexts
  }

  return false
}

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
}

export interface Report {
  id: string
  title: string
  generated: string
  target: string
  vulnerabilities: number
  format: string
  filePath: string | null
  summary: string | null
  severity: string
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
  timeout?: number
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

class ApiService {
  private async invokeCommand<T>(command: string, args: any = {}): Promise<T> {
    if (!isTauriEnvironment()) {
      const errorMsg = `Tauri command ${command} called but not in Tauri environment`
      console.error(errorMsg)
      throw new Error(errorMsg)
    }

    try {
      console.log(`🔗 Attempting Tauri command: ${command}`, args)
      const { invoke } = await import('@tauri-apps/api/tauri')
      console.log('Tauri invoke imported successfully')

      const result = await invoke(command, args)
      console.log(`✅ Tauri Response for ${command}:`, result)
      return result as T
    } catch (error) {
      console.error(`❌ Tauri command failed: ${command}`, error)
      console.error(`Command: ${command}, Args:`, args)
      console.error('Error details:', error)
      
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
      const stats = await this.invokeCommand('get_stats')
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
    try {
      const scans = await this.invokeCommand('list_scans')
      return { data: scans }
    } catch (error) {
      console.error('Failed to get scans:', error)
      return { data: [] }
    }
  }

  async getScan(scanId: string) {
    try {
      const scan = await this.invokeCommand('get_scan', { scanId })
      return { data: scan }
    } catch (error) {
      console.error('Failed to get scan:', error)
      return { data: null }
    }
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

  async startScan(_scanId: string) {
    // For now, just return success - actual scan execution will be handled by workflows
    return { data: { success: true, message: 'Scan started' } }
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
    try {
      const manualTools = await this.invokeCommand('list_manual_tools')
      return { data: { manual_tools: Array.isArray(manualTools) ? manualTools : [] } }
    } catch (error) {
      console.error('Failed to get manual tools:', error)
      return { data: { manual_tools: [] } }
    }
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
    try {
      const reports = await this.invokeCommand('list_reports')
      return reports
    } catch (error) {
      console.error('Failed to get reports:', error)
      return []
    }
  }

  async getReport(reportId: string) {
    try {
      const report = await this.invokeCommand('get_report', { reportId })
      return report
    } catch (error) {
      console.error('Failed to get report:', error)
      return null
    }
  }

  async createReport(reportData: {
    scanId: string
    title?: string
    format: string
  }) {
    try {
      const reportId = await this.invokeCommand('create_report', {
        reportData: {
          scan_id: reportData.scanId,
          title: reportData.title || 'Scan Report',
          format: reportData.format,
          content: ''
        }
      })
      return { success: true, reportId }
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
    try {
      const templates = await this.invokeCommand('load_workflow_templates')
      return { data: templates }
    } catch (error) {
      console.error('Failed to get workflow templates:', error)
      return { data: [] }
    }
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

  async executeWorkflow(workflowTemplateId: string, inputs: Record<string, string>) {
    try {
      const result = await this.invokeCommand('execute_workflow', {
        workflowId: workflowTemplateId,
        inputs
      })
      return result
    } catch (error) {
      console.error('Failed to execute workflow:', error)
      throw error
    }
  }

  async getWorkflowStatus(executionId: string) {
    try {
      const status = await this.invokeCommand('get_workflow_status', { executionId })
      return status
    } catch (error) {
      console.error('Failed to get workflow status:', error)
      return null
    }
  }

  async stopWorkflow(executionId: string) {
    try {
      const result = await this.invokeCommand('stop_workflow_execution', { executionId })
      return result
    } catch (error) {
      console.error('Failed to stop workflow:', error)
      return { success: true, message: 'Workflow stopped' }
    }
  }

  async getExecutionArtifacts(executionId: string): Promise<WorkflowArtifact[]> {
    try {
      const artifacts = await this.invokeCommand('get_workflow_artifacts', { executionId })
      return Array.isArray(artifacts) ? artifacts : []
    } catch (error) {
      console.error('Failed to get execution artifacts:', error)
      return []
    }
  }

  async getExecutionFindings(executionId: string): Promise<any[]> {
    try {
      const findings = await this.invokeCommand('get_workflow_findings', { executionId })
      return Array.isArray(findings) ? findings : []
    } catch (error) {
      console.error('Failed to get execution findings:', error)
      return []
    }
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
}

// Create singleton instance
export const apiService = new ApiService()

// React Query hooks
export const useApi = () => {
  return apiService
}

export default apiService
