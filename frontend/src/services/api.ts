/**
 * API service for HTTP requests to the FastAPI backend
 */

// API base URL - works for both web and desktop apps
export const API_BASE_URL = (() => {
  // Check if we're in a desktop app context
  if (typeof window !== 'undefined') {
    const origin = window.location.origin
    const hostname = window.location.hostname
    const port = window.location.port

    console.log('🌐 App context:', { origin, hostname, port })

    // For Tauri desktop app (tauri://localhost)
    if (origin.startsWith('tauri://')) {
      console.log('🖥️ Desktop app detected, using localhost:8000')
      return 'http://localhost:8000'
    }

    // For web development (localhost:5173, localhost:5174, etc.)
    if (hostname === 'localhost' || hostname === '127.0.0.1') {
      console.log('🌐 Web development detected, using localhost:8000')
      return 'http://localhost:8000'
    }
  }

  // Default fallback
  console.log('🔄 Using default API base URL')
  return 'http://localhost:8000'
})()

export interface ApiResponse<T = any> {
  data?: T
  error?: string
  message?: string
}

export interface Scan {
  id: string
  target: string
  scan_type: string
  status: string
  progress: number
  started: string | null
  completed: string | null
  agents: string[]
  current_test?: string
  vulnerabilities?: number
  critical?: number
  high?: number
  medium?: number
  low?: number
  target_validated?: boolean
  scanType?: string  // Keep for backward compatibility
}

export interface Tool {
  name: string
  description: string
  category: string
  status: string
  installed: boolean
  available: boolean
  version: string | null
  raw_version?: string | null
  path?: string | null
  command_template: string[]
  output_format: string
  os_dependencies: string[]
  missing_dependencies: string[]
  last_check?: string | null
  last_seen?: string | null
  last_error?: string | null
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
}

export interface WorkflowTemplate {
  id: string
  name: string
  description: string
  category: string
  steps: WorkflowStep[]
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
  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    try {
      const url = `${API_BASE_URL}${endpoint}`
      console.log(`🔗 API Request: ${options.method || 'GET'} ${url}`)
      console.log(`🌐 Request origin: ${window.location.origin}`)
      console.log(`📍 Request location: ${window.location.href}`)

      const response = await fetch(url, {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          ...options.headers,
        },
        ...options,
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }))
        console.error(`❌ API Error ${response.status}:`, errorData)
        throw new Error(errorData.error || `HTTP ${response.status}`)
      }

      const data = await response.json()
      console.log(`✅ API Response:`, { status: response.status, dataType: typeof data, dataLength: Array.isArray(data) ? data.length : 'N/A' })
      return { data }
    } catch (error) {
      console.error(`API request failed: ${endpoint}`, error)
      return {
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      }
    }
  }

  // Health endpoints
  async getHealth() {
    return this.request('/api/health/')
  }

  async getDetailedHealth() {
    return this.request<SystemStats>('/api/health/')
  }

  // Scan endpoints
  async getScans() {
    return this.request<Scan[]>('/api/scans/')
  }

  async getScan(scanId: string) {
    return this.request<Scan>(`/api/scans/${scanId}`)
  }

  async createScan(scanData: {
    target: string
    scan_type?: string
    agents?: string[]
  }) {
    return this.request<Scan>('/api/scans/', {
      method: 'POST',
      body: JSON.stringify(scanData),
    })
  }

  async runQuickScan(target: string) {
    return this.request<Scan>('/api/scans/', {
      method: 'POST',
      body: JSON.stringify({ target, scan_type: 'Quick Scan' }),
    })
  }

  async startScan(scanId: string) {
    return this.request(`/api/scans/${scanId}/start`, {
      method: 'POST',
    })
  }

  async deleteScan(scanId: string) {
    return this.request(`/api/scans/${scanId}`, {
      method: 'DELETE',
    })
  }

  async getScanVulnerabilities(scanId: string) {
    return this.request(`/api/scans/${scanId}/vulnerabilities`)
  }

  async getScanReports(scanId: string) {
    return this.request(`/api/scans/${scanId}/reports`)
  }

  // Tool endpoints
  async getTools() {
    return this.request<Tool[]>('/api/tools/')
  }

  async getTool(toolName: string) {
    return this.request<Tool>(`/api/tools/${toolName}`)
  }

  async checkToolAvailability(toolName: string) {
    return this.request(`/api/tools/${toolName}/check`)
  }

  async refreshToolsStatus() {
    return this.request('/api/tools/refresh', {
      method: 'POST',
    })
  }

  async addManualTool(data: { tool_name: string; tool_path: string; category: string }) {
    return this.request('/api/tools/tools/manual/add', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  }

  async removeManualTool(toolName: string) {
    return this.request(`/api/tools/tools/manual/${toolName}`, {
      method: 'DELETE',
    })
  }

  async getManualTools() {
    return this.request('/api/tools/tools/manual/list')
  }

  // Report endpoints
  async getReports(params?: {
    skip?: number
    limit?: number
    scan_id?: string
  }) {
    const queryParams = new URLSearchParams()
    if (params?.skip) queryParams.append('skip', params.skip.toString())
    if (params?.limit) queryParams.append('limit', params.limit.toString())
    if (params?.scan_id) queryParams.append('scan_id', params.scan_id)

    const query = queryParams.toString()
    return this.request<Report[]>(`/api/reports/${query ? `?${query}` : ''}`)
  }

  async getReport(reportId: string) {
    return this.request<Report>(`/api/reports/${reportId}`)
  }

  async createReport(reportData: {
    scanId: string
    title?: string
    format: string
  }) {
    return this.request<Report>('/api/reports/', {
      method: 'POST',
      body: JSON.stringify(reportData),
    })
  }

  async downloadReport(reportId: string) {
    const response = await fetch(`${API_BASE_URL}/api/reports/${reportId}/download`)
    if (!response.ok) {
      throw new Error('Failed to download report')
    }
    return response
  }

  async deleteReport(reportId: string) {
    return this.request(`/api/reports/${reportId}`, {
      method: 'DELETE',
    })
  }

  // Recon endpoints
  async getReconPlans() {
    return this.request('/api/recon/plans')
  }

  async getReconPlan(planId: string) {
    return this.request(`/api/recon/plans/${planId}`)
  }

  async getReconTemplates() {
    return this.request('/api/recon/templates')
  }

  async generateReconPlan(target: string, template: string = 'auto') {
    return this.request('/api/recon/plans/generate', {
      method: 'POST',
      body: JSON.stringify({ target, template }),
    })
  }

  async executeReconPlan(planId: string, target: string) {
    return this.request(`/api/recon/plans/${planId}/execute`, {
      method: 'POST',
      body: JSON.stringify({ target }),
    })
  }

  // Workflow endpoints
  async getWorkflowTemplates(checkCompatibility: boolean = true) {
    const params = checkCompatibility ? '?check_compatibility=true' : ''
    return this.request(`/api/workflows/${params}`)
  }

  async executeWorkflow(workflowTemplateId: string, inputs: Record<string, string>) {
    return this.request('/api/workflows/execute', {
      method: 'POST',
      body: JSON.stringify({
        workflow_id: workflowTemplateId,
        inputs
      }),
    })
  }

  async getWorkflowStatus(executionId: string) {
    return this.request(`/api/workflows/${executionId}/status`)
  }

  async loadWorkflowTemplatesTauri() {
    try {
      const { invoke } = await import('@tauri-apps/api/tauri')
      return await invoke('load_workflow_templates')
    } catch (error) {
      console.error('Failed to load workflow templates from Tauri:', error)
      throw error
    }
  }

  async getSystemMetrics() {
    return this.request('/api/metrics/')
  }
}

// Create singleton instance
export const apiService = new ApiService()

// React Query hooks
export const useApi = () => {
  return apiService
}

export default apiService
