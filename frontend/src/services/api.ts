/**
 * API service for HTTP requests to the FastAPI backend
 */

const API_BASE_URL = 'http://localhost:8000'

export interface ApiResponse<T = any> {
  data?: T
  error?: string
  message?: string
}

export interface Scan {
  id: string
  target: string
  status: string
  progress: number
  started_at: string
  completed_at: string | null
  findings_count?: number
}

export interface Tool {
  name: string
  description: string
  category: string
  command_template: string[]
  output_format: string
  installed: boolean
  version: string | null
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

class ApiService {
  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    try {
      const url = `${API_BASE_URL}${endpoint}`

      const response = await fetch(url, {
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
        ...options,
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }))
        throw new Error(errorData.error || `HTTP ${response.status}`)
      }

      const data = await response.json()
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

  async createScan(target: string) {
    return this.request<Scan>('/api/scans/', {
      method: 'POST',
      body: JSON.stringify({ target }),
    })
  }

  async runQuickScan(target: string, tools: string = 'subfinder') {
    return this.request('/api/scans/', {
      method: 'POST',
      body: JSON.stringify({ target, tools }),
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
}

// Create singleton instance
export const apiService = new ApiService()

// React Query hooks
export const useApi = () => {
  return apiService
}

export default apiService
