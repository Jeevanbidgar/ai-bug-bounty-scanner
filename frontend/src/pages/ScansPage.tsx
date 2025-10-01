import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus,
  Play,
  Square,
  Eye,
  Trash2,
  Search,
  Settings,
  Clock,
  Target,
  FolderOpen,
  Tag,
  AlertCircle,
  CheckCircle,
  Loader2
} from 'lucide-react'
import { Button } from '../components/ui/Button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Progress } from '../components/ui/Progress'
import { Input } from '../components/ui/Input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/Select'
// Import API_BASE_URL for debugging
import { API_BASE_URL } from '../services/api'
import { apiService, Scan, WorkflowTemplate, WorkflowCompatibility } from '../services/api'
// WebSocket integration will be added later

// API functions
const fetchScans = async (): Promise<Scan[]> => {
  try {
    console.log('🔍 Fetching scans from API...')
    console.log('🎯 Calling apiService.getScans()')

    const response = await apiService.getScans()
    console.log('📡 Raw API response:', response)

    if (response.error) {
      console.error('❌ API returned error:', response.error)
      throw new Error(`API Error: ${response.error}`)
    }

    if (!response.data) {
      console.warn('⚠️ API response has no data property')
      return []
    }

    const scans = response.data
    console.log('✅ Successfully fetched scans:', Array.isArray(scans) ? scans.length : 'not array')

    if (!Array.isArray(scans)) {
      console.error('❌ API response data is not an array:', typeof scans)
      throw new Error('API response data is not an array')
    }

    return scans
  } catch (error) {
    console.error('❌ Error in fetchScans:', error)
    console.error('❌ Error stack:', error instanceof Error ? error.stack : 'No stack')
    throw error // Re-throw to let React Query handle it
  }
}

const createScan = async (scanData: any): Promise<Scan> => {
  try {
    const response = await apiService.createScan(scanData)
    if (response.error) {
      throw new Error(response.error)
    }
    return response.data!
  } catch (error) {
    console.error('Error creating scan:', error)
    throw error
  }
}

const startScan = async (scanId: string): Promise<void> => {
  try {
    const response = await apiService.startScan(scanId)
    if (response.error) {
      throw new Error(response.error)
    }
    // These operations don't return data, just success/error
  } catch (error) {
    console.error('Error starting scan:', error)
    throw error
  }
}

const deleteScan = async (scanId: string): Promise<void> => {
  try {
    const response = await apiService.deleteScan(scanId)
    if (response.error) {
      throw new Error(response.error)
    }
    // These operations don't return data, just success/error
  } catch (error) {
    console.error('Error deleting scan:', error)
    throw error
  }
}

const ScansPage = () => {
  const queryClient = useQueryClient()

  // Search and filtering
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')

  // Enhanced scan creation dialog state
  const [showCreateDialog, setShowCreateDialog] = useState(false)
  const [selectedWorkflow, setSelectedWorkflow] = useState<string>('')
  const [scanTarget, setScanTarget] = useState('')
  const [scanName, setScanName] = useState('')
  const [scanDescription, setScanDescription] = useState('')
  const [scanTags, setScanTags] = useState('')
  const [workingDirectory, setWorkingDirectory] = useState('')
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null)
  const [showScanDetails, setShowScanDetails] = useState(false)
  const [scanLogs, setScanLogs] = useState<string[]>([])
  const [scanArtifacts, setScanArtifacts] = useState<any[]>([])
  const [scanFindings, setScanFindings] = useState<any[]>([])

  // Debug logging for navigation
  console.log('🚀 ScansPage component rendered!')
  console.log('📍 Location:', window.location.href)
  console.log('🌐 Origin:', window.location.origin)
  console.log('🔗 API Base URL:', API_BASE_URL)
  console.log('🎯 Expected scan URL:', `${API_BASE_URL}/api/scans/`)

  // React Query for data fetching with real-time updates
  const { data: scans, isLoading, error, refetch } = useQuery({
    queryKey: ['scans'],
    queryFn: fetchScans,
    refetchInterval: 3000, // Poll every 3 seconds for real-time updates
    staleTime: 1000, // Consider data stale after 1 second
  })

  const { data: workflowTemplates } = useQuery<WorkflowTemplate[]>({
    queryKey: ['workflow-templates'],
    queryFn: async () => {
      const result = await apiService.getWorkflowTemplates(true) // Include compatibility info
      return result.data as WorkflowTemplate[]
    },
    retry: 3,
  })

  // Mutations
  const executeWorkflowMutation = useMutation({
    mutationFn: async (data: { workflow_id: string; inputs: Record<string, string>; working_directory?: string }) => {
      const response = await apiService.executeWorkflow(data.workflow_id, data.inputs)
      if (response.error) throw new Error(response.error)
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      setShowCreateDialog(false)
      resetForm()
    },
    onError: (error) => {
      console.error('Failed to execute workflow:', error)
    }
  })

  const startScanMutation = useMutation({
    mutationFn: (scanId: string) => apiService.startScan(scanId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
    onError: (error) => {
      console.error('Failed to start scan:', error)
    }
  })

  const stopScanMutation = useMutation({
    mutationFn: (scanId: string) => apiService.stopScan(scanId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
    onError: (error) => {
      console.error('Failed to stop scan:', error)
    }
  })

  const deleteScanMutation = useMutation({
    mutationFn: (scanId: string) => apiService.deleteScan(scanId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
    onError: (error) => {
      console.error('Failed to delete scan:', error)
    }
  })

  const getWorkflowStatusMutation = useMutation({
    mutationFn: async (executionId: string) => {
      const response = await apiService.getWorkflowStatus(executionId)
      if (response.error) throw new Error(response.error)
      return response.data
    },
    onSuccess: (data) => {
      setScanLogs(data?.logs || [])
      // Note: artifacts and findings would need separate API calls
      // For now, we'll show basic workflow status
    }
  })

  // Helper function to reset form
  const resetForm = () => {
    setSelectedWorkflow('')
    setScanTarget('')
    setScanName('')
    setScanDescription('')
    setScanTags('')
    setWorkingDirectory('')
  }

  // Debug logging
  console.log('ScansPage state:', {
    isLoading,
    error,
    scansLength: scans?.length || 0,
    workflowTemplatesLength: workflowTemplates?.length || 0,
  })

  // Handle loading state - show loading if loading or no scans yet
  if (isLoading || (scans?.length === 0 && !error)) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-3xl font-bold text-white">Scans</h1>
        </div>
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
          <span className="ml-3 text-gray-400">Loading scans...</span>
        </div>
      </div>
    )
  }

  // Handle error state
  if (error) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-3xl font-bold text-white">Scans</h1>
        </div>
        <div className="flex items-center justify-center py-12">
          <div className="text-center">
            <div className="text-red-500 text-4xl mb-4">⚠️</div>
            <h3 className="text-lg font-semibold text-white mb-2">Failed to Load Scans</h3>
            <p className="text-gray-400 mb-4">Error: {error || 'Unknown error'}</p>
            <Button onClick={() => refetch()} variant="outline">
              Try Again
            </Button>
          </div>
        </div>
      </div>
    )
  }

  // Enhanced workflow execution handler
  const handleCreateScan = () => {
    if (!selectedWorkflow) {
      alert('Please select a workflow template')
      return
    }

    if (!scanTarget.trim()) {
      alert('Please enter a target URL or domain')
      return
    }

    // Generate working directory if not provided
    const workdir = workingDirectory.trim() || `./results/${scanTarget.trim().replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}`

    const inputs = {
      target: scanTarget.trim(),
      workdir: workdir
    }

    executeWorkflowMutation.mutate({
      workflow_id: selectedWorkflow,
      inputs: inputs,
      working_directory: workdir
    })
  }

  // Handlers for scan actions
  const handleStartScan = (scanId: string) => {
    startScanMutation.mutate(scanId)
  }

  const handleStopScan = (scanId: string) => {
    stopScanMutation.mutate(scanId)
  }

  const handleDeleteScan = (scanId: string) => {
    if (confirm('Are you sure you want to delete this scan? This action cannot be undone.')) {
      deleteScanMutation.mutate(scanId)
    }
  }

  // Filter scans based on search and status
  const filteredScans = (scans || []).filter((scan: Scan) => {
    const matchesSearch = scan.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         scan.target.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesStatus = statusFilter === 'all' || scan.status === statusFilter
    return matchesSearch && matchesStatus
  })

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'running': return 'bg-blue-600'
      case 'completed': return 'bg-green-600'
      case 'failed': return 'bg-red-600'
      case 'pending': return 'bg-yellow-600'
      case 'cancelled': return 'bg-gray-600'
      default: return 'bg-gray-600'
    }
  }

  const getStatusBadgeColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'running': return 'bg-blue-600'
      case 'completed': return 'bg-green-600'
      case 'failed': return 'bg-red-600'
      case 'pending': return 'bg-yellow-600'
      case 'cancelled': return 'bg-gray-600'
      default: return 'bg-gray-600'
    }
  }

  // Removed unused getStatusIcon function

  const handleCreateScanClick = () => {
    if (!newScanTarget.trim()) return
    handleCreateScan()
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white">Security Scans</h1>
          <p className="text-gray-400 mt-2 text-sm sm:text-base">
            Manage and monitor your security scanning operations
          </p>
        </div>
        <Button onClick={() => setShowCreateDialog(true)} className="w-fit">
          <Plus className="mr-2 h-4 w-4" />
          New Scan
        </Button>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="flex-1">
          <Input
            placeholder="Search scans..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full"
          />
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-full sm:w-48">
            <SelectValue placeholder="Filter by status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="running">Running</SelectItem>
            <SelectItem value="completed">Completed</SelectItem>
            <SelectItem value="failed">Failed</SelectItem>
            <SelectItem value="pending">Pending</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Enhanced Scan Creation Dialog */}
      {showCreateDialog && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <Card className="w-full max-w-2xl bg-gray-900 border-gray-700 max-h-[90vh] overflow-y-auto">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-blue-400">
                <Target className="h-5 w-5" />
                Create New Scan
              </CardTitle>
              <CardDescription className="text-gray-400">
                Configure a new security scanning operation with workflow templates
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Workflow Template Selection */}
              <div className="space-y-2">
                <label className="text-sm font-medium text-gray-300">Workflow Template</label>
                <Select value={selectedWorkflow} onValueChange={setSelectedWorkflow}>
                  <SelectTrigger className="h-11 bg-gray-800 border-gray-600 text-white">
                    <SelectValue placeholder="Select a workflow template" />
                  </SelectTrigger>
                  <SelectContent>
                    {workflowTemplates?.map((template: WorkflowTemplate) => {
                      const isCompatible = template.compatibility?.compatible !== false
                      const missingTools = template.compatibility?.missing_tools || []

                      return (
                        <SelectItem
                          key={template.id}
                          value={template.id}
                          disabled={!isCompatible}
                        >
                          <div className="flex items-center gap-2">
                            <Badge className={`text-xs ${
                              template.category === 'reconnaissance' ? 'bg-blue-600' :
                              template.category === 'vulnerability' ? 'bg-red-600' : 'bg-purple-600'
                            }`}>
                              {template.category}
                            </Badge>
                            {template.name}
                            {!isCompatible && (
                              <Badge className="text-xs bg-red-600 ml-2">
                                Missing: {missingTools.join(', ')}
                              </Badge>
                            )}
                            {isCompatible && template.compatibility && (
                              <Badge className="text-xs bg-green-600 ml-2">
                                ✓ Ready
                              </Badge>
                            )}
                          </div>
                        </SelectItem>
                      )
                    })}
                  </SelectContent>
                </Select>
              </div>

              {/* Target Configuration */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium text-gray-300">Target Domain/IP</label>
                  <Input
                    placeholder="example.com or https://api.example.com"
                    value={scanTarget}
                    onChange={(e) => setScanTarget(e.target.value)}
                    className="bg-gray-800 border-gray-600 text-white"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium text-gray-300">Scan Name</label>
                  <Input
                    placeholder="My Security Audit"
                    value={scanName}
                    onChange={(e) => setScanName(e.target.value)}
                    className="bg-gray-800 border-gray-600 text-white"
                  />
                </div>
              </div>

              {/* Working Directory */}
              <div className="space-y-2">
                <label className="text-sm font-medium text-gray-300 flex items-center gap-2">
                  <FolderOpen className="h-4 w-4" />
                  Working Directory
                </label>
                <Input
                  placeholder="./results/example_com_1703123456789"
                  value={workingDirectory}
                  onChange={(e) => setWorkingDirectory(e.target.value)}
                  className="bg-gray-800 border-gray-600 text-white"
                />
                <p className="text-xs text-gray-400">
                  Leave empty to auto-generate based on target and timestamp
                </p>
              </div>

              {/* Description and Tags */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium text-gray-300">Description</label>
                  <Input
                    placeholder="Optional description for this scan"
                    value={scanDescription}
                    onChange={(e) => setScanDescription(e.target.value)}
                    className="bg-gray-800 border-gray-600 text-white"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium text-gray-300 flex items-center gap-2">
                    <Tag className="h-4 w-4" />
                    Tags (comma-separated)
                  </label>
                  <Input
                    placeholder="bug-bounty, api, urgent"
                    value={scanTags}
                    onChange={(e) => setScanTags(e.target.value)}
                    className="bg-gray-800 border-gray-600 text-white"
                  />
                </div>
              </div>

              {/* Workflow Preview */}
              {selectedWorkflow && workflowTemplates && (
                <div className="p-4 bg-gray-800 rounded-lg border border-gray-700">
                  <h4 className="text-sm font-medium text-gray-300 mb-3">Workflow Preview</h4>
                  <div className="space-y-2">
                    <div className="text-sm text-gray-400">
                      Selected: <span className="text-white font-medium">
                        {workflowTemplates.find((t: WorkflowTemplate) => t.id === selectedWorkflow)?.name}
                      </span>
                    </div>
                    <div className="text-xs text-gray-500">
                      Steps: {workflowTemplates.find((t: WorkflowTemplate) => t.id === selectedWorkflow)?.steps.length || 0}
                    </div>
                    {(() => {
                      const workflow = workflowTemplates.find((t: WorkflowTemplate) => t.id === selectedWorkflow)
                      const compatibility = workflow?.compatibility

                      if (compatibility && !compatibility.compatible) {
                        return (
                          <div className="mt-3 p-3 bg-red-900/20 border border-red-500 rounded-lg">
                            <div className="flex items-center gap-2 text-red-400">
                              <AlertCircle className="h-4 w-4" />
                              <span className="text-sm">
                                Missing tools: {compatibility.missing_tools.join(', ')}
                              </span>
                            </div>
                          </div>
                        )
                      }
                      return null
                    })()}
                  </div>
                </div>
              )}

              {/* Action Buttons */}
              <div className="flex flex-col sm:flex-row gap-3 pt-4">
                <Button
                  onClick={handleCreateScan}
                  disabled={!selectedWorkflow || !scanTarget.trim() || executeWorkflowMutation.isPending}
                  className="flex-1 bg-blue-600 hover:bg-blue-700"
                >
                  {executeWorkflowMutation.isPending ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin mr-2" />
                      Executing Workflow...
                    </>
                  ) : (
                    <>
                      <Play className="h-4 w-4 mr-2" />
                      Execute Workflow
                    </>
                  )}
                </Button>
                <Button
                  variant="outline"
                  onClick={() => setShowCreateDialog(false)}
                  className="flex-1"
                >
                  Cancel
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Scans List */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="grid gap-4">
            {[1, 2, 3].map((i) => (
              <Card key={i} className="animate-pulse">
                <CardContent className="p-6">
                  <div className="h-4 bg-gray-700 rounded w-1/4 mb-4"></div>
                  <div className="h-3 bg-gray-700 rounded w-1/2 mb-2"></div>
                  <div className="h-3 bg-gray-700 rounded w-3/4"></div>
                </CardContent>
              </Card>
            ))}
          </div>
        ) : error ? (
          <Card>
            <CardContent className="p-12 text-center">
              <div className="text-red-400">
                <h3 className="text-lg font-medium mb-2">Error Loading Scans</h3>
                <p className="text-sm">{error}</p>
              </div>
            </CardContent>
          </Card>
        ) : filteredScans.length === 0 ? (
          <Card>
            <CardContent className="p-12 text-center">
              <div className="text-gray-400">
                <div className="text-4xl mb-4">🔍</div>
                <h3 className="text-lg font-medium mb-2">No Scans Found</h3>
                <p className="text-sm mb-4">No scans match your current filters.</p>
                <Button onClick={() => refetch()} variant="outline">
                  Refresh
                </Button>
              </div>
            </CardContent>
          </Card>
        ) : (
          filteredScans.map((scan) => (
            <Card key={scan.id}>
              <CardContent className="p-6">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4">
                  <div className="flex items-center space-x-3 min-w-0">
                    <div className={`w-3 h-3 rounded-full ${getStatusColor(scan.status)} flex-shrink-0 animate-pulse`}></div>
                    <div className="min-w-0">
                      <h3 className="font-semibold text-white truncate">{scan.name || scan.target}</h3>
                      <div className="flex items-center gap-2 text-sm text-gray-400">
                        <Badge className={`text-xs ${getStatusBadgeColor(scan.status)}`}>
                          {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
                        </Badge>
                        <span>•</span>
                        <span className="truncate">
                          {scan.workflow_id ?
                            `Workflow: ${workflowTemplates?.find(w => w.id === scan.workflow_id)?.name || scan.workflow_id}` :
                            (scan.scan_type || scan.scanType || 'Custom Scan')
                          }
                        </span>
                        <span>•</span>
                        <span>Started {scan.started ? new Date(scan.started).toLocaleDateString() : 'Unknown'}</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2 flex-shrink-0">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => {
                        setSelectedScan(scan)
                        setShowScanDetails(true)
                        getWorkflowStatusMutation.mutate(scan.id)
                      }}
                    >
                      <Eye className="h-4 w-4" />
                    </Button>
                    {scan.status === 'pending' && (
                      <Button
                        size="sm"
                        onClick={() => handleStartScan(scan.id)}
                        disabled={startScanMutation.isPending}
                      >
                        <Play className="h-4 w-4" />
                      </Button>
                    )}
                    {scan.status === 'running' && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => handleStopScan(scan.id)}
                        disabled={stopScanMutation.isPending}
                      >
                        <Square className="h-4 w-4" />
                      </Button>
                    )}
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleDeleteScan(scan.id)}
                      disabled={deleteScanMutation.isPending}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>

                {/* Current Step Information */}
                {scan.current_test && (
                  <div className="mb-4 p-3 bg-gray-800 rounded-lg border border-gray-700">
                    <div className="flex items-center gap-2 mb-2">
                      <Clock className="h-4 w-4 text-blue-400" />
                      <span className="text-sm font-medium text-blue-400">Current Step</span>
                    </div>
                    <p className="text-sm text-white font-medium">{scan.current_test}</p>
                    {scan.current_step && (
                      <p className="text-xs text-gray-400 mt-1">
                        Step {scan.current_step} of {scan.total_steps || '?'}
                      </p>
                    )}
                  </div>
                )}

                {/* Progress and Statistics */}
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4">
                  <div className="flex items-center space-x-4">
                    <div className="flex items-center gap-2">
                      <Progress value={scan.progress || 0} className="w-full sm:w-32" />
                      <span className="text-sm text-gray-400 whitespace-nowrap">
                        {scan.progress || 0}%
                      </span>
                    </div>
                    {scan.estimated_time && (
                      <div className="text-xs text-gray-500">
                        Est. {scan.estimated_time}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center space-x-4">
                    {scan.vulnerabilities !== undefined && scan.vulnerabilities > 0 && (
                      <div className="text-center sm:text-right">
                        <p className="text-sm text-gray-400">Findings</p>
                        <p className="text-lg font-semibold text-white">{scan.vulnerabilities}</p>
                      </div>
                    )}
                    {scan.duration && (
                      <div className="text-center sm:text-right">
                        <p className="text-sm text-gray-400">Duration</p>
                        <p className="text-sm font-semibold text-white">{scan.duration}</p>
                      </div>
                    )}
                  </div>
                </div>

                {/* Workflow and Tags */}
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                  <div className="flex items-center space-x-2 min-w-0">
                    {scan.workflow_id && (
                      <>
                        <span className="text-sm text-gray-400 flex-shrink-0">Workflow:</span>
                        <Badge className="bg-purple-600 text-xs">
                          {workflowTemplates?.find(w => w.id === scan.workflow_id)?.name || scan.workflow_id}
                        </Badge>
                      </>
                    )}
                    {scan.tags && scan.tags.length > 0 && (
                      <>
                        <span className="text-sm text-gray-400 flex-shrink-0">Tags:</span>
                        <div className="flex flex-wrap gap-1 min-w-0">
                          {scan.tags.slice(0, 3).map((tag: string) => (
                            <Badge key={tag} variant="secondary" className="text-xs">
                              {tag}
                            </Badge>
                          ))}
                          {scan.tags.length > 3 && (
                            <Badge variant="secondary" className="text-xs">
                              +{scan.tags.length - 3}
                            </Badge>
                          )}
                        </div>
                      </>
                    )}
                  </div>
                  <div className="flex items-center space-x-2 flex-shrink-0">
                    {scan.critical && scan.critical > 0 && (
                      <Badge className="bg-red-600 text-xs">Critical: {scan.critical}</Badge>
                    )}
                    {scan.high && scan.high > 0 && (
                      <Badge className="bg-orange-600 text-xs">High: {scan.high}</Badge>
                    )}
                    {scan.medium && scan.medium > 0 && (
                      <Badge className="bg-yellow-600 text-xs">Medium: {scan.medium}</Badge>
                    )}
                    {scan.low && scan.low > 0 && (
                      <Badge className="bg-blue-600 text-xs">Low: {scan.low}</Badge>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>

      {filteredScans.length === 0 && !isLoading && (
        <Card>
          <CardContent className="p-12 text-center">
            <div className="text-gray-400">
              <Search className="mx-auto h-12 w-12 mb-4" />
              <h3 className="text-lg font-medium text-white mb-2">No scans found</h3>
              <p>Start your first security scan to get started.</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Scan Details Modal */}
      {showScanDetails && selectedScan && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <Card className="w-full max-w-4xl bg-gray-900 border-gray-700 max-h-[90vh] overflow-hidden flex flex-col">
            <CardHeader className="flex-shrink-0">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2 text-blue-400">
                    <Eye className="h-5 w-5" />
                    Scan Details: {selectedScan.name || selectedScan.target}
                  </CardTitle>
                  <CardDescription className="text-gray-400">
                    {selectedScan.workflow_id ?
                      `Workflow: ${workflowTemplates?.find(w => w.id === selectedScan.workflow_id)?.name || selectedScan.workflow_id}` :
                      (selectedScan.scan_type || selectedScan.scanType || 'Custom Scan')
                    }
                  </CardDescription>
                </div>
                <Button
                  variant="outline"
                  onClick={() => {
                    setShowScanDetails(false)
                    setSelectedScan(null)
                    setScanLogs([])
                    setScanArtifacts([])
                    setScanFindings([])
                  }}
                >
                  Close
                </Button>
              </div>
            </CardHeader>

            <CardContent className="flex-1 overflow-hidden flex flex-col">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-full">
                {/* Logs Panel */}
                <div className="lg:col-span-2 flex flex-col">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-medium text-white">Execution Logs</h3>
                    <div className="flex items-center gap-2">
                      <Badge className={getStatusBadgeColor(selectedScan.status)}>
                        {selectedScan.status.charAt(0).toUpperCase() + selectedScan.status.slice(1)}
                      </Badge>
                      {selectedScan.progress !== undefined && (
                        <span className="text-sm text-gray-400">
                          {selectedScan.progress}%
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="flex-1 bg-gray-800 rounded-lg p-4 overflow-y-auto border border-gray-700">
                    {scanLogs.length > 0 ? (
                      <div className="space-y-2 font-mono text-sm">
                        {scanLogs.map((log, index) => (
                          <div key={index} className="text-gray-300">
                            {log}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-gray-500 text-center py-8">
                        {getWorkflowStatusMutation.isPending ? (
                          <div className="flex items-center justify-center gap-2">
                            <Loader2 className="h-4 w-4 animate-spin" />
                            Loading logs...
                          </div>
                        ) : (
                          'No logs available'
                        )}
                      </div>
                    )}
                  </div>
                </div>

                {/* Sidebar */}
                <div className="space-y-6">
                  {/* Scan Info */}
                  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <h4 className="text-sm font-medium text-gray-300 mb-3">Scan Information</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-400">Target:</span>
                        <span className="text-white truncate">{selectedScan.target}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Status:</span>
                        <Badge className={getStatusBadgeColor(selectedScan.status)}>
                          {selectedScan.status}
                        </Badge>
                      </div>
                      {selectedScan.started && (
                        <div className="flex justify-between">
                          <span className="text-gray-400">Started:</span>
                          <span className="text-white">{new Date(selectedScan.started).toLocaleString()}</span>
                        </div>
                      )}
                      {selectedScan.finished && (
                        <div className="flex justify-between">
                          <span className="text-gray-400">Finished:</span>
                          <span className="text-white">{new Date(selectedScan.finished).toLocaleString()}</span>
                        </div>
                      )}
                      {selectedScan.duration && (
                        <div className="flex justify-between">
                          <span className="text-gray-400">Duration:</span>
                          <span className="text-white">{selectedScan.duration}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Artifacts */}
                  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <h4 className="text-sm font-medium text-gray-300 mb-3">Artifacts</h4>
                    {scanArtifacts.length > 0 ? (
                      <div className="space-y-2">
                        {scanArtifacts.map((artifact, index) => (
                          <div key={index} className="flex items-center justify-between p-2 bg-gray-700 rounded">
                            <div>
                              <div className="text-sm text-white">{artifact.name}</div>
                              <div className="text-xs text-gray-400">{artifact.type}</div>
                            </div>
                            <Button size="sm" variant="outline">
                              Download
                            </Button>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-gray-500 text-sm">No artifacts available</div>
                    )}
                  </div>

                  {/* Findings Summary */}
                  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <h4 className="text-sm font-medium text-gray-300 mb-3">Findings Summary</h4>
                    <div className="grid grid-cols-2 gap-2">
                      {['Critical', 'High', 'Medium', 'Low'].map((severity) => {
                        const count = selectedScan[severity.toLowerCase() as keyof Scan] as number || 0
                        return (
                          <div key={severity} className="text-center">
                            <div className={`text-lg font-bold ${
                              severity === 'Critical' ? 'text-red-400' :
                              severity === 'High' ? 'text-orange-400' :
                              severity === 'Medium' ? 'text-yellow-400' : 'text-blue-400'
                            }`}>
                              {count}
                            </div>
                            <div className="text-xs text-gray-400">{severity}</div>
                          </div>
                        )
                      })}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <h4 className="text-sm font-medium text-gray-300 mb-3">Actions</h4>
                    <div className="space-y-2">
                      <Button className="w-full" variant="outline">
                        Export Results
                      </Button>
                      <Button className="w-full" variant="outline">
                        Download All Artifacts
                      </Button>
                      {selectedScan.status === 'running' && (
                        <Button
                          className="w-full"
                          variant="outline"
                          onClick={() => handleStopScan(selectedScan.id)}
                        >
                          Stop Scan
                        </Button>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}

export default ScansPage
