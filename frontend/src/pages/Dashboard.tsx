import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingUp,
  Zap,
  Play,
  RefreshCw,
  Settings,
  Zap as Lightning,
  Target,
  Database,
  Cpu,
  HardDrive,
  Workflow,
  AlertCircle,
  Loader2
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Input } from '../components/ui/Input'
import { Progress } from '../components/ui/Progress'
import { Badge } from '../components/ui/Badge'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/Select'
import { WorkflowDetailsModal } from '../components/WorkflowDetailsModal'
import { useState, useEffect } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { useNavigate } from 'react-router-dom'
import apiService, { WorkflowTemplate } from '../services/api'
import { useWorkflowEvents } from '../hooks/useWorkflowEvents'

// Types for Rust integration
interface SystemInfo {
  os: string;
  arch: string;
  total_memory_mb: string;
  available_memory_mb: string;
  cpu_cores: string;
}

interface SystemMetrics {
  total_scans: number;
  active_scans: number;
  completed_scans: number;
  total_vulnerabilities: number;
  critical_issues: number;
  tools_available: number;
  tools_total: number;
  tools_unavailable: number;
  system_health: string;
  health_details: {
    scan_capacity: string;
    tool_availability: string;
    database: string;
  };
}

// ToolInfo interface removed - using the one from Rust backend

const Dashboard = () => {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [targetUrl, setTargetUrl] = useState('')
  const [selectedWorkflow, setSelectedWorkflow] = useState<string>('')
  const [selectedWorkflowDetails, setSelectedWorkflowDetails] = useState<WorkflowTemplate | null>(null)
  const [isWorkflowModalOpen, setIsWorkflowModalOpen] = useState(false)
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null)

  // Fetch data using our API service and Rust backend
  const { data: health, error: healthError } = useQuery({
    queryKey: ['health'],
    queryFn: () => apiService.getHealth(),
    refetchInterval: 10000,
  })

  const { data: scansResponse, isLoading: scansLoading, error: scansError } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const response = await apiService.getScans()
      return response.data || []
    },
    refetchInterval: 5000,
  })

  const scans = Array.isArray(scansResponse) ? scansResponse : []

  const { data: toolsResponse, error: toolsError } = useQuery({
    queryKey: ['tools'],
    queryFn: async () => {
      const response = await apiService.getTools()
      return response.data || []
    },
    refetchInterval: 30000,
  })

  const tools = Array.isArray(toolsResponse) ? toolsResponse : []

  // Fetch workflow templates with compatibility info
  const { data: workflowTemplatesResponse, error: workflowsError } = useQuery({
    queryKey: ['workflow-templates'],
    queryFn: async () => {
      const response = await apiService.getWorkflowTemplates(true) // Check compatibility
      return (response as any).data || []
    },
    retry: 3,
  })

  const workflowTemplates: WorkflowTemplate[] = Array.isArray(workflowTemplatesResponse) ? workflowTemplatesResponse : []

  // Fetch system metrics
  const { data: systemMetrics } = useQuery({
    queryKey: ['system-metrics'],
    queryFn: async () => {
      const response = await apiService.getSystemMetrics()
      return (response as any).data
    },
    refetchInterval: 30000, // Update every 30 seconds
  })

  // Workflow execution mutation
  const workflowMutation = useMutation({
    mutationFn: async ({ workflowId, inputs }: { workflowId: string, inputs: Record<string, string> }) => {
      const response = await apiService.executeWorkflow(workflowId, inputs)
      return (response as any).data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      // Navigate to scans page to see the execution
      navigate('/scans')
    },
    onError: (error) => {
      console.error('Workflow execution failed:', error)
    }
  })

  // Rust backend integration
  useEffect(() => {
    const loadSystemInfo = async () => {
      try {
        const info = await invoke<SystemInfo>('get_system_info')
        setSystemInfo(info)
      } catch (error) {
        console.error('Failed to load system info:', error)
      }
    }

    loadSystemInfo()

    // Refresh every 30 seconds
    const interval = setInterval(() => {
      loadSystemInfo()
    }, 30000)

    return () => clearInterval(interval)
  }, [])

  // Listen to workflow events for real-time updates
  useWorkflowEvents(null, {
    onExecutionStarted: (event) => {
      console.log('📡 Workflow started:', event.execution_id)
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
    onStatusUpdate: (event) => {
      console.log('📊 Workflow progress:', event.execution_id, `${event.progress}%`)
      // Update scan progress in cache
      queryClient.setQueryData(['scans'], (oldData: any) => {
        if (!Array.isArray(oldData)) return oldData
        return oldData.map((scan: any) =>
          scan.id === event.execution_id
            ? { ...scan, progress: event.progress, status: event.status }
            : scan
        )
      })
    },
    onExecutionCompleted: (event) => {
      console.log('✅ Workflow completed:', event.execution_id)
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
    onExecutionFailed: (event) => {
      console.log('❌ Workflow failed:', event.execution_id)
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
    onStepStarted: (event) => {
      console.log('🔧 Step started:', event.step_name)
    },
    onStepCompleted: (event) => {
      console.log('✓ Step completed:', event.step_name)
    }
  })

  const handleWorkflowExecution = () => {
    if (targetUrl.trim() && selectedWorkflow) {
      const inputs = {
        target: targetUrl.trim(),
        workdir: `./results/${targetUrl.trim().replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}`
      }
      workflowMutation.mutate({ workflowId: selectedWorkflow, inputs })
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'running': return <Activity className="h-4 w-4 animate-pulse text-blue-500" />
      case 'completed': return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'failed': return <AlertTriangle className="h-4 w-4 text-red-500" />
      case 'pending': return <Clock className="h-4 w-4 text-yellow-500" />
      default: return <Clock className="h-4 w-4 text-gray-500" />
    }
  }

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'N/A'
    return new Date(dateString).toLocaleString()
  }

  return (
    <div className="space-y-6">
      {/* Enhanced Header - Fixed Layout */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="relative flex-shrink-0">
            <Shield className="h-10 w-10 text-blue-500" />
            <div className="absolute -top-1 -right-1 w-3 h-3 bg-green-500 rounded-full animate-pulse" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-3xl font-bold text-white">
                UniHack
              </h1>
              <Badge className="bg-green-600 hover:bg-green-700 text-xs inline-flex items-center">
                <Lightning className="h-3 w-3 mr-1" />
                Online
              </Badge>
            </div>
            <p className="text-gray-400 mt-1 text-sm">
              Intelligent security tool orchestration platform
            </p>
          </div>
        </div>

        {/* System Status */}
        <div className="flex items-center gap-4 lg:gap-6">
          <div className="flex flex-col items-center px-3 py-2 bg-gray-800 rounded-lg border border-gray-700">
            <div className="text-xs text-gray-400 mb-1">Health</div>
            <div className="flex items-center gap-1.5">
              <div className={`w-2 h-2 rounded-full ${health?.data ? 'bg-green-500' : 'bg-red-500'}`} />
              <span className="text-white font-medium text-sm">
                {health?.data ? 'Online' : 'Offline'}
              </span>
            </div>
          </div>

          {systemMetrics && (
            <div className="flex flex-col items-center px-3 py-2 bg-gray-800 rounded-lg border border-gray-700">
              <div className="text-xs text-gray-400 mb-1">Active Scans</div>
              <div className="text-white font-medium text-sm flex items-center gap-1">
                <Activity className="h-3.5 w-3.5" />
                {systemMetrics.active_scans}
              </div>
            </div>
          )}

          {systemMetrics && (
            <div className="flex flex-col items-center px-3 py-2 bg-gray-800 rounded-lg border border-gray-700">
              <div className="text-xs text-gray-400 mb-1">Available Tools</div>
              <div className="text-white font-medium text-sm flex items-center gap-1">
                <Zap className="h-3.5 w-3.5" />
                {systemMetrics.tools_available}/{systemMetrics.tools_total}
              </div>
            </div>
          )}

          {systemInfo && (
            <div className="flex flex-col items-center px-3 py-2 bg-gray-800 rounded-lg border border-gray-700">
              <div className="text-xs text-gray-400 mb-1">CPU</div>
              <div className="text-white font-medium text-sm flex items-center gap-1">
                <Cpu className="h-3.5 w-3.5" />
                {systemInfo.cpu_cores} cores
              </div>
            </div>
          )}

          {systemInfo && (
            <div className="flex flex-col items-center px-3 py-2 bg-gray-800 rounded-lg border border-gray-700">
              <div className="text-xs text-gray-400 mb-1">Memory</div>
              <div className="text-white font-medium text-sm flex items-center gap-1">
                <HardDrive className="h-3.5 w-3.5" />
                {Math.round(parseInt(systemInfo.available_memory_mb) / 1024)}GB free
              </div>
            </div>
          )}

          {systemMetrics && (
            <div className="flex flex-col items-center px-3 py-2 bg-gray-800 rounded-lg border border-gray-700">
              <div className="text-xs text-gray-400 mb-1">System Health</div>
              <div className="flex items-center gap-1.5">
                <div className={`w-2 h-2 rounded-full ${
                  systemMetrics.system_health === 'healthy' ? 'bg-green-500' :
                  systemMetrics.system_health === 'warning' ? 'bg-yellow-500' : 'bg-red-500'
                }`} />
                <span className="text-white font-medium text-sm capitalize">
                  {systemMetrics.system_health}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Quick Workflow Execution Card - Enhanced Design */}
      {(healthError || scansError || toolsError || workflowsError) && (
        <Card className="bg-red-900/20 border-red-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-5 w-5" />
              Connection Issues Detected
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {healthError && (
              <p className="text-red-300 text-sm">
                <strong>Health:</strong> {healthError instanceof Error ? healthError.message : 'Failed to load'}
              </p>
            )}
            {scansError && (
              <p className="text-red-300 text-sm">
                <strong>Scans:</strong> {scansError instanceof Error ? scansError.message : 'Failed to load'}
              </p>
            )}
            {toolsError && (
              <p className="text-red-300 text-sm">
                <strong>Tools:</strong> {toolsError instanceof Error ? toolsError.message : 'Failed to load'}
              </p>
            )}
            {workflowsError && (
              <p className="text-red-300 text-sm">
                <strong>Workflows:</strong> {workflowsError instanceof Error ? workflowsError.message : 'Failed to load'}
              </p>
            )}
          </CardContent>
        </Card>
      )}

      <Card className="border-blue-500/30 bg-gradient-to-br from-gray-800 to-gray-900 shadow-xl">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-blue-400 text-lg">
            <Workflow className="h-5 w-5" />
            Quick Workflow Execution
          </CardTitle>
          <CardDescription className="text-gray-400">
            Select a workflow template and target to execute security scanning workflows
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Workflow Template Selection */}
          <div className="space-y-2">
            <label className="text-sm font-medium text-gray-300">Workflow Template</label>
                     <Select value={selectedWorkflow} onValueChange={setSelectedWorkflow}>
                      <SelectTrigger className="h-11 bg-gray-900 border-gray-700 text-white">
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

          {/* Target Input */}
          <div className="space-y-2">
            <label className="text-sm font-medium text-gray-300">Target Domain</label>
            <div className="flex gap-3">
              <Input
                placeholder="example.com"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                className="h-11 bg-gray-900 border-gray-700 focus:border-blue-500 text-white placeholder-gray-500 flex-1"
                onKeyPress={(e) => e.key === 'Enter' && handleWorkflowExecution()}
              />
              <Button
                onClick={handleWorkflowExecution}
                disabled={!targetUrl.trim() || !selectedWorkflow || workflowMutation.isPending}
                className="h-11 px-6 bg-blue-600 hover:bg-blue-700 text-white font-medium whitespace-nowrap"
              >
                {workflowMutation.isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />
                    Executing...
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4 mr-2" />
                    Execute Workflow
                  </>
                )}
              </Button>
            </div>
          </div>

                   {/* Workflow Preview */}
                  {selectedWorkflow && workflowTemplates && (
                    <div className="p-3 bg-gray-900 rounded-lg border border-gray-700">
                      <div className="text-xs text-gray-400 mb-2">Workflow Steps:</div>
                      <div className="flex gap-2 flex-wrap">
                        {workflowTemplates.find((t: WorkflowTemplate) => t.id === selectedWorkflow)?.steps.map((step) => (
                          <Badge key={step.id} className="bg-green-600 text-xs">
                            {step.name}
                          </Badge>
                        ))}
                      </div>
                      
                      {/* Tool Requirements */}
                      {(() => {
                        const workflow = workflowTemplates.find((t: WorkflowTemplate) => t.id === selectedWorkflow)
                        const compatibility = workflow?.compatibility
                        
                        if (compatibility) {
                          return (
                            <div className="mt-3 pt-3 border-t border-gray-700">
                              <div className="text-xs text-gray-400 mb-2">Required Tools:</div>
                              <div className="flex gap-2 flex-wrap">
                                {compatibility.required_tools.map((tool) => {
                                  const isAvailable = compatibility.available_tools.includes(tool)
                                  return (
                                    <Badge 
                                      key={tool} 
                                      className={`text-xs ${isAvailable ? 'bg-green-600' : 'bg-red-600'}`}
                                    >
                                      {isAvailable ? '✓' : '✗'} {tool}
                                    </Badge>
                                  )
                                })}
                              </div>
                              {compatibility.missing_tools.length > 0 && (
                                <div className="text-xs text-red-400 mt-2">
                                  ⚠️ Missing tools: {compatibility.missing_tools.join(', ')}. Please install them to use this workflow.
                                </div>
                              )}
                            </div>
                          )
                        }
                        return null
                      })()}
                      
                      <div className="text-xs text-gray-500 mt-2">
                        Target: {targetUrl || 'example.com'} | Workdir: ./results/{targetUrl?.replace(/[^a-zA-Z0-9]/g, '_') || 'example_com'}_{Date.now()}
                      </div>
                    </div>
                  )}

          {/* Error Display */}
          {workflowMutation.error && (
            <div className="p-3 bg-red-900/20 border border-red-500 rounded-lg">
              <div className="flex items-center gap-2 text-red-400">
                <AlertCircle className="h-4 w-4" />
                <span className="text-sm">
                  Workflow execution failed: {(workflowMutation.error as Error).message || 'Unknown error'}
                </span>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Enhanced Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-gradient-to-br from-gray-800 to-gray-900 border-gray-700">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-gray-300">Total Scans</CardTitle>
            <Database className="h-4 w-4 text-blue-400 flex-shrink-0" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">
              {scansLoading ? '...' : (scans.length || 0)}
            </div>
            <p className="text-xs text-gray-400 mt-1">
              Security assessments
            </p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-gray-800 to-gray-900 border-gray-700">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-gray-300">Tools</CardTitle>
            <Zap className="h-4 w-4 text-green-400 flex-shrink-0" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">
              {tools.filter((tool: any) => tool.installed).length}
            </div>
            <p className="text-xs text-gray-400 mt-1">
              {tools.length} total discovered
            </p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-gray-800 to-gray-900 border-gray-700">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-gray-300">Health</CardTitle>
            <Activity className="h-4 w-4 text-green-400 flex-shrink-0" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">
              {health?.data ? 'Online' : 'Offline'}
            </div>
            <p className="text-xs text-gray-400 mt-1">
              Backend API status
            </p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-gray-800 to-gray-900 border-gray-700">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-gray-300">Active</CardTitle>
            <Clock className="h-4 w-4 text-orange-400 flex-shrink-0" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">
              {scans.filter((scan: any) => scan.status === 'running').length}
            </div>
            <p className="text-xs text-gray-400 mt-1">
              Currently executing
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Recent Scans - Enhanced */}
        <Card className="bg-gray-800 border-gray-700">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-lg">
              <TrendingUp className="h-5 w-5 text-blue-400" />
              Recent Scans
            </CardTitle>
            <CardDescription className="text-sm">
              Latest security scan results
            </CardDescription>
          </CardHeader>
          <CardContent>
            {scansLoading ? (
              <div className="space-y-3">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="animate-pulse">
                    <div className="h-20 bg-gray-700 rounded-lg"></div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="space-y-3">
                {scans.slice(0, 5).map((scan: any) => (
                  <div key={scan.id} className="p-3 bg-gray-900 rounded-lg border border-gray-700 hover:border-gray-600 transition-colors">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2 min-w-0 flex-1">
                        {getStatusIcon(scan.status)}
                        <div className="min-w-0">
                          <span className="font-medium text-white text-sm block truncate">{scan.target}</span>
                          <div className="text-xs text-gray-400">ID: {scan.id.slice(0, 8)}...</div>
                        </div>
                      </div>
                      <Badge className={`text-xs flex-shrink-0 ml-2 ${
                        scan.status === 'completed' ? 'bg-green-600' :
                        scan.status === 'running' ? 'bg-blue-600' :
                        scan.status === 'failed' ? 'bg-red-600' : 'bg-yellow-600'
                      }`}>
                        {scan.status}
                      </Badge>
                    </div>

                    <div className="space-y-1.5">
                      <div className="flex justify-between text-xs">
                        <span className="text-gray-400">Progress</span>
                        <span className="text-white font-medium">{scan.progress}%</span>
                      </div>
                      <Progress value={scan.progress} className="h-1.5" />

                      <div className="flex justify-between text-xs text-gray-400 pt-1">
                        <span>{formatDate(scan.started_at)}</span>
                        {scan.findings_count && (
                          <span className="text-blue-400">{scan.findings_count} findings</span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}

                {scans.length === 0 && (
                  <div className="text-center text-gray-400 py-8">
                    <Target className="h-10 w-10 mx-auto mb-3 opacity-50" />
                    <h3 className="text-base font-medium text-white mb-1">No scans yet</h3>
                    <p className="text-xs">Start your first scan above!</p>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Available Workflows - Show compatibility status */}
        <Card className="bg-gray-800 border-gray-700">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-lg">
              <Workflow className="h-5 w-5 text-purple-400" />
              Available Workflows
            </CardTitle>
            <CardDescription className="text-sm">
              Workflows and their tool requirements
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {workflowTemplates.length > 0 ? (
                workflowTemplates.map((workflow: WorkflowTemplate) => {
                  // Check if workflow has compatibility info
                  const hasCompatibility = workflow.compatibility !== undefined
                  const isCompatible = hasCompatibility ? workflow.compatibility.compatible : false
                  const missingTools = hasCompatibility ? workflow.compatibility.missing_tools : []
                  const requiredTools = hasCompatibility ? workflow.compatibility.required_tools.length : 0
                  const availableToolsCount = hasCompatibility ? workflow.compatibility.available_tools.length : 0

                  return (
                    <div 
                      key={workflow.id} 
                      className={`flex items-center justify-between p-2.5 bg-gray-900 rounded-lg border transition-colors cursor-pointer ${
                        isCompatible 
                          ? 'border-green-700 hover:border-green-600 hover:bg-gray-850' 
                          : 'border-gray-700 hover:border-gray-600 hover:bg-gray-850'
                      }`}
                      onClick={() => {
                        setSelectedWorkflowDetails(workflow)
                        setIsWorkflowModalOpen(true)
                      }}
                    >
                      <div className="flex items-center gap-2.5 min-w-0 flex-1">
                        <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
                          isCompatible ? 'bg-green-500' : 'bg-red-500'
                        }`} />
                        <div className="min-w-0">
                          <div className="font-medium text-white text-sm truncate">{workflow.name}</div>
                          <div className="text-xs text-gray-400 truncate">
                            {isCompatible ? (
                              <span className="text-green-400">✓ All tools available</span>
                            ) : (
                              <span className="text-red-400">
                                Missing: {missingTools.slice(0, 2).join(', ')}
                                {missingTools.length > 2 && ` +${missingTools.length - 2} more`}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0 ml-2">
                        <Badge className={`text-xs ${
                          isCompatible ? 'bg-green-600' : 'bg-red-600/70'
                        }`}>
                          {hasCompatibility ? `${availableToolsCount}/${requiredTools}` : 'N/A'}
                        </Badge>
                        {isCompatible && (
                          <Play className="h-4 w-4 text-green-400" />
                        )}
                      </div>
                    </div>
                  )
                })
              ) : (
                <div className="text-center text-gray-400 py-8">
                  <Workflow className="h-10 w-10 mx-auto mb-3 opacity-50" />
                  <p className="text-xs">No workflows found</p>
                  <Button 
                    variant="outline" 
                    size="sm" 
                    className="mt-3 text-xs"
                    onClick={() => queryClient.invalidateQueries({ queryKey: ['workflow-templates'] })}
                  >
                    <RefreshCw className="h-3 w-3 mr-1.5" />
                    Refresh Workflows
                  </Button>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Enhanced Features Overview */}
      <Card className="bg-gradient-to-br from-gray-800 to-gray-900 border-gray-700">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-lg">
            <Lightning className="h-5 w-5 text-yellow-400" />
            Agent-Based Security Scanning
          </CardTitle>
          <CardDescription className="text-sm">
            Intelligent workflows that orchestrate security tools automatically
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="text-center p-4 bg-blue-500/10 rounded-lg border border-blue-500/20">
              <Shield className="h-8 w-8 text-blue-400 mx-auto mb-2" />
              <div className="font-semibold text-white text-sm mb-1">Reconnaissance</div>
              <div className="text-xs text-gray-400">
                Subdomain discovery, port scanning, service enumeration
              </div>
            </div>

            <div className="text-center p-4 bg-green-500/10 rounded-lg border border-green-500/20">
              <CheckCircle className="h-8 w-8 text-green-400 mx-auto mb-2" />
              <div className="font-semibold text-white text-sm mb-1">Vulnerability Assessment</div>
              <div className="text-xs text-gray-400">
                CVE scanning, misconfiguration detection, web vulnerabilities
              </div>
            </div>

            <div className="text-center p-4 bg-purple-500/10 rounded-lg border border-purple-500/20">
              <TrendingUp className="h-8 w-8 text-purple-400 mx-auto mb-2" />
              <div className="font-semibold text-white text-sm mb-1">Intelligent Reporting</div>
              <div className="text-xs text-gray-400">
                Automated report generation with risk scoring
              </div>
            </div>
          </div>

          {/* Workflow Preview */}
          <div className="p-3 bg-gray-900 rounded-lg border border-gray-700">
            <div className="text-xs text-gray-400 mb-2">Sample Workflow:</div>
            <div className="flex items-center gap-2 flex-wrap">
              <Badge className="bg-blue-600 text-xs">subfinder</Badge>
              <span className="text-gray-500 text-xs">→</span>
              <Badge className="bg-green-600 text-xs">amass</Badge>
              <span className="text-gray-500 text-xs">→</span>
              <Badge className="bg-purple-600 text-xs">nuclei</Badge>
              <span className="text-gray-500 text-xs">→</span>
              <Badge className="bg-orange-600 text-xs">Report</Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Workflow Details Modal */}
      <WorkflowDetailsModal
        workflow={selectedWorkflowDetails}
        isOpen={isWorkflowModalOpen}
        onClose={() => {
          setIsWorkflowModalOpen(false)
          setSelectedWorkflowDetails(null)
        }}
      />
    </div>
  )
}

export default Dashboard
