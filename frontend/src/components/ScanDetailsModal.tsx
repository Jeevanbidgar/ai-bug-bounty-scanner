import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Eye,
  Clock,
  Download,
  AlertCircle,
  CheckCircle,
  Loader2,
  Play,
  Square,
  X
} from 'lucide-react'
import { Button } from './ui/Button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/Card'
import { Badge } from './ui/Badge'
import { Progress } from './ui/Progress'

import type { Scan, WorkflowTemplate } from '../services/api'
import { apiService } from '../services/api'
import { useWorkflowEvents } from '../hooks/useWorkflowEvents'

interface ScanDetailsModalProps {
  scan: Scan
  workflowTemplates: WorkflowTemplate[] | undefined
  onClose: () => void
}

export const ScanDetailsModal = ({ scan, workflowTemplates, onClose }: ScanDetailsModalProps) => {
  const [scanLogs, setScanLogs] = useState<string[]>([])
  const [scanArtifacts, setScanArtifacts] = useState<any[]>([])
  const [scanFindings, setScanFindings] = useState<any[]>([])

  // Fetch scan details
  const { data: scanDetails, isLoading: isLoadingDetails } = useQuery({
    queryKey: ['scan-details', scan.id],
    queryFn: async () => {
      const [artifactsResponse, findingsResponse] = await Promise.all([
        apiService.getExecutionArtifacts(scan.id),
        apiService.getExecutionFindings(scan.id)
      ])
      return {
        artifacts: Array.isArray(artifactsResponse) ? artifactsResponse : [],
        findings: Array.isArray(findingsResponse) ? findingsResponse : []
      }
    },
    enabled: !!scan.id
  })

  // Set up workflow event listeners for real-time updates
  const { isListening } = useWorkflowEvents(scan.id, {
    onStdout: (data) => {
      setScanLogs(prev => [...prev, data.line])
    },
    onStderr: (data) => {
      setScanLogs(prev => [...prev, `[ERROR] ${data.line}`])
    },
    onStepStarted: (data) => {
      setScanLogs(prev => [...prev, `[STEP STARTED] ${data.step_name}`])
    },
    onStepCompleted: (data) => {
      setScanLogs(prev => [...prev, `[STEP COMPLETED] ${data.step_id}`])
    },
    onStepFailed: (data) => {
      setScanLogs(prev => [...prev, `[STEP FAILED] ${data.step_id}: ${data.error}`])
    },
    onExecutionCompleted: () => {
      setScanLogs(prev => [...prev, `[EXECUTION COMPLETED]`])
    },
    onExecutionFailed: (data) => {
      setScanLogs(prev => [...prev, `[EXECUTION FAILED] ${data.failed_steps.join(', ')}`])
    }
  })

  // Update state when details are loaded
  useEffect(() => {
    if (scanDetails) {
      setScanArtifacts(scanDetails.artifacts)
      setScanFindings(scanDetails.findings)
    }
  }, [scanDetails])

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

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <Card className="w-full max-w-4xl bg-gray-900 border-gray-700 max-h-[90vh] overflow-hidden flex flex-col">
        <CardHeader className="flex-shrink-0">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2 text-blue-400">
                <Eye className="h-5 w-5" />
                Scan Details: {scan.name || scan.target}
              </CardTitle>
              <CardDescription className="text-gray-400">
                {scan.workflow_id ?
                  `Workflow: ${workflowTemplates?.find(w => w.id === scan.workflow_id)?.name || scan.workflow_id}` :
                  (scan.scan_type || 'Custom Scan')
                }
              </CardDescription>
            </div>
            <Button variant="outline" onClick={onClose}>
              <X className="h-4 w-4" />
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
                  <Badge className={getStatusBadgeColor(scan.status)}>
                    {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
                  </Badge>
                  {scan.progress !== undefined && (
                    <span className="text-sm text-gray-400">
                      {scan.progress}%
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
                    {isLoadingDetails ? (
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
                    <span className="text-white truncate">{scan.target}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Status:</span>
                    <Badge className={getStatusBadgeColor(scan.status)}>
                      {scan.status}
                    </Badge>
                  </div>
                  {scan.started && (
                    <div className="flex justify-between">
                      <span className="text-gray-400">Started:</span>
                      <span className="text-white">{new Date(scan.started).toLocaleString()}</span>
                    </div>
                  )}
                  {scan.completed && (
                    <div className="flex justify-between">
                      <span className="text-gray-400">Finished:</span>
                      <span className="text-white">{new Date(scan.completed).toLocaleString()}</span>
                    </div>
                  )}
                  {scan.duration && (
                    <div className="flex justify-between">
                      <span className="text-gray-400">Duration:</span>
                      <span className="text-white">{scan.duration}</span>
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
                          <Download className="h-4 w-4" />
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
                    const count = scan[severity.toLowerCase() as keyof Scan] as number || 0
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
                  {scan.status === 'running' && (
                    <Button
                      className="w-full"
                      variant="outline"
                      onClick={() => {
                        // Handle stop scan
                        console.log('Stopping scan:', scan.id)
                      }}
                    >
                      <Square className="h-4 w-4 mr-2" />
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
  )
}
