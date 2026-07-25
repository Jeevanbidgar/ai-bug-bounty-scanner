import { useState, useEffect } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Eye,
  Download,
  Loader2,
  Square,
  X
} from 'lucide-react'
import { Button } from './ui/Button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/Card'
import { Badge } from './ui/Badge'

import type { Scan, WorkflowArtifact, WorkflowTemplate } from '../services/api'
import { apiService } from '../services/api'
import { useScanEvents } from '../hooks/useScanEvents'
import { useWorkflowEvents } from '../hooks/useWorkflowEvents'
import { useNotificationStore } from '../stores/notificationStore'

interface ScanDetailsModalProps {
  scan: Scan
  workflowTemplates: WorkflowTemplate[] | undefined
  onClose: () => void
}

export const ScanDetailsModal = ({ scan, workflowTemplates, onClose }: ScanDetailsModalProps) => {
  const queryClient = useQueryClient()
  const [scanLogs, setScanLogs] = useState<string[]>([])
  const [scanArtifacts, setScanArtifacts] = useState<WorkflowArtifact[]>([])
  const [scanFindings, setScanFindings] = useState<any[]>([])
  const [liveStatus, setLiveStatus] = useState(scan.status)
  const [liveProgress, setLiveProgress] = useState(scan.progress)
  const [actionError, setActionError] = useState<string | null>(null)
  const addNotification = useNotificationStore((state) => state.addNotification)

  // Fetch scan details
  const { data: scanDetails, isLoading: isLoadingDetails, error: detailsError, refetch: refetchDetails } = useQuery({
    queryKey: ['scan-details', scan.id],
    queryFn: async () => {
      if (scan.status.toLowerCase() === 'pending') {
        return { execution: null, artifacts: [], findings: [] }
      }
      const executionResponse = await apiService.getWorkflowStatus(scan.id)
      const [artifactsResponse, findingsResponse] = await Promise.all([
        apiService.getExecutionArtifacts(scan.id),
        apiService.getExecutionFindings(scan.id)
      ])
      return {
        execution: executionResponse,
        artifacts: Array.isArray(artifactsResponse) ? artifactsResponse : [],
        findings: Array.isArray(findingsResponse) ? findingsResponse : []
      }
    },
    enabled: !!scan.id
  })

  // Set up workflow event listeners for real-time updates
  useWorkflowEvents(scanDetails?.execution?.execution_id ?? null, {
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
      setScanLogs(prev => [...prev, `[STEP COMPLETED] ${data.step_name}`])
    },
    onStepFailed: (data) => {
      setScanLogs(prev => [...prev, `[STEP FAILED] ${data.step_id}: ${data.error}`])
    },
    onExecutionCompleted: () => {
      setScanLogs(prev => [...prev, `[EXECUTION COMPLETED]`])
    },
    onExecutionFailed: () => {
      setScanLogs(prev => [...prev, '[EXECUTION FAILED] See the step error above for details.'])
    }
  })

  useScanEvents({
    onScanStarted: () => setLiveStatus('running'),
    onProgressUpdate: (event) => {
      setLiveStatus(event.status)
      setLiveProgress(event.progress)
    },
    onScanCompleted: () => {
      setLiveStatus('completed')
      setLiveProgress(100)
      refetchDetails()
    },
    onScanFailed: () => {
      setLiveStatus('failed')
      refetchDetails()
    },
    onScanCancelled: () => {
      setLiveStatus('cancelled')
      refetchDetails()
    }
  }, scan.id)

  // Update state when details are loaded
  useEffect(() => {
    if (scanDetails) {
      setScanArtifacts(scanDetails.artifacts)
      setScanFindings(scanDetails.findings)
      setScanLogs(scanDetails.execution?.logs ?? [])
    }
  }, [scanDetails])

  useEffect(() => {
    setLiveStatus(scan.status)
    setLiveProgress(scan.progress)
  }, [scan.id, scan.progress, scan.status])

  const stopMutation = useMutation({
    mutationFn: () => apiService.stopScan(scan.id),
    onSuccess: () => {
      setActionError(null)
      setLiveStatus('cancelled')
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      queryClient.invalidateQueries({ queryKey: ['scan-details', scan.id] })
      addNotification({ level: 'warning', title: 'Stop requested', message: `UniHack is stopping ${scan.name || scan.target} and retaining completed evidence.`, href: '/scans', actionLabel: 'Open scans' })
    },
    onError: (error) => setActionError(String(error))
  })

  const exportMutation = useMutation({
    mutationFn: async () => {
      const report = await apiService.createReport({ scanId: scan.id, format: 'html' })
      await apiService.revealReport(report.id)
      return report
    },
    onSuccess: () => {
      setActionError(null)
      queryClient.invalidateQueries({ queryKey: ['reports'] })
      addNotification({ level: 'success', title: 'Report generated', message: `An HTML evidence report for ${scan.name || scan.target} is ready.`, href: '/reports', actionLabel: 'Open reports' })
    },
    onError: (error) => setActionError(String(error))
  })

  useEffect(() => {
    const close = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !stopMutation.isPending && !exportMutation.isPending) onClose()
    }
    window.addEventListener('keydown', close)
    return () => window.removeEventListener('keydown', close)
  }, [exportMutation.isPending, onClose, stopMutation.isPending])

  const revealArtifact = async (artifactId: string) => {
    setActionError(null)
    try {
      await apiService.revealWorkflowArtifact(scan.id, artifactId)
      addNotification({ level: 'info', title: 'Artifact revealed', message: 'The managed evidence file was opened in the system file manager.' })
    } catch (error) {
      setActionError(String(error))
    }
  }

  const revealResults = async () => {
    setActionError(null)
    try {
      await apiService.revealScanResults(scan.id)
      addNotification({ level: 'info', title: 'Results folder opened', message: `Managed results for ${scan.name || scan.target} were opened.` })
    } catch (error) {
      setActionError(String(error))
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
    <div
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="scan-details-title"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !stopMutation.isPending && !exportMutation.isPending) onClose()
      }}
    >
      <Card className="w-full max-w-4xl bg-gray-900 border-gray-700 max-h-[90vh] overflow-hidden flex flex-col">
        <CardHeader className="flex-shrink-0">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle id="scan-details-title" className="flex items-center gap-2 text-blue-400">
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
            <Button variant="outline" onClick={onClose} aria-label="Close scan details" disabled={stopMutation.isPending || exportMutation.isPending}>
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
                  <Badge className={getStatusBadgeColor(liveStatus)}>
                    {liveStatus.charAt(0).toUpperCase() + liveStatus.slice(1)}
                  </Badge>
                  {liveProgress !== undefined && (
                    <span className="text-sm text-gray-400">
                      {liveProgress}%
                    </span>
                  )}
                </div>
              </div>

              <div className="flex-1 bg-gray-800 rounded-lg p-4 overflow-y-auto border border-gray-700">
                {detailsError ? (
                  <div className="grid h-full min-h-36 place-items-center text-center" role="alert">
                    <div>
                      <p className="text-sm font-medium text-red-300">Evidence could not be loaded</p>
                      <p className="mt-2 max-w-md text-xs text-gray-500">{detailsError.message}</p>
                      <Button className="mt-3" size="sm" variant="outline" onClick={() => refetchDetails()}>Try again</Button>
                    </div>
                  </div>
                ) : scanLogs.length > 0 ? (
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
                    <Badge className={getStatusBadgeColor(liveStatus)}>
                      {liveStatus}
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
                          <div className="text-xs text-gray-400">{artifact.artifact_type}</div>
                        </div>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => revealArtifact(artifact.id)}
                          title="Reveal artifact in the system file manager"
                        >
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
                <h4 className="text-sm font-medium text-gray-300 mb-3">
                  Findings Summary ({scanFindings.length})
                </h4>
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
                  {actionError && (
                    <p className="rounded bg-red-950 p-2 text-xs text-red-300">{actionError}</p>
                  )}
                  <Button
                    className="w-full"
                    variant="outline"
                    disabled={exportMutation.isPending}
                    onClick={() => exportMutation.mutate()}
                  >
                    {exportMutation.isPending ? 'Generating…' : 'Generate HTML Report'}
                  </Button>
                  <Button className="w-full" variant="outline" onClick={revealResults}>
                    Reveal Results Folder
                  </Button>
                  {liveStatus === 'running' && (
                    <Button
                      className="w-full"
                      variant="outline"
                      disabled={stopMutation.isPending}
                      onClick={() => stopMutation.mutate()}
                    >
                      {stopMutation.isPending
                        ? <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        : <Square className="h-4 w-4 mr-2" />}
                      {stopMutation.isPending ? 'Stopping…' : 'Stop Scan'}
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
