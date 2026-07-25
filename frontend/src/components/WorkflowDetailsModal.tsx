import React, { useState, useEffect, useCallback } from 'react'
import { Badge } from './ui/Badge'
import { Button } from './ui/Button'
import { CheckCircle2, XCircle, ArrowRight, Workflow, Clock, Package, X, Loader2 } from 'lucide-react'
import { WorkflowTemplate, apiService } from '../services/api'
import { useNavigate } from 'react-router-dom'

interface WorkflowDetailsModalProps {
  workflow: WorkflowTemplate | null
  isOpen: boolean
  onClose: () => void
}

interface WorkflowDetails {
  id: string
  name: string
  description: string
  category: string
  inputs: Record<string, string>
  steps: Array<{
    id: string
    name: string
    description: string
    run: string[]
    needs: string[]
    timeout: number
  }>
  compatibility: {
    compatible: boolean
    required_tools: string[]
    available_tools: string[]
    missing_tools: string[]
    compatibility_percentage: number
    warnings: string[]
  }
}

export function WorkflowDetailsModal({ workflow, isOpen, onClose }: WorkflowDetailsModalProps) {
  const [workflowDetails, setWorkflowDetails] = useState<WorkflowDetails | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()

  const loadWorkflowDetails = useCallback(async () => {
    if (!workflow) return
    
    setLoading(true)
    setError(null)
    try {
      const response = await apiService.getWorkflowDetails(workflow.id)
      setWorkflowDetails(response.data as WorkflowDetails)
    } catch (err) {
      console.error('Failed to load workflow details:', err)
      setError('Failed to load workflow details')
    } finally {
      setLoading(false)
    }
  }, [workflow])

  useEffect(() => {
    if (isOpen && workflow) {
      loadWorkflowDetails()
    }
  }, [isOpen, workflow, loadWorkflowDetails])

  useEffect(() => {
    if (!isOpen) return
    const close = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', close)
    return () => window.removeEventListener('keydown', close)
  }, [isOpen, onClose])

  if (!workflow) return null

  const hasCompatibility = workflowDetails?.compatibility !== undefined
  const isCompatible = hasCompatibility ? workflowDetails.compatibility.compatible : false
  const compatibilityPercentage = hasCompatibility 
    ? workflowDetails.compatibility.compatibility_percentage 
    : 0

  const toolsUsed = hasCompatibility && workflowDetails.compatibility.required_tools
    ? workflowDetails.compatibility.required_tools
    : []

  const availableTools = hasCompatibility ? workflowDetails.compatibility.available_tools : []
  const missingTools = hasCompatibility ? workflowDetails.compatibility.missing_tools : []

  return (
    <div
      className={`fixed inset-0 z-50 flex items-center justify-center p-4 ${
        isOpen ? 'visible' : 'invisible'
      }`}
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="workflow-details-title"
    >
      {/* Backdrop */}
      <div
        className={`absolute inset-0 bg-black transition-opacity duration-300 ${
          isOpen ? 'opacity-60' : 'opacity-0'
        }`}
      />

      {/* Modal Content */}
      <div
        className={`relative w-full max-w-4xl max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-700 rounded-lg shadow-2xl transition-all duration-300 ${
          isOpen ? 'opacity-100 scale-100' : 'opacity-0 scale-95'
        }`}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Close Button */}
        <button
          type="button"
          onClick={onClose}
          className="absolute top-4 right-4 z-10 p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
          aria-label="Close workflow details"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header */}
        <div className="p-6 border-b border-slate-700">
          <div className="flex items-start justify-between pr-12">
            <div className="flex-1">
              <h2 id="workflow-details-title" className="text-2xl font-bold text-white flex items-center gap-2">
                <Workflow className="w-6 h-6 text-blue-400" />
                {workflow.name}
              </h2>
              <p className="text-slate-400 mt-2">
                {workflow.description}
              </p>
            </div>
            {hasCompatibility && (
              <Badge
                variant={isCompatible ? 'default' : 'destructive'}
                className={`${
                  isCompatible
                    ? 'bg-green-500/20 text-green-400 border-green-500/30'
                    : 'bg-red-500/20 text-red-400 border-red-500/30'
                } px-3 py-1 flex-shrink-0`}
              >
                {isCompatible ? (
                  <CheckCircle2 className="w-4 h-4 mr-1" />
                ) : (
                  <XCircle className="w-4 h-4 mr-1" />
                )}
                {Math.round(compatibilityPercentage)}% Compatible
              </Badge>
            )}
          </div>
        </div>

        {/* Body */}
        <div className="p-6">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
              <span className="ml-3 text-slate-400">Loading workflow details...</span>
            </div>
          ) : error ? (
            <div className="text-center py-12">
              <XCircle className="w-12 h-12 text-red-400 mx-auto mb-3" />
              <p className="text-red-400">{error}</p>
              <Button onClick={loadWorkflowDetails} className="mt-4">
                Retry
              </Button>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Workflow Information */}
              <div className="grid gap-4 sm:grid-cols-3">
                <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
                  <div className="flex items-center gap-2 text-slate-400 mb-1">
                    <Package className="w-4 h-4" />
                    <span className="text-sm">Category</span>
                  </div>
                  <div className="text-white font-medium capitalize">{workflow.category}</div>
                </div>
                <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
                  <div className="flex items-center gap-2 text-slate-400 mb-1">
                    <Workflow className="w-4 h-4" />
                    <span className="text-sm">Steps</span>
                  </div>
                  <div className="text-white font-medium">
                    {workflowDetails?.steps.length || workflow.steps_count} steps
                  </div>
                </div>
                <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
                  <div className="flex items-center gap-2 text-slate-400 mb-1">
                    <Clock className="w-4 h-4" />
                    <span className="text-sm">Tools Required</span>
                  </div>
                  <div className="text-white font-medium">{toolsUsed.length} tools</div>
                </div>
              </div>

              {/* Workflow Diagram */}
              <div className="bg-slate-800/30 rounded-lg p-6 border border-slate-700">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                  <Workflow className="w-5 h-5 text-blue-400" />
                  Workflow Steps
                </h3>
                <div className="space-y-3">
                  {workflowDetails?.steps.map((step, index) => (
                    <div key={step.id} className="flex items-start gap-3">
                      <div className="flex-shrink-0 w-8 h-8 rounded-full bg-blue-500/20 border-2 border-blue-400 flex items-center justify-center text-blue-400 font-semibold text-sm">
                        {index + 1}
                      </div>
                      <div className="flex-1 bg-slate-700/50 rounded-lg p-4 border border-slate-600">
                        <div className="text-white font-medium mb-1">{step.name}</div>
                        <div className="text-slate-400 text-sm mb-2">{step.description}</div>
                        <div className="flex flex-wrap gap-2 items-center">
                          <Badge variant="outline" className="text-xs bg-slate-800/50 text-slate-300">
                            <Package className="w-3 h-3 mr-1" />
                            {step.run[0]}
                          </Badge>
                          {step.timeout && (
                            <Badge variant="outline" className="text-xs bg-slate-800/50 text-slate-400">
                              <Clock className="w-3 h-3 mr-1" />
                              {step.timeout}s timeout
                            </Badge>
                          )}
                          {step.needs.length > 0 && (
                            <Badge variant="outline" className="text-xs bg-blue-500/10 text-blue-400">
                              Depends on: {step.needs.join(', ')}
                            </Badge>
                          )}
                        </div>
                      </div>
                      {index < (workflowDetails?.steps.length || 0) - 1 && (
                        <div className="flex-shrink-0 flex items-center justify-center">
                          <ArrowRight className="w-5 h-5 text-slate-600" />
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Tools Section */}
              <div className="bg-slate-800/30 rounded-lg p-6 border border-slate-700">
            <h3 className="text-lg font-semibold text-white mb-4">Required Tools</h3>
            
            {toolsUsed.length > 0 ? (
              <div className="space-y-4">
                {/* Available Tools */}
                {availableTools.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-green-400 mb-2 flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4" />
                      Available ({availableTools.length})
                    </h4>
                    <div className="flex flex-wrap gap-2">
                      {availableTools.map((tool) => (
                        <Badge
                          key={tool}
                          variant="outline"
                          className="bg-green-500/10 text-green-400 border-green-500/30 px-3 py-1"
                        >
                          <CheckCircle2 className="w-3 h-3 mr-1" />
                          {tool}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Missing Tools */}
                {missingTools.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-red-400 mb-2 flex items-center gap-2">
                      <XCircle className="w-4 h-4" />
                      Missing ({missingTools.length})
                    </h4>
                    <div className="flex flex-wrap gap-2">
                      {missingTools.map((tool) => (
                        <Badge
                          key={tool}
                          variant="outline"
                          className="bg-red-500/10 text-red-400 border-red-500/30 px-3 py-1"
                        >
                          <XCircle className="w-3 h-3 mr-1" />
                          {tool}
                        </Badge>
                      ))}
                    </div>
                    <div className="mt-3 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                      <p className="text-sm text-yellow-400">
                        ⚠️ Install the missing tools to run this workflow. Check the Tools page for installation instructions.
                      </p>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-slate-400 text-center py-4">
                No tool requirements specified
              </div>
            )}
          </div>

          {/* Inputs Section */}
          {workflow.inputs && Object.keys(workflow.inputs).length > 0 && (
            <div className="bg-slate-800/30 rounded-lg p-6 border border-slate-700">
              <h3 className="text-lg font-semibold text-white mb-4">Required Inputs</h3>
              <div className="space-y-2">
                {Object.entries(workflow.inputs).map(([key, value]) => (
                  <div key={key} className="flex items-center justify-between p-3 bg-slate-700/30 rounded-lg">
                    <span className="text-slate-300 font-medium">{key}</span>
                    <code className="text-sm text-blue-400 bg-slate-900/50 px-2 py-1 rounded">
                      {value}
                    </code>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Warnings */}
          {hasCompatibility && workflowDetails?.compatibility.warnings && workflowDetails.compatibility.warnings.length > 0 && (
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
              <h4 className="text-yellow-400 font-medium mb-2">⚠️ Warnings</h4>
              <ul className="space-y-1">
                {workflowDetails.compatibility.warnings.map((warning, index) => (
                  <li key={index} className="text-sm text-yellow-300">
                    • {warning}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <div className="flex flex-col-reverse gap-2 border-t border-slate-700 pt-5 sm:flex-row sm:justify-end">
            <Button variant="outline" onClick={() => { onClose(); navigate(`/workflows?workflow=${encodeURIComponent(workflow.id)}`) }}>Open in Workflow Studio</Button>
            <Button onClick={() => { onClose(); navigate(`/scans?workflow=${encodeURIComponent(workflow.id)}`) }}>Configure authorized run</Button>
          </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
