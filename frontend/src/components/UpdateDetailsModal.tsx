import React, { useState, useEffect } from 'react'
import { X, RefreshCw, ExternalLink, Clock, CheckCircle, XCircle, AlertTriangle, ArrowUpCircle } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/Card'
import { Badge } from './ui/Badge'
import { Button } from './ui/Button'
import type { CoordinatedUpdateResult, EnhancedVersionCheckResult } from '../services/api'
import apiService from '../services/api'
import { useToast } from '../hooks/useToast'
import Toast from './ui/Toast'

interface UpdateDetailsModalProps {
  toolName: string
  onClose: () => void
}

const UpdateDetailsModal: React.FC<UpdateDetailsModalProps> = ({ toolName, onClose }) => {
  const [result, setResult] = useState<CoordinatedUpdateResult | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const { toasts, success, error: showError, info, removeToast } = useToast()

  const fetchUpdateDetails = async (showProgress = false) => {
    try {
      if (showProgress) {
        setIsRefreshing(true)
        info(`Checking for ${toolName} updates...`)
      }

      const updateResult = await apiService.checkToolUpdateEnhanced(toolName)
      setResult(updateResult)

      if (showProgress) {
        if (updateResult.has_update) {
          success(`Found updates for ${toolName}`)
        } else {
          success(`${toolName} is up to date`)
        }
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to check for updates'
      showError(errorMessage)
    } finally {
      setIsLoading(false)
      setIsRefreshing(false)
    }
  }

  useEffect(() => {
    fetchUpdateDetails()
  }, [toolName])

  const handleRefresh = () => {
    fetchUpdateDetails(true)
  }

  const getManagerIcon = (manager: string) => {
    switch (manager.toLowerCase()) {
      case 'go':
        return '🐹'
      case 'npm':
        return '⬢'
      case 'pipx':
        return '🔐'
      case 'apt':
        return '🐧'
      case 'winget':
        return '🪟'
      case 'homebrew':
        return '🍺'
      case 'gem':
        return '💎'
      case 'cargo':
        return '🦀'
      default:
        return '📦'
    }
  }

  const getUpdateTypeColor = (updateType?: string) => {
    switch (updateType) {
      case 'major':
        return 'bg-red-700 text-red-100'
      case 'minor':
        return 'bg-orange-700 text-orange-100'
      case 'patch':
        return 'bg-blue-700 text-blue-100'
      case 'prerelease':
        return 'bg-purple-700 text-purple-100'
      default:
        return 'bg-gray-700 text-gray-100'
    }
  }

  const formatDuration = (duration: number) => {
    if (duration < 1000) {
      return `${duration}ms`
    }
    return `${(duration / 1000).toFixed(1)}s`
  }

  const formatTimestamp = (timestamp?: string) => {
    if (!timestamp) return 'Unknown'
    try {
      return new Date(timestamp).toLocaleString()
    } catch {
      return timestamp
    }
  }

  if (isLoading) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
        <div className="bg-gray-900 rounded-lg max-w-2xl w-full border border-gray-700 shadow-2xl">
          <div className="p-6 text-center">
            <Clock className="h-8 w-8 animate-spin mx-auto mb-4 text-blue-500" />
            <h2 className="text-xl font-bold text-white mb-2">Checking for Updates</h2>
            <p className="text-gray-400">Analyzing {toolName} across multiple package managers...</p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <div className="bg-gray-900 rounded-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto border border-gray-700 shadow-2xl">
        {/* Header */}
        <div className="sticky top-0 bg-gray-900 border-b border-gray-700 px-6 py-4 flex items-center justify-between z-10">
          <div>
            <h2 className="text-2xl font-bold text-white">Update Details</h2>
            <p className="text-sm text-gray-400">{toolName}</p>
          </div>
          <div className="flex items-center gap-2">
            <Button
              onClick={handleRefresh}
              variant="outline"
              size="sm"
              disabled={isRefreshing}
              className="text-gray-400 hover:text-white"
            >
              {isRefreshing ? (
                <RefreshCw className="h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="h-4 w-4" />
              )}
            </Button>
            <Button
              onClick={onClose}
              variant="ghost"
              size="sm"
              className="text-gray-400 hover:text-white"
            >
              <X className="h-5 w-5" />
            </Button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {result && (
            <>
              {/* Summary */}
              <Card>
                <CardHeader>
                  <CardTitle>Summary</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-sm text-gray-400 mb-1">Status</p>
                      <div className="flex items-center gap-2">
                        {result.has_update ? (
                          <ArrowUpCircle className="h-5 w-5 text-yellow-500" />
                        ) : (
                          <CheckCircle className="h-5 w-5 text-green-500" />
                        )}
                        <span className="text-white font-medium">
                          {result.has_update ? 'Updates Available' : 'Up to Date'}
                        </span>
                      </div>
                    </div>
                    <div>
                      <p className="text-sm text-gray-400 mb-1">Managers Checked</p>
                      <span className="text-white font-medium">{result.managers_checked}</span>
                    </div>
                    <div>
                      <p className="text-sm text-gray-400 mb-1">Duration</p>
                      <span className="text-white font-medium">{formatDuration(result.duration)}</span>
                    </div>
                    <div>
                      <p className="text-sm text-gray-400 mb-1">Best Result</p>
                      <span className="text-white font-medium">
                        {result.best_result?.package_manager || 'None'}
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Best Result */}
              {result.best_result && (
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      {getManagerIcon(result.best_result.package_manager)}
                      Best Result ({result.best_result.package_manager})
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <p className="text-sm text-gray-400 mb-1">Current Version</p>
                        <span className="text-white font-mono">
                          {result.best_result.current_version || 'Unknown'}
                        </span>
                      </div>
                      <div>
                        <p className="text-sm text-gray-400 mb-1">Latest Version</p>
                        <span className="text-white font-mono">
                          {result.best_result.latest_version || 'Unknown'}
                        </span>
                      </div>
                      <div>
                        <p className="text-sm text-gray-400 mb-1">Update Type</p>
                        <Badge className={getUpdateTypeColor(result.best_result.update_type)}>
                          {result.best_result.update_type || 'Unknown'}
                        </Badge>
                      </div>
                      <div>
                        <p className="text-sm text-gray-400 mb-1">Source</p>
                        <span className="text-white font-mono text-sm">
                          {result.best_result.source || 'Unknown'}
                        </span>
                      </div>
                    </div>
                    {result.best_result.diagnostic && (
                      <div>
                        <p className="text-sm text-gray-400 mb-1">Diagnostic</p>
                        <p className="text-white text-sm bg-gray-800 p-2 rounded">
                          {result.best_result.diagnostic}
                        </p>
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* All Results */}
              <Card>
                <CardHeader>
                  <CardTitle>All Package Manager Results</CardTitle>
                  <CardDescription>
                    Detailed results from each package manager that was checked
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {Object.entries(result.results).map(([manager, managerResult]) => (
                    <div key={manager} className="bg-gray-800 rounded-lg p-4">
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center gap-2">
                          <span className="text-lg">{getManagerIcon(manager)}</span>
                          <span className="font-medium text-white">{manager}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          {managerResult.error ? (
                            <XCircle className="h-4 w-4 text-red-500" />
                          ) : managerResult.has_update ? (
                            <ArrowUpCircle className="h-4 w-4 text-yellow-500" />
                          ) : (
                            <CheckCircle className="h-4 w-4 text-green-500" />
                          )}
                          <Badge className={getUpdateTypeColor(managerResult.update_type)}>
                            {managerResult.error ? 'Error' : 
                             managerResult.has_update ? 'Update Available' : 'Up to Date'}
                          </Badge>
                        </div>
                      </div>
                      
                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                          <p className="text-gray-400 mb-1">Current</p>
                          <span className="text-white font-mono">
                            {managerResult.current_version || 'Unknown'}
                          </span>
                        </div>
                        <div>
                          <p className="text-gray-400 mb-1">Latest</p>
                          <span className="text-white font-mono">
                            {managerResult.latest_version || 'Unknown'}
                          </span>
                        </div>
                        <div>
                          <p className="text-gray-400 mb-1">Source</p>
                          <span className="text-white font-mono text-xs">
                            {managerResult.source || 'Unknown'}
                          </span>
                        </div>
                        <div>
                          <p className="text-gray-400 mb-1">Checked At</p>
                          <span className="text-white text-xs">
                            {formatTimestamp(managerResult.checked_at)}
                          </span>
                        </div>
                      </div>

                      {managerResult.error && (
                        <div className="mt-3 p-3 bg-red-900/20 border border-red-700 rounded">
                          <p className="text-sm text-red-300">
                            <strong>Error:</strong> {managerResult.error}
                          </p>
                          {managerResult.diagnostic && (
                            <p className="text-sm text-red-200 mt-1">
                              <strong>Diagnostic:</strong> {managerResult.diagnostic}
                            </p>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </CardContent>
              </Card>
            </>
          )}
        </div>
      </div>

      {/* Toast Notifications */}
      <div className="fixed top-4 right-4 z-[60] space-y-2">
        {toasts.map((toast) => (
          <Toast
            key={toast.id}
            {...toast}
            onClose={() => removeToast(toast.id)}
          />
        ))}
      </div>
    </div>
  )
}

export default UpdateDetailsModal
