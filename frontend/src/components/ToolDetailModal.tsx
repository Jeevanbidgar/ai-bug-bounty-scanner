import { useState, useEffect, useMemo } from 'react'
import { X, CheckCircle, XCircle, AlertTriangle, Loader2, Play, RefreshCw, Download, Trash2, ArrowUpCircle, Info } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/Card'
import { Badge } from './ui/Badge'
import { Button } from './ui/Button'
import type { Tool, ToolInstallationInfo } from '../services/api'
import { useToast } from '../hooks/useToast'
import Toast from './ui/Toast'
import apiService from '../services/api'
import UpdateDetailsModal from './UpdateDetailsModal'

interface ToolDetailModalProps {
  tool: Tool
  onClose: () => void
  onToolUpdate?: (updatedTool: Tool) => void
  onInstallStart?: (toolName: string) => void
}

const INSTALL_METHOD_LABELS: Record<string, string> = {
  go: 'Go install',
  pipx: 'pipx',
  'git-pip': 'Git + pip',
  apt: 'APT',
  winget: 'WinGet',
  cargo: 'Cargo',
  npm: 'npm',
  gem: 'Ruby gem',
  homebrew: 'Homebrew',
  manual: 'Manual',
  runtime: 'Runtime helper',
}

const INSTALL_METHOD_ICONS: Record<string, string> = {
  go: '🐹',
  pipx: '🔐',
  'git-pip': '📦',
  apt: '🐧',
  winget: '🪟',
  cargo: '🦀',
  npm: '⬢',
  gem: '💎',
  homebrew: '🍺',
  manual: '🛠️',
  runtime: '⚙️',
}

const toTitleCase = (value: string) =>
  value
    .split(/[-_ ]+/)
    .filter(Boolean)
    .map(part => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ')

const getInstallMethodLabel = (method?: string | null) => {
  if (!method) {
    return 'recommended'
  }

  return INSTALL_METHOD_LABELS[method] ?? toTitleCase(method)
}

const formatInstallMethod = (method?: string | null) => {
  if (!method) {
    return 'recommended method'
  }

  const label = getInstallMethodLabel(method)
  const icon = INSTALL_METHOD_ICONS[method]
  return icon ? `${icon} ${label}` : label
}

const ToolDetailModal = ({ tool: initialTool, onClose, onToolUpdate, onInstallStart }: ToolDetailModalProps) => {
  const [tool, setTool] = useState(initialTool)
  const [isTestRunning, setIsTestRunning] = useState(false)
  const [testOutput, setTestOutput] = useState<string | null>(null)
  const [testError, setTestError] = useState<string | null>(null)
  const [isRechecking, setIsRechecking] = useState(false)
  const [isInstalling, setIsInstalling] = useState(false)
  const [isUpdating, setIsUpdating] = useState(false)
  const [isUninstalling, setIsUninstalling] = useState(false)
  const [updateAvailable, setUpdateAvailable] = useState<boolean>(false)
  const [showUpdateDetails, setShowUpdateDetails] = useState(false)
  const [installationInfo, setInstallationInfo] = useState<ToolInstallationInfo | null>(null)
  const [selectedInstallMethod, setSelectedInstallMethod] = useState<string | null>(null)
  const { toasts, success, error: showError, info, removeToast } = useToast()
  const operationInProgress = isInstalling || isUpdating || isUninstalling

  useEffect(() => {
    const close = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !operationInProgress) onClose()
    }
    window.addEventListener('keydown', close)
    return () => window.removeEventListener('keydown', close)
  }, [onClose, operationInProgress])

  const availableMethods = useMemo(() => {
    if (installationInfo) {
      return installationInfo.automated_install_methods
    }
    const unique = new Set<string>()
    if (tool.install_method) {
      unique.add(tool.install_method)
    }
    if (installationInfo?.install_method) {
      unique.add(installationInfo.install_method)
    }
    (tool.alternative_install_methods || []).forEach(method => {
      if (method) {
        unique.add(method)
      }
    })
    return Array.from(unique)
  }, [tool.install_method, tool.alternative_install_methods, installationInfo])

  useEffect(() => {
    if (selectedInstallMethod && !availableMethods.includes(selectedInstallMethod)) {
      setSelectedInstallMethod(null)
    }
  }, [availableMethods, selectedInstallMethod])

  const recommendedMethod = useMemo(() => {
    if (availableMethods.length === 0) {
      return null
    }

    const preferences: string[] = []

    if (installationInfo?.recommended_install_method) {
      preferences.push(installationInfo.recommended_install_method)
    }

    if (tool.install_method) {
      preferences.push(tool.install_method)
    }
    if (installationInfo?.install_method) {
      preferences.push(installationInfo.install_method)
    }

    for (const method of preferences) {
      if (method && availableMethods.includes(method)) {
        return method
      }
    }

    return availableMethods[0]
  }, [availableMethods, installationInfo, tool.install_method])

  const recommendedMethodLabel = recommendedMethod ? formatInstallMethod(recommendedMethod) : 'Recommended'
  const recommendedMethodDescription = recommendedMethod
    ? `via ${recommendedMethodLabel}`
    : 'using the recommended method'

  const otherMethods = useMemo(
    () => availableMethods.filter(method => !recommendedMethod || method !== recommendedMethod),
    [availableMethods, recommendedMethod]
  )

  useEffect(() => {
    const fetchInstallationInfo = async () => {
      try {
        const installData = await apiService.getToolInstallationInfo(tool.name)
        setInstallationInfo(installData)
      } catch (error) {
        console.error('Failed to get installation info:', error)
      }
    }

    const fetchVersion = async () => {
      if (tool.installed) {
        try {
          const version = await apiService.getToolVersion(tool.name)
          if (version) {
            setTool(prev => ({ ...prev, raw_version: version }))
          }
        } catch (error) {
          console.error('Failed to fetch version:', error)
        }
      }
    }

    const checkForUpdates = async () => {
      if (tool.installed) {
        try {
          // Use optimized single-manager check (fast, targeted)
          const result = await apiService.checkToolUpdate(tool.name)
          if (result.has_update) {
            setUpdateAvailable(true)
          } else {
            setUpdateAvailable(false)
          }
        } catch (error) {
          console.error('Failed to check for updates:', error)
          setUpdateAvailable(false)
        }
      }
    }

    fetchInstallationInfo()
    fetchVersion()
    checkForUpdates()
  }, [tool.name, tool.installed])

  const getStatusBadge = () => {
    if (tool.installed) {
      return <Badge className="bg-green-700 text-green-100">Available</Badge>
    } else {
      return <Badge className="bg-red-700 text-red-100">Not Installed</Badge>
    }
  }

  const getStatusIcon = () => {
    if (tool.installed) {
      return <CheckCircle className="h-5 w-5 text-green-500" />
    } else {
      return <XCircle className="h-5 w-5 text-red-500" />
    }
  }

  const handleTestRun = async () => {
    setIsTestRunning(true)
    setTestError(null)
    setTestOutput(null)

    try {
      const result = await apiService.testTool(tool.name)
      if (result.success) {
        setTestOutput(`${result.output || 'Command completed successfully'}\n\nPath: ${result.path}\nDuration: ${result.durationMs} ms`)
      } else {
        setTestError(`Health check exited with code ${result.exitCode ?? 'unknown'}.${result.output ? `\n${result.output}` : ''}`)
      }
    } catch (error) {
      setTestError(error instanceof Error ? error.message : 'Failed to run test')
    } finally {
      setIsTestRunning(false)
    }
  }

  const handleRecheck = async () => {
    setIsRechecking(true)
    const previousStatus = tool.installed

    try {
      const updatedTool = await apiService.recheckTool(tool.name)

      if (updatedTool) {
        // Update the local state
        setTool(updatedTool)

        // Notify parent component of the update
        if (onToolUpdate) {
          onToolUpdate(updatedTool)
        }

        // Fetch version if installed
        if (updatedTool.installed) {
          try {
            const version = await apiService.getToolVersion(tool.name)
            if (version) {
              const toolWithVersion = { ...updatedTool, raw_version: version }
              setTool(toolWithVersion)
              if (onToolUpdate) {
                onToolUpdate(toolWithVersion)
              }
            }
          } catch (error) {
            console.error('Failed to fetch version:', error)
          }
        }

        // Show appropriate notification
        if (updatedTool.installed && !previousStatus) {
          success(`${updatedTool.name} is now available!`)
        } else if (!updatedTool.installed && previousStatus) {
          info(`${updatedTool.name} is no longer available`)
        } else {
          success(`${updatedTool.name} status checked`)
        }
      }
    } catch (error) {
      console.error('Failed to recheck tool:', error)
      showError(`Failed to recheck ${tool.name}`)
    } finally {
      setIsRechecking(false)
    }
  }

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'Never'

    try {
      const date = new Date(dateString)
      return date.toLocaleString()
    } catch {
      return dateString
    }
  }

  const handleInstall = async (installMethod?: string) => {
    setIsInstalling(true)

    // Notify parent to show installation progress modal
    if (onInstallStart) {
      onInstallStart(tool.name)
    }

    try {
      const methodToUse = installMethod || selectedInstallMethod || recommendedMethod || tool.install_method

      if (methodToUse && methodToUse !== tool.install_method) {
        info(`Installing ${tool.name} via ${formatInstallMethod(methodToUse)}...`)
        const result = await apiService.installToolWithMethod(tool.name, methodToUse)

        if (result.success) {
          success(result.message)

          // Recheck tool status after installation
          const updatedTool = await apiService.recheckTool(tool.name)
          if (updatedTool) {
            // Fetch version
            try {
              const version = await apiService.getToolVersion(tool.name)
              if (version) {
                updatedTool.raw_version = version
              }
            } catch (error) {
              console.error('Failed to fetch version:', error)
            }

            setTool(updatedTool)

            // Notify parent component
            if (onToolUpdate) {
              onToolUpdate(updatedTool)
            }
          }
        } else {
          showError(result.message)
        }
      } else {
        info(`Installing ${tool.name}...`)
        const result = await apiService.installTool(tool.name)

        if (result.success) {
          success(result.message)

          // Recheck tool status after installation
          const updatedTool = await apiService.recheckTool(tool.name)
          if (updatedTool) {
            // Fetch version
            try {
              const version = await apiService.getToolVersion(tool.name)
              if (version) {
                updatedTool.raw_version = version
              }
            } catch (error) {
              console.error('Failed to fetch version:', error)
            }

            setTool(updatedTool)

            // Notify parent component
            if (onToolUpdate) {
              onToolUpdate(updatedTool)
            }
          }
        } else {
          showError(result.message)
        }
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to install tool'
      showError(errorMessage)
    } finally {
      setIsInstalling(false)
    }
  }

  const handleUpdate = async () => {
    setIsUpdating(true)

    try {
      info(`Updating ${tool.name}...`)
      const result = await apiService.updateTool(tool.name)

      if (result.success) {
        success(result.message)

        // Recheck tool status after update
        const updatedTool = await apiService.recheckTool(tool.name)
        if (updatedTool) {
          // Fetch new version
          try {
            const version = await apiService.getToolVersion(tool.name)
            if (version) {
              updatedTool.raw_version = version
            }
          } catch (error) {
            console.error('Failed to fetch version:', error)
          }

          setTool(updatedTool)
          setUpdateAvailable(false) // Reset update flag

          // Notify parent component
          if (onToolUpdate) {
            onToolUpdate(updatedTool)
          }
        }
      } else {
        showError(result.message)
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to update tool'
      showError(errorMessage)
    } finally {
      setIsUpdating(false)
    }
  }

  const handleViewUpdateDetails = () => {
    setShowUpdateDetails(true)
  }

  const handleUninstall = async () => {
    if (!confirm(`Are you sure you want to uninstall ${tool.name}?`)) {
      return
    }

    setIsUninstalling(true)

    try {
      info(`Uninstalling ${tool.name}...`)
      const message = await apiService.uninstallTool(tool.name)

      success(message)

      // Recheck tool status after uninstallation
      const updatedTool = await apiService.recheckTool(tool.name)
      if (updatedTool) {
        setTool(updatedTool)

        // Notify parent component
        if (onToolUpdate) {
          onToolUpdate(updatedTool)
        }
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to uninstall tool'
      showError(errorMessage)
    } finally {
      setIsUninstalling(false)
    }
  }

  const canInstall = availableMethods.length > 0
  const requiresManualInstall = Boolean(installationInfo?.available_install_methods.includes('manual') && !canInstall)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" onMouseDown={() => { if (!operationInProgress) onClose() }}>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="tool-detail-title"
        className="bg-gray-900 rounded-lg max-w-3xl w-full max-h-[90vh] overflow-y-auto border border-gray-700 shadow-2xl"
        onMouseDown={(event) => event.stopPropagation()}
      >
        {/* Header */}
        <div className="sticky top-0 bg-gray-900 border-b border-gray-700 px-6 py-4 flex items-center justify-between z-10">
          <div className="flex items-center gap-3">
            {getStatusIcon()}
            <div>
              <h2 id="tool-detail-title" className="text-2xl font-bold text-white">{tool.name}</h2>
              <p className="text-sm text-gray-400">{tool.category}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {getStatusBadge()}
            <Button
              onClick={onClose}
              variant="ghost"
              size="sm"
              aria-label="Close tool details"
              className="text-gray-400 hover:text-white"
            >
              <X className="h-5 w-5" />
            </Button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Description */}
          <Card>
            <CardHeader>
              <CardTitle>Description</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-300">{tool.description}</p>
            </CardContent>
          </Card>

          {/* Installation Details */}
          <Card>
            <CardHeader>
              <CardTitle>Installation Details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-gray-400 mb-1">Status</p>
                  <div className="flex items-center gap-2">
                    {getStatusIcon()}
                    <span className="text-white font-medium">
                      {tool.installed ? 'Installed' : 'Not Installed'}
                    </span>
                  </div>
                </div>

                <div>
                  <p className="text-sm text-gray-400 mb-1">Version</p>
                  <div className="flex items-center gap-2">
                    <p className="text-white font-mono">
                      {tool.raw_version || tool.version || 'Unknown'}
                    </p>
                    {updateAvailable && (
                      <Badge className="text-xs bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300">
                        Update available
                      </Badge>
                    )}
                    {tool.installed && (
                      <Button
                        onClick={handleViewUpdateDetails}
                        variant="ghost"
                        size="sm"
                        className="text-gray-400 hover:text-white"
                        title="View detailed update information from all package managers"
                      >
                        <Info className="h-3 w-3" />
                      </Button>
                    )}
                  </div>
                </div>

                <div>
                  <p className="text-sm text-gray-400 mb-1">Path</p>
                  <p className="text-white font-mono text-sm break-all">
                    {tool.path || 'Not found'}
                  </p>
                </div>

                <div>
                  <p className="text-sm text-gray-400 mb-1">Output Format</p>
                  <p className="text-white font-mono">
                    {tool.output_format}
                  </p>
                </div>

                {installationInfo && (
                  <div className="col-span-2">
                    <p className="text-sm text-gray-400 mb-1">Installation Method</p>
                    <div className="flex items-center gap-2">
                      <Badge className={
                        installationInfo.install_method === 'go' ? 'bg-green-700 text-green-100' :
                          installationInfo.install_method === 'pipx' ? 'bg-yellow-700 text-yellow-100' :
                            installationInfo.install_method === 'git-pip' ? 'bg-yellow-700 text-yellow-100' :
                              installationInfo.install_method === 'apt' ? 'bg-blue-700 text-blue-100' :
                                installationInfo.install_method === 'cargo' ? 'bg-orange-700 text-orange-100' :
                                  installationInfo.install_method === 'gem' ? 'bg-red-700 text-red-100' :
                                    installationInfo.install_method === 'homebrew' ? 'bg-orange-700 text-orange-100' :
                                      installationInfo.install_method === 'manual' ? 'bg-purple-700 text-purple-100' :
                                        installationInfo.install_method === 'runtime' ? 'bg-gray-700 text-gray-100' :
                                          'bg-gray-700 text-gray-100'
                      }>
                        {installationInfo.install_method}
                      </Badge>
                      {canInstall && (
                        <span className="text-xs text-green-400">• One-click install available</span>
                      )}
                      {!canInstall && requiresManualInstall && (
                        <span className="text-xs text-gray-400">• Manual installation required</span>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* Command Template */}
              {tool.command_template && tool.command_template.length > 0 && (
                <div>
                  <p className="text-sm text-gray-400 mb-2">Command Template</p>
                  <div className="bg-gray-800 rounded-lg p-3 font-mono text-sm text-gray-300">
                    {tool.command_template.join(' ')}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Dependencies */}
          {(tool.os_dependencies.length > 0 || tool.missing_dependencies.length > 0) && (
            <Card>
              <CardHeader>
                <CardTitle>Dependencies</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {tool.os_dependencies.length > 0 && (
                  <div>
                    <p className="text-sm text-gray-400 mb-2">OS Dependencies</p>
                    <div className="flex flex-wrap gap-2">
                      {tool.os_dependencies.map((dep) => (
                        <Badge key={dep} className="bg-blue-700 text-blue-100">
                          {dep}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {tool.missing_dependencies.length > 0 && (
                  <div>
                    <p className="text-sm text-gray-400 mb-2 flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-yellow-500" />
                      Missing Dependencies
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {tool.missing_dependencies.map((dep) => (
                        <Badge key={dep} className="bg-red-700 text-red-100">
                          {dep}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Installation Helper */}
          {!tool.installed && installationInfo && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-yellow-500" />
                  Installation Instructions
                </CardTitle>
                <CardDescription>
                  Approved installation paths for {installationInfo.platform}. The backend rejects methods not listed here.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {canInstall ? (
                  <div className="bg-green-900/20 border border-green-700 rounded-lg p-4 space-y-3">
                    <p className="text-sm text-green-300 font-medium flex items-center gap-2">
                      <CheckCircle className="h-4 w-4" />
                      Install directly from this app
                    </p>
                    <p className="text-sm text-green-100">
                      Use the <strong>Install {tool.name}</strong> button below to perform an automated installation {recommendedMethodDescription}.
                    </p>
                    {otherMethods.length > 0 && (
                      <p className="text-xs text-green-200">
                        Alternate methods supported: {otherMethods.map(method => formatInstallMethod(method)).join(', ')}
                      </p>
                    )}
                    <div className="bg-blue-900/20 border border-blue-700 rounded-lg p-4">
                      <p className="text-sm text-blue-200">
                        After installation completes, click <strong>Recheck Status</strong> to confirm the tool is available.
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="bg-gray-800 rounded-lg p-4 space-y-4">
                    <div className="text-center space-y-2">
                      <p className="text-gray-300 font-medium">
                        🔧 Manual Installation Required
                      </p>
                      <p className="text-sm text-gray-400">
                        {requiresManualInstall
                          ? `${tool.name} requires a manual installation that does not yet have an audited automation recipe.`
                          : `No automatic installation commands are currently configured for ${tool.name}.`
                        }
                      </p>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Check History */}
          <Card>
            <CardHeader>
              <CardTitle>Check History</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-400">Last Checked:</span>
                <span className="text-white">{formatDate(tool.last_checked)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Last Seen:</span>
                <span className="text-white">{formatDate(tool.last_seen)}</span>
              </div>
              {tool.last_error && (
                <div className="mt-3 p-3 bg-red-900/20 border border-red-700 rounded-lg">
                  <p className="text-sm text-red-300">
                    <strong>Last Error:</strong> {tool.last_error}
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Test Run Section */}
          {tool.installed && (
            <Card>
              <CardHeader>
                <CardTitle>Test Run</CardTitle>
                <CardDescription>
                  Execute a test command to verify the tool is working correctly
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <Button
                  onClick={handleTestRun}
                  disabled={isTestRunning}
                  className="w-full"
                >
                  {isTestRunning ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Running Test...
                    </>
                  ) : (
                    <>
                      <Play className="mr-2 h-4 w-4" />
                      Run Test Command
                    </>
                  )}
                </Button>

                {testOutput && (
                  <div className="bg-gray-800 rounded-lg p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <p className="text-sm text-gray-400">Test Output:</p>
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    </div>
                    <pre className="text-sm text-green-300 whitespace-pre-wrap font-mono">
                      {testOutput}
                    </pre>
                  </div>
                )}

                {testError && (
                  <div className="bg-red-900/20 border border-red-700 rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <XCircle className="h-4 w-4 text-red-500" />
                      <p className="text-sm text-red-400 font-medium">Test Failed</p>
                    </div>
                    <p className="text-sm text-red-300">{testError}</p>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </div>

        {/* Footer Actions */}
        <div className="sticky bottom-0 bg-gray-900 border-t border-gray-700 px-6 py-4">
          <div className="flex flex-col gap-3">
            {/* Installation Method Selector (if alternatives available) */}
            {!tool.installed && canInstall && availableMethods.length > 1 && (
              <div className="p-3 bg-gray-800/50 rounded-lg border border-gray-700">
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Installation Method
                </label>
                <div className="flex flex-wrap gap-2">
                  {/* Primary method button */}
                  <button
                    type="button"
                    onClick={() => setSelectedInstallMethod(recommendedMethod)}
                    className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${(selectedInstallMethod === recommendedMethod || selectedInstallMethod === null)
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                      }`}
                  >
                    {recommendedMethodLabel}
                    <span className="ml-1 text-xs opacity-75">(recommended)</span>
                  </button>

                  {/* Alternative method buttons */}
                  {otherMethods.map((method) => (
                    <button
                      type="button"
                      key={method}
                      onClick={() => setSelectedInstallMethod(method)}
                      className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${selectedInstallMethod === method
                        ? 'bg-blue-600 text-white'
                        : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                        }`}
                    >
                      {formatInstallMethod(method)}
                    </button>
                  ))}
                </div>
                <p className="mt-2 text-xs text-gray-400">
                  {selectedInstallMethod === 'pipx' && '🔐 pipx: Isolated environment, no sudo required'}
                  {selectedInstallMethod === 'git-pip' && '📦 git-pip: Clone and install from source'}
                  {selectedInstallMethod === 'homebrew' && '🍺 Homebrew: macOS package manager, no sudo required'}
                  {(!selectedInstallMethod || selectedInstallMethod === recommendedMethod) && `✨ Using recommended installation method${recommendedMethodLabel ? ` (${recommendedMethodLabel})` : ''}`}
                </p>
              </div>
            )}

            {/* Installation Actions Row */}
            {canInstall && (
              <div className="flex gap-2">
                {!tool.installed ? (
                  <Button
                    onClick={() => handleInstall()}
                    className="flex-1 bg-blue-600 hover:bg-blue-700"
                    disabled={isInstalling}
                  >
                    {isInstalling ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        Installing...
                      </>
                    ) : (
                      <>
                        <Download className="mr-2 h-4 w-4" />
                        Install {tool.name}
                        {selectedInstallMethod && selectedInstallMethod !== recommendedMethod && (
                          <span className="ml-1 text-xs opacity-75">via {formatInstallMethod(selectedInstallMethod)}</span>
                        )}
                      </>
                    )}
                  </Button>
                ) : (
                  <>
                    <Button
                      onClick={handleUpdate}
                      variant="outline"
                      className={`flex-1 ${updateAvailable ? 'border-green-600 text-green-400 hover:bg-green-900/30' : 'border-blue-600 text-blue-400 hover:bg-blue-900/30'}`}
                      disabled={isUpdating}
                    >
                      {isUpdating ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Updating...
                        </>
                      ) : (
                        <>
                          <ArrowUpCircle className="mr-2 h-4 w-4" />
                          Update {updateAvailable && '✨'}
                        </>
                      )}
                    </Button>
                    <Button
                      onClick={handleUninstall}
                      variant="outline"
                      className="flex-1 border-red-600 text-red-400 hover:bg-red-900/30"
                      disabled={isUninstalling}
                    >
                      {isUninstalling ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Uninstalling...
                        </>
                      ) : (
                        <>
                          <Trash2 className="mr-2 h-4 w-4" />
                          Uninstall
                        </>
                      )}
                    </Button>
                  </>
                )}
              </div>
            )}

            {/* General Actions Row */}
            <div className="flex gap-3">
              <Button
                onClick={handleRecheck}
                variant="outline"
                className="flex-1"
                disabled={isRechecking}
              >
                {isRechecking ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Rechecking...
                  </>
                ) : (
                  <>
                    <RefreshCw className="mr-2 h-4 w-4" />
                    Recheck Status
                  </>
                )}
              </Button>
              <Button onClick={onClose} className="flex-1">
                Close
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* Update Details Modal */}
      {showUpdateDetails && (
        <UpdateDetailsModal
          toolName={tool.name}
          onClose={() => setShowUpdateDetails(false)}
        />
      )}

      {/* Toast Notifications */}
      <div className="fixed top-4 right-4 z-[60] space-y-2">
        {toasts.map((toast) => (
          <Toast
            key={toast.id}
            {...toast}
            fixed={false}
            onClose={() => removeToast(toast.id)}
          />
        ))}
      </div>
    </div>
  )
}

export default ToolDetailModal
