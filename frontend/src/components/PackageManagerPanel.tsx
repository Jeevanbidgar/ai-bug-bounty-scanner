import React, { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/Card'
import { Button } from './ui/Button'
import { Badge } from './ui/Badge'
import { 
  CheckCircle, 
  XCircle, 
  Download, 
  RefreshCw, 
  AlertTriangle,
  Loader2,
  Terminal,
  Package,
  ChevronDown,
  ChevronUp
} from 'lucide-react'
import apiService, { PackageManagerInfo } from '../services/api'
import { useToast } from '../hooks/useToast'

interface PackageManagerPanelProps {
  onInstallComplete?: () => void
}

export const PackageManagerPanel: React.FC<PackageManagerPanelProps> = ({
  onInstallComplete
}) => {
  const [managers, setManagers] = useState<PackageManagerInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [installing, setInstalling] = useState<PackageManagerInfo['manager_type'] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [isExpanded, setIsExpanded] = useState(false)
  const [checkingManager, setCheckingManager] = useState<PackageManagerInfo['manager_type'] | null>(null)
  const { success, error: showError, info } = useToast()

  const loadPackageManagers = async () => {
    try {
      setLoading(true)
      setError(null)
      const detected = await apiService.detectPackageManagers()
      setManagers(detected)
    } catch (err) {
      setError('Failed to detect package managers')
      console.error('Error detecting package managers:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadPackageManagers()
  }, [])

  const getManagerName = (manager: PackageManagerInfo): string => {
    switch (manager.manager_type) {
      case 'go': return 'Go'
      case 'pipx': return 'Pipx'
      case 'apt': return 'APT'
      case 'winget': return 'WinGet'
      case 'cargo': return 'Cargo (Rust)'
      case 'npm': return 'npm (Node.js)'
      case 'gem': return 'gem (Ruby)'
      case 'homebrew': return 'Homebrew'
      default: return 'Unknown'
    }
  }

  const installManager = async (manager: PackageManagerInfo) => {
    const managerType = manager.manager_type
    const managerName = getManagerName(manager)
    setInstalling(managerType)
    
    try {
      let result
      
      switch (managerType) {
        case 'go':
          result = await apiService.installPackageManagerGo()
          break
        case 'pipx':
          result = await apiService.installPackageManagerPipx()
          break
        case 'winget':
          result = await apiService.installPackageManagerWinget()
          break
        default:
          throw new Error(`Installation not supported for ${managerName}`)
      }

      if (result.success) {
        success(result.message)
        
        // Reload managers after installation
        await loadPackageManagers()
        onInstallComplete?.()

        if (result.requires_restart) {
          info('Please restart the application to use the newly installed package manager.')
        }
      } else {
        throw new Error(result.message)
      }
    } catch (err: unknown) {
      showError(err instanceof Error ? err.message : `Failed to install ${managerName}`)
    } finally {
      setInstalling(null)
    }
  }

  const recheckManager = async (manager: PackageManagerInfo) => {
    const managerType = manager.manager_type
    const managerName = getManagerName(manager)

    if (!(managerType === 'go' || managerType === 'pipx' || managerType === 'apt' || managerType === 'winget')) {
      return
    }

    setCheckingManager(managerType)

    try {
      const updated = await apiService.checkPackageManager(managerType)

      setManagers(prev => prev.map(existing =>
        existing.manager_type === updated.manager_type ? updated : existing
      ))

      if (updated.available) {
        if (!manager.available) {
          success(`${managerName} is now available`)
          onInstallComplete?.()
        } else {
          success(`${managerName} is available`)
        }
      } else {
        info(`${managerName} is still unavailable`)
      }
    } catch (err) {
      console.error('Error rechecking package manager:', err)
      showError(`Failed to recheck ${managerName}`)
    } finally {
      setCheckingManager(null)
    }
  }

  const getStatusBadge = (manager: PackageManagerInfo) => {
    if (manager.available) {
      return (
        <Badge variant="default" className="flex items-center gap-1">
          <CheckCircle className="h-3 w-3" />
          Available
        </Badge>
      )
    }
    return (
      <Badge variant="destructive" className="flex items-center gap-1">
        <XCircle className="h-3 w-3" />
        Not Available
      </Badge>
    )
  }

  const getIcon = (manager: PackageManagerInfo) => {
    switch (manager.manager_type) {
      case 'go':
        return <Terminal className="h-5 w-5 text-emerald-500" />
      case 'pipx':
        return <Terminal className="h-5 w-5 text-sky-500" />
      case 'apt':
        return <Package className="h-5 w-5 text-blue-500" />
      case 'winget':
        return <Package className="h-5 w-5 text-indigo-400" />
      case 'cargo':
        return <Package className="h-5 w-5 text-orange-500" />
      case 'npm':
        return <Package className="h-5 w-5 text-red-500" />
      case 'gem':
        return <Package className="h-5 w-5 text-rose-500" />
      case 'homebrew':
        return <Package className="h-5 w-5 text-amber-500" />
      default:
        return <Package className="h-5 w-5" />
    }
  }

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Package Managers</CardTitle>
          <CardDescription>Detecting available package managers...</CardDescription>
        </CardHeader>
        <CardContent className="flex justify-center items-center py-8">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    )
  }

  if (error) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Package Managers</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border border-red-700 bg-red-900/20 p-4">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-red-500" />
              <p className="text-sm text-red-300">{error}</p>
            </div>
          </div>
          <Button onClick={loadPackageManagers} className="mt-4" variant="outline">
            <RefreshCw className="h-4 w-4 mr-2" />
            Retry
          </Button>
        </CardContent>
      </Card>
    )
  }

  const availableCount = managers.filter(m => m.available).length
  const unavailableManagers = managers.filter(m => !m.available)

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <button type="button" className="flex-1 text-left" onClick={() => setIsExpanded(!isExpanded)} aria-expanded={isExpanded}>
            <div className="flex items-center gap-2">
              <CardTitle>Package Managers</CardTitle>
              {isExpanded ? (
                <ChevronUp className="h-5 w-5 text-gray-400" />
              ) : (
                <ChevronDown className="h-5 w-5 text-gray-400" />
              )}
            </div>
            <CardDescription>
              {availableCount} of {managers.length} package managers available
            </CardDescription>
          </button>
          <Button onClick={loadPackageManagers} variant="outline" size="sm">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </CardHeader>
      
      {isExpanded && (
        <CardContent className="space-y-4">
          {/* Available Managers */}
          <div className="space-y-2">
            {managers.filter(m => m.available).map((manager) => {
              const name = getManagerName(manager)
              const canRecheck = manager.manager_type === 'go' || manager.manager_type === 'pipx' || manager.manager_type === 'apt' || manager.manager_type === 'winget'

              return (
                <div
                  key={manager.manager_type}
                  className="flex items-center justify-between p-3 border rounded-lg bg-background"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-md bg-primary/10 text-primary">
                      {getIcon(manager)}
                    </div>
                    <div>
                      <div className="font-medium">{name}</div>
                      <div className="text-sm text-muted-foreground">
                        {manager.version || 'Version unknown'}
                      </div>
                      {manager.path && (
                        <div className="text-xs text-muted-foreground font-mono">
                          {manager.path}
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {getStatusBadge(manager)}
                    {canRecheck && (
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => recheckManager(manager)}
                        disabled={checkingManager === manager.manager_type}
                      >
                        {checkingManager === manager.manager_type ? (
                          <>
                            <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                            Checking
                          </>
                        ) : (
                          <>
                            <RefreshCw className="h-4 w-4 mr-1" />
                            Recheck
                          </>
                        )}
                      </Button>
                    )}
                  </div>
                </div>
              )
            })}
          </div>

          {/* Unavailable Managers */}
          {unavailableManagers.length > 0 && (
            <div className="space-y-2 pt-4 border-t">
              <h4 className="text-sm font-medium text-muted-foreground mb-2">
                Not Installed
              </h4>
              {unavailableManagers.map((manager) => {
                const name = getManagerName(manager)
                const isInstalling = installing === manager.manager_type
                const canInstall = manager.manager_type === 'go' || manager.manager_type === 'pipx' || manager.manager_type === 'winget'
                const canRecheck = manager.manager_type === 'go' || manager.manager_type === 'pipx' || manager.manager_type === 'apt' || manager.manager_type === 'winget'

                return (
                  <div
                    key={manager.manager_type}
                    className="flex items-center justify-between p-3 border rounded-lg bg-muted/50"
                  >
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-md bg-muted text-muted-foreground">
                        {getIcon(manager)}
                      </div>
                      <div>
                        <div className="font-medium">{name}</div>
                        <div className="text-sm text-muted-foreground">
                          {manager.error || 'Not found on system'}
                        </div>
                        {manager.error && (
                          <div className="mt-2 rounded-md border border-red-900/40 bg-red-950/40 p-2">
                            <p className="text-xs leading-relaxed text-red-200 whitespace-pre-wrap">
                              {manager.error}
                            </p>
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {getStatusBadge(manager)}
                      {canRecheck && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => recheckManager(manager)}
                          disabled={checkingManager === manager.manager_type}
                        >
                          {checkingManager === manager.manager_type ? (
                            <>
                              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                              Checking...
                            </>
                          ) : (
                            <>
                              <RefreshCw className="h-4 w-4 mr-2" />
                              Recheck
                            </>
                          )}
                        </Button>
                      )}
                      {canInstall && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => installManager(manager)}
                          disabled={isInstalling}
                        >
                          {isInstalling ? (
                            <>
                              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                              Installing...
                            </>
                          ) : (
                            <>
                              <Download className="h-4 w-4 mr-2" />
                              Install
                            </>
                          )}
                        </Button>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )}

          {/* Info Alert */}
          <div className="rounded-md border border-blue-700 bg-blue-900/20 p-4">
            <p className="text-sm text-blue-300">
              Package managers are required to install security tools automatically.
              Supported managers: <strong>Go</strong> (Go tools), <strong>Pipx</strong> (Python tools),
              <strong>Cargo</strong> (Rust tools), <strong>npm</strong> (Node.js tools),
              <strong>gem</strong> (Ruby tools), <strong>APT</strong> (Linux), <strong>WinGet</strong> (Windows),
              <strong>Homebrew</strong> (macOS).
            </p>
          </div>
        </CardContent>
      )}
    </Card>
  )
}
