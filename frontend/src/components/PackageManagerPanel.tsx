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
  Package
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
  const [installing, setInstalling] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
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
      default: return 'Unknown'
    }
  }

  const installManager = async (managerName: string) => {
    setInstalling(managerName)
    
    try {
      let result
      
      switch (managerName.toLowerCase()) {
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
    } catch (err: any) {
      showError(err.message || `Failed to install ${managerName}`)
    } finally {
      setInstalling(null)
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

  const getIcon = (managerName: string) => {
    const name = managerName.toLowerCase()
    if (name.includes('go')) {
      return <Terminal className="h-5 w-5" />
    }
    if (name.includes('cargo') || name.includes('rust')) {
      return <Package className="h-5 w-5 text-orange-500" />
    }
    if (name.includes('npm') || name.includes('node')) {
      return <Package className="h-5 w-5 text-red-500" />
    }
    if (name.includes('gem') || name.includes('ruby')) {
      return <Package className="h-5 w-5 text-red-600" />
    }
    return <Package className="h-5 w-5" />
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
          <div>
            <CardTitle>Package Managers</CardTitle>
            <CardDescription>
              {availableCount} of {managers.length} package managers available
            </CardDescription>
          </div>
          <Button onClick={loadPackageManagers} variant="outline" size="sm">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Available Managers */}
        <div className="space-y-2">
          {managers.filter(m => m.available).map((manager) => {
            const name = getManagerName(manager)
            return (
              <div
                key={name}
                className="flex items-center justify-between p-3 border rounded-lg bg-background"
              >
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-md bg-primary/10 text-primary">
                    {getIcon(name)}
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
              const isInstalling = installing === name
              const canInstall = ['Go', 'Pipx', 'WinGet'].includes(name)

              return (
                <div
                  key={name}
                  className="flex items-center justify-between p-3 border rounded-lg bg-muted/50"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-md bg-muted text-muted-foreground">
                      {getIcon(name)}
                    </div>
                    <div>
                      <div className="font-medium">{name}</div>
                      <div className="text-sm text-muted-foreground">
                        {manager.error || 'Not found on system'}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {getStatusBadge(manager)}
                    {canInstall && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => installManager(name)}
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
            <strong>gem</strong> (Ruby tools), <strong>APT</strong> (Linux), <strong>WinGet</strong> (Windows).
          </p>
        </div>
      </CardContent>
    </Card>
  )
}
