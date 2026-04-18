import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiService } from '../services/api'
import {
  Save,
  RefreshCw,
  Database,
  Shield,
  Bell,
  Zap,
  HardDrive,
  Clock
} from 'lucide-react'
import { Button } from '../components/ui/Button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card'
import { Input } from '../components/ui/Input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/Select'
import { Badge } from '../components/ui/Badge'
import { PackageManagerTest } from '../components/PackageManagerTest'
import { TelemetryDebugView } from '../components/TelemetryDebugView'

// Default configuration structure
const defaultConfig = {
  database: {
    url: 'sqlite+aiosqlite:///./ai_bug_bounty_scanner.db',
    max_connections: 10,
    timeout: 30
  },
  scanning: {
    max_concurrent_scans: 5,
    scan_timeout: 3600,
    default_scan_type: 'quick'
  },
  notifications: {
    email_enabled: false,
    slack_enabled: false,
    webhook_url: ''
  },
  security: {
    require_authorization: true,
    audit_logging: true,
    data_retention_days: 90
  },
  performance: {
    worker_processes: 2,
    redis_url: 'redis://localhost:6379'
  }
}

const SettingsPage = () => {
  const [config, setConfig] = useState(defaultConfig)
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false)

  const { data: systemStats } = useQuery({
    queryKey: ['system-stats'],
    queryFn: async () => {
      const health = await apiService.getDetailedHealth()
      if (!health.data) throw new Error('Failed to fetch system stats')
      return health.data
    },
    refetchInterval: 10000 // Refresh every 10 seconds
  })

  const handleConfigChange = (section: string, key: string, value: any) => {
    setConfig(prev => ({
      ...prev,
      [section]: {
        ...(prev as any)[section],
        [key]: value
      }
    }))
    setHasUnsavedChanges(true)
  }

  const handleSaveConfig = () => {
    // In a real implementation, this would save to backend
    console.log('Saving config:', config)
    setHasUnsavedChanges(false)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white">Settings</h1>
          <p className="text-gray-400 mt-2 text-sm sm:text-base">
            Configure system settings and preferences
          </p>
        </div>
        <div className="flex items-center space-x-2 flex-wrap">
          {hasUnsavedChanges && (
            <Badge variant="outline" className="text-yellow-400 border-yellow-400 text-xs">
              Unsaved Changes
            </Badge>
          )}
          <Button onClick={handleSaveConfig} disabled={!hasUnsavedChanges} className="w-fit">
            <Save className="mr-2 h-4 w-4" />
            Save Changes
          </Button>
        </div>
      </div>

      {/* Package Manager Test (Development) */}
      <Card className="border-2 border-blue-500">
        <CardContent className="p-0">
          <PackageManagerTest />
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Main Settings */}
        <div className="xl:col-span-2 space-y-6">

          {/* Database Settings */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Database className="mr-2 h-5 w-5" />
                Database Configuration
              </CardTitle>
              <CardDescription>
                Database connection and performance settings
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Database URL
                </label>
                <Input
                  value={config.database.url}
                  onChange={(e) => handleConfigChange('database', 'url', e.target.value)}
                  placeholder="sqlite+aiosqlite:///./ai_bug_bounty_scanner.db"
                />
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Max Connections
                  </label>
                  <Input
                    type="number"
                    value={config.database.max_connections}
                    onChange={(e) => handleConfigChange('database', 'max_connections', parseInt(e.target.value))}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Timeout (seconds)
                  </label>
                  <Input
                    type="number"
                    value={config.database.timeout}
                    onChange={(e) => handleConfigChange('database', 'timeout', parseInt(e.target.value))}
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Scanning Settings */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Zap className="mr-2 h-5 w-5" />
                Scanning Configuration
              </CardTitle>
              <CardDescription>
                Control scan behavior and resource usage
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Max Concurrent Scans
                  </label>
                  <Input
                    type="number"
                    value={config.scanning.max_concurrent_scans}
                    onChange={(e) => handleConfigChange('scanning', 'max_concurrent_scans', parseInt(e.target.value))}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Scan Timeout (seconds)
                  </label>
                  <Input
                    type="number"
                    value={config.scanning.scan_timeout}
                    onChange={(e) => handleConfigChange('scanning', 'scan_timeout', parseInt(e.target.value))}
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Default Scan Type
                </label>
                <Select
                  value={config.scanning.default_scan_type}
                  onValueChange={(value) => handleConfigChange('scanning', 'default_scan_type', value)}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="quick">Quick Scan</SelectItem>
                    <SelectItem value="full">Full Scan</SelectItem>
                    <SelectItem value="custom">Custom Scan</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardContent>
          </Card>

          {/* Security Settings */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Shield className="mr-2 h-5 w-5" />
                Security & Compliance
              </CardTitle>
              <CardDescription>
                Security controls and compliance settings
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <label className="text-sm font-medium text-gray-300">
                    Require Authorization for High-Risk Tools
                  </label>
                  <p className="text-xs text-gray-400 mt-1">
                    Require explicit approval before running high-risk tools
                  </p>
                </div>
                <input
                  type="checkbox"
                  checked={config.security.require_authorization}
                  onChange={(e) => handleConfigChange('security', 'require_authorization', e.target.checked)}
                  className="rounded border-gray-600 bg-gray-700 text-blue-600 focus:ring-blue-500"
                />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <label className="text-sm font-medium text-gray-300">
                    Enable Audit Logging
                  </label>
                  <p className="text-xs text-gray-400 mt-1">
                    Log all scan activities for compliance
                  </p>
                </div>
                <input
                  type="checkbox"
                  checked={config.security.audit_logging}
                  onChange={(e) => handleConfigChange('security', 'audit_logging', e.target.checked)}
                  className="rounded border-gray-600 bg-gray-700 text-blue-600 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Data Retention (days)
                </label>
                <Input
                  type="number"
                  value={config.security.data_retention_days}
                  onChange={(e) => handleConfigChange('security', 'data_retention_days', parseInt(e.target.value))}
                />
              </div>
            </CardContent>
          </Card>

          {/* Performance Settings */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <HardDrive className="mr-2 h-5 w-5" />
                Performance & Infrastructure
              </CardTitle>
              <CardDescription>
                Worker processes and infrastructure settings
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Worker Processes
                </label>
                <Input
                  type="number"
                  value={config.performance.worker_processes}
                  onChange={(e) => handleConfigChange('performance', 'worker_processes', parseInt(e.target.value))}
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Redis URL
                </label>
                <Input
                  value={config.performance.redis_url}
                  onChange={(e) => handleConfigChange('performance', 'redis_url', e.target.value)}
                  placeholder="redis://localhost:6379"
                />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* System Status Sidebar */}
        <div className="space-y-6">
          {/* System Health */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Clock className="mr-2 h-5 w-5" />
                System Health
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-400">Status:</span>
                <Badge className={(systemStats as any)?.system_health === 'healthy' ? 'bg-green-600' : 'bg-yellow-600'}>
                  {(systemStats as any)?.system_health || 'Unknown'}
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-400">Active Scans:</span>
                <span className="text-white">{(systemStats as any)?.active_scans || 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-400">Available Tools:</span>
                <span className="text-white">{(systemStats as any)?.tools_available || 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-400">Critical Issues:</span>
                <span className="text-red-400">{(systemStats as any)?.critical_issues || 0}</span>
              </div>
            </CardContent>
          </Card>

          {/* Quick Actions */}
          <Card>
            <CardHeader>
              <CardTitle>Quick Actions</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <Button className="w-full justify-start" variant="outline">
                <RefreshCw className="mr-2 h-4 w-4" />
                Refresh System Status
              </Button>
              <Button className="w-full justify-start" variant="outline">
                <Database className="mr-2 h-4 w-4" />
                Backup Database
              </Button>
              <Button className="w-full justify-start" variant="outline">
                <Bell className="mr-2 h-4 w-4" />
                Test Notifications
              </Button>
            </CardContent>
          </Card>

          {/* Version Info */}
          <Card>
            <CardHeader>
              <CardTitle>Version Information</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">UniHack:</span>
                <span className="text-white">v2.0.0</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Python:</span>
                <span className="text-white">3.9+</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Node.js:</span>
                <span className="text-white">18+</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Tauri:</span>
                <span className="text-white">1.6+</span>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Telemetry Debug View */}
      <div className="mt-8">
        <Card>
          <CardHeader>
            <CardTitle>Update Checker Telemetry</CardTitle>
            <CardDescription>
              Debug view for update checker telemetry and performance metrics
            </CardDescription>
          </CardHeader>
          <CardContent>
            <TelemetryDebugView />
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

export default SettingsPage
