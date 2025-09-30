import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingUp,
  Users,
  Zap,
  Play,
  Plus,
  RefreshCw,
  Settings,
  Zap as Lightning,
  Target,
  Database,
  Cpu,
  HardDrive
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Input } from '../components/ui/Input'
import { Progress } from '../components/ui/Progress'
import { Badge } from '../components/ui/Badge'
import { useState, useEffect } from 'react'
import { invoke } from '@tauri-apps/api/tauri'
import apiService from '../services/api'

// Types for Rust integration
interface SystemInfo {
  os: string;
  arch: string;
  total_memory_mb: string;
  available_memory_mb: string;
  cpu_cores: string;
}

interface ToolInfo {
  name: string;
  description: string;
  category: string;
  installed: boolean;
  version?: string;
  path?: string;
  last_check?: string;
}

interface AppState {
  tools_count: number;
  installed_tools_count: number;
  backend_running: boolean;
}

const Dashboard = () => {
  const queryClient = useQueryClient()
  const [targetUrl, setTargetUrl] = useState('')
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null)
  const [appState, setAppState] = useState<AppState | null>(null)

  // Fetch data using our API service and Rust backend
  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: () => apiService.getHealth(),
    refetchInterval: 10000,
  })

  const { data: scans, isLoading: scansLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: () => apiService.getScans(),
    refetchInterval: 5000,
  })

  const { data: tools } = useQuery({
    queryKey: ['tools'],
    queryFn: () => apiService.getTools(),
    refetchInterval: 30000,
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

    const loadAppState = async () => {
      try {
        const state = await invoke<AppState>('get_application_state')
        setAppState(state)
      } catch (error) {
        console.error('Failed to load app state:', error)
      }
    }

    loadSystemInfo()
    loadAppState()

    // Refresh every 30 seconds
    const interval = setInterval(() => {
      loadAppState()
    }, 30000)

    return () => clearInterval(interval)
  }, [])

  // Mutations
  const quickScanMutation = useMutation({
    mutationFn: (target: string) => apiService.runQuickScan(target),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      setTargetUrl('')
    }
  })

  const handleQuickScan = () => {
    if (targetUrl.trim()) {
      quickScanMutation.mutate(targetUrl)
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
      {/* Enhanced Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="relative">
            <Shield className="h-12 w-12 text-blue-500" />
            <div className="absolute -top-1 -right-1 w-3 h-3 bg-green-500 rounded-full animate-pulse" />
          </div>
          <div>
            <h1 className="text-4xl font-bold text-white flex items-center gap-3">
              AI Bug Bounty Scanner
              <Badge className="bg-green-600 hover:bg-green-700 text-xs">
                <Lightning className="h-3 w-3 mr-1" />
                Online
              </Badge>
            </h1>
            <p className="text-gray-400 mt-1">
              Intelligent security tool orchestration platform
            </p>
          </div>
        </div>

        {/* System Status */}
        <div className="hidden md:flex items-center gap-6">
          <div className="text-center">
            <div className="text-sm text-gray-400">System Health</div>
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${health?.data ? 'bg-green-500' : 'bg-red-500'}`} />
              <span className="text-white font-medium">
                {health?.data ? 'Online' : 'Offline'}
              </span>
            </div>
          </div>

          {systemInfo && (
            <div className="text-center">
              <div className="text-sm text-gray-400">CPU Cores</div>
              <div className="text-white font-medium flex items-center gap-1">
                <Cpu className="h-4 w-4" />
                {systemInfo.cpu_cores}
              </div>
            </div>
          )}

          {systemInfo && (
            <div className="text-center">
              <div className="text-sm text-gray-400">Memory</div>
              <div className="text-white font-medium flex items-center gap-1">
                <HardDrive className="h-4 w-4" />
                {Math.round(parseInt(systemInfo.available_memory_mb) / 1024)}GB
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Quick Scan Card - Enhanced Design */}
      <Card className="border-blue-500/30 bg-gradient-to-br from-gray-900 via-gray-900 to-gray-800 shadow-xl">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-3 text-blue-400 text-xl">
            <Target className="h-6 w-6" />
            Quick Recon Scan
          </CardTitle>
          <CardDescription className="text-gray-300">
            Enter a domain to perform intelligent subdomain discovery and reconnaissance
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <div className="flex-1">
              <Input
                placeholder="example.com"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                className="h-12 text-lg bg-gray-800 border-gray-600 focus:border-blue-500"
                onKeyPress={(e) => e.key === 'Enter' && handleQuickScan()}
              />
            </div>
            <Button
              onClick={handleQuickScan}
              disabled={!targetUrl.trim() || quickScanMutation.isPending}
              className="h-12 px-8 bg-blue-600 hover:bg-blue-700 text-white font-medium"
              size="lg"
            >
              {quickScanMutation.isPending ? (
                <>
                  <RefreshCw className="h-5 w-5 animate-spin mr-2" />
                  Scanning...
                </>
              ) : (
                <>
                  <Play className="h-5 w-5 mr-2" />
                  Start Scan
                </>
              )}
            </Button>
          </div>

          {/* Scan Preview */}
          <div className="mt-4 p-3 bg-gray-800 rounded-lg">
            <div className="text-sm text-gray-400 mb-2">Will execute:</div>
            <div className="flex gap-2 flex-wrap">
              <Badge className="bg-green-600">subfinder</Badge>
              <Badge className="bg-blue-600">amass</Badge>
              <Badge className="bg-purple-600">nuclei</Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Enhanced Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card className="bg-gradient-to-br from-gray-800 to-gray-900 border-gray-700">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-gray-300">Total Scans</CardTitle>
            <Database className="h-4 w-4 text-blue-400" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-white">
              {scansLoading ? '...' : scans?.data?.length || 0}
            </div>
            <p className="text-xs text-gray-400">
              Security assessments completed
            </p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-gray-800 to-gray-900 border-gray-700">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-gray-300">Available Tools</CardTitle>
            <Zap className="h-5 w-5 text-green-400" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-white">
              {appState?.installed_tools_count || 0}
            </div>
            <p className="text-xs text-gray-400">
              {appState?.tools_count || 0} total configured
            </p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-gray-800 to-gray-900 border-gray-700">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-gray-300">System Health</CardTitle>
            <Activity className="h-4 w-4 text-green-400" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-white">
              {health?.data ? 'Online' : 'Offline'}
            </div>
            <p className="text-xs text-gray-400">
              Backend API status
            </p>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-gray-800 to-gray-900 border-gray-700">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-gray-300">Active Scans</CardTitle>
            <Clock className="h-4 w-4 text-orange-400" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-white">
              {scans?.data?.filter((scan: any) => scan.status === 'running').length || 0}
            </div>
            <p className="text-xs text-gray-400">
              Currently executing
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Scans - Enhanced */}
        <Card className="bg-gray-800 border-gray-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5 text-blue-400" />
              Recent Scans
            </CardTitle>
            <CardDescription>
              Latest security scan results and progress
            </CardDescription>
          </CardHeader>
          <CardContent>
            {scansLoading ? (
              <div className="space-y-4">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="animate-pulse">
                    <div className="h-20 bg-gray-700 rounded-lg"></div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="space-y-4">
                {scans?.data?.slice(0, 5).map((scan: any) => (
                  <div key={scan.id} className="p-4 bg-gray-900 rounded-lg border border-gray-600">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center space-x-3">
                        {getStatusIcon(scan.status)}
                        <div>
                          <span className="font-medium text-white">{scan.target}</span>
                          <div className="text-sm text-gray-400">ID: {scan.id.slice(0, 8)}...</div>
                        </div>
                      </div>
                      <Badge className={`${
                        scan.status === 'completed' ? 'bg-green-600' :
                        scan.status === 'running' ? 'bg-blue-600' :
                        scan.status === 'failed' ? 'bg-red-600' : 'bg-yellow-600'
                      }`}>
                        {scan.status}
                      </Badge>
                    </div>

                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-400">Progress</span>
                        <span className="text-white">{scan.progress}%</span>
                      </div>
                      <Progress value={scan.progress} className="h-2" />

                      <div className="flex justify-between text-xs text-gray-400">
                        <span>Started: {formatDate(scan.started_at)}</span>
                        {scan.findings_count && (
                          <span>{scan.findings_count} findings</span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}

                {(!scans?.data || scans.data.length === 0) && (
                  <div className="text-center text-gray-400 py-12">
                    <Target className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <h3 className="text-lg font-medium text-white mb-2">No scans yet</h3>
                    <p className="text-sm">Start your first scan using the form above!</p>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Available Tools - Enhanced */}
        <Card className="bg-gray-800 border-gray-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Settings className="h-5 w-5 text-green-400" />
              Available Tools
            </CardTitle>
            <CardDescription>
              Security tools detected and ready for use
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {(tools?.data || []).slice(0, 8).map((tool: any) => (
                <div key={tool.name} className="flex items-center justify-between p-3 bg-gray-900 rounded-lg border border-gray-600">
                  <div className="flex items-center gap-3">
                    <div className={`w-3 h-3 rounded-full ${tool.installed ? 'bg-green-500' : 'bg-red-500'}`} />
                    <div>
                      <div className="font-medium text-white">{tool.name}</div>
                      <div className="text-sm text-gray-400">{tool.description}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge className={`text-xs ${
                      tool.category === 'recon' ? 'bg-blue-600' :
                      tool.category === 'vulnerability' ? 'bg-red-600' :
                      tool.category === 'network' ? 'bg-green-600' : 'bg-gray-600'
                    }`}>
                      {tool.category}
                    </Badge>
                    {tool.version && (
                      <span className="text-xs text-gray-400">v{tool.version}</span>
                    )}
                  </div>
                </div>
              ))}

              {(tools?.data || []).length === 0 && (
                <div className="text-center text-gray-400 py-8">
                  <Settings className="h-8 w-8 mx-auto mb-3 opacity-50" />
                  <p className="text-sm">No tools detected yet</p>
                  <Button variant="outline" size="sm" className="mt-3">
                    <RefreshCw className="h-4 w-4 mr-2" />
                    Refresh Tools
                  </Button>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Enhanced Features Overview */}
      <Card className="bg-gradient-to-br from-gray-800 to-gray-900 border-gray-700">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-xl">
            <Lightning className="h-6 w-6 text-yellow-400" />
            Agent-Based Security Scanning
          </CardTitle>
          <CardDescription className="text-gray-300">
            Intelligent workflows that orchestrate multiple security tools automatically
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="text-center p-6 bg-blue-500/10 rounded-xl border border-blue-500/20">
              <Shield className="h-10 w-10 text-blue-400 mx-auto mb-3" />
              <div className="font-semibold text-white mb-2">Reconnaissance</div>
              <div className="text-sm text-gray-400">
                Subdomain discovery, port scanning, service enumeration
              </div>
            </div>

            <div className="text-center p-6 bg-green-500/10 rounded-xl border border-green-500/20">
              <CheckCircle className="h-10 w-10 text-green-400 mx-auto mb-3" />
              <div className="font-semibold text-white mb-2">Vulnerability Assessment</div>
              <div className="text-sm text-gray-400">
                CVE scanning, misconfiguration detection, web vulnerabilities
              </div>
            </div>

            <div className="text-center p-6 bg-purple-500/10 rounded-xl border border-purple-500/20">
              <TrendingUp className="h-10 w-10 text-purple-400 mx-auto mb-3" />
              <div className="font-semibold text-white mb-2">Intelligent Reporting</div>
              <div className="text-sm text-gray-400">
                Automated report generation with risk scoring and recommendations
              </div>
            </div>
          </div>

          {/* Workflow Preview */}
          <div className="mt-6 p-4 bg-gray-900 rounded-lg">
            <div className="text-sm text-gray-400 mb-3">Sample Workflow Preview:</div>
            <div className="flex items-center gap-3 text-sm">
              <Badge className="bg-blue-600">subfinder</Badge>
              <span className="text-gray-500">→</span>
              <Badge className="bg-green-600">amass</Badge>
              <span className="text-gray-500">→</span>
              <Badge className="bg-purple-600">nuclei</Badge>
              <span className="text-gray-500">→</span>
              <Badge className="bg-orange-600">Report</Badge>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

export default Dashboard
