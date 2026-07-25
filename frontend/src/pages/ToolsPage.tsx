import { useState, useEffect, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  RefreshCw,
  CheckCircle,
  Search,
  Plus,
  Trash2,
  AlertTriangle,
  Loader2,
  ArrowUpCircle,
  ChevronUp
} from 'lucide-react'
import { Button } from '../components/ui/Button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Input } from '../components/ui/Input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/Select'
import { ToastContainer } from '../components/ui/Toast'
import { useToast } from '../hooks/useToast'
import ToolDetailModal from '../components/ToolDetailModal'
import { InstallationProgressModal } from '../components/InstallationProgressModal'
import { PackageManagerPanel } from '../components/PackageManagerPanel'
import { ToolCard } from '../components/ToolCard'

import type { Tool } from '../services/api'

// API functions using our service
import apiService from '../services/api'
import { appBridge } from '../bridge/appBridge'

const ToolsPage = () => {
  const [searchTerm, setSearchTerm] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [packageManagerFilter, setPackageManagerFilter] = useState('all')
  const [showAddToolDialog, setShowAddToolDialog] = useState(false)
  const [isManualToolSectionExpanded, setIsManualToolSectionExpanded] = useState(false)
  const [manualToolName, setManualToolName] = useState('')
  const [manualToolPath, setManualToolPath] = useState('')
  const [manualToolCategory, setManualToolCategory] = useState('custom')
  const [selectedTool, setSelectedTool] = useState<Tool | null>(null)
  const [toolUpdates, setToolUpdates] = useState<Record<string, { hasUpdate: boolean; latestVersion: string | null }>>({})
  const [isInitialDiscovery, setIsInitialDiscovery] = useState(false)
  const [discoveryProgress, setDiscoveryProgress] = useState(0)

  // State for installation progress modal
  const [isInstalling, setIsInstalling] = useState(false)
  const [installingTool, setInstallingTool] = useState<string | null>(null)

  const queryClient = useQueryClient()
  const { toasts, success, error: showError, info, warning, removeToast } = useToast()

  const { data: tools, isLoading, error, refetch } = useQuery({
    queryKey: ['tools'],
    queryFn: async () => (await apiService.getTools(false)).data,
    refetchInterval: isInitialDiscovery ? 2000 : false, // Poll every 2s during initial discovery
    refetchOnWindowFocus: false,
  })

  // Detect if this is the initial discovery and trigger it explicitly
  useEffect(() => {
    const triggerInitialDiscovery = async () => {
      // If we have no tools (empty cache), trigger discovery explicitly
      if (tools && tools.length === 0 && !isLoading) {
        setIsInitialDiscovery(true)

        // Trigger discovery with forceRefresh=true
        try {
          await apiService.getTools(true)
          // After triggering, refetch will poll via refetchInterval
          refetch()
        } catch (err) {
          console.error('Failed to trigger initial discovery:', err)
          setIsInitialDiscovery(false)
        }
      } else if (tools?.length) {
        // Once we have tools data, discovery is complete
        if (isInitialDiscovery) {
          setDiscoveryProgress(100)
          setTimeout(() => setIsInitialDiscovery(false), 500) // Brief delay to show 100%
        }
      }
    }

    triggerInitialDiscovery()
  }, [isLoading, tools, isInitialDiscovery, refetch])

  const refreshMutation = useMutation({
    mutationFn: async () => {
      // Call getTools with forceRefresh=true to trigger tool discovery
      const result = await apiService.getTools(true)
      return result
    },
    onSuccess: (data) => {
      refetch()
      const toolCount = data.data?.length || 0
      const installedCount = data.data?.filter(t => t.installed).length || 0
      success(`Tools refreshed! Found ${installedCount} of ${toolCount} tools installed`)
    },
    onError: (err) => {
      showError(err instanceof Error ? err.message : 'Failed to refresh tools')
    }
  })

  const addManualToolMutation = useMutation({
    mutationFn: (data: { tool_name: string; tool_path: string; category: string }) =>
      apiService.addManualTool(data),
    onSuccess: () => {
      refetch()
      queryClient.invalidateQueries({ queryKey: ['manual-tools'] })
      setShowAddToolDialog(false)
      setManualToolName('')
      setManualToolPath('')
      setManualToolCategory('custom')
      success('Manual tool registered and queued for local capability review')
    },
    onError: (error) => showError(error instanceof Error ? error.message : 'Failed to register manual tool'),
  })

  const removeManualToolMutation = useMutation({
    mutationFn: (toolName: string) => apiService.removeManualTool(toolName),
    onSuccess: () => {
      refetch()
      queryClient.invalidateQueries({ queryKey: ['manual-tools'] })
      success('Manual tool registration removed')
    },
    onError: (error) => showError(error instanceof Error ? error.message : 'Failed to remove manual tool'),
  })

  useEffect(() => {
    if (!showAddToolDialog) return
    const close = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !addManualToolMutation.isPending) setShowAddToolDialog(false)
    }
    window.addEventListener('keydown', close)
    return () => window.removeEventListener('keydown', close)
  }, [addManualToolMutation.isPending, showAddToolDialog])

  const { data: manualTools, error: manualToolsError, refetch: refetchManualTools } = useQuery({
    queryKey: ['manual-tools'],
    queryFn: () => apiService.getManualTools(),
  })

  // Check for updates mutation - triggered manually via button click
  const checkUpdatesMutation = useMutation({
    mutationFn: async () => {
      if (!tools) return {}

      info('Checking for updates...')

      // Only check installed tools with valid paths
      const installedTools = tools.filter((t: Tool) => t.installed && t.path)
      const updates: Record<string, { hasUpdate: boolean; latestVersion: string | null }> = {}

      let checkedCount = 0
      let updatesFound = 0
      let failedCount = 0

      // Check updates for all installed tools
      for (const tool of installedTools) {
        try {
          const result = await apiService.checkToolUpdate(tool.name)
          if (result.error) {
            failedCount++
            continue
          }
          updates[tool.name] = {
            hasUpdate: result.has_update,
            latestVersion: result.latest_version
          }
          if (result.has_update) {
            updatesFound++
          }
          checkedCount++
        } catch {
          failedCount++
        }
      }

      return { updates, checkedCount, updatesFound, failedCount }
    },
    onSuccess: (data) => {
      if (data) {
        setToolUpdates(data.updates)
        if (data.checkedCount === 0 && data.failedCount > 0) {
          warning(`Update checks were unavailable for ${data.failedCount} installed tool(s)`)
        } else if (data.updatesFound > 0) {
          success(`Found ${data.updatesFound} update(s) available for ${data.checkedCount} tool(s)`)
        } else {
          const suffix = data.failedCount > 0 ? `; ${data.failedCount} could not be checked` : ''
          success(`All ${data.checkedCount} checked tool(s) are up to date${suffix}`)
        }
      }
    },
    onError: (error) => {
      showError('Failed to check for updates')
      console.error('Update check error:', error)
    },
  })

  const filteredTools = useMemo(() => {
    const filtered = (tools ?? []).filter((tool: Tool) => {
      const matchesSearch = tool.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        tool.description.toLowerCase().includes(searchTerm.toLowerCase())
      const matchesCategory = categoryFilter === 'all' || tool.category === categoryFilter
      const matchesStatus = statusFilter === 'all' ||
        (statusFilter === 'installed' && tool.installed) ||
        (statusFilter === 'not-installed' && !tool.installed) ||
        (statusFilter === 'updates-available' && tool.installed && toolUpdates[tool.name]?.hasUpdate)

      const allInstallMethods: string[] = []
      if (tool.install_method) {
        allInstallMethods.push(tool.install_method)
      }
      if (tool.alternative_install_methods) {
        allInstallMethods.push(...tool.alternative_install_methods)
      }
      const matchesPackageManager = packageManagerFilter === 'all' ||
        allInstallMethods.some(method =>
          method === packageManagerFilter ||
          (packageManagerFilter === 'git-pip' && method.includes('git'))
        )
      return matchesSearch && matchesCategory && matchesStatus && matchesPackageManager
    })

    return filtered
  }, [tools, searchTerm, categoryFilter, statusFilter, packageManagerFilter, toolUpdates])

  const getCategoryDisplayName = (category: string) => {
    const categoryNames: Record<string, string> = {
      'recon': 'Reconnaissance',
      'web': 'Web Application',
      'network': 'Network',
      'fuzzing': 'Fuzzing',
      'injection': 'Injection',
      'signature': 'Signature',
      'tls_waf': 'TLS/WAF',
      'api_auth': 'API/Auth',
      'host_audit': 'Host Audit',
      'metadata': 'Metadata',
      'reporting': 'Reporting',
      'osint': 'OSINT',
      'ml_fp': 'ML/False Positive'
    }
    return categoryNames[category] || category
  }

  const categories = useMemo(() => {
    return Array.from(new Set((tools ?? []).map((tool) => tool.category)))
  }, [tools])

  const installationMethodLabels: Record<string, string> = {
    go: 'Go',
    'git-pip': 'Git + pip',
    pipx: 'pipx',
    apt: 'APT',
    winget: 'WinGet',
    cargo: 'Cargo',
    gem: 'Ruby gem',
    npm: 'npm',
    homebrew: 'Homebrew',
    manual: 'Manual setup',
    runtime: 'System runtime',
  }

  const autoInstallMethods = ['go', 'git-pip', 'pipx', 'apt', 'winget', 'cargo', 'gem', 'npm', 'homebrew']

  // Initial discovery loading state with overlay
  if (isInitialDiscovery || (isLoading && !tools)) {
    return (
      <div className="fixed inset-0 bg-gray-900 z-50 flex items-center justify-center">
        <div className="text-center space-y-6 max-w-md px-6">
          <div className="relative">
            <Loader2 className="h-16 w-16 animate-spin text-blue-500 mx-auto" />
            <div className="absolute inset-0 flex items-center justify-center">
              <Search className="h-8 w-8 text-blue-300 animate-pulse" />
            </div>
          </div>
          <div className="space-y-2">
            <h2 className="text-2xl font-bold text-white">Discovering Security Tools</h2>
            <p className="text-gray-400">
              Scanning your system for available security tools...
            </p>
          </div>
          {discoveryProgress > 0 && discoveryProgress < 100 && (
            <div className="space-y-2">
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div
                  className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${discoveryProgress}%` }}
                ></div>
              </div>
              <p className="text-sm text-gray-500">{discoveryProgress}% complete</p>
            </div>
          )}
          <div className="flex items-center justify-center gap-2 text-sm text-gray-500">
            <AlertTriangle className="h-4 w-4" />
            <span>This may take a few moments on first run</span>
          </div>
        </div>
      </div>
    )
  }

  // Error state
  if (error) {
    return (
      <div className="space-y-6">
        <Card className="bg-red-900/20 border-red-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-5 w-5" />
              Failed to Load Tools
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-red-300 mb-4">
              {error instanceof Error ? error.message : 'An unexpected error occurred'}
            </p>
            <Button
              onClick={() => refetch()}
              variant="outline"
              className="border-red-600 text-red-400 hover:bg-red-900/30"
            >
              <RefreshCw className="mr-2 h-4 w-4" />
              Try Again
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Toast Container */}
      <ToastContainer toasts={toasts} onRemove={removeToast} />


      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white">Security Tools</h1>
          <p className="text-gray-400 mt-2 text-sm sm:text-base">
            Manage and monitor available security scanning tools
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            onClick={() => checkUpdatesMutation.mutate()}
            className="w-fit bg-purple-600 hover:bg-purple-700"
            disabled={checkUpdatesMutation.isPending}
            title="Check for updates on installed tools"
          >
            {checkUpdatesMutation.isPending ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Checking...
              </>
            ) : (
              <>
                <ArrowUpCircle className="mr-2 h-4 w-4" />
                Check Updates
              </>
            )}
          </Button>
          <Button
            onClick={() => refreshMutation.mutate()}
            className="w-fit"
            disabled={refreshMutation.isPending}
            title="Refresh tool discovery status"
          >
            {refreshMutation.isPending ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Refreshing...
              </>
            ) : (
              <>
                <RefreshCw className="mr-2 h-4 w-4" />
                Refresh Status
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Package Managers Section */}
      <PackageManagerPanel
        onInstallComplete={() => {
          success('Package manager installed successfully!')
          refetch()
        }}
      />

      {/* Filters */}
      <div className="flex flex-col lg:flex-row gap-4">
        <div className="flex-1">
          <Input
            placeholder="Search tools..."
            aria-label="Search tools"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full"
          />
        </div>
        <Select value={categoryFilter} onValueChange={setCategoryFilter}>
          <SelectTrigger className="w-full lg:w-48" aria-label="Filter tools by category">
            <SelectValue placeholder="Category" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Categories</SelectItem>
            {categories.map(category => (
              <SelectItem key={category} value={category}>
                {getCategoryDisplayName(category)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-full lg:w-48" aria-label="Filter tools by status">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="installed">Installed</SelectItem>
            <SelectItem value="not-installed">Not Installed</SelectItem>
            <SelectItem value="updates-available">Updates Available</SelectItem>
          </SelectContent>
        </Select>
        <Select value={packageManagerFilter} onValueChange={setPackageManagerFilter}>
          <SelectTrigger className="w-full lg:w-48" aria-label="Filter tools by package manager">
            <SelectValue placeholder="Package Manager" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Package Managers</SelectItem>
            <SelectItem value="go">Go</SelectItem>
            <SelectItem value="cargo">Cargo (Rust)</SelectItem>
            <SelectItem value="gem">gem (Ruby)</SelectItem>
            <SelectItem value="git-pip">Python (pipx/git)</SelectItem>
            <SelectItem value="apt">APT (Linux)</SelectItem>
            <SelectItem value="homebrew">Homebrew (macOS)</SelectItem>
            <SelectItem value="manual">Manual Install</SelectItem>
            <SelectItem value="runtime">Runtime/System</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Manual Tool Management - Collapsible */}
      <div className="space-y-2">
        {!isManualToolSectionExpanded ? (
          <Button
            onClick={() => setIsManualToolSectionExpanded(true)}
            variant="outline"
            size="sm"
            className="w-auto bg-gray-800 hover:bg-gray-700 border-gray-600 text-gray-300"
          >
            <Plus className="h-4 w-4 mr-2" />
            Add Tool Manually
            {(manualTools?.data?.manual_tools?.length ?? 0) > 0 && (
              <Badge className="ml-2 bg-blue-600 text-white">
                {manualTools?.data?.manual_tools?.length}
              </Badge>
            )}
          </Button>
        ) : (
          <Card className="bg-gradient-to-br from-gray-800 to-gray-900 border-gray-700">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <CardTitle className="flex items-center gap-2 text-blue-400">
                    <Plus className="h-5 w-5" />
                    Manual Tool Management
                  </CardTitle>
                  <CardDescription className="text-gray-400">
                    Add tools that weren't automatically discovered or are in non-standard locations
                  </CardDescription>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    onClick={() => setShowAddToolDialog(true)}
                    className="bg-blue-600 hover:bg-blue-700"
                    size="sm"
                  >
                    <Plus className="h-4 w-4 mr-2" />
                    Add Tool
                  </Button>
                  <Button
                    onClick={() => setIsManualToolSectionExpanded(false)}
                    variant="ghost"
                    size="sm"
                    className="text-gray-400 hover:text-white"
                    aria-label="Collapse manual tool management"
                  >
                    <ChevronUp className="h-5 w-5" />
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {manualToolsError ? (
                <div className="rounded-xl border border-red-400/20 bg-red-400/[0.05] p-4 text-sm text-red-200" role="alert">
                  <p>Manual tool registrations could not be loaded.</p>
                  <Button className="mt-3" size="sm" variant="ghost" onClick={() => refetchManualTools()}>Try again</Button>
                </div>
              ) : (manualTools?.data?.manual_tools?.length ?? 0) > 0 ? (
                <div className="space-y-3">
                  <h4 className="text-sm font-medium text-gray-300">Manually Added Tools:</h4>
                  <div className="grid gap-3">
                    {(manualTools?.data?.manual_tools ?? []).map((toolName: string) => {
                      const tool = tools?.find((t: Tool) => t.name === toolName)
                      return (
                        <div key={toolName} className="flex items-center justify-between p-3 bg-gray-900 rounded-lg border border-gray-700">
                          <div className="flex items-center gap-3">
                            <CheckCircle className="h-4 w-4 text-green-500" />
                            <div>
                              <span className="font-medium text-white">{toolName}</span>
                              {tool && <div className="text-sm text-gray-400">{tool.path}</div>}
                            </div>
                          </div>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              if (window.confirm(`Remove the manual registration for ${toolName}?`)) removeManualToolMutation.mutate(toolName)
                            }}
                            className="text-red-400 border-red-400 hover:bg-red-400 hover:text-white"
                            aria-label={`Remove manual tool ${toolName}`}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      )
                    })}
                  </div>
                </div>
              ) : (
                <div className="text-center py-8 text-gray-400">
                  <Plus className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No manually added tools yet</p>
                  <p className="text-sm">Click "Add Tool" to add tools in non-standard locations</p>
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>

      {/* Add Manual Tool Dialog */}
      {showAddToolDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 p-4" role="dialog" aria-modal="true" aria-labelledby="manual-tool-dialog-title">
          <Card className="w-full max-w-md bg-gray-900 border-gray-700">
            <CardHeader>
              <CardTitle id="manual-tool-dialog-title" className="text-blue-400">Add Manual Tool</CardTitle>
              <CardDescription className="text-gray-400">
                Add a tool that wasn't automatically discovered
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <label htmlFor="manual-tool-name" className="text-sm font-medium text-gray-300">Tool Name</label>
                <Input
                  id="manual-tool-name"
                  placeholder="e.g., httpx"
                  value={manualToolName}
                  onChange={(e) => setManualToolName(e.target.value)}
                  className="bg-gray-800 border-gray-600 text-white"
                />
              </div>
              <div className="space-y-2">
                <label htmlFor="manual-tool-path" className="text-sm font-medium text-gray-300">Tool Path</label>
                <Input
                  id="manual-tool-path"
                  placeholder="e.g., /usr/local/bin/httpx"
                  value={manualToolPath}
                  onChange={(e) => setManualToolPath(e.target.value)}
                  className="bg-gray-800 border-gray-600 text-white"
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium text-gray-300">Category</label>
                <Select value={manualToolCategory} onValueChange={setManualToolCategory}>
                  <SelectTrigger className="bg-gray-800 border-gray-600 text-white" aria-label="Manual tool category">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="custom">Custom</SelectItem>
                    <SelectItem value="recon">Reconnaissance</SelectItem>
                    <SelectItem value="web">Web Application</SelectItem>
                    <SelectItem value="network">Network</SelectItem>
                    <SelectItem value="vulnerability">Vulnerability</SelectItem>
                    <SelectItem value="utility">Utility</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="flex gap-3 pt-4">
                <Button
                  onClick={() => addManualToolMutation.mutate({
                    tool_name: manualToolName,
                    tool_path: manualToolPath,
                    category: manualToolCategory
                  })}
                  disabled={!manualToolName.trim() || !manualToolPath.trim() || addManualToolMutation.isPending}
                  className="flex-1 bg-blue-600 hover:bg-blue-700"
                >
                  {addManualToolMutation.isPending ? 'Adding...' : 'Add Tool'}
                </Button>
                <Button
                  variant="outline"
                  onClick={() => setShowAddToolDialog(false)}
                  className="flex-1"
                >
                  Cancel
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Tools Grid */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 min-[1180px]:grid-cols-3">
        {isLoading ? (
          // Loading skeletons
          Array.from({ length: 6 }).map((_, i) => (
            <Card key={i} className="min-h-[244px] animate-pulse">
              <CardContent className="p-5">
                <div className="flex items-center gap-3">
                  <div className="h-10 w-10 rounded-xl bg-white/[0.06]" />
                  <div className="flex-1 space-y-2">
                    <div className="h-4 w-1/2 rounded bg-white/[0.07]" />
                    <div className="h-2.5 w-1/3 rounded bg-white/[0.05]" />
                  </div>
                  <div className="h-6 w-20 rounded-full bg-white/[0.06]" />
                </div>
                <div className="mt-5 h-10 rounded-lg bg-white/[0.04]" />
                <div className="mt-4 h-14 rounded-xl bg-white/[0.05]" />
                <div className="mt-4 h-px bg-white/[0.06]" />
              </CardContent>
            </Card>
          ))
        ) : (
          filteredTools.map((tool: Tool) => {
            const installMethod = tool.install_method || tool.available_install_methods?.[0] || (tool.installed ? 'runtime' : 'manual')
            const hasAutoInstall = autoInstallMethods.includes(installMethod) ||
              tool.available_install_methods?.some(method => autoInstallMethods.includes(method))
            const update = toolUpdates[tool.name]
            return (
              <ToolCard
                key={tool.name}
                tool={tool}
                categoryLabel={getCategoryDisplayName(tool.category)}
                installMethodLabel={installationMethodLabels[installMethod] || installMethod}
                automatedInstallAvailable={Boolean(hasAutoInstall)}
                hasUpdate={Boolean(update?.hasUpdate)}
                latestVersion={update?.latestVersion || null}
                onOpen={() => setSelectedTool(tool)}
              />
            )
          })
        )}
      </div>

      {filteredTools.length === 0 && !isLoading && (
        <Card>
          <CardContent className="p-12 text-center">
            <div className="text-gray-400">
              <Search className="mx-auto h-12 w-12 mb-4" />
              <h3 className="text-lg font-medium text-white mb-2">No tools found</h3>
              <p>Try adjusting your search or filter criteria.</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-xl sm:text-2xl font-bold text-white">{tools?.length ?? 0}</div>
            <div className="text-sm text-gray-400">Total Tools</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-xl sm:text-2xl font-bold text-green-400">
              {(tools ?? []).filter((t: Tool) => t.installed).length}
            </div>
            <div className="text-sm text-gray-400">Installed</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-xl sm:text-2xl font-bold text-red-400">
              {(tools ?? []).filter((t: Tool) => !t.installed).length}
            </div>
            <div className="text-sm text-gray-400">Not Installed</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-xl sm:text-2xl font-bold text-blue-400">
              {categories.length}
            </div>
            <div className="text-sm text-gray-400">Categories</div>
          </CardContent>
        </Card>
      </div>

      {/* Tool Detail Modal */}
      {selectedTool && (
        <ToolDetailModal
          tool={selectedTool}
          onClose={() => setSelectedTool(null)}
          onInstallStart={(toolName) => {
            if (appBridge.capabilities.events) {
              setInstallingTool(toolName)
              setIsInstalling(true)
            }
          }}
          onToolUpdate={(updatedTool) => {
            // Update the selected tool in local state
            setSelectedTool(updatedTool)

            // CRITICAL FIX: Update React Query cache directly
            // This prevents the tool from reverting to "Not Installed" when modal closes
            queryClient.setQueryData<Tool[]>(['tools'], (oldData) => oldData?.map((tool) =>
              tool.name === updatedTool.name ? updatedTool : tool
            ))
          }}
        />
      )}

      {/* Installation Progress Modal */}
      {isInstalling && installingTool && (
        <InstallationProgressModal
          isOpen={isInstalling}
          toolName={installingTool}
          onClose={() => {
            setIsInstalling(false)
            setInstallingTool(null)
            // Refetch tools to update status
            refetch()
          }}
        />
      )}
    </div>
  )
}

export default ToolsPage
