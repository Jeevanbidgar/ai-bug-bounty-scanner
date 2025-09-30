import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import {
  RefreshCw,
  CheckCircle,
  XCircle,
  Settings,
  Search
} from 'lucide-react'
import { Button } from '../components/ui/Button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Input } from '../components/ui/Input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/Select'

interface Tool {
  name: string
  description: string
  category: string
  command_template: string[]
  output_format: string
  installed: boolean
  version: string | null
}

// API functions using our service
import apiService from '../services/api'

const ToolsPage = () => {
  const [searchTerm, setSearchTerm] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')

  const { data: tools, isLoading, refetch } = useQuery({
    queryKey: ['tools'],
    queryFn: () => apiService.getTools(),
  })

  const refreshMutation = useMutation({
    mutationFn: () => apiService.refreshToolsStatus(),
    onSuccess: () => {
      refetch()
    }
  })

  const filteredTools = (tools?.data || []).filter(tool => {
    const matchesSearch = tool.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         tool.description.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesCategory = categoryFilter === 'all' || tool.category === categoryFilter
    const matchesStatus = statusFilter === 'all' ||
      (statusFilter === 'installed' && tool.installed) ||
      (statusFilter === 'not_installed' && !tool.installed)
    return matchesSearch && matchesCategory && matchesStatus
  })

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

  const getStatusIcon = (tool: Tool) => {
    if (tool.installed) {
      return <CheckCircle className="h-4 w-4 text-green-500" />
    } else {
      return <XCircle className="h-4 w-4 text-red-500" />
    }
  }

  const getRiskLevel = (tool: Tool) => {
    // This would come from the tool registry in a real implementation
    if (tool.name === 'sqlmap' || tool.name === 'nmap') {
      return { level: 'high', color: 'bg-red-600' }
    } else if (tool.name === 'nuclei' || tool.name === 'amass') {
      return { level: 'medium', color: 'bg-yellow-600' }
    } else {
      return { level: 'low', color: 'bg-green-600' }
    }
  }

  const categories = Array.from(new Set((tools?.data || []).map(tool => tool.category)))

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-white">Security Tools</h1>
          <p className="text-gray-400 mt-2">
            Manage and monitor available security scanning tools
          </p>
        </div>
        <Button onClick={() => refreshMutation.mutate()}>
          <RefreshCw className="mr-2 h-4 w-4" />
          Refresh Status
        </Button>
      </div>

      {/* Filters */}
      <div className="flex gap-4">
        <div className="flex-1">
          <Input
            placeholder="Search tools..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full"
          />
        </div>
        <Select value={categoryFilter} onValueChange={setCategoryFilter}>
          <SelectTrigger className="w-48">
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
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="installed">Installed</SelectItem>
            <SelectItem value="not_installed">Not Installed</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Tools Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {isLoading ? (
          // Loading skeletons
          Array.from({ length: 6 }).map((_, i) => (
            <Card key={i} className="animate-pulse">
              <CardContent className="p-6">
                <div className="h-4 bg-gray-700 rounded w-3/4 mb-2"></div>
                <div className="h-3 bg-gray-700 rounded w-full mb-4"></div>
                <div className="flex space-x-2">
                  <div className="h-6 bg-gray-700 rounded w-16"></div>
                  <div className="h-6 bg-gray-700 rounded w-20"></div>
                </div>
              </CardContent>
            </Card>
          ))
        ) : (
          filteredTools.map((tool) => {
            const risk = getRiskLevel(tool)
            return (
              <Card key={tool.id}>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      {getStatusIcon(tool)}
                      <CardTitle className="text-lg">{tool.name}</CardTitle>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Badge className={risk.color} variant="secondary">
                        {risk.level}
                      </Badge>
                      <Button size="sm" variant="ghost">
                        <Settings className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                  <CardDescription>{tool.description}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-gray-400">Category:</span>
                    <Badge variant="outline">
                      {getCategoryDisplayName(tool.category)}
                    </Badge>
                  </div>

                  <div className="flex items-center justify-between text-sm">
                    <span className="text-gray-400">Version:</span>
                    <span className="text-white">
                      {tool.version || 'Unknown'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-sm">
                    <span className="text-gray-400">Status:</span>
                    <div className="flex items-center space-x-1">
                      {tool.installed ? (
                        <CheckCircle className="h-4 w-4 text-green-500" />
                      ) : (
                        <XCircle className="h-4 w-4 text-red-500" />
                      )}
                      <span className={tool.installed ? 'text-green-400' : 'text-red-400'}>
                        {tool.installed ? 'Installed' : 'Not Installed'}
                      </span>
                    </div>
                  </div>

                  {tool.lastCheck && (
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-gray-400">Last Check:</span>
                      <span className="text-gray-300">
                        {new Date(tool.lastCheck).toLocaleDateString()}
                      </span>
                    </div>
                  )}

                  <div className="pt-2 border-t border-gray-700">
                    <div className="text-xs text-gray-400 mb-2">Command Template:</div>
                    <code className="text-xs text-gray-300 bg-gray-800 p-2 rounded block overflow-x-auto">
                      {tool.command_template.join(' ')}
                    </code>
                  </div>
                </CardContent>
              </Card>
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
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-white">{(tools?.data || []).length}</div>
            <div className="text-sm text-gray-400">Total Tools</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-green-400">
              {(tools?.data || []).filter((t: Tool) => t.installed).length}
            </div>
            <div className="text-sm text-gray-400">Installed</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-red-400">
              {(tools?.data || []).filter((t: Tool) => !t.installed).length}
            </div>
            <div className="text-sm text-gray-400">Not Installed</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-blue-400">
              {categories.length}
            </div>
            <div className="text-sm text-gray-400">Categories</div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

export default ToolsPage
