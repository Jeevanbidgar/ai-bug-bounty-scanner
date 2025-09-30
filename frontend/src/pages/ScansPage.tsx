import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus,
  Play,
  Square,
  Eye,
  Trash2,
  Search
} from 'lucide-react'
import { Button } from '../components/ui/Button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Progress } from '../components/ui/Progress'
import { Input } from '../components/ui/Input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/Select'
import { apiService, Scan } from '../services/api'
// WebSocket integration will be added later

// API functions
const fetchScans = async (): Promise<Scan[]> => {
  const response = await apiService.getScans()
  return response.data || []
}

const createScan = async (scanData: any): Promise<Scan> => {
  const response = await apiService.createScan(scanData)
  if (response.error) throw new Error(response.error)
  return response.data!
}

const startScan = async (scanId: string): Promise<void> => {
  const response = await apiService.startScan(scanId)
  if (response.error) throw new Error(response.error)
}

const deleteScan = async (scanId: string): Promise<void> => {
  const response = await apiService.deleteScan(scanId)
  if (response.error) throw new Error(response.error)
}

const ScansPage = () => {
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [newScanTarget, setNewScanTarget] = useState('')
  const [newScanType, setNewScanType] = useState('Quick Scan')

  const queryClient = useQueryClient()

  // WebSocket integration for real-time updates will be added later

  const { data: scans = [], isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: fetchScans
  })

  const createScanMutation = useMutation({
    mutationFn: createScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      setShowCreateForm(false)
      setNewScanTarget('')
      setNewScanType('Quick Scan')
    }
  })

  const startScanMutation = useMutation({
    mutationFn: startScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    }
  })

  const deleteScanMutation = useMutation({
    mutationFn: deleteScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    }
  })

  const filteredScans = scans.filter(scan => {
    const matchesSearch = scan.target.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesStatus = statusFilter === 'all' || scan.status === statusFilter
    return matchesSearch && matchesStatus
  })

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'running': return 'bg-blue-600'
      case 'completed': return 'bg-green-600'
      case 'failed': return 'bg-red-600'
      case 'pending': return 'bg-yellow-600'
      case 'cancelled': return 'bg-gray-600'
      default: return 'bg-gray-600'
    }
  }

  // Removed unused getStatusIcon function

  const handleCreateScan = () => {
    if (!newScanTarget.trim()) return

    createScanMutation.mutate({
      target: newScanTarget,
      scanType: newScanType
    })
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-white">Security Scans</h1>
          <p className="text-gray-400 mt-2">
            Manage and monitor your security scanning operations
          </p>
        </div>
        <Button onClick={() => setShowCreateForm(true)}>
          <Plus className="mr-2 h-4 w-4" />
          New Scan
        </Button>
      </div>

      {/* Filters */}
      <div className="flex gap-4">
        <div className="flex-1">
          <Input
            placeholder="Search scans..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full"
          />
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Filter by status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="running">Running</SelectItem>
            <SelectItem value="completed">Completed</SelectItem>
            <SelectItem value="failed">Failed</SelectItem>
            <SelectItem value="pending">Pending</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Create Scan Form */}
      {showCreateForm && (
        <Card>
          <CardHeader>
            <CardTitle>Create New Scan</CardTitle>
            <CardDescription>
              Start a new security assessment scan
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Target URL/Domain
              </label>
              <Input
                placeholder="https://example.com"
                value={newScanTarget}
                onChange={(e) => setNewScanTarget(e.target.value)}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Scan Type
              </label>
              <Select value={newScanType} onValueChange={setNewScanType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="Quick Scan">Quick Scan</SelectItem>
                  <SelectItem value="Full Scan">Full Scan</SelectItem>
                  <SelectItem value="Custom Scan">Custom Scan</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex gap-2">
              <Button onClick={handleCreateScan} disabled={createScanMutation.isPending}>
                {createScanMutation.isPending ? 'Creating...' : 'Create Scan'}
              </Button>
              <Button variant="outline" onClick={() => setShowCreateForm(false)}>
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Scans List */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="grid gap-4">
            {[1, 2, 3].map((i) => (
              <Card key={i} className="animate-pulse">
                <CardContent className="p-6">
                  <div className="h-4 bg-gray-700 rounded w-1/4 mb-4"></div>
                  <div className="h-3 bg-gray-700 rounded w-1/2 mb-2"></div>
                  <div className="h-3 bg-gray-700 rounded w-3/4"></div>
                </CardContent>
              </Card>
            ))}
          </div>
        ) : (
          filteredScans.map((scan) => (
            <Card key={scan.id}>
              <CardContent className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    <div className={`w-3 h-3 rounded-full ${getStatusColor(scan.status)}`}></div>
                    <div>
                      <h3 className="font-semibold text-white">{scan.target}</h3>
                      <p className="text-sm text-gray-400">
                        {scan.scanType} • Started {new Date(scan.started).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Button size="sm" variant="outline">
                      <Eye className="h-4 w-4" />
                    </Button>
                    {scan.status === 'pending' && (
                      <Button
                        size="sm"
                        onClick={() => startScanMutation.mutate(scan.id)}
                        disabled={startScanMutation.isPending}
                      >
                        <Play className="h-4 w-4" />
                      </Button>
                    )}
                    {scan.status === 'running' && (
                      <Button size="sm" variant="outline">
                        <Square className="h-4 w-4" />
                      </Button>
                    )}
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => deleteScanMutation.mutate(scan.id)}
                      disabled={deleteScanMutation.isPending}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>

                {scan.current_test && (
                  <div className="mb-4">
                    <p className="text-sm text-blue-400">{scan.current_test}</p>
                  </div>
                )}

                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-4">
                    <Progress value={scan.progress} className="w-32" />
                    <span className="text-sm text-gray-400">{scan.progress}%</span>
                  </div>
                  <div className="flex items-center space-x-4">
                    {scan.vulnerabilities > 0 && (
                      <div className="text-right">
                        <p className="text-sm text-gray-400">Vulnerabilities</p>
                        <p className="text-lg font-semibold text-white">{scan.vulnerabilities}</p>
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="text-sm text-gray-400">Agents:</span>
                    <div className="flex space-x-1">
                      {scan.agents.slice(0, 3).map((agent) => (
                        <Badge key={agent} variant="secondary" className="text-xs">
                          {agent}
                        </Badge>
                      ))}
                      {scan.agents.length > 3 && (
                        <Badge variant="secondary" className="text-xs">
                          +{scan.agents.length - 3}
                        </Badge>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center space-x-4">
                    {scan.critical > 0 && (
                      <Badge className="bg-red-600">Critical: {scan.critical}</Badge>
                    )}
                    {scan.high > 0 && (
                      <Badge className="bg-orange-600">High: {scan.high}</Badge>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>

      {filteredScans.length === 0 && !isLoading && (
        <Card>
          <CardContent className="p-12 text-center">
            <div className="text-gray-400">
              <Search className="mx-auto h-12 w-12 mb-4" />
              <h3 className="text-lg font-medium text-white mb-2">No scans found</h3>
              <p>Start your first security scan to get started.</p>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

export default ScansPage
