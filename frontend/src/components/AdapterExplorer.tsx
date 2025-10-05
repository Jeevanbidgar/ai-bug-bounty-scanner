import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Shield,
  Clock,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Loader2,
  Filter,
  Search,
  Code,
  Copy,
  Check
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/Card'
import { Badge } from './ui/Badge'
import { Button } from './ui/Button'
import { Input } from './ui/Input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/Select'
import apiService, { type AdapterInfo } from '../services/api'
import { useToast } from '../hooks/useToast'

interface AdapterExplorerProps {
  onSelectAdapter?: (adapter: AdapterInfo) => void
  selectedAdapter?: AdapterInfo | null
}

export const AdapterExplorer = ({ onSelectAdapter, selectedAdapter }: AdapterExplorerProps) => {
  const [searchTerm, setSearchTerm] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const [riskFilter, setRiskFilter] = useState('all')
  const [selectedAdapterInfo, setSelectedAdapterInfo] = useState<AdapterInfo | null>(selectedAdapter || null)
  const [commandPreview, setCommandPreview] = useState<string[]>([])
  const [targetInput, setTargetInput] = useState('example.com')
  const [copiedCommand, setCopiedCommand] = useState(false)

  const { success, error: showError } = useToast()

  // Query all adapters
  const { data: adapters, isLoading } = useQuery({
    queryKey: ['adapters'],
    queryFn: () => apiService.listAdapters(),
    staleTime: 5 * 60 * 1000, // 5 minutes
  })

  // Query categories
  const { data: categories } = useQuery({
    queryKey: ['adapter_categories'],
    queryFn: () => apiService.getAdapterCategories(),
    staleTime: 10 * 60 * 1000, // 10 minutes
  })

  // Update command preview when adapter or target changes
  useEffect(() => {
    const updatePreview = async () => {
      if (selectedAdapterInfo && targetInput) {
        try {
          const command = await apiService.buildToolCommandWithDefaults(
            selectedAdapterInfo.tool_name,
            targetInput,
            null
          )
          setCommandPreview(command)
        } catch (error) {
          console.error('Failed to build command preview:', error)
          setCommandPreview([])
        }
      }
    }
    updatePreview()
  }, [selectedAdapterInfo, targetInput])

  // Filter adapters
  const filteredAdapters = adapters?.filter(adapter => {
    const matchesSearch = adapter.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         adapter.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         adapter.tool_name.toLowerCase().includes(searchTerm.toLowerCase())
    
    const matchesCategory = categoryFilter === 'all' || adapter.category === categoryFilter
    const matchesRisk = riskFilter === 'all' || adapter.risk_level === riskFilter

    return matchesSearch && matchesCategory && matchesRisk
  }) || []

  const handleSelectAdapter = (adapter: AdapterInfo) => {
    setSelectedAdapterInfo(adapter)
    if (onSelectAdapter) {
      onSelectAdapter(adapter)
    }
  }

  const handleCopyCommand = () => {
    if (commandPreview.length > 0) {
      navigator.clipboard.writeText(commandPreview.join(' '))
      setCopiedCommand(true)
      success('Command copied to clipboard')
      setTimeout(() => setCopiedCommand(false), 2000)
    }
  }

  const getRiskLevelColor = (risk: string) => {
    switch (risk.toLowerCase()) {
      case 'low': return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
      case 'medium': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
      case 'high': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
      default: return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200'
    }
  }

  const getCategoryDisplay = (category: string) => {
    return category
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ')
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-8">
        <Loader2 className="h-8 w-8 animate-spin text-blue-500" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Filter className="h-5 w-5" />
            Adapter Explorer
          </CardTitle>
          <CardDescription>
            Browse and configure security tool adapters ({filteredAdapters.length} of {adapters?.length || 0} adapters)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <Input
                placeholder="Search adapters..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>

            {/* Category filter */}
            <Select value={categoryFilter} onValueChange={setCategoryFilter}>
              <SelectTrigger>
                <SelectValue placeholder="Filter by category" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Categories</SelectItem>
                {categories?.map(category => (
                  <SelectItem key={category} value={category}>
                    {getCategoryDisplay(category)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            {/* Risk filter */}
            <Select value={riskFilter} onValueChange={setRiskFilter}>
              <SelectTrigger>
                <SelectValue placeholder="Filter by risk level" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Risk Levels</SelectItem>
                <SelectItem value="low">Low Risk</SelectItem>
                <SelectItem value="medium">Medium Risk</SelectItem>
                <SelectItem value="high">High Risk</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Adapters Grid and Details */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Adapters List */}
        <div className="space-y-2 max-h-[600px] overflow-y-auto">
          {filteredAdapters.length === 0 ? (
            <Card>
              <CardContent className="p-8 text-center text-gray-500">
                <XCircle className="h-12 w-12 mx-auto mb-2 opacity-50" />
                <p>No adapters found matching your filters</p>
              </CardContent>
            </Card>
          ) : (
            filteredAdapters.map((adapter) => (
              <div
                key={adapter.tool_name}
                className="cursor-pointer"
                onClick={() => handleSelectAdapter(adapter)}
              >
                <Card
                  className={`transition-all hover:shadow-md ${
                    selectedAdapterInfo?.tool_name === adapter.tool_name
                      ? 'ring-2 ring-blue-500 bg-blue-50 dark:bg-blue-950'
                      : ''
                  }`}
                >
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <CardTitle className="text-base font-semibold">
                        {adapter.name}
                      </CardTitle>
                      <code className="text-xs text-gray-500 dark:text-gray-400">
                        {adapter.tool_name}
                      </code>
                    </div>
                    <div className="flex gap-1">
                      <Badge className={getRiskLevelColor(adapter.risk_level)}>
                        {adapter.risk_level}
                      </Badge>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="pt-2">
                  <p className="text-sm text-gray-600 dark:text-gray-300 mb-2">
                    {adapter.description}
                  </p>
                  <div className="flex items-center gap-4 text-xs text-gray-500">
                    <span className="flex items-center gap-1">
                      <Code className="h-3 w-3" />
                      {getCategoryDisplay(adapter.category)}
                    </span>
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {adapter.timeout}s timeout
                    </span>
                    {adapter.requires_authorization && (
                      <span className="flex items-center gap-1 text-amber-600">
                        <Shield className="h-3 w-3" />
                        Requires Auth
                      </span>
                    )}
                  </div>
                </CardContent>
              </Card>
              </div>
            ))
          )}
        </div>

        {/* Adapter Details & Command Builder */}
        <div className="space-y-4">
          {selectedAdapterInfo ? (
            <>
              {/* Adapter Info Card */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <CheckCircle className="h-5 w-5 text-green-500" />
                    {selectedAdapterInfo.name}
                  </CardTitle>
                  <CardDescription>
                    {selectedAdapterInfo.description}
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Metadata */}
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="font-semibold text-gray-700 dark:text-gray-300">Tool:</span>
                      <code className="ml-2 bg-gray-100 dark:bg-gray-800 px-2 py-0.5 rounded">
                        {selectedAdapterInfo.tool_name}
                      </code>
                    </div>
                    <div>
                      <span className="font-semibold text-gray-700 dark:text-gray-300">Category:</span>
                      <span className="ml-2">{getCategoryDisplay(selectedAdapterInfo.category)}</span>
                    </div>
                    <div>
                      <span className="font-semibold text-gray-700 dark:text-gray-300">Risk Level:</span>
                      <Badge className={`ml-2 ${getRiskLevelColor(selectedAdapterInfo.risk_level)}`}>
                        {selectedAdapterInfo.risk_level}
                      </Badge>
                    </div>
                    <div>
                      <span className="font-semibold text-gray-700 dark:text-gray-300">Timeout:</span>
                      <span className="ml-2">{selectedAdapterInfo.timeout}s</span>
                    </div>
                  </div>

                  {/* Authorization Warning */}
                  {selectedAdapterInfo.requires_authorization && (
                    <div className="flex items-start gap-2 p-3 bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 rounded-lg">
                      <AlertTriangle className="h-5 w-5 text-amber-600 mt-0.5 flex-shrink-0" />
                      <div className="text-sm">
                        <p className="font-semibold text-amber-900 dark:text-amber-100">Authorization Required</p>
                        <p className="text-amber-700 dark:text-amber-200">
                          This tool performs active scanning and requires explicit authorization to scan the target.
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Expected Outputs */}
                  <div>
                    <span className="font-semibold text-sm text-gray-700 dark:text-gray-300">Expected Outputs:</span>
                    <ul className="mt-2 space-y-1">
                      {selectedAdapterInfo.expected_outputs.map((output, idx) => (
                        <li key={idx} className="text-sm text-gray-600 dark:text-gray-400 flex items-center gap-2">
                          <CheckCircle className="h-3 w-3 text-green-500" />
                          <code className="bg-gray-100 dark:bg-gray-800 px-2 py-0.5 rounded text-xs">
                            {output}
                          </code>
                        </li>
                      ))}
                    </ul>
                  </div>
                </CardContent>
              </Card>

              {/* Command Builder Card */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Code className="h-5 w-5" />
                    Command Builder
                  </CardTitle>
                  <CardDescription>
                    Generate commands with default configuration
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Target Input */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Target
                    </label>
                    <Input
                      placeholder="example.com"
                      value={targetInput}
                      onChange={(e) => setTargetInput(e.target.value)}
                    />
                  </div>

                  {/* Command Preview */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                        Command Preview
                      </label>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={handleCopyCommand}
                        disabled={commandPreview.length === 0}
                      >
                        {copiedCommand ? (
                          <>
                            <Check className="h-4 w-4 mr-1" />
                            Copied
                          </>
                        ) : (
                          <>
                            <Copy className="h-4 w-4 mr-1" />
                            Copy
                          </>
                        )}
                      </Button>
                    </div>
                    <div className="bg-gray-900 dark:bg-black p-4 rounded-lg overflow-x-auto">
                      <code className="text-green-400 text-sm font-mono whitespace-nowrap">
                        {commandPreview.length > 0 ? commandPreview.join(' ') : 'Enter a target to preview command'}
                      </code>
                    </div>
                  </div>

                  {/* Command Breakdown */}
                  {commandPreview.length > 0 && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        Command Arguments
                      </label>
                      <div className="space-y-1">
                        {commandPreview.map((arg, idx) => (
                          <div
                            key={idx}
                            className="flex items-center gap-2 text-xs bg-gray-50 dark:bg-gray-800 p-2 rounded"
                          >
                            <Badge variant="outline" className="text-xs">
                              {idx}
                            </Badge>
                            <code className="flex-1 text-gray-700 dark:text-gray-300">{arg}</code>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </>
          ) : (
            <Card>
              <CardContent className="p-12 text-center text-gray-500">
                <Code className="h-16 w-16 mx-auto mb-4 opacity-30" />
                <p className="text-lg font-medium mb-1">Select an Adapter</p>
                <p className="text-sm">
                  Choose an adapter from the list to view details and build commands
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}

export default AdapterExplorer
