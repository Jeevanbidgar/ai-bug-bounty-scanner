import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  FileText,
  Download,
  Eye,
  Trash2,
  Plus,
  AlertTriangle,
  CheckCircle,
  Info
} from 'lucide-react'
import { Button } from '../components/ui/Button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Input } from '../components/ui/Input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/Select'

interface Report {
  id: string
  title: string
  generated: string
  target: string
  vulnerabilities: number
  format: string
  filePath: string | null
  summary: string | null
  severity: string
}

// API functions using Tauri commands
import { apiService } from '../services/api'

const fetchReports = async (): Promise<Report[]> => {
  try {
    const reports = await apiService.getReports()
    return Array.isArray(reports) ? reports : []
  } catch (error) {
    console.error('Failed to fetch reports:', error)
    return []
  }
}

const generateReport = async (scanId: string, format: string, title?: string): Promise<Report> => {
  try {
    const result = await apiService.createReport({ scanId, format, title })
    if (result.success && result.reportId) {
      // Fetch the created report
      const report = await apiService.getReport(result.reportId as string)
      if (report) {
        return report as Report
      }
    }
    throw new Error('Failed to generate report')
  } catch (error) {
    console.error('Failed to generate report:', error)
    throw error
  }
}

const deleteReport = async (reportId: string): Promise<void> => {
  try {
    await apiService.deleteReport(reportId)
  } catch (error) {
    console.error('Failed to delete report:', error)
    throw error
  }
}

const ReportsPage = () => {
  const [searchTerm, setSearchTerm] = useState('')
  const [formatFilter, setFormatFilter] = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [showGenerateForm, setShowGenerateForm] = useState(false)
  const [selectedScanId, setSelectedScanId] = useState('')
  const [reportFormat, setReportFormat] = useState('HTML')
  const [reportTitle, setReportTitle] = useState('')

  const queryClient = useQueryClient()

  const { data: reports = [], isLoading, error } = useQuery({
    queryKey: ['reports'],
    queryFn: fetchReports
  })

  const generateReportMutation = useMutation({
    mutationFn: () => generateReport(selectedScanId, reportFormat, reportTitle),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] })
      setShowGenerateForm(false)
      setSelectedScanId('')
      setReportFormat('HTML')
      setReportTitle('')
    }
  })

  const deleteReportMutation = useMutation({
    mutationFn: (reportId: string) => deleteReport(reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] })
    }
  })

  const filteredReports = reports.filter(report => {
    const matchesSearch = report.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         report.target.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesFormat = formatFilter === 'all' || report.format.toLowerCase() === formatFilter.toLowerCase()
    const matchesSeverity = severityFilter === 'all' || report.severity === severityFilter
    return matchesSearch && matchesFormat && matchesSeverity
  })

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-red-600'
      case 'high': return 'bg-orange-600'
      case 'medium': return 'bg-yellow-600'
      case 'low': return 'bg-green-600'
      default: return 'bg-gray-600'
    }
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return <AlertTriangle className="h-4 w-4" />
      case 'high': return <AlertTriangle className="h-4 w-4" />
      case 'medium': return <Info className="h-4 w-4" />
      case 'low': return <CheckCircle className="h-4 w-4" />
      default: return <Info className="h-4 w-4" />
    }
  }

  const handleGenerateReport = () => {
    if (!selectedScanId) return
    generateReportMutation.mutate()
  }

  const handleDownloadReport = (report: Report) => {
    // In a real implementation, this would trigger a download
    console.log('Downloading report:', report.id)
  }

  const handleDeleteReport = (reportId: string) => {
    if (confirm('Are you sure you want to delete this report?')) {
      deleteReportMutation.mutate(reportId)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white">Security Reports</h1>
          <p className="text-gray-400 mt-2 text-sm sm:text-base">
            Generate and manage security assessment reports
          </p>
        </div>
        <Button onClick={() => setShowGenerateForm(true)} className="w-fit">
          <Plus className="mr-2 h-4 w-4" />
          Generate Report
        </Button>
      </div>

      {/* Filters */}
      <div className="flex flex-col lg:flex-row gap-4">
        <div className="flex-1">
          <Input
            placeholder="Search reports..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full"
          />
        </div>
        <Select value={formatFilter} onValueChange={setFormatFilter}>
          <SelectTrigger className="w-full lg:w-48">
            <SelectValue placeholder="Format" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Formats</SelectItem>
            <SelectItem value="html">HTML</SelectItem>
            <SelectItem value="pdf">PDF</SelectItem>
            <SelectItem value="json">JSON</SelectItem>
            <SelectItem value="csv">CSV</SelectItem>
          </SelectContent>
        </Select>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-full lg:w-48">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Generate Report Form */}
      {showGenerateForm && (
        <Card>
          <CardHeader>
            <CardTitle>Generate New Report</CardTitle>
            <CardDescription>
              Create a security assessment report from scan results
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Scan ID
              </label>
              <Input
                placeholder="Enter scan ID"
                value={selectedScanId}
                onChange={(e) => setSelectedScanId(e.target.value)}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Report Title (Optional)
              </label>
              <Input
                placeholder="Custom report title"
                value={reportTitle}
                onChange={(e) => setReportTitle(e.target.value)}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Format
              </label>
              <Select value={reportFormat} onValueChange={setReportFormat}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="HTML">HTML</SelectItem>
                  <SelectItem value="PDF">PDF</SelectItem>
                  <SelectItem value="JSON">JSON</SelectItem>
                  <SelectItem value="CSV">CSV</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex gap-2">
              <Button onClick={handleGenerateReport} disabled={generateReportMutation.isPending}>
                {generateReportMutation.isPending ? 'Generating...' : 'Generate Report'}
              </Button>
              <Button variant="outline" onClick={() => setShowGenerateForm(false)}>
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Reports List */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="grid gap-4">
            {[1, 2, 3].map((i) => (
              <Card key={i} className="animate-pulse">
                <CardContent className="p-6">
                  <div className="h-4 bg-gray-700 rounded w-1/2 mb-4"></div>
                  <div className="h-3 bg-gray-700 rounded w-3/4 mb-2"></div>
                  <div className="h-3 bg-gray-700 rounded w-1/4"></div>
                </CardContent>
              </Card>
            ))}
          </div>
        ) : (
          filteredReports.map((report) => (
            <Card key={report.id}>
              <CardContent className="p-6">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4">
                  <div className="flex items-center space-x-3 min-w-0">
                    <FileText className="h-8 w-8 text-blue-500 flex-shrink-0" />
                    <div className="min-w-0">
                      <h3 className="font-semibold text-white truncate">{report.title}</h3>
                      <p className="text-sm text-gray-400">
                        Generated {new Date(report.generated).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2 flex-shrink-0">
                    <Badge className={getSeverityColor(report.severity)} variant="secondary">
                      <div className="flex items-center space-x-1">
                        {getSeverityIcon(report.severity)}
                        <span className="capitalize">{report.severity}</span>
                      </div>
                    </Badge>
                    <Button size="sm" variant="outline">
                      <Eye className="h-4 w-4" />
                    </Button>
                    {report.filePath && (
                      <Button size="sm" onClick={() => handleDownloadReport(report)}>
                        <Download className="h-4 w-4" />
                      </Button>
                    )}
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleDeleteReport(report.id)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-white">{report.target}</div>
                    <div className="text-sm text-gray-400">Target</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-white">{report.vulnerabilities}</div>
                    <div className="text-sm text-gray-400">Vulnerabilities</div>
                  </div>
                  <div className="text-center">
                    <div className="text-lg font-semibold text-white uppercase">{report.format}</div>
                    <div className="text-sm text-gray-400">Format</div>
                  </div>
                </div>

                {report.summary && (
                  <div className="bg-gray-800 rounded-lg p-4">
                    <p className="text-sm text-gray-300">{report.summary}</p>
                  </div>
                )}
              </CardContent>
            </Card>
          ))
        )}
      </div>

      {filteredReports.length === 0 && !isLoading && (
        <Card>
          <CardContent className="p-12 text-center">
            <div className="text-gray-400">
              <FileText className="mx-auto h-12 w-12 mb-4" />
              <h3 className="text-lg font-medium text-white mb-2">No reports found</h3>
              <p>Generate your first security report to get started.</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-white">{reports.length}</div>
            <div className="text-sm text-gray-400">Total Reports</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-green-400">
              {reports.filter(r => r.severity === 'low' || r.severity === 'medium').length}
            </div>
            <div className="text-sm text-gray-400">Clean Reports</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-yellow-400">
              {reports.filter(r => r.severity === 'high').length}
            </div>
            <div className="text-sm text-gray-400">High Risk</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-red-400">
              {reports.filter(r => r.severity === 'critical').length}
            </div>
            <div className="text-sm text-gray-400">Critical</div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

export default ReportsPage
