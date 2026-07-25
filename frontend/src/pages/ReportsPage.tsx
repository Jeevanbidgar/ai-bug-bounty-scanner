import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  AlertTriangle,
  Check,
  Copy,
  Eye,
  FileArchive,
  FileJson,
  FileOutput,
  FileText,
  FolderOpen,
  Loader2,
  Plus,
  Search,
  ShieldCheck,
  Trash2,
  X,
} from 'lucide-react'
import apiService, { type Report, type Scan } from '../services/api'
import { Button } from '../components/ui/Button'
import { Input } from '../components/ui/Input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/Select'
import { useNotificationStore } from '../stores/notificationStore'

const formatNotes: Record<string, { label: string; note: string; icon: React.ReactNode }> = {
  html: { label: 'HTML', note: 'Human-readable local review', icon: <FileText className="h-4 w-4" /> },
  json: { label: 'JSON', note: 'Structured automation export', icon: <FileJson className="h-4 w-4" /> },
  sarif: { label: 'SARIF 2.1', note: 'Compatible findings interchange', icon: <ShieldCheck className="h-4 w-4" /> },
}

const severityStyles: Record<string, string> = {
  critical: 'border-red-400/20 bg-red-400/[0.07] text-red-200',
  high: 'border-orange-400/20 bg-orange-400/[0.07] text-orange-200',
  medium: 'border-amber-400/20 bg-amber-400/[0.07] text-amber-200',
  low: 'border-cyan-400/20 bg-cyan-400/[0.07] text-cyan-200',
  none: 'border-emerald-400/20 bg-emerald-400/[0.07] text-emerald-200',
}

const ReportsPage = () => {
  const queryClient = useQueryClient()
  const [searchTerm, setSearchTerm] = useState('')
  const [formatFilter, setFormatFilter] = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [showGenerateForm, setShowGenerateForm] = useState(false)
  const [selectedScanId, setSelectedScanId] = useState('')
  const [reportFormat, setReportFormat] = useState('html')
  const [reportTitle, setReportTitle] = useState('')
  const [preview, setPreview] = useState<Report | null>(null)
  const [deleteCandidate, setDeleteCandidate] = useState<Report | null>(null)
  const [copiedReportId, setCopiedReportId] = useState<string | null>(null)
  const addNotification = useNotificationStore((state) => state.addNotification)

  const reportsQuery = useQuery({ queryKey: ['reports'], queryFn: () => apiService.getReports() })
  const scansQuery = useQuery({
    queryKey: ['scans', 'report-options'],
    queryFn: async () => (await apiService.getScans()).data as Scan[],
  })
  const reports = useMemo(() => reportsQuery.data ?? [], [reportsQuery.data])
  const scans = useMemo(() => scansQuery.data ?? [], [scansQuery.data])

  const generateReport = useMutation({
    mutationFn: () => apiService.createReport({
      scanId: selectedScanId,
      format: reportFormat,
      title: reportTitle.trim() || undefined,
    }),
    onSuccess: (report) => {
      queryClient.invalidateQueries({ queryKey: ['reports'] })
      setPreview(report)
      setShowGenerateForm(false)
      setSelectedScanId('')
      setReportFormat('html')
      setReportTitle('')
      addNotification({ level: 'success', title: 'Report generated', message: `${report.title} is hashed and stored in UniHack’s managed report directory.`, href: '/reports', actionLabel: 'Review report' })
    },
  })
  const deleteReport = useMutation({
    mutationFn: (reportId: string) => apiService.deleteReport(reportId),
    onSuccess: (_result, reportId) => {
      queryClient.invalidateQueries({ queryKey: ['reports'] })
      if (preview?.id === reportId) setPreview(null)
      setDeleteCandidate(null)
      addNotification({ level: 'success', title: 'Report deleted', message: 'The managed export and report record were removed. The source scan remains intact.' })
    },
  })
  const loadPreview = useMutation({
    mutationFn: (reportId: string) => apiService.getReport(reportId),
    onSuccess: (report) => setPreview(report),
  })
  const revealReport = useMutation({
    mutationFn: (reportId: string) => apiService.revealReport(reportId),
    onSuccess: () => addNotification({ level: 'info', title: 'Report revealed', message: 'The managed export was opened in the system file manager.' }),
  })

  useEffect(() => {
    if (!showGenerateForm && !preview && !deleteCandidate) return
    const close = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return
      if (deleteCandidate) setDeleteCandidate(null)
      else if (preview) setPreview(null)
      else setShowGenerateForm(false)
    }
    window.addEventListener('keydown', close)
    return () => window.removeEventListener('keydown', close)
  }, [deleteCandidate, preview, showGenerateForm])

  const filteredReports = useMemo(() => reports.filter((report) => {
    const search = searchTerm.trim().toLowerCase()
    const matchesSearch = !search || [report.title, report.target, report.scanId, report.format]
      .some((value) => value.toLowerCase().includes(search))
    return matchesSearch
      && (formatFilter === 'all' || report.format.toLowerCase() === formatFilter)
      && (severityFilter === 'all' || report.severity.toLowerCase() === severityFilter)
  }), [formatFilter, reports, searchTerm, severityFilter])

  const findings = reports.reduce((total, report) => total + report.vulnerabilityCount, 0)
  const formats = new Set(reports.map((report) => report.format.toLowerCase())).size
  const latestReport = reports.slice().sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0]
  const requestError = generateReport.error ?? deleteReport.error ?? loadPreview.error ?? revealReport.error

  const copyExportPath = async (report: Report) => {
    if (!report.filePath) return
    try {
      await navigator.clipboard.writeText(report.filePath)
      setCopiedReportId(report.id)
      window.setTimeout(() => setCopiedReportId(null), 1800)
      addNotification({ level: 'success', title: 'Export path copied', message: report.filePath })
    } catch (error) {
      addNotification({ level: 'error', title: 'Copy failed', message: error instanceof Error ? error.message : 'The system clipboard is unavailable.' })
    }
  }

  return (
    <div className="space-y-5">
      <header className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <div className="mb-3 flex items-center gap-2"><FileArchive className="h-4 w-4 text-cyan-300" /><span className="console-label text-cyan-200">Evidence delivery</span></div>
          <h1 className="console-heading text-3xl sm:text-4xl">Reports</h1>
          <p className="mt-3 max-w-2xl text-sm text-slate-400">Turn persisted findings into integrity-hashed HTML, JSON, or SARIF exports without sending evidence to a remote service.</p>
        </div>
        <Button onClick={() => setShowGenerateForm(true)}><Plus className="mr-2 h-4 w-4" />Generate report</Button>
      </header>

      {requestError && <div role="alert" className="rounded-xl border border-red-400/20 bg-red-400/[0.05] p-4 text-sm text-red-200">{requestError.message}</div>}

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Report overview">
        <MetricPanel label="Exports" value={reports.length.toString()} note="Managed local files" tone="text-white" />
        <MetricPanel label="Findings represented" value={findings.toString()} note="Across retained reports" tone="text-violet-200" />
        <MetricPanel label="Formats used" value={formats.toString()} note="HTML · JSON · SARIF" tone="text-cyan-200" />
        <MetricPanel label="Latest export" value={latestReport ? new Date(latestReport.createdAt).toLocaleDateString() : '—'} note={latestReport?.title ?? 'No report generated'} tone="text-emerald-200" />
      </section>

      <section className="surface-panel rounded-2xl p-3">
        <div className="grid gap-2 md:grid-cols-[minmax(240px,1fr)_180px_180px]">
          <div className="relative"><Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" /><Input className="pl-9" placeholder="Search title, target, scan, or format…" value={searchTerm} onChange={(event) => setSearchTerm(event.target.value)} aria-label="Search reports" /></div>
          <Select value={formatFilter} onValueChange={setFormatFilter}><SelectTrigger aria-label="Filter reports by format"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All formats</SelectItem><SelectItem value="html">HTML</SelectItem><SelectItem value="json">JSON</SelectItem><SelectItem value="sarif">SARIF</SelectItem></SelectContent></Select>
          <Select value={severityFilter} onValueChange={setSeverityFilter}><SelectTrigger aria-label="Filter reports by severity"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All severities</SelectItem><SelectItem value="critical">Critical</SelectItem><SelectItem value="high">High</SelectItem><SelectItem value="medium">Medium</SelectItem><SelectItem value="low">Low</SelectItem><SelectItem value="none">No findings</SelectItem></SelectContent></Select>
        </div>
      </section>

      {reportsQuery.isLoading ? <div className="surface-panel grid min-h-80 place-items-center rounded-2xl"><Loader2 className="h-7 w-7 animate-spin text-cyan-300" /></div> : reportsQuery.error ? (
        <div className="surface-panel grid min-h-80 place-items-center rounded-2xl p-8 text-center"><div><AlertTriangle className="mx-auto h-8 w-8 text-red-300" /><h2 className="mt-4 text-base font-semibold text-white">Reports could not be loaded</h2><p className="mt-2 text-xs text-slate-500">{reportsQuery.error.message}</p><Button className="mt-4" variant="outline" onClick={() => reportsQuery.refetch()}>Try again</Button></div></div>
      ) : filteredReports.length ? (
        <section className="grid gap-3 xl:grid-cols-2" aria-label="Generated reports">
          {filteredReports.map((report) => {
            const format = formatNotes[report.format.toLowerCase()] ?? formatNotes.json
            return (
              <article key={report.id} className="surface-panel surface-panel-interactive rounded-2xl p-5">
                <div className="flex items-start gap-3">
                  <div className="grid h-10 w-10 flex-shrink-0 place-items-center rounded-xl border border-cyan-400/15 bg-cyan-400/[0.06] text-cyan-200">{format.icon}</div>
                  <div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><h2 className="truncate text-sm font-semibold text-white">{report.title}</h2><span className={`rounded-full border px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider ${severityStyles[report.severity.toLowerCase()] ?? severityStyles.none}`}>{report.severity}</span></div><p className="mt-1 truncate text-xs text-slate-500">{report.target}</p><p className="mt-2 text-[10px] uppercase tracking-wider text-slate-700">{format.label} · {formatBytes(report.sizeBytes ?? 0)} · {new Date(report.createdAt).toLocaleString()}</p></div>
                </div>
                <div className="mt-4 grid grid-cols-3 gap-2"><ReportMetric label="Findings" value={report.vulnerabilityCount.toString()} /><ReportMetric label="SHA-256" value={report.sha256 ? `${report.sha256.slice(0, 12)}…` : 'Unavailable'} /><ReportMetric label="Scan" value={report.scanId.slice(0, 12)} /></div>
                <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-white/[0.06] pt-4">
                  <Button size="sm" variant="outline" onClick={() => loadPreview.mutate(report.id)}><Eye className="mr-1.5 h-3.5 w-3.5" />Preview</Button>
                  {report.filePath && <Button size="sm" variant="ghost" onClick={() => revealReport.mutate(report.id)}><FolderOpen className="mr-1.5 h-3.5 w-3.5" />Reveal</Button>}
                  {report.filePath && <Button size="sm" variant="ghost" onClick={() => copyExportPath(report)}>{copiedReportId === report.id ? <Check className="mr-1.5 h-3.5 w-3.5 text-emerald-300" /> : <Copy className="mr-1.5 h-3.5 w-3.5" />}{copiedReportId === report.id ? 'Copied' : 'Copy path'}</Button>}
                  <Button size="sm" variant="ghost" className="ml-auto text-slate-600 hover:text-red-300" onClick={() => setDeleteCandidate(report)} aria-label={`Delete ${report.title}`}><Trash2 className="h-3.5 w-3.5" /></Button>
                </div>
              </article>
            )
          })}
        </section>
      ) : <div className="surface-panel grid min-h-80 place-items-center rounded-2xl p-8 text-center"><div><FileOutput className="mx-auto h-9 w-9 text-slate-700" /><h2 className="mt-4 text-base font-semibold text-white">{reports.length ? 'No matching reports' : 'No reports yet'}</h2><p className="mx-auto mt-2 max-w-sm text-xs leading-relaxed text-slate-500">{reports.length ? 'Change the filters to reveal another export.' : 'Complete or select a scan, then create a local evidence package in the format your review process needs.'}</p><Button className="mt-5" onClick={() => setShowGenerateForm(true)}><Plus className="mr-2 h-4 w-4" />Generate first report</Button></div></div>}

      {showGenerateForm && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-[#02050a]/85 p-4 backdrop-blur-md" role="dialog" aria-modal="true" aria-labelledby="generate-report-title">
          <div className="surface-panel w-full max-w-2xl rounded-3xl border-cyan-400/15 p-5 shadow-[0_30px_100px_rgba(0,0,0,.65)] sm:p-6">
            <div className="flex items-start justify-between gap-4"><div><p className="console-label text-cyan-200">Local evidence export</p><h2 id="generate-report-title" className="console-heading mt-2 text-xl">Generate a report</h2><p className="mt-2 text-xs text-slate-500">The backend renders, hashes, and stores the export inside UniHack’s managed report directory.</p></div><Button size="sm" variant="ghost" onClick={() => setShowGenerateForm(false)} aria-label="Close report generator"><X className="h-4 w-4" /></Button></div>
            <div className="mt-5 space-y-4">
              <label className="block text-[11px] font-medium text-slate-500">Source scan<Select value={selectedScanId} onValueChange={setSelectedScanId}><SelectTrigger className="mt-2" aria-label="Source scan"><SelectValue placeholder="Select a retained scan" /></SelectTrigger><SelectContent>{scans.map((scan) => <SelectItem key={scan.id} value={scan.id}>{scan.name || scan.target} — {scan.target}</SelectItem>)}</SelectContent></Select></label>
              {scansQuery.error ? <div role="alert" className="rounded-xl border border-red-400/15 bg-red-400/[0.04] p-3 text-xs text-red-200"><p>Source scans could not be loaded: {scansQuery.error.message}</p><Button className="mt-2" size="sm" variant="ghost" onClick={() => scansQuery.refetch()}>Retry scans</Button></div> : !scansQuery.isLoading && !scans.length ? <p className="rounded-xl border border-amber-400/15 bg-amber-400/[0.04] p-3 text-xs text-amber-100/70">No scans are available. <Link to="/scans" className="font-semibold text-cyan-300">Launch a workflow first →</Link></p> : null}
              <label className="block text-[11px] font-medium text-slate-500">Report title <span className="text-slate-700">optional</span><Input className="mt-2" value={reportTitle} onChange={(event) => setReportTitle(event.target.value)} maxLength={200} placeholder="External perimeter assessment" /></label>
              <div><p className="text-[11px] font-medium text-slate-500">Export format</p><div className="mt-2 grid gap-2 sm:grid-cols-3">{Object.entries(formatNotes).map(([value, option]) => <button key={value} type="button" onClick={() => setReportFormat(value)} className={`rounded-xl border p-3 text-left ${reportFormat === value ? 'border-cyan-400/30 bg-cyan-400/[0.07]' : 'border-white/[0.07] bg-white/[0.02] hover:border-white/15'}`}><span className="flex items-center gap-2 text-xs font-semibold text-slate-200">{option.icon}{option.label}</span><span className="mt-2 block text-[10px] leading-relaxed text-slate-600">{option.note}</span></button>)}</div></div>
              <div className="flex justify-end gap-2 pt-2"><Button variant="ghost" onClick={() => setShowGenerateForm(false)}>Cancel</Button><Button onClick={() => generateReport.mutate()} disabled={!selectedScanId || generateReport.isPending}>{generateReport.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <FileOutput className="mr-2 h-4 w-4" />}Generate {formatNotes[reportFormat]?.label ?? 'report'}</Button></div>
            </div>
          </div>
        </div>
      )}

      {preview && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-[#02050a]/85 p-4 backdrop-blur-md" role="dialog" aria-modal="true" aria-labelledby="report-preview-title">
          <div className="surface-panel flex max-h-[88vh] w-full max-w-4xl flex-col overflow-hidden rounded-3xl border-violet-400/15">
            <div className="flex items-start justify-between gap-4 border-b border-white/[0.07] p-5"><div><p className="console-label text-violet-200">{preview.format.toUpperCase()} evidence preview</p><h2 id="report-preview-title" className="console-heading mt-2 text-lg">{preview.title}</h2><p className="mt-1 break-all text-[10px] text-slate-600">{preview.filePath}</p></div><Button size="sm" variant="ghost" onClick={() => setPreview(null)} aria-label="Close report preview"><X className="h-4 w-4" /></Button></div>
            <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-words bg-[#03070d] p-5 text-xs leading-6 text-slate-300">{preview.content || 'No stored report content was returned.'}</pre>
          </div>
        </div>
      )}

      {deleteCandidate && (
        <div className="fixed inset-0 z-[60] grid place-items-center bg-[#02050a]/80 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="delete-report-title"><div className="surface-panel w-full max-w-md rounded-2xl p-5"><div className="flex items-start gap-3"><AlertTriangle className="mt-0.5 h-5 w-5 text-red-300" /><div><h2 id="delete-report-title" className="text-sm font-semibold text-white">Delete this report?</h2><p className="mt-2 text-xs leading-relaxed text-slate-500">The report record and its managed export file will be removed. The source scan and findings remain intact.</p></div></div><div className="mt-5 flex justify-end gap-2"><Button variant="ghost" onClick={() => setDeleteCandidate(null)}>Cancel</Button><Button onClick={() => deleteReport.mutate(deleteCandidate.id)} disabled={deleteReport.isPending}><Trash2 className="mr-2 h-4 w-4" />Delete report</Button></div></div></div>
      )}
    </div>
  )
}

const MetricPanel = ({ label, value, note, tone }: { label: string; value: string; note: string; tone: string }) => <div className="surface-panel rounded-2xl p-4"><p className="console-label">{label}</p><p className={`metric-value mt-2 truncate text-2xl font-semibold ${tone}`}>{value}</p><p className="mt-1 truncate text-xs text-slate-600">{note}</p></div>
const ReportMetric = ({ label, value }: { label: string; value: string }) => <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-3"><p className="truncate text-xs font-semibold text-slate-300" title={value}>{value}</p><p className="mt-1 text-[9px] uppercase tracking-wider text-slate-700">{label}</p></div>
const formatBytes = (bytes: number) => bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`

export default ReportsPage
