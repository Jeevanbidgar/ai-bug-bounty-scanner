import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useSearchParams } from 'react-router-dom'
import {
  Activity,
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  Clock3,
  Eye,
  FileSearch,
  Filter,
  GitBranch,
  Loader2,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  ShieldCheck,
  Square,
  Target,
  Trash2,
  Wrench,
  X,
  XCircle,
} from 'lucide-react'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { Input } from '../components/ui/Input'
import { Progress } from '../components/ui/Progress'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/Select'
import apiService, { type Scan, type WorkflowTemplate } from '../services/api'
import { ScanDetailsModal } from '../components/ScanDetailsModal'
import { useScanEvents } from '../hooks/useScanEvents'
import {
  formatToolName,
  getTargetPlaceholder,
  getWorkflowCatalogEntry,
  workflowActivityStyles,
} from '../data/workflowCatalog'
import { useNotificationStore } from '../stores/notificationStore'

type ConfirmAction = { kind: 'start' | 'delete'; scan: Scan } | null

const statusStyles: Record<string, { dot: string; badge: string; label: string }> = {
  running: { dot: 'bg-cyan-400 shadow-[0_0_12px_rgba(34,211,238,.7)]', badge: 'border-cyan-400/20 bg-cyan-400/[0.07] text-cyan-200', label: 'Running' },
  completed: { dot: 'bg-emerald-400', badge: 'border-emerald-400/20 bg-emerald-400/[0.07] text-emerald-200', label: 'Completed' },
  failed: { dot: 'bg-red-400', badge: 'border-red-400/20 bg-red-400/[0.07] text-red-200', label: 'Failed' },
  pending: { dot: 'bg-amber-400', badge: 'border-amber-400/20 bg-amber-400/[0.07] text-amber-200', label: 'Pending' },
  cancelled: { dot: 'bg-slate-500', badge: 'border-white/10 bg-white/[0.04] text-slate-400', label: 'Cancelled' },
  interrupted: { dot: 'bg-orange-400', badge: 'border-orange-400/20 bg-orange-400/[0.07] text-orange-200', label: 'Interrupted' },
}

const formatDateTime = (value?: string) => {
  if (!value) return 'Not started'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
}

const relativeDuration = (started?: string, completed?: string) => {
  if (!started) return '—'
  const start = new Date(started).getTime()
  const end = completed ? new Date(completed).getTime() : Date.now()
  if (!Number.isFinite(start) || !Number.isFinite(end)) return '—'
  const minutes = Math.max(0, Math.round((end - start) / 60_000))
  if (minutes < 60) return `${minutes}m`
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`
}

const ScansPage = () => {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [showLauncher, setShowLauncher] = useState(false)
  const [selectedWorkflow, setSelectedWorkflow] = useState('')
  const [workflowSearch, setWorkflowSearch] = useState('')
  const [scanTarget, setScanTarget] = useState('')
  const [scanName, setScanName] = useState('')
  const [scanDescription, setScanDescription] = useState('')
  const [workingDirectory, setWorkingDirectory] = useState('')
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false)
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null)
  const [confirmAction, setConfirmAction] = useState<ConfirmAction>(null)
  const addNotification = useNotificationStore((state) => state.addNotification)

  useScanEvents({
    onScanStarted: () => queryClient.invalidateQueries({ queryKey: ['scans'] }),
    onProgressUpdate: (event) => {
      queryClient.setQueryData(['scans'], (oldData: unknown) => {
        if (!Array.isArray(oldData)) return oldData
        return oldData.map((scan: Scan) => scan.id === event.scan_id
          ? { ...scan, progress: event.progress, status: event.status, current_test: event.current_test }
          : scan)
      })
    },
    onScanCompleted: () => queryClient.invalidateQueries({ queryKey: ['scans'] }),
    onScanFailed: () => queryClient.invalidateQueries({ queryKey: ['scans'] }),
    onScanCancelled: () => queryClient.invalidateQueries({ queryKey: ['scans'] }),
  })

  const scansQuery = useQuery({
    queryKey: ['scans'],
    queryFn: async () => (await apiService.getScans()).data as Scan[],
    refetchInterval: 10_000,
    staleTime: 5_000,
  })
  const workflowsQuery = useQuery({
    queryKey: ['workflow-templates'],
    queryFn: async () => (await apiService.getWorkflowTemplates(true)).data as WorkflowTemplate[],
    staleTime: 30_000,
  })

  const scans = useMemo(() => Array.isArray(scansQuery.data) ? scansQuery.data : [], [scansQuery.data])
  const workflows = useMemo(() => workflowsQuery.data ?? [], [workflowsQuery.data])
  const selectedTemplate = workflows.find((workflow) => workflow.id === selectedWorkflow)
  const selectedMetadata = selectedTemplate ? getWorkflowCatalogEntry(selectedTemplate) : null

  useEffect(() => {
    const requestedWorkflow = searchParams.get('workflow')
    if (!requestedWorkflow || !workflows.some((workflow) => workflow.id === requestedWorkflow)) return
    setSelectedWorkflow(requestedWorkflow)
    setShowLauncher(true)
    setSearchParams({}, { replace: true })
  }, [searchParams, setSearchParams, workflows])

  useEffect(() => {
    const shouldLockScroll = showLauncher || Boolean(confirmAction)
    if (!shouldLockScroll) return
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return
      if (confirmAction) setConfirmAction(null)
      else setShowLauncher(false)
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [confirmAction, showLauncher])

  const resetLauncher = () => {
    setSelectedWorkflow('')
    setWorkflowSearch('')
    setScanTarget('')
    setScanName('')
    setScanDescription('')
    setWorkingDirectory('')
    setAuthorizationConfirmed(false)
  }

  const openLauncher = (workflowId?: string, scan?: Scan) => {
    resetLauncher()
    const firstReady = workflows.find((workflow) => workflow.compatibility?.compatible !== false)
    setSelectedWorkflow(workflowId ?? firstReady?.id ?? workflows[0]?.id ?? '')
    if (scan) {
      setScanTarget(scan.target)
      setScanName(`${scan.name || scan.target} rerun`)
      setScanDescription(scan.description ?? '')
    }
    setShowLauncher(true)
  }

  const executeWorkflow = useMutation({
    mutationFn: () => apiService.executeWorkflow(selectedWorkflow, { target: scanTarget.trim() }, {
      workingDirectory: workingDirectory.trim() || undefined,
      scanName: scanName.trim() || undefined,
      description: scanDescription.trim() || undefined,
      authorizationConfirmed,
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      setShowLauncher(false)
      resetLauncher()
      addNotification({ level: 'success', title: 'Workflow launched', message: 'Native execution started. Live progress and retained evidence are available in Scans.', href: '/scans', actionLabel: 'Monitor scan' })
    },
  })
  const startScan = useMutation({
    mutationFn: (scanId: string) => apiService.startScan(scanId, true),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      addNotification({ level: 'success', title: 'Scan started', message: 'The authorized pending scan is now running.', href: '/scans', actionLabel: 'Monitor scan' })
    },
  })
  const stopScan = useMutation({
    mutationFn: (scanId: string) => apiService.stopScan(scanId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      addNotification({ level: 'warning', title: 'Stop requested', message: 'UniHack is terminating the native scanner process tree and will retain completed evidence.', href: '/scans', actionLabel: 'Open scans' })
    },
  })
  const deleteScan = useMutation({
    mutationFn: (scanId: string) => apiService.deleteScan(scanId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      addNotification({ level: 'success', title: 'Scan record deleted', message: 'The retained database record was removed. Managed result files remain available on disk.' })
    },
  })

  const filteredScans = useMemo(() => scans.filter((scan) => {
    const search = searchTerm.trim().toLowerCase()
    const matchesSearch = !search || [scan.name, scan.target, scan.workflow_id, scan.scan_type]
      .some((value) => value?.toLowerCase().includes(search))
    return matchesSearch && (statusFilter === 'all' || scan.status.toLowerCase() === statusFilter)
  }), [scans, searchTerm, statusFilter])
  const launcherWorkflows = useMemo(() => workflows.filter((workflow) => {
    const search = workflowSearch.trim().toLowerCase()
    return !search || [workflow.name, workflow.description, workflow.category, getWorkflowCatalogEntry(workflow).intent]
      .some((value) => value.toLowerCase().includes(search))
  }), [workflowSearch, workflows])

  const runningCount = scans.filter((scan) => scan.status.toLowerCase() === 'running').length
  const completedCount = scans.filter((scan) => scan.status.toLowerCase() === 'completed').length
  const findingCount = scans.reduce((total, scan) => total + (scan.vulnerabilities ?? 0), 0)
  const workflowName = (scan: Scan) => workflows.find((workflow) => workflow.id === scan.workflow_id)?.name ?? scan.workflow_id ?? scan.scan_type ?? 'Custom scan'
  const canExecute = Boolean(selectedTemplate && selectedTemplate.compatibility?.compatible !== false && scanTarget.trim() && authorizationConfirmed)

  const runConfirmedAction = () => {
    if (!confirmAction) return
    if (confirmAction.kind === 'start') startScan.mutate(confirmAction.scan.id)
    else deleteScan.mutate(confirmAction.scan.id)
    setConfirmAction(null)
  }

  return (
    <div className="space-y-5">
      <header className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <div className="mb-3 flex items-center gap-2"><Activity className="h-4 w-4 text-cyan-300" /><span className="console-label text-cyan-200">Execution operations</span></div>
          <h1 className="console-heading text-3xl sm:text-4xl">Scans</h1>
          <p className="mt-3 max-w-2xl text-sm text-slate-400">Launch proven workflows, monitor native execution, and move from raw artifacts to reviewable findings.</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => scansQuery.refetch()} disabled={scansQuery.isFetching}><RefreshCw className={`mr-2 h-4 w-4 ${scansQuery.isFetching ? 'animate-spin' : ''}`} />Refresh</Button>
          <Button onClick={() => openLauncher()}><Plus className="mr-2 h-4 w-4" />Launch workflow</Button>
        </div>
      </header>

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Scan overview">
        {[
          { label: 'All scans', value: scans.length, note: 'Retained execution records', tone: 'text-white' },
          { label: 'Running', value: runningCount, note: runningCount ? 'Live native processes' : 'No active workload', tone: 'text-cyan-200' },
          { label: 'Completed', value: completedCount, note: 'Ready for evidence review', tone: 'text-emerald-200' },
          { label: 'Findings', value: findingCount, note: 'Parsed across all scans', tone: 'text-violet-200' },
        ].map((metric) => <div key={metric.label} className="surface-panel rounded-2xl p-4"><p className="console-label">{metric.label}</p><p className={`metric-value mt-2 text-2xl font-semibold ${metric.tone}`}>{metric.value}</p><p className="mt-1 text-xs text-slate-600">{metric.note}</p></div>)}
      </section>

      <section className="surface-panel rounded-2xl p-3">
        <div className="grid gap-2 sm:grid-cols-[minmax(240px,1fr)_190px]">
          <div className="relative"><Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" /><Input className="pl-9" value={searchTerm} onChange={(event) => setSearchTerm(event.target.value)} placeholder="Search target, workflow, or scan name…" aria-label="Search scans" /></div>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger aria-label="Filter scans by status"><Filter className="mr-2 h-3.5 w-3.5 text-slate-500" /><SelectValue /></SelectTrigger>
            <SelectContent><SelectItem value="all">All statuses</SelectItem>{Object.entries(statusStyles).map(([value, status]) => <SelectItem key={value} value={value}>{status.label}</SelectItem>)}</SelectContent>
          </Select>
        </div>
      </section>

      {scansQuery.isLoading ? (
        <div className="surface-panel grid min-h-[360px] place-items-center rounded-2xl"><Loader2 className="h-7 w-7 animate-spin text-cyan-300" /></div>
      ) : scansQuery.error ? (
        <div className="surface-panel grid min-h-[360px] place-items-center rounded-2xl p-8 text-center"><div><AlertCircle className="mx-auto h-8 w-8 text-red-300" /><h2 className="mt-4 text-base font-semibold text-white">Scans could not be loaded</h2><p className="mt-2 text-xs text-slate-500">{scansQuery.error.message}</p><Button className="mt-4" variant="outline" onClick={() => scansQuery.refetch()}>Try again</Button></div></div>
      ) : filteredScans.length ? (
        <section className="space-y-3" aria-label="Scan history">
          {filteredScans.map((scan) => {
            const status = statusStyles[scan.status.toLowerCase()] ?? statusStyles.cancelled
            const isRunning = scan.status.toLowerCase() === 'running'
            const findings = scan.vulnerabilities ?? 0
            return (
              <article key={scan.id} className="surface-panel surface-panel-interactive overflow-hidden rounded-2xl">
                <div className="grid gap-4 p-4 lg:grid-cols-[minmax(0,1fr)_200px_auto] lg:items-center">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`h-2 w-2 rounded-full ${status.dot} ${isRunning ? 'animate-pulse' : ''}`} />
                      <h2 className="truncate text-sm font-semibold text-slate-100">{scan.name || scan.target || 'Unnamed scan'}</h2>
                      <span className={`rounded-full border px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider ${status.badge}`}>{status.label}</span>
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-slate-500">
                      <span className="flex items-center gap-1.5"><Target className="h-3.5 w-3.5 text-slate-600" />{scan.target}</span>
                      <span className="flex items-center gap-1.5"><GitBranch className="h-3.5 w-3.5 text-slate-600" />{workflowName(scan)}</span>
                      <span className="flex items-center gap-1.5"><Clock3 className="h-3.5 w-3.5 text-slate-600" />{formatDateTime(scan.started)}</span>
                    </div>
                    {isRunning && <div className="mt-4"><div className="mb-2 flex items-center justify-between text-[10px] uppercase tracking-wider"><span className="text-cyan-200">{scan.current_test || scan.current_step || 'Preparing workflow'}</span><span className="text-slate-600">{scan.progress ?? 0}%</span></div><Progress value={scan.progress ?? 0} /></div>}
                    {!isRunning && scan.description && <p className="mt-3 line-clamp-1 text-xs text-slate-600">{scan.description}</p>}
                  </div>

                  <div className="grid grid-cols-2 gap-2 lg:border-l lg:border-white/[0.06] lg:pl-4">
                    <div className="rounded-xl bg-white/[0.025] p-3"><p className="text-[10px] uppercase tracking-wider text-slate-600">Findings</p><p className={`metric-value mt-1 text-lg font-semibold ${findings ? 'text-violet-200' : 'text-slate-400'}`}>{findings}</p></div>
                    <div className="rounded-xl bg-white/[0.025] p-3"><p className="text-[10px] uppercase tracking-wider text-slate-600">Duration</p><p className="metric-value mt-1 text-lg font-semibold text-slate-300">{scan.duration || relativeDuration(scan.started, scan.completed)}</p></div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 lg:justify-end">
                    <Button size="sm" variant="outline" onClick={() => setSelectedScan(scan)}><Eye className="mr-1.5 h-3.5 w-3.5" />Evidence</Button>
                    {scan.workflow_id && !isRunning && <Button size="sm" variant="ghost" onClick={() => openLauncher(scan.workflow_id, scan)}><RotateCcw className="mr-1.5 h-3.5 w-3.5" />Rerun</Button>}
                    {scan.status.toLowerCase() === 'pending' && <Button size="sm" onClick={() => setConfirmAction({ kind: 'start', scan })}><Play className="mr-1.5 h-3.5 w-3.5" />Start</Button>}
                    {isRunning && <Button size="sm" variant="outline" onClick={() => stopScan.mutate(scan.id)} disabled={stopScan.isPending}><Square className="mr-1.5 h-3.5 w-3.5" />Stop</Button>}
                    {!isRunning && <Button size="sm" variant="ghost" className="text-slate-600 hover:text-red-300" onClick={() => setConfirmAction({ kind: 'delete', scan })} aria-label={`Delete ${scan.name || scan.target}`}><Trash2 className="h-3.5 w-3.5" /></Button>}
                  </div>
                </div>
                {(scan.critical || scan.high || scan.medium || scan.low) ? <div className="flex flex-wrap items-center gap-2 border-t border-white/[0.055] bg-black/10 px-4 py-2.5 text-[10px]"><span className="mr-1 uppercase tracking-wider text-slate-700">Severity</span>{scan.critical ? <Badge variant="destructive">{scan.critical} critical</Badge> : null}{scan.high ? <Badge variant="outline" className="border-orange-400/20 text-orange-200">{scan.high} high</Badge> : null}{scan.medium ? <Badge variant="outline" className="border-amber-400/20 text-amber-200">{scan.medium} medium</Badge> : null}{scan.low ? <Badge variant="outline" className="border-cyan-400/20 text-cyan-200">{scan.low} low</Badge> : null}</div> : null}
              </article>
            )
          })}
        </section>
      ) : (
        <div className="surface-panel grid min-h-[360px] place-items-center rounded-2xl p-8 text-center"><div><FileSearch className="mx-auto h-9 w-9 text-slate-700" /><h2 className="mt-4 text-base font-semibold text-white">{scans.length ? 'No matching scans' : 'No scans yet'}</h2><p className="mx-auto mt-2 max-w-sm text-xs leading-relaxed text-slate-500">{scans.length ? 'Change the search or status filter to reveal more history.' : 'Choose a packaged workflow, confirm target authorization, and UniHack will retain its evidence here.'}</p>{!scans.length && <Button className="mt-5" onClick={() => openLauncher()}><Plus className="mr-2 h-4 w-4" />Launch first workflow</Button>}</div></div>
      )}

      {showLauncher && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-[#02050a]/85 p-4 backdrop-blur-md" role="dialog" aria-modal="true" aria-labelledby="workflow-launcher-title">
          <div className="surface-panel flex max-h-[92vh] w-full max-w-6xl flex-col overflow-hidden rounded-3xl border-cyan-400/15 shadow-[0_30px_100px_rgba(0,0,0,.65)]">
            <div className="flex items-start justify-between gap-4 border-b border-white/[0.07] px-5 py-4 sm:px-6">
              <div><div className="flex items-center gap-2 text-cyan-200"><Play className="h-4 w-4" /><span className="console-label text-cyan-200">Guided execution</span></div><h2 id="workflow-launcher-title" className="console-heading mt-2 text-xl">Launch a packaged workflow</h2><p className="mt-1 text-xs text-slate-500">Select by outcome, verify host readiness, then authorize one target.</p></div>
              <Button variant="ghost" size="sm" onClick={() => setShowLauncher(false)} aria-label="Close workflow launcher"><X className="h-4 w-4" /></Button>
            </div>

            <div className="grid min-h-0 flex-1 md:grid-cols-[minmax(0,1.15fr)_minmax(300px,.85fr)]">
              <section className="min-h-0 border-b border-white/[0.07] p-4 md:border-b-0 md:border-r sm:p-5" aria-label="Workflow choices">
                <div className="relative"><Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" /><Input className="pl-9" value={workflowSearch} onChange={(event) => setWorkflowSearch(event.target.value)} placeholder="Search by outcome, category, or workflow…" autoFocus /></div>
                <div className="mt-3 grid max-h-[54vh] gap-2 overflow-y-auto pr-1 sm:grid-cols-2 md:max-h-[65vh]">
                  {launcherWorkflows.map((workflow) => {
                    const metadata = getWorkflowCatalogEntry(workflow)
                    const ready = workflow.compatibility?.compatible !== false
                    const selected = workflow.id === selectedWorkflow
                    return (
                      <button key={workflow.id} type="button" onClick={() => { setSelectedWorkflow(workflow.id); setAuthorizationConfirmed(false) }} className={`rounded-2xl border p-4 text-left transition-colors ${selected ? 'border-cyan-400/35 bg-cyan-400/[0.08]' : 'border-white/[0.07] bg-white/[0.02] hover:border-white/15 hover:bg-white/[0.035]'}`}>
                        <div className="flex items-start justify-between gap-3"><span className={`rounded-full border px-2 py-1 text-[9px] font-semibold uppercase tracking-wider ${workflowActivityStyles[metadata.activity]}`}>{metadata.activity}</span>{ready ? <CheckCircle2 className="h-4 w-4 text-emerald-300" /> : <AlertCircle className="h-4 w-4 text-amber-300" />}</div>
                        <h3 className="mt-3 text-sm font-semibold text-slate-100">{workflow.name}</h3>
                        <p className="mt-1.5 line-clamp-2 text-[11px] leading-relaxed text-slate-500">{metadata.intent}</p>
                        <div className="mt-3 flex flex-wrap gap-x-3 gap-y-1 text-[10px] uppercase tracking-wider text-slate-600"><span>{workflow.steps_count} steps</span><span>{metadata.duration}</span><span>{ready ? 'ready' : `${workflow.compatibility?.missing_tools.length ?? 0} missing`}</span></div>
                      </button>
                    )
                  })}
                </div>
              </section>

              <section className="min-h-0 overflow-y-auto p-5 sm:p-6" aria-label="Workflow launch configuration">
                {selectedTemplate && selectedMetadata ? (
                  <div className="space-y-5">
                    <div><p className="console-label">Selected procedure</p><h3 className="console-heading mt-2 text-lg">{selectedTemplate.name}</h3><p className="mt-2 text-xs leading-relaxed text-slate-500">{selectedMetadata.bestFor}</p></div>
                    <div className="grid grid-cols-2 gap-2">
                      <div className="rounded-xl border border-white/[0.07] bg-white/[0.025] p-3"><p className="text-[10px] uppercase tracking-wider text-slate-600">Target type</p><p className="mt-1.5 text-sm capitalize text-slate-200">{selectedMetadata.targetKind}</p></div>
                      <div className="rounded-xl border border-white/[0.07] bg-white/[0.025] p-3"><p className="text-[10px] uppercase tracking-wider text-slate-600">Typical runtime</p><p className="mt-1.5 text-sm text-slate-200">{selectedMetadata.duration}</p></div>
                    </div>
                    <div><div className="flex items-center justify-between"><p className="console-label">Tool chain</p><button type="button" onClick={() => navigate(`/workflows?workflow=${encodeURIComponent(selectedTemplate.id)}`)} className="flex items-center gap-1 text-[11px] text-cyan-300 hover:text-cyan-200">Inspect Studio <ArrowRight className="h-3 w-3" /></button></div><div className="mt-2 flex flex-wrap gap-1.5">{selectedTemplate.compatibility?.required_tools.map((tool) => { const missing = selectedTemplate.compatibility?.missing_tools.includes(tool); return <span key={tool} className={`rounded-lg border px-2 py-1 font-mono text-[10px] ${missing ? 'border-amber-400/20 bg-amber-400/[0.05] text-amber-200' : 'border-emerald-400/15 bg-emerald-400/[0.045] text-emerald-200/80'}`}>{formatToolName(tool)}{missing ? ' · missing' : ''}</span> })}</div></div>
                    {selectedTemplate.compatibility?.compatible === false && <div className="rounded-xl border border-amber-400/20 bg-amber-400/[0.05] p-3"><div className="flex items-start gap-2"><Wrench className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-300" /><div><p className="text-xs font-semibold text-amber-100">Host is not ready</p><p className="mt-1 text-[11px] leading-relaxed text-amber-100/65">Install {selectedTemplate.compatibility.missing_tools.map(formatToolName).join(', ')} from Tools before running this workflow.</p></div></div></div>}
                    {selectedMetadata.prerequisites?.map((prerequisite) => <div key={prerequisite} className="flex items-start gap-2 rounded-xl border border-violet-400/15 bg-violet-400/[0.04] p-3 text-[11px] leading-relaxed text-violet-100/75"><AlertCircle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-violet-300" />{prerequisite}</div>)}
                    <label className="block text-[11px] font-medium text-slate-500">Authorized target<Input className="mt-2" value={scanTarget} onChange={(event) => setScanTarget(event.target.value)} placeholder={getTargetPlaceholder(selectedMetadata.targetKind)} /></label>
                    <div className="grid gap-3 sm:grid-cols-2"><label className="block text-[11px] font-medium text-slate-500">Scan name <span className="text-slate-700">optional</span><Input className="mt-2" value={scanName} onChange={(event) => setScanName(event.target.value)} placeholder="Q3 perimeter review" /></label><label className="block text-[11px] font-medium text-slate-500">Result folder <span className="text-slate-700">optional</span><Input className="mt-2" value={workingDirectory} onChange={(event) => setWorkingDirectory(event.target.value)} placeholder="Managed automatically" /></label></div>
                    <label className="block text-[11px] font-medium text-slate-500">Operator note <span className="text-slate-700">optional</span><Input className="mt-2" value={scanDescription} onChange={(event) => setScanDescription(event.target.value)} placeholder="Scope reference or assessment context" /></label>
                    <label className="flex items-start gap-3 rounded-xl border border-amber-400/15 bg-amber-400/[0.045] p-3 text-[11px] leading-relaxed text-slate-300"><input type="checkbox" checked={authorizationConfirmed} onChange={(event) => setAuthorizationConfirmed(event.target.checked)} className="mt-0.5 accent-cyan-400" /><span><strong className="font-semibold text-amber-100">Authorization confirmation.</strong> I own this target or have explicit permission to perform this security test.</span></label>
                    {executeWorkflow.error && <p role="alert" className="rounded-xl border border-red-400/15 bg-red-400/[0.05] p-3 text-[11px] text-red-200">{executeWorkflow.error.message}</p>}
                    <Button className="w-full" size="lg" disabled={!canExecute || executeWorkflow.isPending} onClick={() => executeWorkflow.mutate()}>{executeWorkflow.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />}{selectedTemplate.compatibility?.compatible === false ? 'Install missing tools first' : 'Authorize and launch'}</Button>
                  </div>
                ) : <div className="grid min-h-72 place-items-center text-center"><div><GitBranch className="mx-auto h-8 w-8 text-slate-700" /><p className="mt-3 text-xs text-slate-500">Select a workflow to configure its run.</p></div></div>}
              </section>
            </div>
          </div>
        </div>
      )}

      {confirmAction && (
        <div className="fixed inset-0 z-[60] grid place-items-center bg-[#02050a]/80 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="confirm-scan-action-title">
          <div className="surface-panel w-full max-w-md rounded-2xl p-5">
            <div className="flex items-start gap-3">{confirmAction.kind === 'delete' ? <XCircle className="mt-0.5 h-5 w-5 text-red-300" /> : <ShieldCheck className="mt-0.5 h-5 w-5 text-amber-300" />}<div><h2 id="confirm-scan-action-title" className="text-sm font-semibold text-white">{confirmAction.kind === 'delete' ? 'Delete scan record?' : 'Start authorized scan?'}</h2><p className="mt-2 text-xs leading-relaxed text-slate-500">{confirmAction.kind === 'delete' ? 'The database record and stored findings will be removed. Managed result files remain in the results folder.' : `This will start native execution against ${confirmAction.scan.target}. Continue only with explicit permission.`}</p></div></div>
            <div className="mt-5 flex justify-end gap-2"><Button variant="ghost" onClick={() => setConfirmAction(null)}>Cancel</Button><Button onClick={runConfirmedAction}>{confirmAction.kind === 'delete' ? <Trash2 className="mr-2 h-4 w-4" /> : <Play className="mr-2 h-4 w-4" />}{confirmAction.kind === 'delete' ? 'Delete record' : 'Start scan'}</Button></div>
          </div>
        </div>
      )}

      {selectedScan && <ScanDetailsModal scan={selectedScan} workflowTemplates={workflows} onClose={() => setSelectedScan(null)} />}
    </div>
  )
}

export default ScansPage
