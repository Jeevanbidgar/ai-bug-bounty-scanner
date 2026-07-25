import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Check,
  CheckCircle2,
  Clock3,
  Code2,
  Copy,
  FileOutput,
  Filter,
  Loader2,
  RefreshCw,
  Search,
  ShieldCheck,
  Sparkles,
  Wrench,
  XCircle,
} from 'lucide-react'
import apiService, { type AdapterInfo, type CommandPreview, type Tool, type WorkflowTemplate } from '../services/api'
import { Badge } from './ui/Badge'
import { Button } from './ui/Button'
import { Input } from './ui/Input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/Select'
import { formatToolName } from '../data/workflowCatalog'
import { useNotificationStore } from '../stores/notificationStore'

interface AdapterExplorerProps {
  onSelectAdapter?: (adapter: AdapterInfo) => void
  selectedAdapter?: AdapterInfo | null
}

const riskStyles: Record<string, string> = {
  low: 'border-emerald-400/20 bg-emerald-400/[0.07] text-emerald-200',
  medium: 'border-cyan-400/20 bg-cyan-400/[0.07] text-cyan-200',
  high: 'border-amber-400/20 bg-amber-400/[0.07] text-amber-200',
  critical: 'border-red-400/20 bg-red-400/[0.07] text-red-200',
}

const originLabels: Record<AdapterInfo['origin'], string> = {
  specialized: 'Specialized',
  bundled_profile: 'Bundled profile',
  auto_detected: 'Auto-generated',
}

const quoteArgument = (argument: string) => {
  if (/^[a-zA-Z0-9_./:=@?&%+,-]+$/.test(argument)) return argument
  return `'${argument.split("'").join("'\\''")}'`
}

const AdapterExplorer = ({ onSelectAdapter, selectedAdapter }: AdapterExplorerProps) => {
  const navigate = useNavigate()
  const [searchTerm, setSearchTerm] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const [riskFilter, setRiskFilter] = useState('all')
  const [selectedToolName, setSelectedToolName] = useState(selectedAdapter?.tool_name ?? '')
  const [targetInput, setTargetInput] = useState('example.com')
  const [commandPreview, setCommandPreview] = useState<CommandPreview | null>(null)
  const [previewError, setPreviewError] = useState('')
  const [copied, setCopied] = useState(false)
  const addNotification = useNotificationStore((state) => state.addNotification)

  const adaptersQuery = useQuery({
    queryKey: ['adapters'],
    queryFn: () => apiService.listAdapters(),
    staleTime: 5 * 60 * 1000,
  })
  const toolsQuery = useQuery({
    queryKey: ['tools'],
    queryFn: async () => (await apiService.getTools()).data,
    staleTime: 30_000,
  })
  const workflowsQuery = useQuery({
    queryKey: ['workflow-templates'],
    queryFn: async () => (await apiService.getWorkflowTemplates(true)).data as WorkflowTemplate[],
    staleTime: 30_000,
  })

  const adapters = useMemo(() => adaptersQuery.data ?? [], [adaptersQuery.data])
  const selectedAdapterInfo = adapters.find((adapter) => adapter.tool_name === selectedToolName) ?? null

  useEffect(() => {
    if (!selectedToolName && adapters.length) setSelectedToolName(adapters[0].tool_name)
  }, [adapters, selectedToolName])

  useEffect(() => {
    let active = true
    setCopied(false)
    setPreviewError('')
    setCommandPreview(null)
    if (!selectedAdapterInfo || !targetInput.trim()) return () => { active = false }
    if (selectedAdapterInfo.status === 'review_required') {
      setPreviewError(`Auto-adapter for '${selectedAdapterInfo.tool_name}' requires review before command previews are enabled`)
      return () => { active = false }
    }

    const timer = window.setTimeout(() => {
      apiService.buildToolCommandWithDefaults(selectedAdapterInfo.tool_name, targetInput.trim(), null)
        .then((preview) => {
          if (active) setCommandPreview(preview)
        })
        .catch((error) => {
          if (active) setPreviewError(error instanceof Error ? error.message : 'Unable to build preview')
        })
    }, 180)

    return () => {
      active = false
      window.clearTimeout(timer)
    }
  }, [selectedAdapterInfo, targetInput])

  const toolsByName = useMemo(
    () => new Map((toolsQuery.data ?? []).map((tool: Tool) => [tool.name.toLowerCase(), tool])),
    [toolsQuery.data],
  )
  const categories = useMemo(
    () => [...new Set(adapters.map((adapter) => adapter.category))].sort(),
    [adapters],
  )
  const filteredAdapters = useMemo(() => adapters.filter((adapter) => {
    const search = searchTerm.trim().toLowerCase()
    const matchesSearch = !search || [adapter.name, adapter.tool_name, adapter.description, adapter.category]
      .some((value) => value.toLowerCase().includes(search))
    return matchesSearch
      && (categoryFilter === 'all' || adapter.category === categoryFilter)
      && (riskFilter === 'all' || adapter.risk_level.toLowerCase() === riskFilter)
  }), [adapters, categoryFilter, riskFilter, searchTerm])

  const selectedTool = selectedAdapterInfo
    ? toolsByName.get(selectedAdapterInfo.tool_name.toLowerCase())
    : undefined
  const usedByWorkflows = useMemo(() => {
    if (!selectedAdapterInfo) return []
    return (workflowsQuery.data ?? []).filter((workflow) =>
      workflow.compatibility?.required_tools.some((tool) => tool.toLowerCase() === selectedAdapterInfo.tool_name.toLowerCase()),
    )
  }, [selectedAdapterInfo, workflowsQuery.data])
  const readyAdapters = adapters.filter((adapter) => adapter.status === 'ready')
  const autoGeneratedCount = adapters.filter((adapter) => adapter.origin === 'auto_detected').length
  const reviewRequiredCount = adapters.filter((adapter) => adapter.status === 'review_required').length
  const eligibleInstalledTools = (toolsQuery.data ?? []).filter((tool) =>
    tool.installed
    && tool.category.toLowerCase() !== 'utility'
    && tool.install_method !== 'runtime'
    && tool.install_method !== 'manual',
  )
  const installedReadyCount = eligibleInstalledTools.filter((tool) =>
    readyAdapters.some((adapter) => adapter.tool_name.toLowerCase() === tool.name.toLowerCase()),
  ).length

  const handleSelect = (adapter: AdapterInfo) => {
    setSelectedToolName(adapter.tool_name)
    onSelectAdapter?.(adapter)
  }

  const handleCopy = async () => {
    if (!commandPreview?.argv.length) return
    try {
      await navigator.clipboard.writeText(commandPreview.argv.map(quoteArgument).join(' '))
      setCopied(true)
      addNotification({ level: 'success', title: 'Command preview copied', message: `${selectedAdapterInfo?.name ?? 'Tool'} argv was copied for review. No command was executed.` })
      window.setTimeout(() => setCopied(false), 1800)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Clipboard access was denied'
      setPreviewError(message)
      addNotification({ level: 'error', title: 'Copy failed', message })
    }
  }

  if (adaptersQuery.isLoading) {
    return <div className="surface-panel grid min-h-[440px] place-items-center rounded-2xl"><Loader2 className="h-7 w-7 animate-spin text-cyan-300" /></div>
  }

  if (adaptersQuery.error) {
    return <div className="surface-panel grid min-h-[440px] place-items-center rounded-2xl p-8 text-center" role="alert"><div><AlertTriangle className="mx-auto h-8 w-8 text-red-300" /><h2 className="mt-4 text-base font-semibold text-white">Tool contracts could not be loaded</h2><p className="mt-2 max-w-md text-xs text-slate-500">{adaptersQuery.error.message}</p><Button className="mt-4" variant="outline" onClick={() => adaptersQuery.refetch()}>Try again</Button></div></div>
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/[0.06] bg-white/[0.02] px-3 py-2">
        <p className="text-xs text-slate-500">Contracts refresh against the current local tool inventory.</p>
        <Button
          size="sm"
          variant="ghost"
          disabled={adaptersQuery.isFetching || toolsQuery.isFetching || workflowsQuery.isFetching}
          onClick={() => Promise.all([adaptersQuery.refetch(), toolsQuery.refetch(), workflowsQuery.refetch()])}
        >
          <RefreshCw className={`mr-2 h-3.5 w-3.5 ${adaptersQuery.isFetching || toolsQuery.isFetching || workflowsQuery.isFetching ? 'animate-spin' : ''}`} />
          Refresh contracts
        </Button>
      </div>
      {(toolsQuery.error || workflowsQuery.error) && <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-400/20 bg-amber-400/[0.05] px-4 py-3 text-xs text-amber-100" role="status"><span>Coverage context is incomplete: {toolsQuery.error?.message ?? workflowsQuery.error?.message}</span><Button size="sm" variant="ghost" onClick={() => Promise.all([toolsQuery.refetch(), workflowsQuery.refetch()])}>Retry context</Button></div>}
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Adapter coverage">
        <div className="surface-panel rounded-2xl p-4">
          <p className="console-label">Supported tools</p>
          <p className="metric-value mt-2 text-2xl font-semibold text-white">{readyAdapters.length}<span className="ml-1 text-sm font-normal text-slate-600">of {adapters.length} contracts</span></p>
          <p className="mt-1 text-xs text-slate-500">Ready contracts can produce validated structured arguments.</p>
        </div>
        <div className="surface-panel rounded-2xl p-4">
          <p className="console-label">Installed coverage</p>
          <p className="metric-value mt-2 text-2xl font-semibold text-emerald-200">{installedReadyCount}<span className="ml-1 text-sm font-normal text-slate-600">of {eligibleInstalledTools.length} eligible</span></p>
          <p className="mt-1 text-xs text-slate-500">Installed catalog tools are analyzed automatically.</p>
        </div>
        <div className="surface-panel rounded-2xl p-4">
          <p className="console-label">Auto-generated</p>
          <p className="metric-value mt-2 text-2xl font-semibold text-cyan-200">{autoGeneratedCount}<span className="ml-1 text-sm font-normal text-slate-600">local profiles</span></p>
          <p className="mt-1 text-xs text-slate-500">Derived from installed binary help and version evidence.</p>
        </div>
        <div className="surface-panel rounded-2xl p-4">
          <p className="console-label">Needs review</p>
          <p className="metric-value mt-2 text-2xl font-semibold text-amber-200">{reviewRequiredCount}<span className="ml-1 text-sm font-normal text-slate-600">quarantined</span></p>
          <p className="mt-1 text-xs text-slate-500">Ambiguous contracts cannot build or execute commands.</p>
        </div>
      </section>

      <section className="surface-panel rounded-2xl p-3">
        <div className="grid gap-2 md:grid-cols-[minmax(220px,1fr)_220px_160px]">
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" />
            <Input className="pl-9" value={searchTerm} onChange={(event) => setSearchTerm(event.target.value)} placeholder="Search supported tools, evidence, categories…" aria-label="Search adapters" />
          </div>
          <Select value={categoryFilter} onValueChange={setCategoryFilter}>
            <SelectTrigger aria-label="Filter adapters by category"><Filter className="mr-2 h-3.5 w-3.5 text-slate-500" /><SelectValue /></SelectTrigger>
            <SelectContent><SelectItem value="all">All categories</SelectItem>{categories.map((category) => <SelectItem key={category} value={category}>{category}</SelectItem>)}</SelectContent>
          </Select>
          <Select value={riskFilter} onValueChange={setRiskFilter}>
            <SelectTrigger aria-label="Filter adapters by activity"><SelectValue /></SelectTrigger>
            <SelectContent><SelectItem value="all">All activity</SelectItem><SelectItem value="low">Low</SelectItem><SelectItem value="medium">Medium</SelectItem><SelectItem value="high">High</SelectItem></SelectContent>
          </Select>
        </div>
      </section>

      <div className="grid gap-4 xl:grid-cols-[330px_minmax(0,1fr)]">
        <section className="surface-panel rounded-2xl p-3" aria-label="Adapter catalog">
          <div className="flex items-center justify-between px-2 pb-3 pt-1"><div><p className="console-label">Tool contracts</p><p className="mt-1 text-xs text-slate-600">{filteredAdapters.length} matching tools</p></div><Wrench className="h-4 w-4 text-cyan-300" /></div>
          <div className="max-h-[720px] space-y-1.5 overflow-y-auto pr-1">
            {filteredAdapters.map((adapter) => {
              const selected = adapter.tool_name === selectedToolName
              const tool = toolsByName.get(adapter.tool_name.toLowerCase())
              return (
                <button key={adapter.tool_name} type="button" onClick={() => handleSelect(adapter)} className={`w-full rounded-xl border p-3 text-left transition-colors ${selected ? 'border-cyan-400/30 bg-cyan-400/[0.08]' : 'border-transparent hover:border-white/10 hover:bg-white/[0.03]'}`}>
                  <div className="flex items-start gap-3">
                    <span className={`mt-1.5 h-2 w-2 flex-shrink-0 rounded-full ${tool?.installed ? 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,.55)]' : 'bg-slate-700'}`} />
                    <span className="min-w-0 flex-1">
                      <span className="flex items-center justify-between gap-2"><span className="truncate text-sm font-semibold text-slate-100">{adapter.name}</span><span className={`rounded-full border px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider ${riskStyles[adapter.risk_level.toLowerCase()] ?? riskStyles.medium}`}>{adapter.risk_level}</span></span>
                      <span className="mt-1 block truncate text-[11px] text-slate-500">{adapter.description}</span>
                      <span className="mt-2 flex flex-wrap items-center gap-2 text-[10px] uppercase tracking-wider text-slate-600"><span>{adapter.category}</span><span>·</span><span>{tool?.installed ? `v${tool.version ?? 'detected'}` : 'not installed'}</span><span>·</span><span className={adapter.origin === 'auto_detected' ? 'text-cyan-400' : ''}>{originLabels[adapter.origin]}</span>{adapter.status === 'review_required' && <span className="text-amber-300">review</span>}</span>
                    </span>
                  </div>
                </button>
              )
            })}
            {!filteredAdapters.length && <div className="p-8 text-center"><XCircle className="mx-auto h-7 w-7 text-slate-700" /><p className="mt-3 text-xs text-slate-500">No adapters match these filters.</p></div>}
          </div>
        </section>

        {selectedAdapterInfo ? (
          <div className="space-y-4">
            <section className="surface-panel rounded-2xl p-5">
              <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2"><h2 className="console-heading text-xl">{selectedAdapterInfo.name}</h2><Badge variant="outline" className="font-mono normal-case tracking-normal">{selectedAdapterInfo.tool_name}</Badge><Badge variant="outline" className={selectedAdapterInfo.origin === 'auto_detected' ? 'border-cyan-400/20 bg-cyan-400/[0.06] text-cyan-200' : ''}>{selectedAdapterInfo.origin === 'auto_detected' && <Sparkles className="mr-1 h-3 w-3" />}{originLabels[selectedAdapterInfo.origin]}</Badge></div>
                  <p className="mt-2 max-w-2xl text-sm leading-relaxed text-slate-400">{selectedAdapterInfo.description}</p>
                </div>
                <div className={`flex items-center gap-2 rounded-xl border px-3 py-2 text-xs ${selectedTool?.installed ? 'border-emerald-400/20 bg-emerald-400/[0.06] text-emerald-200' : 'border-amber-400/20 bg-amber-400/[0.06] text-amber-200'}`}>
                  {selectedTool?.installed ? <CheckCircle2 className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4" />}
                  {selectedTool?.installed ? `Ready${selectedTool.version ? ` · v${selectedTool.version}` : ''}` : 'Install required'}
                </div>
              </div>

              <div className="mt-5 grid gap-3 sm:grid-cols-3">
                <div className="rounded-xl border border-white/[0.07] bg-white/[0.025] p-3"><div className="flex items-center gap-2 text-[11px] text-slate-500"><Activity className="h-3.5 w-3.5 text-cyan-300" />Activity</div><p className="mt-2 text-sm font-medium capitalize text-slate-200">{selectedAdapterInfo.risk_level} impact</p></div>
                <div className="rounded-xl border border-white/[0.07] bg-white/[0.025] p-3"><div className="flex items-center gap-2 text-[11px] text-slate-500"><Clock3 className="h-3.5 w-3.5 text-violet-300" />Timeout ceiling</div><p className="mt-2 text-sm font-medium text-slate-200">{Math.round(selectedAdapterInfo.timeout / 60)} minutes</p></div>
                <div className="rounded-xl border border-white/[0.07] bg-white/[0.025] p-3"><div className="flex items-center gap-2 text-[11px] text-slate-500"><FileOutput className="h-3.5 w-3.5 text-emerald-300" />Evidence</div><p className="mt-2 truncate text-sm font-medium text-slate-200">{selectedAdapterInfo.expected_outputs.join(', ')}</p></div>
              </div>

              {selectedAdapterInfo.requires_authorization && <div className="mt-4 flex items-start gap-3 rounded-xl border border-amber-400/15 bg-amber-400/[0.045] p-3"><ShieldCheck className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-300" /><p className="text-xs leading-relaxed text-amber-100/75">Active adapter. UniHack requires explicit target authorization before any workflow containing this tool can execute.</p></div>}
              {selectedAdapterInfo.origin === 'auto_detected' && <div className={`mt-3 flex items-start gap-3 rounded-xl border p-3 ${selectedAdapterInfo.status === 'ready' ? 'border-cyan-400/15 bg-cyan-400/[0.045]' : 'border-amber-400/20 bg-amber-400/[0.05]'}`}><Sparkles className={`mt-0.5 h-4 w-4 flex-shrink-0 ${selectedAdapterInfo.status === 'ready' ? 'text-cyan-300' : 'text-amber-300'}`} /><p className="text-xs leading-relaxed text-slate-300"><span className="font-semibold">{Math.round(selectedAdapterInfo.confidence * 100)}% inference confidence.</span> {selectedAdapterInfo.status === 'ready' ? 'The installed CLI exposed an explicit target contract. Runtime authorization and executable verification still apply.' : 'The CLI contract is ambiguous, so this profile is quarantined and cannot build commands.'}</p></div>}
            </section>

            <div className="grid gap-4 lg:grid-cols-[minmax(0,1.25fr)_minmax(260px,.75fr)]">
              <section className="surface-panel rounded-2xl p-5">
                <div className="flex items-start justify-between gap-3"><div><p className="console-label">Structured command preview</p><p className="mt-2 text-xs text-slate-500">Inspection only. The backend still owns execution, validation, and authorization.</p></div><Code2 className="h-4 w-4 text-cyan-300" /></div>
                <label className="mt-4 block text-[11px] font-medium text-slate-500">Authorized target<Input className="mt-2" value={targetInput} onChange={(event) => setTargetInput(event.target.value)} placeholder="example.com" /></label>
                <div className="mt-4 overflow-hidden rounded-xl border border-white/[0.08] bg-[#03070d]">
                  <div className="flex items-center justify-between border-b border-white/[0.06] px-3 py-2"><span className="text-[10px] uppercase tracking-wider text-slate-600">argv · never a shell string</span><Button type="button" size="sm" variant="ghost" onClick={handleCopy} disabled={!commandPreview?.argv.length}>{copied ? <Check className="mr-1.5 h-3.5 w-3.5 text-emerald-300" /> : <Copy className="mr-1.5 h-3.5 w-3.5" />}{copied ? 'Copied' : 'Copy preview'}</Button></div>
                  <div className="min-h-24 overflow-x-auto p-4 font-mono text-xs leading-6 text-emerald-300">
                    {previewError ? <span className="text-red-300">{previewError}</span> : commandPreview?.argv.length ? commandPreview.argv.map((argument, index) => <span key={`${argument}-${index}`} className="mr-2 inline-block"><span className="mr-1 text-slate-700">{index}</span>{argument}</span>) : <span className="text-slate-700">Enter a target to inspect the argument vector.</span>}
                  </div>
                  {commandPreview?.stdin && <div className="border-t border-white/[0.06] px-4 py-3 text-xs"><span className="text-slate-600">stdin</span><code className="ml-3 text-violet-200">{commandPreview.stdin}</code></div>}
                </div>
              </section>

              <section className="surface-panel rounded-2xl p-5">
                <p className="console-label">Used by workflows</p>
                <p className="mt-2 text-xs text-slate-500">Open a packaged procedure to inspect the tool in context.</p>
                <div className="mt-4 space-y-2">
                  {usedByWorkflows.slice(0, 6).map((workflow) => (
                    <button key={workflow.id} type="button" onClick={() => navigate(`/workflows?workflow=${encodeURIComponent(workflow.id)}`)} className="group flex w-full items-center justify-between gap-3 rounded-xl border border-white/[0.07] bg-white/[0.025] p-3 text-left hover:border-violet-400/20 hover:bg-violet-400/[0.045]">
                      <span className="min-w-0"><span className="block truncate text-xs font-semibold text-slate-200">{workflow.name}</span><span className="mt-1 block text-[10px] uppercase tracking-wider text-slate-600">{workflow.steps_count} steps · {workflow.category}</span></span><ArrowUpRight className="h-3.5 w-3.5 flex-shrink-0 text-slate-700 group-hover:text-violet-300" />
                    </button>
                  ))}
                  {!usedByWorkflows.length && <p className="rounded-xl border border-dashed border-white/10 p-4 text-xs text-slate-600">No packaged workflow currently references {formatToolName(selectedAdapterInfo.tool_name)}.</p>}
                </div>
              </section>
            </div>
          </div>
        ) : <div className="surface-panel grid min-h-[420px] place-items-center rounded-2xl text-center"><div><Code2 className="mx-auto h-8 w-8 text-slate-700" /><p className="mt-3 text-sm text-slate-500">Select an adapter to inspect it.</p></div></div>}
      </div>
    </div>
  )
}

export default AdapterExplorer
