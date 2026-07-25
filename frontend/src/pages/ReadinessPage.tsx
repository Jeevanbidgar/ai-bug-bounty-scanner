import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Boxes, CheckCircle2, CircleAlert, Cloud, MonitorCog, PackageCheck, RefreshCw, Server, TerminalSquare, Workflow } from 'lucide-react'
import apiService, { type PackageManagerInfo, type Tool, type WorkflowTemplate } from '../services/api'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'

const managerLabel: Record<PackageManagerInfo['manager_type'], string> = {
  apt: 'APT', cargo: 'Cargo', gem: 'RubyGems', go: 'Go', homebrew: 'Homebrew', npm: 'npm', pipx: 'Pipx', winget: 'WinGet',
}

const ReadinessPage = () => {
  const queryClient = useQueryClient()
  const systemQuery = useQuery({ queryKey: ['readiness-system'], queryFn: () => apiService.getSystemInfo() })
  const toolsQuery = useQuery({ queryKey: ['readiness-tools'], queryFn: async () => (await apiService.getTools(false)).data })
  const managersQuery = useQuery({ queryKey: ['readiness-managers'], queryFn: () => apiService.detectPackageManagers() })
  const workflowsQuery = useQuery({ queryKey: ['readiness-workflows'], queryFn: async () => (await apiService.getWorkflowTemplates(true)).data as WorkflowTemplate[] })

  const tools = toolsQuery.data ?? []
  const managers = managersQuery.data ?? []
  const workflows = workflowsQuery.data ?? []
  const installed = tools.filter((tool) => tool.installed)
  const missing = tools.filter((tool) => !tool.installed)
  const availableManagers = managers.filter((manager) => manager.available)
  const compatibleWorkflows = workflows.filter((workflow) => workflow.compatibility?.compatible !== false)
  const checks = [Boolean(systemQuery.data), installed.length > 0, availableManagers.length > 0, compatibleWorkflows.length > 0]
  const readinessScore = Math.round((checks.filter(Boolean).length / checks.length) * 100)
  const loading = systemQuery.isLoading || toolsQuery.isLoading || managersQuery.isLoading || workflowsQuery.isLoading
  const error = systemQuery.error ?? toolsQuery.error ?? managersQuery.error ?? workflowsQuery.error

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <div className="mb-3 flex items-center gap-2"><MonitorCog className="h-4 w-4 text-cyan-300" /><span className="console-label text-cyan-200">Host readiness</span></div>
          <h1 className="console-heading text-3xl sm:text-4xl">Native execution readiness</h1>
          <p className="mt-3 max-w-2xl text-sm text-slate-400">Understand what can run on this host before starting a workflow. Alternate runners remain explicit and disabled until separately configured.</p>
        </div>
        <Button variant="outline" onClick={() => queryClient.invalidateQueries({ predicate: (query) => String(query.queryKey[0]).startsWith('readiness-') })} disabled={loading}>
          <RefreshCw className={`mr-2 h-4 w-4 ${loading ? 'animate-spin' : ''}`} />Refresh probes
        </Button>
      </header>

      {error && <div className="rounded-xl border border-red-400/20 bg-red-400/[0.05] p-4 text-sm text-red-200" role="alert">Readiness probing failed: {error.message}</div>}

      <section className="surface-panel overflow-hidden rounded-2xl" aria-labelledby="readiness-score-title">
        <div className="grid gap-6 p-5 lg:grid-cols-[240px_minmax(0,1fr)] lg:p-6">
          <div className="rounded-2xl border border-cyan-400/15 bg-cyan-400/[0.045] p-5">
            <p id="readiness-score-title" className="console-label text-cyan-200">Readiness score</p>
            <p className="mt-3 text-5xl font-semibold tracking-tight text-white">{loading ? '—' : `${readinessScore}%`}</p>
            <p className="mt-3 text-xs leading-relaxed text-slate-500">A host capability summary, not permission to scan. Target authorization is still required for every execution.</p>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <ReadinessCheck title="Host runtime" detail={systemQuery.data ? `${systemQuery.data.os} · ${systemQuery.data.arch} · ${systemQuery.data.cpu_cores} cores` : 'Detecting operating system and architecture'} ready={Boolean(systemQuery.data)} icon={<Server className="h-4 w-4" />} />
            <ReadinessCheck title="Native tools" detail={`${installed.length} installed · ${missing.length} missing`} ready={installed.length > 0} icon={<TerminalSquare className="h-4 w-4" />} />
            <ReadinessCheck title="Package managers" detail={availableManagers.length ? availableManagers.map((manager) => managerLabel[manager.manager_type]).join(', ') : 'No supported package manager detected'} ready={availableManagers.length > 0} icon={<PackageCheck className="h-4 w-4" />} />
            <ReadinessCheck title="Packaged workflows" detail={`${compatibleWorkflows.length} of ${workflows.length} compatible now`} ready={compatibleWorkflows.length > 0} icon={<Workflow className="h-4 w-4" />} />
          </div>
        </div>
      </section>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_390px]">
        <section className="surface-panel rounded-2xl p-5" aria-labelledby="tool-readiness-title">
          <div className="flex items-center justify-between gap-3">
            <div><p className="console-label">Native inventory</p><h2 id="tool-readiness-title" className="mt-2 text-lg font-semibold text-white">Tool coverage</h2></div>
            <Link to="/tools" className="text-xs font-medium text-cyan-300 hover:text-cyan-200">Manage tools →</Link>
          </div>
          <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {tools.slice(0, 18).map((tool: Tool) => (
              <div key={tool.name} className="flex items-center gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] p-3">
                <span className={`h-2 w-2 flex-shrink-0 rounded-full ${tool.installed ? 'bg-emerald-400' : 'bg-amber-400'}`} />
                <span className="min-w-0 flex-1"><span className="block truncate text-xs font-medium text-slate-200">{tool.name}</span><span className="mt-1 block truncate text-[10px] uppercase tracking-wider text-slate-600">{tool.installed ? tool.version ?? 'installed' : tool.available_install_methods.join(' · ') || 'manual review'}</span></span>
              </div>
            ))}
          </div>
          {tools.length > 18 && <p className="mt-3 text-xs text-slate-600">Showing 18 of {tools.length} catalog tools.</p>}
        </section>

        <section className="surface-panel rounded-2xl p-5" aria-labelledby="runner-targets-title">
          <p className="console-label">Execution boundary</p>
          <h2 id="runner-targets-title" className="mt-2 text-lg font-semibold text-white">Runner targets</h2>
          <div className="mt-4 space-y-3">
            <RunnerTarget icon={<TerminalSquare className="h-4 w-4" />} name="Native" status="ready" detail="Default. Uses verified host executables and structured argv." />
            <RunnerTarget icon={<MonitorCog className="h-4 w-4" />} name="WSL" status="disabled" detail={systemQuery.data?.os === 'windows' ? 'Windows host detected; runner is not configured.' : 'Available only on supported Windows hosts.'} />
            <RunnerTarget icon={<Boxes className="h-4 w-4" />} name="Container" status="disabled" detail="Opt-in isolation runner is not implemented or silently selected." />
            <RunnerTarget icon={<Cloud className="h-4 w-4" />} name="Remote" status="planned" detail="Future option for tools that cannot reasonably run locally." />
          </div>
          <div className="mt-4 rounded-xl border border-amber-400/15 bg-amber-400/[0.04] p-3 text-[11px] leading-relaxed text-amber-100/75">No readiness result elevates privileges, installs a runner, or changes execution target automatically.</div>
        </section>
      </div>
    </div>
  )
}

const ReadinessCheck = ({ title, detail, ready, icon }: { title: string; detail: string; ready: boolean; icon: React.ReactNode }) => (
  <div className="rounded-xl border border-white/[0.07] bg-white/[0.025] p-4">
    <div className="flex items-center gap-2 text-xs font-semibold text-white">{ready ? <CheckCircle2 className="h-4 w-4 text-emerald-300" /> : <CircleAlert className="h-4 w-4 text-amber-300" />}{icon}{title}</div>
    <p className="mt-2 text-xs leading-relaxed text-slate-500">{detail}</p>
  </div>
)

const RunnerTarget = ({ icon, name, status, detail }: { icon: React.ReactNode; name: string; status: 'ready' | 'disabled' | 'planned'; detail: string }) => (
  <div className="rounded-xl border border-white/[0.07] bg-white/[0.025] p-3">
    <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">{icon}<span className="flex-1">{name}</span><Badge variant="outline" className={status === 'ready' ? 'border-emerald-400/20 text-emerald-300' : 'text-slate-500'}>{status}</Badge></div>
    <p className="mt-2 text-[11px] leading-relaxed text-slate-500">{detail}</p>
  </div>
)

export default ReadinessPage
