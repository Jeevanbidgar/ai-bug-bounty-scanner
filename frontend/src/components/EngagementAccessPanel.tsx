import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  Ban,
  CheckCircle2,
  Clock3,
  Plus,
  RefreshCw,
  ShieldCheck,
  Target,
  X,
} from 'lucide-react'
import { FormEvent, useMemo, useState } from 'react'
import { appBridge } from '../bridge/appBridge'
import { useNotificationStore } from '../stores/notificationStore'
import { Badge } from './ui/Badge'
import { Button } from './ui/Button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/Card'
import { Input } from './ui/Input'

type RiskTier = 'read_only' | 'passive' | 'active' | 'maintenance'

interface ScopeBudget {
  maxExecutions: number
  maxConcurrentProcesses: number
  maxRuntimeSeconds: number
  maxOutputBytes: number
}

interface AuthorizedTarget {
  original: string
  canonical: string
  kind: 'hostname' | 'ip' | 'cidr' | 'url'
}

interface EngagementScope {
  id: string
  revision: number
  name: string
  principalId: string
  targets: AuthorizedTarget[]
  workflowIds: string[]
  allowedRiskTier: RiskTier
  startsAt: string
  expiresAt: string
  budget: ScopeBudget
  createdAt: string
  revokedAt: string | null
}

interface McpAuditEvent {
  id: string
  capability: string
  requestId: string
  scopeId: string | null
  outcome: string
  eventHash: string
  createdAt: string
}

const DEFAULT_BUDGET: ScopeBudget = {
  maxExecutions: 25,
  maxConcurrentProcesses: 4,
  maxRuntimeSeconds: 14_400,
  maxOutputBytes: 500_000_000,
}

const EngagementAccessPanel = () => {
  const queryClient = useQueryClient()
  const addNotification = useNotificationStore((state) => state.addNotification)
  const [showCreate, setShowCreate] = useState(false)
  const [revokeCandidate, setRevokeCandidate] = useState<string | null>(null)
  const [name, setName] = useState('')
  const [targets, setTargets] = useState('')
  const [workflowIds, setWorkflowIds] = useState('')
  const [riskTier, setRiskTier] = useState<RiskTier>('active')
  const [durationMinutes, setDurationMinutes] = useState('480')
  const [maxExecutions, setMaxExecutions] = useState('25')
  const [maxConcurrent, setMaxConcurrent] = useState('4')
  const [maxRuntimeMinutes, setMaxRuntimeMinutes] = useState('240')
  const [maxOutputMb, setMaxOutputMb] = useState('500')
  const [authorized, setAuthorized] = useState(false)

  const scopesQuery = useQuery({
    queryKey: ['engagement-scopes'],
    queryFn: () => appBridge.invoke<EngagementScope[]>('list_engagement_scopes'),
  })
  const activityQuery = useQuery({
    queryKey: ['mcp-audit-activity'],
    queryFn: () => appBridge.invoke<McpAuditEvent[]>('list_mcp_audit_activity', { limit: 24 }),
  })

  const createScope = useMutation({
    mutationFn: () => appBridge.invoke<EngagementScope>('create_engagement_scope', {
      request: {
        name: name.trim(),
        targets: splitValues(targets),
        workflowIds: splitValues(workflowIds),
        allowedRiskTier: riskTier,
        durationMinutes: Number(durationMinutes),
        authorizationConfirmed: authorized,
        budget: {
          maxExecutions: Number(maxExecutions),
          maxConcurrentProcesses: Number(maxConcurrent),
          maxRuntimeSeconds: Number(maxRuntimeMinutes) * 60,
          maxOutputBytes: Number(maxOutputMb) * 1_000_000,
        },
      },
    }),
    onSuccess: async (scope) => {
      resetForm()
      setShowCreate(false)
      await refreshGovernance()
      addNotification({
        level: 'success',
        title: 'Engagement authorized',
        message: `${scope.name} is available to paired AI clients until ${formatDate(scope.expiresAt)}.`,
      })
    },
    onError: (error) => addNotification({
      level: 'error',
      title: 'Engagement was not created',
      message: error instanceof Error ? error.message : String(error),
    }),
  })

  const revokeScope = useMutation({
    mutationFn: (scopeId: string) => appBridge.invoke<EngagementScope>('revoke_engagement_scope', { scopeId }),
    onSuccess: async (scope) => {
      setRevokeCandidate(null)
      await refreshGovernance()
      addNotification({
        level: 'warning',
        title: 'Engagement revoked',
        message: `${scope.name} cannot authorize future runs.`,
      })
    },
    onError: (error) => addNotification({
      level: 'error',
      title: 'Revocation failed',
      message: error instanceof Error ? error.message : String(error),
    }),
  })

  const activeScopes = useMemo(
    () => (scopesQuery.data ?? []).filter((scope) => scopeStatus(scope) === 'active').length,
    [scopesQuery.data],
  )

  const refreshGovernance = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['engagement-scopes'] }),
      queryClient.invalidateQueries({ queryKey: ['mcp-audit-activity'] }),
    ])
  }

  const resetForm = () => {
    setName('')
    setTargets('')
    setWorkflowIds('')
    setRiskTier('active')
    setDurationMinutes('480')
    setMaxExecutions(String(DEFAULT_BUDGET.maxExecutions))
    setMaxConcurrent(String(DEFAULT_BUDGET.maxConcurrentProcesses))
    setMaxRuntimeMinutes(String(DEFAULT_BUDGET.maxRuntimeSeconds / 60))
    setMaxOutputMb(String(DEFAULT_BUDGET.maxOutputBytes / 1_000_000))
    setAuthorized(false)
  }

  const submit = (event: FormEvent) => {
    event.preventDefault()
    createScope.mutate()
  }

  const queryError = scopesQuery.error ?? activityQuery.error

  return (
    <section className="space-y-5" aria-labelledby="engagement-access-title">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-2">
            <Badge>{activeScopes} active</Badge>
            <Badge variant="outline">Desktop approval only</Badge>
          </div>
          <h2 id="engagement-access-title" className="text-xl font-semibold text-white">Engagement access</h2>
          <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-400">
            Define exactly what a paired AI client may target. Creating or expanding this boundary is never an MCP capability.
          </p>
        </div>
        <Button onClick={() => setShowCreate((visible) => !visible)} aria-expanded={showCreate}>
          {showCreate ? <X className="mr-2 h-4 w-4" /> : <Plus className="mr-2 h-4 w-4" />}
          {showCreate ? 'Close form' : 'New engagement'}
        </Button>
      </div>

      {queryError && (
        <div role="alert" className="rounded-2xl border border-red-400/20 bg-red-400/[0.06] p-4 text-sm text-red-200">
          {queryError instanceof Error ? queryError.message : String(queryError)}
        </div>
      )}

      {showCreate && (
        <Card className="border-cyan-400/20 bg-cyan-400/[0.025]">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><ShieldCheck className="h-5 w-5 text-cyan-300" />Authorize a bounded engagement</CardTitle>
            <CardDescription>The daemon signs this immutable revision. MCP clients can select it but cannot edit it.</CardDescription>
          </CardHeader>
          <CardContent className="mt-5">
            <form onSubmit={submit} className="space-y-5">
              <div className="grid gap-4 lg:grid-cols-2">
                <Field label="Engagement name" htmlFor="engagement-name" hint="A recognizable project or assessment label.">
                  <Input id="engagement-name" value={name} onChange={(event) => setName(event.target.value)} maxLength={120} required placeholder="Acme authorized assessment" />
                </Field>
                <Field label="Duration in minutes" htmlFor="engagement-duration" hint="5 minutes to 30 days. Eight hours is 480 minutes.">
                  <Input id="engagement-duration" type="number" min={5} max={43_200} value={durationMinutes} onChange={(event) => setDurationMinutes(event.target.value)} required />
                </Field>
              </div>

              <div className="grid gap-4 lg:grid-cols-2">
                <Field label="Authorized targets" htmlFor="engagement-targets" hint="One hostname, IP, CIDR, or URL boundary per line.">
                  <textarea id="engagement-targets" value={targets} onChange={(event) => setTargets(event.target.value)} required rows={5} placeholder={'example.com\nhttps://api.example.com/v1\n192.0.2.0/28'} className="w-full resize-y rounded-xl border border-white/10 bg-slate-950/60 px-3 py-2 font-mono text-sm text-white shadow-inner shadow-black/20 placeholder:text-slate-600 focus:border-cyan-400/50 focus:outline-none focus:ring-2 focus:ring-cyan-400/20" />
                </Field>
                <div className="space-y-4">
                  <Field label="Allowed workflow IDs" htmlFor="engagement-workflows" hint="Optional. Leave empty to allow any trusted packaged workflow within the other limits.">
                    <textarea id="engagement-workflows" value={workflowIds} onChange={(event) => setWorkflowIds(event.target.value)} rows={2} placeholder="quick-bug-bounty, discovery-only" className="w-full resize-y rounded-xl border border-white/10 bg-slate-950/60 px-3 py-2 font-mono text-sm text-white placeholder:text-slate-600 focus:border-cyan-400/50 focus:outline-none focus:ring-2 focus:ring-cyan-400/20" />
                  </Field>
                  <Field label="Maximum risk" htmlFor="engagement-risk" hint="Maintenance cannot run privileged or destructive operations.">
                    <select id="engagement-risk" value={riskTier} onChange={(event) => setRiskTier(event.target.value as RiskTier)} className="h-11 w-full rounded-xl border border-white/10 bg-slate-950/60 px-3 text-sm text-white focus:border-cyan-400/50 focus:outline-none focus:ring-2 focus:ring-cyan-400/20">
                      <option value="read_only">Read only</option>
                      <option value="passive">Passive</option>
                      <option value="active">Active scanning</option>
                      <option value="maintenance">Tool maintenance</option>
                    </select>
                  </Field>
                </div>
              </div>

              <fieldset className="rounded-2xl border border-white/[0.07] bg-black/15 p-4">
                <legend className="px-2 text-xs font-semibold uppercase tracking-[0.16em] text-slate-400">Resource budget</legend>
                <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                  <Field label="Executions" htmlFor="budget-executions"><Input id="budget-executions" type="number" min={1} max={10_000} value={maxExecutions} onChange={(event) => setMaxExecutions(event.target.value)} required /></Field>
                  <Field label="Concurrent processes" htmlFor="budget-processes"><Input id="budget-processes" type="number" min={1} max={32} value={maxConcurrent} onChange={(event) => setMaxConcurrent(event.target.value)} required /></Field>
                  <Field label="Runtime minutes" htmlFor="budget-runtime"><Input id="budget-runtime" type="number" min={1} max={1440} value={maxRuntimeMinutes} onChange={(event) => setMaxRuntimeMinutes(event.target.value)} required /></Field>
                  <Field label="Output MB" htmlFor="budget-output"><Input id="budget-output" type="number" min={1} max={5000} value={maxOutputMb} onChange={(event) => setMaxOutputMb(event.target.value)} required /></Field>
                </div>
              </fieldset>

              <label className="flex cursor-pointer items-start gap-3 rounded-2xl border border-amber-400/20 bg-amber-400/[0.055] p-4">
                <input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} className="mt-0.5 h-4 w-4 rounded border-white/20 bg-slate-950 accent-cyan-400" />
                <span>
                  <span className="block text-sm font-medium text-amber-100">I confirm I own these targets or have explicit authorization to assess them.</span>
                  <span className="mt-1 block text-xs leading-5 text-amber-100/60">This creates a signed grant. It does not elevate privileges or permit targets outside these boundaries.</span>
                </span>
              </label>

              <div className="flex flex-col-reverse gap-3 sm:flex-row sm:justify-end">
                <Button variant="ghost" onClick={() => { resetForm(); setShowCreate(false) }}>Cancel</Button>
                <Button type="submit" disabled={!authorized || createScope.isPending || !name.trim() || splitValues(targets).length === 0}>
                  {createScope.isPending ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />}
                  Create signed engagement
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-5 2xl:grid-cols-[1.35fr_0.65fr]">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Target className="h-5 w-5 text-cyan-300" />Authorized scopes</CardTitle>
            <CardDescription>Only active, signed scopes can validate a future mission.</CardDescription>
          </CardHeader>
          <CardContent className="mt-5 space-y-3">
            {scopesQuery.isLoading && <LoadingLine label="Loading engagement scopes…" />}
            {!scopesQuery.isLoading && (scopesQuery.data?.length ?? 0) === 0 && (
              <EmptyState icon={<ShieldCheck className="h-5 w-5" />} title="No engagement access yet" description="Connect your AI client for discovery, then create a scope before enabling any execution." />
            )}
            {(scopesQuery.data ?? []).map((scope) => {
              const status = scopeStatus(scope)
              const confirming = revokeCandidate === scope.id
              return (
                <article key={scope.id} className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-4">
                  <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="font-medium text-slate-100">{scope.name}</h3>
                        <ScopeStatusBadge status={status} />
                        <Badge variant="outline">Risk: {scope.allowedRiskTier.replace('_', ' ')}</Badge>
                      </div>
                      <p className="mt-2 break-all font-mono text-[10px] text-slate-600">{scope.id}</p>
                    </div>
                    {status === 'active' && (
                      confirming ? (
                        <div className="flex flex-wrap gap-2" role="group" aria-label={`Confirm revocation of ${scope.name}`}>
                          <Button variant="outline" size="sm" className="border-red-400/30 text-red-200 hover:bg-red-400/10" onClick={() => revokeScope.mutate(scope.id)} disabled={revokeScope.isPending}>
                            <Ban className="mr-2 h-3.5 w-3.5" />Confirm revoke
                          </Button>
                          <Button variant="ghost" size="sm" onClick={() => setRevokeCandidate(null)}>Keep active</Button>
                        </div>
                      ) : (
                        <Button variant="ghost" size="sm" className="text-slate-400 hover:text-red-200" onClick={() => setRevokeCandidate(scope.id)}><Ban className="mr-2 h-3.5 w-3.5" />Revoke</Button>
                      )
                    )}
                  </div>
                  <div className="mt-4 grid gap-3 text-xs sm:grid-cols-2 xl:grid-cols-4">
                    <Metric label="Targets" value={String(scope.targets.length)} />
                    <Metric label="Workflows" value={scope.workflowIds.length ? String(scope.workflowIds.length) : 'Any trusted'} />
                    <Metric label="Executions" value={String(scope.budget.maxExecutions)} />
                    <Metric label="Expires" value={formatDate(scope.expiresAt)} />
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {scope.targets.slice(0, 5).map((target) => <code key={`${target.kind}:${target.canonical}`} className="rounded-lg border border-white/[0.06] bg-black/20 px-2 py-1 text-[10px] text-slate-400">{target.canonical}</code>)}
                    {scope.targets.length > 5 && <span className="px-2 py-1 text-[10px] text-slate-600">+{scope.targets.length - 5} more</span>}
                  </div>
                </article>
              )
            })}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Activity className="h-5 w-5 text-violet-300" />Recent MCP activity</CardTitle>
            <CardDescription>Sanitized, HMAC-chained local audit events.</CardDescription>
          </CardHeader>
          <CardContent className="mt-5 space-y-2">
            {activityQuery.isLoading && <LoadingLine label="Loading audit activity…" />}
            {!activityQuery.isLoading && (activityQuery.data?.length ?? 0) === 0 && (
              <EmptyState icon={<Activity className="h-5 w-5" />} title="No activity recorded" description="Calls from Codex or Claude will appear here without secrets or raw credentials." />
            )}
            {(activityQuery.data ?? []).map((event) => (
              <div key={event.id} className="rounded-xl border border-white/[0.06] bg-black/15 p-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate text-xs font-medium text-slate-200">{event.capability.replace(/_/g, ' ')}</p>
                    <p className="mt-1 text-[10px] text-slate-600">{formatDate(event.createdAt)}</p>
                  </div>
                  <span className={`rounded-md px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide ${event.outcome === 'success' ? 'bg-emerald-400/10 text-emerald-300' : 'bg-red-400/10 text-red-300'}`}>{event.outcome}</span>
                </div>
                <p className="mt-2 truncate font-mono text-[9px] text-slate-700" title={event.eventHash}>{event.eventHash}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </section>
  )
}

const Field = ({ label, htmlFor, hint, children }: { label: string; htmlFor: string; hint?: string; children: React.ReactNode }) => (
  <div>
    <label htmlFor={htmlFor} className="text-xs font-medium text-slate-300">{label}</label>
    {hint && <p className="mb-2 mt-1 text-[11px] leading-4 text-slate-600">{hint}</p>}
    {!hint && <div className="h-2" />}
    {children}
  </div>
)

const Metric = ({ label, value }: { label: string; value: string }) => (
  <div className="rounded-xl border border-white/[0.05] bg-black/15 p-3">
    <p className="text-[10px] uppercase tracking-[0.14em] text-slate-600">{label}</p>
    <p className="mt-1 truncate font-medium text-slate-300" title={value}>{value}</p>
  </div>
)

const ScopeStatusBadge = ({ status }: { status: ReturnType<typeof scopeStatus> }) => {
  if (status === 'active') return <Badge><CheckCircle2 className="mr-1 h-3 w-3" />Active</Badge>
  if (status === 'revoked') return <Badge variant="destructive"><Ban className="mr-1 h-3 w-3" />Revoked</Badge>
  if (status === 'expired') return <Badge variant="outline"><Clock3 className="mr-1 h-3 w-3" />Expired</Badge>
  return <Badge variant="outline"><Clock3 className="mr-1 h-3 w-3" />Scheduled</Badge>
}

const EmptyState = ({ icon, title, description }: { icon: React.ReactNode; title: string; description: string }) => (
  <div className="rounded-2xl border border-dashed border-white/10 px-5 py-8 text-center">
    <span className="mx-auto grid h-10 w-10 place-items-center rounded-xl bg-white/[0.04] text-slate-500">{icon}</span>
    <p className="mt-3 text-sm font-medium text-slate-300">{title}</p>
    <p className="mx-auto mt-1 max-w-sm text-xs leading-5 text-slate-600">{description}</p>
  </div>
)

const LoadingLine = ({ label }: { label: string }) => (
  <div className="flex items-center justify-center gap-2 py-8 text-xs text-slate-500" role="status"><RefreshCw className="h-4 w-4 animate-spin" />{label}</div>
)

const splitValues = (value: string) => value
  .split(/[\n,]/)
  .map((item) => item.trim())
  .filter(Boolean)

const scopeStatus = (scope: EngagementScope) => {
  if (scope.revokedAt) return 'revoked' as const
  const now = Date.now()
  if (new Date(scope.startsAt).getTime() > now) return 'scheduled' as const
  if (new Date(scope.expiresAt).getTime() <= now) return 'expired' as const
  return 'active' as const
}

const formatDate = (value: string) => new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'short',
}).format(new Date(value))

export default EngagementAccessPanel
