import { useEffect, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Accessibility, Clock, Cpu, HardDrive, MonitorCog, RefreshCw, Save, Shield, Sparkles, Terminal } from 'lucide-react'
import { apiService, type AppSettings } from '../services/api'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card'
import { Input } from '../components/ui/Input'
import { useUiStore } from '../stores/uiStore'
import type { VisualQuality } from '../types/ui'
import { useNotificationStore } from '../stores/notificationStore'

const SettingsPage = () => {
  const visualQuality = useUiStore((state) => state.visualQuality)
  const motion = useUiStore((state) => state.motion)
  const immersiveVisuals = useUiStore((state) => state.immersiveVisuals)
  const highContrast = useUiStore((state) => state.highContrast)
  const vmBaselineMemoryMb = useUiStore((state) => state.vmBaselineMemoryMb)
  const setVisualQuality = useUiStore((state) => state.setVisualQuality)
  const setMotion = useUiStore((state) => state.setMotion)
  const setImmersiveVisuals = useUiStore((state) => state.setImmersiveVisuals)
  const setHighContrast = useUiStore((state) => state.setHighContrast)
  const setVmBaselineMemoryMb = useUiStore((state) => state.setVmBaselineMemoryMb)
  const [draft, setDraft] = useState<AppSettings | null>(null)
  const addNotification = useNotificationStore((state) => state.addNotification)
  const settingsQuery = useQuery({
    queryKey: ['runtime-settings'],
    queryFn: () => apiService.getSettings()
  })
  const healthQuery = useQuery({
    queryKey: ['system-health'],
    queryFn: async () => {
      const response = await apiService.getDetailedHealth()
      if (!response.data) throw new Error(response.error || 'System health is unavailable')
      return response.data
    },
    refetchInterval: 10_000
  })
  const systemQuery = useQuery({
    queryKey: ['system-info'],
    queryFn: () => apiService.getSystemInfo()
  })
  const saveSettings = useMutation({
    mutationFn: (settings: AppSettings) => apiService.updateSettings(settings),
    onSuccess: (settings) => {
      setDraft(settings)
      settingsQuery.refetch()
      addNotification({ level: 'success', title: 'Runtime settings saved', message: 'New workflow steps will use the updated resource limits.' })
    }
  })

  useEffect(() => {
    if (settingsQuery.data) setDraft(settingsQuery.data)
  }, [settingsQuery.data])

  const original = settingsQuery.data
  const changed = Boolean(draft && original && JSON.stringify(draft) !== JSON.stringify(original))
  const valid = Boolean(draft
    && draft.maxParallelSteps >= 1 && draft.maxParallelSteps <= 16
    && draft.defaultStepTimeoutSeconds >= 30 && draft.defaultStepTimeoutSeconds <= 86_400
    && draft.maxOutputLinesPerStream >= 100 && draft.maxOutputLinesPerStream <= 100_000)
  const health = healthQuery.data
  const system = systemQuery.data
  const error = settingsQuery.error ?? saveSettings.error ?? healthQuery.error ?? systemQuery.error

  const updateNumber = (key: keyof AppSettings, value: string) => {
    if (!draft) return
    setDraft({ ...draft, [key]: Number(value) })
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white sm:text-3xl">Runtime Settings</h1>
          <p className="mt-2 text-sm text-gray-400 sm:text-base">
            Tune local workflow resource usage. Changes apply to new steps without restarting the app.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {changed && <Badge variant="outline" className="border-yellow-500 text-yellow-400">Unsaved</Badge>}
          <Button
            disabled={!draft || !changed || !valid || saveSettings.isPending}
            onClick={() => draft && saveSettings.mutate(draft)}
          >
            <Save className="mr-2 h-4 w-4" />
            {saveSettings.isPending ? 'Saving…' : 'Save changes'}
          </Button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-800 bg-red-950/40 p-3 text-sm text-red-300" role="alert">
          {error.message}
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <div className="space-y-6 xl:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center"><Cpu className="mr-2 h-5 w-5" />Workflow execution</CardTitle>
              <CardDescription>Bound CPU, process, and in-memory output pressure for native tool runs.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-5">
              {!draft && !settingsQuery.isError && <p className="text-sm text-gray-400">Loading settings…</p>}
              {draft && (
                <>
                  <NumberSetting
                    label="Maximum parallel steps"
                    help="The maximum number of ready workflow steps started in one DAG layer."
                    value={draft.maxParallelSteps}
                    min={1}
                    max={16}
                    onChange={(value) => updateNumber('maxParallelSteps', value)}
                  />
                  <NumberSetting
                    label="Default step timeout (seconds)"
                    help="Used when a workflow step does not define its own timeout."
                    value={draft.defaultStepTimeoutSeconds}
                    min={30}
                    max={86_400}
                    onChange={(value) => updateNumber('defaultStepTimeoutSeconds', value)}
                  />
                  <NumberSetting
                    label="Captured lines per output stream"
                    help="Maximum retained stdout and stderr lines per attempt. Full file artifacts remain separate."
                    value={draft.maxOutputLinesPerStream}
                    min={100}
                    max={100_000}
                    onChange={(value) => updateNumber('maxOutputLinesPerStream', value)}
                  />
                  {!valid && <p className="text-sm text-yellow-400">One or more values are outside the allowed range.</p>}
                </>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center"><MonitorCog className="mr-2 h-5 w-5 text-cyan-300" />Visual performance</CardTitle>
              <CardDescription>Keep the immersive console useful without undermining the low-memory native runtime.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-5">
              <div className="grid gap-2 sm:grid-cols-[1fr_220px] sm:items-center">
                <div>
                  <label htmlFor="visual-quality" className="text-sm font-medium text-slate-200">3D quality</label>
                  <p className="mt-1 text-xs text-slate-500">Auto adapts device pixel ratio and effects from live frame performance.</p>
                </div>
                <select id="visual-quality" value={visualQuality} onChange={(event) => setVisualQuality(event.target.value as VisualQuality)} className="h-11 rounded-xl border border-white/10 bg-slate-950/60 px-3 text-sm text-white outline-none focus:border-cyan-400/50">
                  <option value="auto">Auto</option>
                  <option value="high">High</option>
                  <option value="balanced">Balanced</option>
                  <option value="low">Low power</option>
                </select>
              </div>
              <div className="grid gap-2 sm:grid-cols-[1fr_220px] sm:items-center">
                <div>
                  <label htmlFor="vm-memory-baseline" className="text-sm font-medium text-slate-200">VM memory baseline</label>
                  <p className="mt-1 text-xs text-slate-500">Used only for the transparent resource-savings comparison; it does not change execution limits.</p>
                </div>
                <select id="vm-memory-baseline" value={vmBaselineMemoryMb} onChange={(event) => setVmBaselineMemoryMb(Number(event.target.value))} className="h-11 rounded-xl border border-white/10 bg-slate-950/60 px-3 text-sm text-white outline-none focus:border-cyan-400/50">
                  <option value={2048}>2 GB</option>
                  <option value={4096}>4 GB</option>
                  <option value={8192}>8 GB</option>
                  <option value={16384}>16 GB</option>
                </select>
              </div>
              <ToggleSetting icon={<Sparkles className="h-4 w-4 text-violet-300" />} label="Immersive topology" help="Render interactive WebGL topology. A complete 2D representation remains available when disabled." checked={immersiveVisuals} onChange={setImmersiveVisuals} />
              <ToggleSetting icon={<Accessibility className="h-4 w-4 text-cyan-300" />} label="Reduced motion" help="Stop page choreography, auto-rotation, continuous scene updates, and physics impulses." checked={motion === 'reduced'} onChange={(checked) => setMotion(checked ? 'reduced' : 'full')} />
              <ToggleSetting icon={<Shield className="h-4 w-4 text-emerald-300" />} label="High contrast" help="Increase panel boundaries and secondary-text contrast throughout the console." checked={highContrast} onChange={setHighContrast} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center"><Shield className="mr-2 h-5 w-5" />Mandatory safety controls</CardTitle>
              <CardDescription>These controls are enforced by the Rust backend and cannot be disabled in settings.</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-3 sm:grid-cols-2">
              <SafetyItem title="Authorization confirmation" text="Required before every security workflow starts." />
              <SafetyItem title="Target validation" text="Rejects option injection, credentials, unsupported schemes, and malformed targets." />
              <SafetyItem title="Declared tools only" text="Workflow steps can execute only registered and healthy tool records." />
              <SafetyItem title="Managed output roots" text="Scan artifacts and report exports cannot escape app-owned directories." />
            </CardContent>
          </Card>
        </div>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between gap-3">
                <CardTitle className="flex items-center"><Clock className="mr-2 h-5 w-5" />System health</CardTitle>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => Promise.all([healthQuery.refetch(), systemQuery.refetch()])}
                  aria-label="Refresh system health"
                >
                  <RefreshCw className={`h-4 w-4 ${healthQuery.isFetching ? 'animate-spin' : ''}`} />
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <StatusRow label="Status" value={health?.system_health ?? 'Unknown'} badge />
              <StatusRow label="Active scans" value={String(health?.active_scans ?? 0)} />
              <StatusRow label="Available tools" value={String(health?.tools_available ?? 0)} />
              <StatusRow label="Critical findings" value={String(health?.critical_issues ?? 0)} danger />
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="flex items-center"><HardDrive className="mr-2 h-5 w-5" />Local runtime</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              <StatusRow label="Operating system" value={system?.os ?? 'Unknown'} />
              <StatusRow label="Architecture" value={system?.arch ?? 'Unknown'} />
              <StatusRow label="CPU cores" value={String(system?.cpu_cores ?? 'Unknown')} />
              <StatusRow label="Memory available" value={system ? `${system.available_memory_mb.toLocaleString()} MB` : 'Unknown'} />
              <StatusRow label="Memory total" value={system ? `${system.total_memory_mb.toLocaleString()} MB` : 'Unknown'} />
              <StatusRow label="UniHack process RAM" value={system ? `${system.process_memory_mb.toLocaleString()} MB` : 'Unknown'} />
              <StatusRow label="UniHack process CPU" value={system ? `${system.process_cpu_percent.toFixed(1)}%` : 'Unknown'} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="flex items-center"><Terminal className="mr-2 h-5 w-5" />Execution mode</CardTitle></CardHeader>
            <CardContent>
              <Badge className="bg-green-700">Native first</Badge>
              <p className="mt-3 text-sm text-gray-400">
                Installed host tools run directly without reserving RAM for a full guest operating system.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}

const NumberSetting = ({
  label,
  help,
  value,
  min,
  max,
  onChange
}: {
  label: string
  help: string
  value: number
  min: number
  max: number
  onChange: (value: string) => void
}) => (
  <div className="grid gap-2 sm:grid-cols-[1fr_180px] sm:items-center">
    <div>
      <label className="text-sm font-medium text-gray-200">{label}</label>
      <p className="mt-1 text-xs text-gray-400">{help}</p>
    </div>
    <Input aria-label={label} type="number" min={min} max={max} value={value} onChange={(event) => onChange(event.target.value)} />
  </div>
)

const SafetyItem = ({ title, text }: { title: string; text: string }) => (
  <div className="rounded-lg border border-gray-800 bg-gray-950/30 p-4">
    <div className="flex items-center text-sm font-medium text-white"><Shield className="mr-2 h-4 w-4 text-green-400" />{title}</div>
    <p className="mt-2 text-xs text-gray-400">{text}</p>
  </div>
)

const ToggleSetting = ({ icon, label, help, checked, onChange }: { icon: React.ReactNode; label: string; help: string; checked: boolean; onChange: (checked: boolean) => void }) => (
  <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-white/[0.07] bg-white/[0.025] p-4 hover:border-white/15">
    <span className="mt-0.5">{icon}</span>
    <span className="min-w-0 flex-1">
      <span className="block text-sm font-medium text-slate-200">{label}</span>
      <span className="mt-1 block text-xs leading-relaxed text-slate-500">{help}</span>
    </span>
    <span className={`relative mt-1 h-6 w-11 flex-shrink-0 rounded-full transition-colors ${checked ? 'bg-cyan-400/70' : 'bg-slate-700'}`}>
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} className="sr-only" />
      <span className={`absolute top-1 h-4 w-4 rounded-full bg-white shadow transition-transform ${checked ? 'translate-x-6' : 'translate-x-1'}`} />
    </span>
  </label>
)

const StatusRow = ({ label, value, badge, danger }: { label: string; value: string; badge?: boolean; danger?: boolean }) => (
  <div className="flex items-center justify-between gap-3 text-sm">
    <span className="text-gray-400">{label}</span>
    {badge
      ? <Badge className={value.toLowerCase() === 'healthy' ? 'bg-green-700' : 'bg-yellow-700'}>{value}</Badge>
      : <span className={danger ? 'text-red-400' : 'text-white'}>{value}</span>}
  </div>
)

export default SettingsPage
