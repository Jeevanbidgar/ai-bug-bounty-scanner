import { Gauge, HardDrive, ServerOff } from 'lucide-react'
import type { SystemInfo } from '../services/api'
import { useUiStore } from '../stores/uiStore'

const formatMemory = (memoryMb: number) => memoryMb >= 1024
  ? `${(memoryMb / 1024).toFixed(1)} GB`
  : `${Math.round(memoryMb)} MB`

export const ResourceSavingsPanel = ({ systemInfo }: { systemInfo: SystemInfo | null }) => {
  const vmBaselineMemoryMb = useUiStore((state) => state.vmBaselineMemoryMb)
  const processMemoryMb = systemInfo?.process_memory_mb ?? 0
  const estimatedAvoidedMb = Math.max(0, vmBaselineMemoryMb - processMemoryMb)
  const processShare = Math.min(100, (processMemoryMb / vmBaselineMemoryMb) * 100)

  return (
    <section className="surface-panel rounded-2xl p-5" aria-labelledby="resource-savings-title">
      <div className="flex flex-col gap-5 xl:flex-row xl:items-center xl:justify-between">
        <div className="max-w-xl">
          <div className="flex items-center gap-2">
            <ServerOff className="h-4 w-4 text-emerald-300" />
            <h2 id="resource-savings-title" className="text-sm font-semibold text-white">VM resource comparison</h2>
          </div>
          <p className="mt-2 text-xs leading-relaxed text-slate-500">
            Current UniHack process usage compared with your configurable VM memory baseline. This is a resource estimate, not an equivalence claim for every workload.
          </p>
        </div>

        <div className="grid min-w-0 flex-1 gap-3 sm:grid-cols-3 xl:max-w-3xl">
          <ResourceMetric icon={<HardDrive className="h-4 w-4" />} label="UniHack RSS" value={systemInfo ? formatMemory(processMemoryMb) : 'Measuring'} />
          <ResourceMetric icon={<Gauge className="h-4 w-4" />} label="Process CPU" value={systemInfo ? `${systemInfo.process_cpu_percent.toFixed(1)}%` : 'Measuring'} />
          <ResourceMetric icon={<ServerOff className="h-4 w-4" />} label="Estimated RAM avoided" value={systemInfo ? formatMemory(estimatedAvoidedMb) : 'Measuring'} accent />
        </div>
      </div>

      <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-slate-800" aria-label={`UniHack uses ${processShare.toFixed(1)} percent of the configured VM memory baseline`}>
        <div className="h-full rounded-full bg-gradient-to-r from-cyan-400 to-emerald-400" style={{ width: `${Math.max(1, processShare)}%` }} />
      </div>
      <div className="mt-2 flex items-center justify-between text-[10px] uppercase tracking-wider text-slate-600">
        <span>Native process</span>
        <span>{formatMemory(vmBaselineMemoryMb)} VM baseline</span>
      </div>
    </section>
  )
}

const ResourceMetric = ({ icon, label, value, accent = false }: { icon: React.ReactNode; label: string; value: string; accent?: boolean }) => (
  <div className={`rounded-xl border p-3 ${accent ? 'border-emerald-400/15 bg-emerald-400/[0.045]' : 'border-white/[0.07] bg-white/[0.025]'}`}>
    <div className={`flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider ${accent ? 'text-emerald-300' : 'text-slate-500'}`}>{icon}{label}</div>
    <p className="mt-2 text-lg font-semibold text-white">{value}</p>
  </div>
)

export default ResourceSavingsPanel
