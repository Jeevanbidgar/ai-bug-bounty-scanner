import {
  AlertTriangle,
  ArrowUpCircle,
  CheckCircle2,
  ChevronRight,
  CircleDashed,
  SquareTerminal,
  Zap,
} from 'lucide-react'
import type { Tool } from '../services/api'

interface ToolCardProps {
  tool: Tool
  categoryLabel: string
  installMethodLabel: string
  automatedInstallAvailable: boolean
  hasUpdate: boolean
  latestVersion: string | null
  onOpen: () => void
}

const formatLastChecked = (value: string | null) => {
  if (!value) return 'Not checked'

  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return 'Not checked'

  return parsed.toLocaleDateString(undefined, {
    day: 'numeric',
    month: 'short',
  })
}

const getStatusPresentation = (tool: Tool) => {
  if (tool.installed) {
    return {
      label: 'Installed',
      icon: CheckCircle2,
      className: 'border-emerald-400/20 bg-emerald-400/[0.08] text-emerald-300',
      accentClassName: 'from-emerald-400/70 via-cyan-400/30 to-transparent',
    }
  }

  if (tool.status === 'error' || tool.status === 'degraded') {
    return {
      label: tool.status === 'degraded' ? 'Needs attention' : 'Error',
      icon: AlertTriangle,
      className: 'border-rose-400/20 bg-rose-400/[0.08] text-rose-300',
      accentClassName: 'from-rose-400/70 via-amber-400/25 to-transparent',
    }
  }

  return {
    label: 'Not installed',
    icon: CircleDashed,
    className: 'border-amber-300/20 bg-amber-300/[0.07] text-amber-200',
    accentClassName: 'from-amber-300/60 via-violet-400/20 to-transparent',
  }
}

export const ToolCard = ({
  tool,
  categoryLabel,
  installMethodLabel,
  automatedInstallAvailable,
  hasUpdate,
  latestVersion,
  onOpen,
}: ToolCardProps) => {
  const status = getStatusPresentation(tool)
  const StatusIcon = status.icon
  const version = tool.version || tool.raw_version || 'Unknown'
  const command = tool.command_template.length > 0
    ? tool.command_template.join(' ')
    : tool.path || tool.name
  const actionLabel = tool.installed
    ? 'Inspect tool'
    : automatedInstallAvailable
      ? 'Install options'
      : 'Setup guide'

  return (
    <button
      type="button"
      onClick={onOpen}
      aria-label={`Open details for ${tool.name}`}
      aria-haspopup="dialog"
      className="group relative flex min-h-[244px] w-full flex-col overflow-hidden rounded-2xl border border-white/[0.09] bg-[linear-gradient(145deg,rgba(17,27,43,0.94),rgba(8,15,26,0.96))] p-5 text-left shadow-[0_18px_44px_rgba(0,0,0,0.16)] transition-[transform,border-color,box-shadow,background-color] duration-200 hover:-translate-y-0.5 hover:border-cyan-300/25 hover:shadow-[0_22px_54px_rgba(0,0,0,0.24),0_0_28px_rgba(34,211,238,0.04)] focus-visible:border-cyan-300/45 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/45 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950"
    >
      <span
        aria-hidden="true"
        className={`absolute inset-x-0 top-0 h-px bg-gradient-to-r ${status.accentClassName}`}
      />

      <div className="flex items-start gap-3.5">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-cyan-300/15 bg-cyan-300/[0.06] text-cyan-200 shadow-[inset_0_1px_rgba(255,255,255,0.04)] transition-colors group-hover:border-cyan-300/25 group-hover:bg-cyan-300/[0.09]">
          <SquareTerminal className="h-[18px] w-[18px]" aria-hidden="true" />
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex min-w-0 items-start justify-between gap-3">
            <div className="min-w-0">
              <h3 className="truncate text-[17px] font-semibold tracking-[-0.02em] text-slate-50">
                {tool.name}
              </h3>
              <p className="mt-1 truncate text-[10px] font-semibold uppercase tracking-[0.14em] text-cyan-200/65">
                {categoryLabel}
              </p>
            </div>

            <span className={`inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium ${status.className}`}>
              <StatusIcon className="h-3.5 w-3.5" aria-hidden="true" />
              {status.label}
            </span>
          </div>
        </div>
      </div>

      <p className="mt-4 min-h-[40px] line-clamp-2 text-[13px] leading-5 text-slate-400">
        {tool.description}
      </p>

      <div className="mt-4 grid grid-cols-2 divide-x divide-white/[0.08] overflow-hidden rounded-xl border border-white/[0.07] bg-slate-950/35">
        <div className="min-w-0 px-3 py-2.5">
          <p className="text-[9px] font-bold uppercase tracking-[0.15em] text-slate-600">Version</p>
          <div className="mt-1 flex min-w-0 items-center gap-1.5">
            <span className="truncate font-mono text-xs text-slate-200">{version}</span>
            {hasUpdate && latestVersion && (
              <span className="truncate text-[10px] font-medium text-emerald-300">→ {latestVersion}</span>
            )}
          </div>
        </div>

        <div className="min-w-0 px-3 py-2.5">
          <p className="text-[9px] font-bold uppercase tracking-[0.15em] text-slate-600">Install via</p>
          <div className="mt-1 flex min-w-0 items-center gap-1.5">
            {automatedInstallAvailable && !tool.installed && (
              <Zap className="h-3 w-3 shrink-0 text-emerald-300" aria-label="Automated installation available" />
            )}
            <span className="truncate text-xs font-medium text-slate-200">{installMethodLabel}</span>
          </div>
        </div>
      </div>

      <div className="mt-auto flex min-w-0 items-center justify-between gap-3 border-t border-white/[0.07] pt-4">
        <div className="flex min-w-0 items-center gap-2 text-slate-500">
          <SquareTerminal className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <code className="truncate font-mono text-[11px] text-slate-400">{command}</code>
          <span className="shrink-0 text-[10px] text-slate-600">· {formatLastChecked(tool.last_checked)}</span>
        </div>

        <span className="inline-flex shrink-0 items-center gap-1 text-[11px] font-semibold text-cyan-200/80 transition-colors group-hover:text-cyan-200">
          {hasUpdate && <ArrowUpCircle className="h-3.5 w-3.5 text-emerald-300" aria-hidden="true" />}
          {actionLabel}
          <ChevronRight className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
        </span>
      </div>
    </button>
  )
}
