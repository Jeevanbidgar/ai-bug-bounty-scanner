import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  Braces,
  FileText,
  LayoutDashboard,
  MonitorCog,
  PlugZap,
  RefreshCw,
  Search,
  Settings,
  ShieldCheck,
  Workflow,
  Wrench,
  X,
} from 'lucide-react'
import { useUiStore } from '../stores/uiStore'

const routeCommands = [
  { label: 'Open mission dashboard', detail: 'System overview and live topology', path: '/', icon: LayoutDashboard },
  { label: 'Open readiness wizard', detail: 'Host tools, package managers, and explicit runners', path: '/readiness', icon: MonitorCog },
  { label: 'Open Workflow Studio', detail: 'Inspect and compose orchestration graphs', path: '/workflows', icon: Workflow },
  { label: 'Open scans', detail: 'Running and historical executions', path: '/scans', icon: Activity },
  { label: 'Open tool inventory', detail: 'Availability, updates, and installation', path: '/tools', icon: Wrench },
  { label: 'Open adapter contracts', detail: 'Structured argv, evidence, and workflow coverage', path: '/adapters', icon: Braces },
  { label: 'Open reports', detail: 'Evidence exports and findings', path: '/reports', icon: FileText },
  { label: 'Open AI and MCP', detail: 'Connect Codex CLI or Claude Code without provider API keys', path: '/integrations', icon: PlugZap },
  { label: 'Open settings', detail: 'Runtime and visual preferences', path: '/settings', icon: Settings },
]

export const CommandPalette = () => {
  const open = useUiStore((state) => state.commandPaletteOpen)
  const setOpen = useUiStore((state) => state.setCommandPaletteOpen)
  const [query, setQuery] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  useEffect(() => {
    if (!open) return
    setQuery('')
    requestAnimationFrame(() => inputRef.current?.focus())
  }, [open])

  useEffect(() => {
    if (!open) return
    const close = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }
    window.addEventListener('keydown', close)
    return () => window.removeEventListener('keydown', close)
  }, [open, setOpen])

  const commands = useMemo(() => {
    const normalized = query.toLowerCase().trim()
    return routeCommands.filter((command) =>
      !normalized || `${command.label} ${command.detail}`.toLowerCase().includes(normalized),
    )
  }, [query])

  if (!open) return null

  const goTo = (path: string) => {
    navigate(path)
    setOpen(false)
  }

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center bg-slate-950/75 px-6 pt-[12vh] backdrop-blur-md" onMouseDown={() => setOpen(false)}>
      <section
        role="dialog"
        aria-modal="true"
        aria-label="UniHack command palette"
        className="surface-panel w-full max-w-2xl overflow-hidden rounded-2xl border-cyan-400/20 shadow-2xl shadow-black/60"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="flex items-center gap-3 border-b border-white/10 px-4">
          <Search className="h-5 w-5 text-cyan-300" />
          <input
            ref={inputRef}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Navigate or run a safe interface action…"
            className="h-14 min-w-0 flex-1 bg-transparent text-sm text-white outline-none placeholder:text-slate-500"
          />
          <button type="button" onClick={() => setOpen(false)} className="rounded-lg p-2 text-slate-500 hover:bg-white/5 hover:text-white" aria-label="Close command palette">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="max-h-[55vh] overflow-y-auto p-2">
          <p className="console-label px-3 pb-2 pt-3">Navigate</p>
          {commands.map((command) => {
            const Icon = command.icon
            return (
              <button
                key={command.path}
                type="button"
                onClick={() => goTo(command.path)}
                className="flex w-full items-center gap-3 rounded-xl px-3 py-3 text-left hover:bg-cyan-400/[0.07] focus:bg-cyan-400/[0.07]"
              >
                <span className="grid h-9 w-9 place-items-center rounded-lg border border-white/10 bg-white/[0.035] text-cyan-300"><Icon className="h-4 w-4" /></span>
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-medium text-slate-100">{command.label}</span>
                  <span className="block truncate text-xs text-slate-500">{command.detail}</span>
                </span>
              </button>
            )
          })}

          <p className="console-label px-3 pb-2 pt-5">System</p>
          <button
            type="button"
            onClick={() => {
              queryClient.invalidateQueries()
              setOpen(false)
            }}
            className="flex w-full items-center gap-3 rounded-xl px-3 py-3 text-left hover:bg-cyan-400/[0.07]"
          >
            <span className="grid h-9 w-9 place-items-center rounded-lg border border-white/10 bg-white/[0.035] text-violet-300"><RefreshCw className="h-4 w-4" /></span>
            <span>
              <span className="block text-sm font-medium text-slate-100">Refresh local state</span>
              <span className="block text-xs text-slate-500">Refetch scans, tools, workflows, and system status</span>
            </span>
          </button>
        </div>

        <footer className="flex items-center justify-between border-t border-white/10 bg-black/10 px-4 py-3 text-xs text-slate-500">
          <span className="flex items-center gap-2"><ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />UI actions never bypass backend authorization</span>
          <span>Esc to close</span>
        </footer>
      </section>
    </div>
  )
}
