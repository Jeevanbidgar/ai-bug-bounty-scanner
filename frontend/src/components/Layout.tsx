import { useEffect, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  Activity,
  Braces,
  Command,
  FileText,
  LayoutDashboard,
  Menu,
  MonitorCog,
  PlugZap,
  PanelLeftClose,
  PanelLeftOpen,
  Search,
  Settings,
  Shield,
  Workflow,
  Wrench,
  X,
} from 'lucide-react'
import { CommandPalette } from './CommandPalette'
import { useUiStore } from '../stores/uiStore'
import { appBridge } from '../bridge/appBridge'
import { NotificationCenter } from './NotificationCenter'
import { useNotificationStore, type NotificationLevel } from '../stores/notificationStore'

interface LayoutProps {
  children: React.ReactNode
}

const navigation = [
  { name: 'Mission', href: '/', icon: LayoutDashboard },
  { name: 'Readiness', href: '/readiness', icon: MonitorCog },
  { name: 'Workflows', href: '/workflows', icon: Workflow },
  { name: 'Scans', href: '/scans', icon: Activity },
  { name: 'Tools', href: '/tools', icon: Wrench },
  { name: 'Adapters', href: '/adapters', icon: Braces },
  { name: 'Reports', href: '/reports', icon: FileText },
  { name: 'AI & MCP', href: '/integrations', icon: PlugZap },
  { name: 'Settings', href: '/settings', icon: Settings },
]

const Layout = ({ children }: LayoutProps) => {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const location = useLocation()
  const collapsed = useUiStore((state) => state.sidebarCollapsed)
  const setCollapsed = useUiStore((state) => state.setSidebarCollapsed)
  const setCommandPaletteOpen = useUiStore((state) => state.setCommandPaletteOpen)
  const highContrast = useUiStore((state) => state.highContrast)
  const addNotification = useNotificationStore((state) => state.addNotification)

  useEffect(() => {
    document.documentElement.classList.toggle('high-contrast', highContrast)
    return () => document.documentElement.classList.remove('high-contrast')
  }, [highContrast])

  useEffect(() => {
    const onShortcut = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setCommandPaletteOpen(true)
      }
    }
    window.addEventListener('keydown', onShortcut)
    return () => window.removeEventListener('keydown', onShortcut)
  }, [setCommandPaletteOpen])

  useEffect(() => {
    if (!appBridge.capabilities.events) return
    let active = true
    const unlisteners: Array<() => void> = []

    const subscribe = async <T,>(eventName: string, handler: (payload: T) => void) => {
      const unlisten = await appBridge.listen<T>(eventName, handler)
      if (active) unlisteners.push(unlisten)
      else unlisten()
    }

    const setup = async () => {
      await Promise.all([
        subscribe<{ notification_type?: NotificationLevel; level?: NotificationLevel; title: string; message: string }>('system:notification', (payload) => {
          addNotification({ level: payload.notification_type ?? payload.level ?? 'info', title: payload.title, message: payload.message })
        }),
        subscribe<{ scan_id: string }>('scan:started', (payload) => addNotification({ level: 'info', title: 'Scan started', message: `Native execution started for scan ${payload.scan_id.slice(0, 12)}.`, href: '/scans', actionLabel: 'Monitor scan', dedupeKey: `scan:${payload.scan_id}` })),
        subscribe<{ scan_id: string }>('scan:completed', (payload) => addNotification({ level: 'success', title: 'Scan completed', message: `Evidence is ready for scan ${payload.scan_id.slice(0, 12)}.`, href: '/scans', actionLabel: 'Review evidence', dedupeKey: `scan:${payload.scan_id}` })),
        subscribe<{ scan_id: string }>('scan:cancelled', (payload) => addNotification({ level: 'warning', title: 'Scan cancelled', message: `Native execution stopped for scan ${payload.scan_id.slice(0, 12)}.`, href: '/scans', actionLabel: 'Open scans', dedupeKey: `scan:${payload.scan_id}` })),
        subscribe<{ scan_id: string; error?: string }>('scan:failed', (payload) => addNotification({ level: 'error', title: 'Scan failed', message: payload.error ?? `Scan ${payload.scan_id.slice(0, 12)} did not complete.`, href: '/scans', actionLabel: 'Inspect failure', dedupeKey: `scan:${payload.scan_id}` })),
        subscribe<{ tool_name: string; installation_method?: string }>('tool:installation_started', (payload) => addNotification({ level: 'info', title: `Installing ${payload.tool_name}`, message: `${payload.installation_method ?? 'Approved installer'} is running locally.`, href: '/tools', actionLabel: 'Open tools', dedupeKey: `tool:${payload.tool_name}` })),
        subscribe<{ tool_name: string; success: boolean; message: string }>('tool:installation_completed', (payload) => addNotification({ level: payload.success ? 'success' : 'error', title: payload.success ? `${payload.tool_name} installed` : `${payload.tool_name} installation failed`, message: payload.message, href: '/tools', actionLabel: 'Open tools', dedupeKey: `tool:${payload.tool_name}` })),
        subscribe<{ tool_name: string; message: string }>('tool:installation_failed', (payload) => addNotification({ level: 'error', title: `${payload.tool_name} installation failed`, message: payload.message, href: '/tools', actionLabel: 'Open tools', dedupeKey: `tool:${payload.tool_name}` })),
      ])
    }

    setup().catch((error) => {
      console.error('Failed to initialize global event notifications:', error)
    })

    return () => {
      active = false
      unlisteners.forEach((unlisten) => unlisten())
    }
  }, [addNotification])

  const activePage = navigation.find((item) => item.href === location.pathname)?.name ?? 'UniHack'

  return (
    <div className="flex h-screen overflow-hidden text-slate-100">
      {sidebarOpen && (
        <button className="fixed inset-0 z-40 bg-slate-950/80 backdrop-blur-sm lg:hidden" onClick={() => setSidebarOpen(false)} aria-label="Close navigation" />
      )}

      <aside className={`fixed inset-y-0 left-0 z-50 flex flex-col border-r border-white/[0.07] bg-[#080e18]/95 shadow-2xl shadow-black/30 backdrop-blur-xl transition-[width,transform] duration-300 lg:relative ${collapsed ? 'lg:w-[84px]' : 'lg:w-[264px]'} w-[264px] ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}`}>
        <div className="flex h-[72px] items-center gap-3 border-b border-white/[0.07] px-4">
          <div className="relative grid h-10 w-10 flex-shrink-0 place-items-center rounded-xl border border-cyan-400/25 bg-gradient-to-br from-cyan-400/15 to-violet-500/15 shadow-[0_0_28px_rgba(34,211,238,0.10)]">
            <Shield className="h-5 w-5 text-cyan-300" />
            <span className="absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full border-2 border-[#080e18] bg-emerald-400" />
          </div>
          {!collapsed && (
            <div className="min-w-0 flex-1">
              <div className="truncate text-[15px] font-semibold tracking-tight text-white">UniHack</div>
              <div className="truncate text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Native Security Console</div>
            </div>
          )}
          <button type="button" className="ml-auto rounded-lg p-2 text-slate-500 hover:bg-white/5 hover:text-white lg:hidden" onClick={() => setSidebarOpen(false)} aria-label="Close navigation"><X className="h-4 w-4" /></button>
        </div>

        <nav className="min-h-0 flex-1 overflow-y-auto px-3 py-5" aria-label="Primary navigation">
          {!collapsed && <p className="console-label mb-3 px-3">Workspace</p>}
          <div className="space-y-1">
            {navigation.map((item) => {
              const Icon = item.icon
              const active = location.pathname === item.href
              return (
                <Link
                  key={item.href}
                  to={item.href}
                  aria-current={active ? 'page' : undefined}
                  title={collapsed ? item.name : undefined}
                  onClick={() => setSidebarOpen(false)}
                  className={`group flex h-11 items-center rounded-xl border px-3 text-sm font-medium transition-all ${collapsed ? 'justify-center' : 'gap-3'} ${active ? 'border-cyan-400/20 bg-cyan-400/[0.09] text-cyan-100 shadow-[inset_3px_0_rgba(34,211,238,0.75)]' : 'border-transparent text-slate-400 hover:border-white/[0.06] hover:bg-white/[0.035] hover:text-white'}`}
                >
                  <Icon className={`h-[18px] w-[18px] flex-shrink-0 ${active ? 'text-cyan-300' : 'text-slate-500 group-hover:text-slate-300'}`} />
                  {!collapsed && <span className="truncate">{item.name}</span>}
                </Link>
              )
            })}
          </div>
        </nav>

        <div className="border-t border-white/[0.07] p-3">
          {!collapsed && (
            <div className="mb-3 rounded-xl border border-emerald-400/10 bg-emerald-400/[0.045] p-3">
              <div className="flex items-center gap-2 text-xs font-medium text-emerald-200"><span className="status-dot" />{appBridge.capabilities.mock ? 'Preview data active' : 'Local backend online'}</div>
              <p className="mt-1.5 text-[11px] leading-relaxed text-slate-500">Native execution · no guest OS reserved</p>
            </div>
          )}
          <button type="button" onClick={() => setCollapsed(!collapsed)} className="hidden h-10 w-full items-center justify-center gap-2 rounded-xl text-xs text-slate-500 hover:bg-white/[0.04] hover:text-slate-200 lg:flex" aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}>
            {collapsed ? <PanelLeftOpen className="h-4 w-4" /> : <><PanelLeftClose className="h-4 w-4" /><span>Collapse</span></>}
          </button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="relative z-30 flex h-[72px] flex-shrink-0 items-center gap-4 border-b border-white/[0.07] bg-[#070c14]/80 px-5 backdrop-blur-xl sm:px-6">
          <button type="button" onClick={() => setSidebarOpen(true)} className="rounded-xl p-2 text-slate-400 hover:bg-white/5 hover:text-white lg:hidden" aria-label="Open navigation"><Menu className="h-5 w-5" /></button>
          <div className="min-w-[120px]">
            <p className="console-label">Operations</p>
            <h1 className="truncate text-sm font-semibold text-slate-100">{activePage}</h1>
          </div>

          <button
            type="button"
            onClick={() => setCommandPaletteOpen(true)}
            className="mx-auto flex h-10 w-full max-w-xl items-center gap-3 rounded-xl border border-white/[0.08] bg-white/[0.025] px-3 text-left text-sm text-slate-500 transition-colors hover:border-cyan-400/20 hover:bg-cyan-400/[0.035]"
          >
            <Search className="h-4 w-4" />
            <span className="min-w-0 flex-1 truncate">Search tools, workflows, scans, reports…</span>
            <kbd className="hidden items-center gap-1 rounded-md border border-white/10 bg-black/20 px-2 py-1 font-mono text-[10px] text-slate-500 sm:flex"><Command className="h-3 w-3" />K</kbd>
          </button>

          <div className="flex items-center gap-2">
            <div className="hidden items-center gap-2 rounded-full border border-emerald-400/15 bg-emerald-400/[0.05] px-3 py-2 text-[11px] font-medium text-emerald-200 xl:flex"><span className="status-dot" />Native ready</div>
            <NotificationCenter />
          </div>
        </header>

        <main className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-[1680px] p-5 sm:p-6 xl:p-8">{children}</div>
        </main>
      </div>

      <CommandPalette />
    </div>
  )
}

export default Layout
