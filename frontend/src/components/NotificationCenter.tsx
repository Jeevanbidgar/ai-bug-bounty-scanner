import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  AlertTriangle,
  Bell,
  Check,
  CheckCircle2,
  CircleAlert,
  Info,
  Trash2,
  X,
} from 'lucide-react'
import { useNotificationStore, type AppNotification } from '../stores/notificationStore'

const levelStyles = {
  info: { icon: Info, iconClass: 'text-cyan-300', panelClass: 'border-cyan-400/15 bg-cyan-400/[0.035]' },
  success: { icon: CheckCircle2, iconClass: 'text-emerald-300', panelClass: 'border-emerald-400/15 bg-emerald-400/[0.035]' },
  warning: { icon: AlertTriangle, iconClass: 'text-amber-300', panelClass: 'border-amber-400/15 bg-amber-400/[0.035]' },
  error: { icon: CircleAlert, iconClass: 'text-red-300', panelClass: 'border-red-400/15 bg-red-400/[0.035]' },
}

const formatTimestamp = (value: string) => {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
}

export const NotificationCenter = () => {
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const navigate = useNavigate()
  const notifications = useNotificationStore((state) => state.notifications)
  const markRead = useNotificationStore((state) => state.markRead)
  const markAllRead = useNotificationStore((state) => state.markAllRead)
  const removeNotification = useNotificationStore((state) => state.removeNotification)
  const clearAll = useNotificationStore((state) => state.clearAll)
  const unreadCount = notifications.filter((notification) => !notification.read).length

  useEffect(() => {
    if (!open) return
    const close = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }
    const closeOutside = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false)
    }
    window.addEventListener('keydown', close)
    window.addEventListener('pointerdown', closeOutside)
    return () => {
      window.removeEventListener('keydown', close)
      window.removeEventListener('pointerdown', closeOutside)
    }
  }, [open])

  const openNotification = (notification: AppNotification) => {
    markRead(notification.id)
    if (notification.href) {
      navigate(notification.href)
      setOpen(false)
    }
  }

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className="relative rounded-xl border border-white/[0.07] bg-white/[0.025] p-2.5 text-slate-400 hover:bg-white/[0.05] hover:text-white"
        aria-label={unreadCount ? `Notifications, ${unreadCount} unread` : 'Notifications'}
        aria-expanded={open}
        aria-controls="notification-center-panel"
      >
        <Bell className="h-4 w-4" />
        {unreadCount > 0 && <span className="absolute right-1.5 top-1.5 grid min-h-3 min-w-3 place-items-center rounded-full bg-cyan-300 px-1 text-[8px] font-bold leading-3 text-slate-950">{unreadCount > 9 ? '9+' : unreadCount}</span>}
      </button>

      {open && (
        <section
          id="notification-center-panel"
          role="dialog"
          aria-label="Notification center"
          className="surface-panel fixed inset-x-3 top-[82px] z-[90] overflow-hidden rounded-2xl border-cyan-400/15 shadow-2xl shadow-black/60 sm:absolute sm:inset-x-auto sm:right-0 sm:top-12 sm:w-[390px]"
        >
          <header className="flex items-center gap-3 border-b border-white/[0.07] px-4 py-3.5">
            <div className="min-w-0 flex-1">
              <h2 className="text-sm font-semibold text-white">Notifications</h2>
              <p className="mt-0.5 text-[10px] uppercase tracking-wider text-slate-600">Local execution and system events</p>
            </div>
            {unreadCount > 0 && (
              <button type="button" onClick={markAllRead} className="flex items-center gap-1.5 rounded-lg px-2 py-1.5 text-[10px] font-medium text-cyan-300 hover:bg-cyan-400/[0.07]">
                <Check className="h-3 w-3" />Mark read
              </button>
            )}
            <button type="button" onClick={() => setOpen(false)} className="rounded-lg p-1.5 text-slate-500 hover:bg-white/5 hover:text-white" aria-label="Close notification center"><X className="h-4 w-4" /></button>
          </header>

          <div className="max-h-[min(62vh,520px)] space-y-2 overflow-y-auto p-3" aria-live="polite">
            {notifications.map((notification) => {
              const style = levelStyles[notification.level]
              const Icon = style.icon
              return (
                <article key={notification.id} className={`group relative rounded-xl border p-3 pr-10 ${style.panelClass} ${notification.read ? 'opacity-70' : ''}`}>
                  <button type="button" onClick={() => openNotification(notification)} className="flex w-full items-start gap-3 text-left">
                    <Icon className={`mt-0.5 h-4 w-4 flex-shrink-0 ${style.iconClass}`} />
                    <span className="min-w-0 flex-1">
                      <span className="flex items-center gap-2 text-xs font-semibold text-slate-100">{notification.title}{!notification.read && <span className="h-1.5 w-1.5 rounded-full bg-cyan-300" />}</span>
                      <span className="mt-1 block text-[11px] leading-relaxed text-slate-400">{notification.message}</span>
                      <span className="mt-2 flex items-center gap-2 text-[9px] uppercase tracking-wider text-slate-700"><span>{formatTimestamp(notification.createdAt)}</span>{notification.href && <span className="text-cyan-400">{notification.actionLabel ?? 'Open'}</span>}</span>
                    </span>
                  </button>
                  <button type="button" onClick={() => removeNotification(notification.id)} className="absolute right-2 top-2 rounded-lg p-1.5 text-slate-700 opacity-0 hover:bg-red-400/10 hover:text-red-300 focus:opacity-100 group-hover:opacity-100" aria-label={`Remove ${notification.title}`}><Trash2 className="h-3 w-3" /></button>
                </article>
              )
            })}
            {!notifications.length && (
              <div className="grid min-h-52 place-items-center p-6 text-center">
                <div><Bell className="mx-auto h-7 w-7 text-slate-700" /><p className="mt-3 text-sm font-medium text-slate-300">All clear</p><p className="mt-1 text-xs text-slate-600">Tool, scan, workflow, and system events will appear here.</p></div>
              </div>
            )}
          </div>

          {notifications.length > 0 && (
            <footer className="border-t border-white/[0.07] p-2">
              <button type="button" onClick={clearAll} className="flex w-full items-center justify-center gap-2 rounded-lg py-2 text-[11px] text-slate-600 hover:bg-white/[0.035] hover:text-slate-300"><Trash2 className="h-3.5 w-3.5" />Clear notification history</button>
            </footer>
          )}
        </section>
      )}
    </div>
  )
}
