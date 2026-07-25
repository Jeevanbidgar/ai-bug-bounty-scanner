import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export type NotificationLevel = 'info' | 'success' | 'warning' | 'error'

export interface AppNotification {
  id: string
  level: NotificationLevel
  title: string
  message: string
  createdAt: string
  read: boolean
  href?: string
  actionLabel?: string
  dedupeKey?: string
}

interface NotificationInput {
  level?: NotificationLevel
  title: string
  message: string
  href?: string
  actionLabel?: string
  dedupeKey?: string
}

interface NotificationState {
  notifications: AppNotification[]
  addNotification: (notification: NotificationInput) => string
  markRead: (id: string) => void
  markAllRead: () => void
  removeNotification: (id: string) => void
  clearAll: () => void
}

const createId = () => globalThis.crypto?.randomUUID?.() ?? `notification-${Date.now()}-${Math.random()}`

export const useNotificationStore = create<NotificationState>()(
  persist(
    (set) => ({
      notifications: [],
      addNotification: (input) => {
        const id = createId()
        const notification: AppNotification = {
          id,
          level: input.level ?? 'info',
          title: input.title,
          message: input.message,
          createdAt: new Date().toISOString(),
          read: false,
          href: input.href,
          actionLabel: input.actionLabel,
          dedupeKey: input.dedupeKey,
        }

        set((state) => ({
          notifications: [
            notification,
            ...state.notifications.filter((item) => !input.dedupeKey || item.dedupeKey !== input.dedupeKey),
          ].slice(0, 80),
        }))
        return id
      },
      markRead: (id) => set((state) => ({
        notifications: state.notifications.map((item) => item.id === id ? { ...item, read: true } : item),
      })),
      markAllRead: () => set((state) => ({
        notifications: state.notifications.map((item) => item.read ? item : { ...item, read: true }),
      })),
      removeNotification: (id) => set((state) => ({
        notifications: state.notifications.filter((item) => item.id !== id),
      })),
      clearAll: () => set({ notifications: [] }),
    }),
    {
      name: 'unihack-notifications',
      partialize: (state) => ({ notifications: state.notifications }),
    },
  ),
)
