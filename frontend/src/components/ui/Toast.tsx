import { useEffect, useState } from 'react'
import { CheckCircle, XCircle, Info, AlertTriangle, X } from 'lucide-react'

export type ToastType = 'success' | 'error' | 'info' | 'warning'

export interface ToastProps {
  message: string
  type?: ToastType
  duration?: number
  onClose?: () => void
}

const Toast = ({ message, type = 'info', duration = 3000, onClose }: ToastProps) => {
  const [isVisible, setIsVisible] = useState(true)

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsVisible(false)
      if (onClose) onClose()
    }, duration)

    return () => clearTimeout(timer)
  }, [duration, onClose])

  if (!isVisible) return null

  const icons = {
    success: <CheckCircle className="h-5 w-5 text-green-400" />,
    error: <XCircle className="h-5 w-5 text-red-400" />,
    info: <Info className="h-5 w-5 text-blue-400" />,
    warning: <AlertTriangle className="h-5 w-5 text-yellow-400" />
  }

  const bgColors = {
    success: 'bg-green-900/40 border-green-700',
    error: 'bg-red-900/40 border-red-700',
    info: 'bg-blue-900/40 border-blue-700',
    warning: 'bg-yellow-900/40 border-yellow-700'
  }

  const textColors = {
    success: 'text-green-300',
    error: 'text-red-300',
    info: 'text-blue-300',
    warning: 'text-yellow-300'
  }

  return (
    <div
      className={`fixed top-4 right-4 z-50 flex items-center gap-3 px-4 py-3 rounded-lg border ${bgColors[type]} shadow-lg animate-slide-in`}
    >
      {icons[type]}
      <p className={`text-sm font-medium ${textColors[type]}`}>{message}</p>
      <button
        onClick={() => {
          setIsVisible(false)
          if (onClose) onClose()
        }}
        className="ml-2 text-gray-400 hover:text-gray-200 transition-colors"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  )
}

// Toast Container to manage multiple toasts
interface ToastContainerProps {
  toasts: Array<ToastProps & { id: string }>
  onRemove: (id: string) => void
}

export const ToastContainer = ({ toasts, onRemove }: ToastContainerProps) => {
  return (
    <div className="fixed top-4 right-4 z-50 space-y-2">
      {toasts.map((toast) => (
        <Toast
          key={toast.id}
          message={toast.message}
          type={toast.type}
          duration={toast.duration}
          onClose={() => onRemove(toast.id)}
        />
      ))}
    </div>
  )
}

export default Toast
