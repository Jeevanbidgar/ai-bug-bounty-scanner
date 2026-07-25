import { useEffect, useRef, useCallback } from 'react'
import { appBridge } from '../bridge/appBridge'

/**
 * Custom hook for managing system-wide Tauri event listeners
 * 
 * Handles tool installation, scan progress, and system notifications
 * with automatic cleanup and reconnection
 */

export interface SystemEventHandlers {
  // Tool Installation Events
  onToolInstallationStarted?: (data: {
    tool_name: string
    installation_method: string
    timestamp: string
  }) => void
  onToolInstallationCompleted?: (data: {
    tool_name: string
    success: boolean
    message: string
    timestamp: string
  }) => void
  onToolInstallationFailed?: (data: {
    tool_name: string
    success: boolean
    message: string
    timestamp: string
  }) => void
  
  // Scan Events
  onScanStarted?: (data: {
    scan_id: string
    timestamp: string
  }) => void
  onScanCompleted?: (data: {
    scan_id: string
    timestamp: string
  }) => void
  onScanFailed?: (data: {
    scan_id: string
    error: string
    timestamp: string
  }) => void
  onScanProgress?: (data: {
    scan_id: string
    progress: number
    current_test: string | null
    status: string
    timestamp: string
  }) => void
  
  // System Notifications
  onSystemNotification?: (data: {
    title: string
    message: string
    level: 'info' | 'warning' | 'error' | 'success'
    timestamp: string
  }) => void
}

export const useSystemEvents = (handlers: SystemEventHandlers) => {
  const unlisten = useRef<(() => void)[]>([])
  const isListening = useRef(false)
  const handlersRef = useRef(handlers)
  handlersRef.current = handlers

  const cleanup = useCallback(() => {
    // Call all unlisten functions
    unlisten.current.forEach(fn => {
      try {
        fn()
      } catch (e) {
        console.error('Error unlistening from event:', e)
      }
    })
    
    // Clear the array
    unlisten.current = []
    isListening.current = false
  }, [])

  const setupListeners = useCallback(async () => {
    if (isListening.current) {
      return
    }
    
    try {
      // Check if we're in a Tauri environment
      if (appBridge.capabilities.events) {
        // Listen to tool installation events
        const toolEvents = [
          'tool:installation_started',
          'tool:installation_completed',
          'tool:installation_failed'
        ]

        for (const eventName of toolEvents) {
          const unlistenFn = await appBridge.listen<any>(eventName, (payload) => {
            switch (eventName) {
              case 'tool:installation_started':
                handlersRef.current.onToolInstallationStarted?.(payload)
                break
              case 'tool:installation_completed':
                if (payload.success) {
                  handlersRef.current.onToolInstallationCompleted?.(payload)
                } else {
                  handlersRef.current.onToolInstallationFailed?.(payload)
                }
                break
              case 'tool:installation_failed':
                handlersRef.current.onToolInstallationFailed?.(payload)
                break
            }
          })

          unlisten.current.push(unlistenFn)
        }

        // Listen to scan events
        const scanEvents = [
          'scan:started',
          'scan:completed',
          'scan:failed',
          'scan:progress_update'
        ]

        for (const eventName of scanEvents) {
          const unlistenFn = await appBridge.listen<any>(eventName, (payload) => {
            switch (eventName) {
              case 'scan:started':
                handlersRef.current.onScanStarted?.(payload)
                break
              case 'scan:completed':
                handlersRef.current.onScanCompleted?.(payload)
                break
              case 'scan:failed':
                handlersRef.current.onScanFailed?.(payload)
                break
              case 'scan:progress_update':
                handlersRef.current.onScanProgress?.(payload)
                break
            }
          })

          unlisten.current.push(unlistenFn)
        }

        // Listen to system notifications
        const notificationEvents = ['system:notification']

        for (const eventName of notificationEvents) {
          const unlistenFn = await appBridge.listen<any>(eventName, (payload) => {
            handlersRef.current.onSystemNotification?.({
              ...payload,
              level: payload.level ?? payload.notification_type ?? 'info',
            })
          })

          unlisten.current.push(unlistenFn)
        }

        isListening.current = true
      }
    } catch (error) {
      console.error('❌ Failed to setup system event listeners:', error)
    }
  }, [])

  // Setup listeners on mount
  useEffect(() => {
    setupListeners()

    // Cleanup on unmount
    return () => {
      cleanup()
    }
  }, [setupListeners, cleanup])

  return {
    isListening: isListening.current,
    cleanup,
    reconnect: setupListeners
  }
}

/**
 * Simplified hook for listening to tool installation events only
 */
export const useToolInstallationEvents = (
  onStarted?: (toolName: string) => void,
  onCompleted?: (toolName: string, success: boolean, message: string) => void
) => {
  return useSystemEvents({
    onToolInstallationStarted: (data) => {
      onStarted?.(data.tool_name)
    },
    onToolInstallationCompleted: (data) => {
      onCompleted?.(data.tool_name, data.success, data.message)
    },
    onToolInstallationFailed: (data) => {
      onCompleted?.(data.tool_name, false, data.message)
    }
  })
}

/**
 * Simplified hook for listening to scan events only
 */
export const useScanEvents = (
  scanId: string | null,
  onProgress?: (progress: number, status: string) => void,
  onCompleted?: () => void,
  onFailed?: (error: string) => void
) => {
  return useSystemEvents({
    onScanProgress: (data) => {
      if (data.scan_id === scanId) {
        onProgress?.(data.progress, data.status)
      }
    },
    onScanCompleted: (data) => {
      if (data.scan_id === scanId) {
        onCompleted?.()
      }
    },
    onScanFailed: (data) => {
      if (data.scan_id === scanId) {
        onFailed?.(data.error)
      }
    }
  })
}
