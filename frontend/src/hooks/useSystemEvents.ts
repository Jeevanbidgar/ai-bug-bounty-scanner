import { useEffect, useRef, useCallback } from 'react'

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
    install_method: string
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

  const cleanup = useCallback(() => {
    console.log('🧹 Cleaning up system event listeners')
    
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
      console.log('⚠️ System event listeners already setup, skipping')
      return
    }

    console.log('🎧 Setting up system event listeners')
    
    try {
      // Check if we're in a Tauri environment
      if (typeof window !== 'undefined' && (window as any).__TAURI__) {
        const { listen } = await import('@tauri-apps/api/event')

        // Listen to tool installation events
        const toolEvents = [
          'tool:installation_started',
          'tool:installation_completed',
          'tool:installation_failed'
        ]

        for (const eventName of toolEvents) {
          const unlistenFn = await listen(eventName, (event: any) => {
            const payload = event.payload
            console.log(`📨 Tool event: ${eventName}`, payload)

            switch (eventName) {
              case 'tool:installation_started':
                handlers.onToolInstallationStarted?.(payload)
                break
              case 'tool:installation_completed':
                if (payload.success) {
                  handlers.onToolInstallationCompleted?.(payload)
                } else {
                  handlers.onToolInstallationFailed?.(payload)
                }
                break
              case 'tool:installation_failed':
                handlers.onToolInstallationFailed?.(payload)
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
          const unlistenFn = await listen(eventName, (event: any) => {
            const payload = event.payload
            console.log(`📨 Scan event: ${eventName}`, payload)

            switch (eventName) {
              case 'scan:started':
                handlers.onScanStarted?.(payload)
                break
              case 'scan:completed':
                handlers.onScanCompleted?.(payload)
                break
              case 'scan:failed':
                handlers.onScanFailed?.(payload)
                break
              case 'scan:progress_update':
                handlers.onScanProgress?.(payload)
                break
            }
          })

          unlisten.current.push(unlistenFn)
        }

        // Listen to system notifications
        const notificationEvents = ['system:notification']

        for (const eventName of notificationEvents) {
          const unlistenFn = await listen(eventName, (event: any) => {
            const payload = event.payload
            console.log(`📨 System event: ${eventName}`, payload)

            handlers.onSystemNotification?.(payload)
          })

          unlisten.current.push(unlistenFn)
        }

        isListening.current = true
        console.log(`✅ System event listeners setup complete (${unlisten.current.length} listeners)`)
      } else {
        console.warn('⚠️ Not in Tauri environment, skipping event listeners')
      }
    } catch (error) {
      console.error('❌ Failed to setup system event listeners:', error)
    }
  }, [handlers])

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
