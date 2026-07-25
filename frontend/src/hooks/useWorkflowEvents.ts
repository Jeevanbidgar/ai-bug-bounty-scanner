import { useEffect, useRef, useCallback } from 'react'
import { appBridge } from '../bridge/appBridge'

/**
 * Custom hook for managing Tauri workflow event listeners
 * 
 * Provides automatic cleanup and reconnection handling for workflow events
 */

interface WorkflowEventHandlers {
  onExecutionStarted?: (data: any) => void
  onExecutionCompleted?: (data: any) => void
  onExecutionFailed?: (data: any) => void
  onExecutionCancelled?: (data: any) => void
  onStatusUpdate?: (data: any) => void
  onStepStarted?: (data: any) => void
  onStepCompleted?: (data: any) => void
  onStepFailed?: (data: any) => void
  onStdout?: (data: any) => void
  onStderr?: (data: any) => void
}

export const useWorkflowEvents = (
  executionId: string | null,
  handlers: WorkflowEventHandlers
) => {
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
    if (isListening.current || !executionId || !appBridge.capabilities.events) {
      return
    }
    
    try {
      // Listen to workflow events with proper cleanup
        const eventNames = [
          'workflow:execution_started',
          'workflow:execution_completed',
          'workflow:execution_failed',
          'workflow:execution_cancelled',
          'workflow:status_update',
          'workflow:step_started',
          'workflow:step_completed',
          'workflow:step_failed',
          'workflow:stdout',
          'workflow:stderr'
        ]

        for (const eventName of eventNames) {
          const unlistenFn = await appBridge.listen<any>(eventName, (payload) => {

            // Only process events for this execution
            if (executionId && payload.execution_id !== executionId) {
              return
            }

            // Route to appropriate handler
            switch (eventName) {
              case 'workflow:execution_started':
                handlersRef.current.onExecutionStarted?.(payload)
                break
              case 'workflow:execution_completed':
                handlersRef.current.onExecutionCompleted?.(payload)
                break
              case 'workflow:execution_failed':
                handlersRef.current.onExecutionFailed?.(payload)
                break
              case 'workflow:execution_cancelled':
                handlersRef.current.onExecutionCancelled?.(payload)
                break
              case 'workflow:status_update':
                handlersRef.current.onStatusUpdate?.(payload)
                break
              case 'workflow:step_started':
                handlersRef.current.onStepStarted?.(payload)
                break
              case 'workflow:step_completed':
                handlersRef.current.onStepCompleted?.(payload)
                break
              case 'workflow:step_failed':
                handlersRef.current.onStepFailed?.(payload)
                break
              case 'workflow:stdout':
                handlersRef.current.onStdout?.(payload)
                break
              case 'workflow:stderr':
                handlersRef.current.onStderr?.(payload)
                break
            }
          })

          unlisten.current.push(unlistenFn)
        }

        isListening.current = true
    } catch (error) {
      console.error('❌ Failed to setup workflow event listeners:', error)
    }
  }, [executionId])

  // Setup listeners when execution ID changes
  useEffect(() => {
    setupListeners()

    // Cleanup on unmount or when execution ID changes
    return () => {
      cleanup()
    }
  }, [executionId, setupListeners, cleanup])

  return {
    isListening: isListening.current,
    cleanup
  }
}
