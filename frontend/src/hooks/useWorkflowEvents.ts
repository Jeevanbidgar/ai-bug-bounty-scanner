import { useEffect, useRef, useCallback } from 'react'

/**
 * Custom hook for managing Tauri workflow event listeners
 * 
 * Provides automatic cleanup and reconnection handling for workflow events
 */

interface WorkflowEventHandlers {
  onExecutionStarted?: (data: any) => void
  onExecutionCompleted?: (data: any) => void
  onExecutionFailed?: (data: any) => void
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

  const cleanup = useCallback(() => {
    console.log(`🧹 Cleaning up workflow event listeners for execution ${executionId}`)
    
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
  }, [executionId])

  const setupListeners = useCallback(async () => {
    if (!executionId || isListening.current) {
      return
    }

    console.log(`🎧 Setting up workflow event listeners for execution ${executionId}`)
    
    try {
      // Check if we're in a Tauri environment
      if (typeof window !== 'undefined' && (window as any).__TAURI__) {
        const { listen } = await import('@tauri-apps/api/event')

        // Listen to workflow events with proper cleanup
        const eventNames = [
          'workflow:execution_started',
          'workflow:execution_completed',
          'workflow:execution_failed',
          'workflow:status_update',
          'workflow:step_started',
          'workflow:step_completed',
          'workflow:step_failed',
          'workflow:stdout',
          'workflow:stderr'
        ]

        for (const eventName of eventNames) {
          const unlistenFn = await listen(eventName, (event: any) => {
            const payload = event.payload

            // Only process events for this execution
            if (payload.execution_id !== executionId) {
              return
            }

            console.log(`📨 Workflow event: ${eventName}`, payload)

            // Route to appropriate handler
            switch (eventName) {
              case 'workflow:execution_started':
                handlers.onExecutionStarted?.(payload)
                break
              case 'workflow:execution_completed':
                handlers.onExecutionCompleted?.(payload)
                break
              case 'workflow:execution_failed':
                handlers.onExecutionFailed?.(payload)
                break
              case 'workflow:status_update':
                handlers.onStatusUpdate?.(payload)
                break
              case 'workflow:step_started':
                handlers.onStepStarted?.(payload)
                break
              case 'workflow:step_completed':
                handlers.onStepCompleted?.(payload)
                break
              case 'workflow:step_failed':
                handlers.onStepFailed?.(payload)
                break
              case 'workflow:stdout':
                handlers.onStdout?.(payload)
                break
              case 'workflow:stderr':
                handlers.onStderr?.(payload)
                break
            }
          })

          unlisten.current.push(unlistenFn)
        }

        isListening.current = true
        console.log(`✅ Workflow event listeners setup complete for execution ${executionId}`)
      } else {
        console.warn('⚠️ Not in Tauri environment, skipping event listeners')
      }
    } catch (error) {
      console.error('❌ Failed to setup workflow event listeners:', error)
    }
  }, [executionId, handlers])

  // Setup listeners when execution ID changes
  useEffect(() => {
    if (executionId) {
      setupListeners()
    }

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

