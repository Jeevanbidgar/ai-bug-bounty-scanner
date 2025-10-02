/**
 * Event service for real-time communication using Tauri events
 * Handles live progress updates, scan status changes, and system notifications
 */

import { listen, UnlistenFn } from '@tauri-apps/api/event'

export interface ScanProgressUpdate {
  scan_id: string
  progress: number
  current_test: string
  status: string
  timestamp: string
}

export interface SystemNotification {
  type: 'info' | 'success' | 'warning' | 'error'
  title: string
  message: string
  timestamp: string
}

export interface WorkflowProgressUpdate {
  execution_id: string
  progress: number
  current_step: string | null
  status: string
  timestamp: string
}

class WebSocketService {
  private listeners: Map<string, Function[]> = new Map()
  private tauriUnlisteners: UnlistenFn[] = []
  private connected = false

  async connect(): Promise<void> {
    try {
      console.log('Setting up Tauri event listeners...')

      // Listen for workflow progress updates
      const workflowProgressUnlisten = await listen<WorkflowProgressUpdate>('workflow-progress', (event) => {
        console.log('Workflow progress event received:', event.payload)
        this.emit('workflow_progress_update', event.payload)
        
        // Also emit as scan progress for backward compatibility
        this.emit('scan_progress_update', {
          scan_id: event.payload.execution_id,
          progress: event.payload.progress,
          current_test: event.payload.current_step || 'N/A',
          status: event.payload.status,
          timestamp: event.payload.timestamp
        })
      })
      this.tauriUnlisteners.push(workflowProgressUnlisten)

      // Listen for workflow step completion
      const stepCompleteUnlisten = await listen('workflow-step-complete', (event) => {
        console.log('Workflow step complete event:', event.payload)
        this.emit('step_complete', event.payload)
      })
      this.tauriUnlisteners.push(stepCompleteUnlisten)

      // Listen for workflow step failed
      const stepFailedUnlisten = await listen('workflow-step-failed', (event) => {
        console.log('Workflow step failed event:', event.payload)
        this.emit('step_failed', event.payload)
        this.emit('scan_error', {
          scan_id: (event.payload as any).execution_id,
          error: (event.payload as any).error_message || 'Step failed'
        })
      })
      this.tauriUnlisteners.push(stepFailedUnlisten)

      // Listen for workflow completion
      const workflowCompleteUnlisten = await listen('workflow-complete', (event) => {
        console.log('Workflow complete event:', event.payload)
        this.emit('workflow_complete', event.payload)
        this.emit('scan_completed', {
          scan_id: (event.payload as any).execution_id,
          result: event.payload
        })
      })
      this.tauriUnlisteners.push(workflowCompleteUnlisten)

      // Listen for workflow errors
      const workflowErrorUnlisten = await listen('workflow-error', (event) => {
        console.error('Workflow error event:', event.payload)
        this.emit('workflow_error', event.payload)
        this.emit('scan_error', {
          scan_id: (event.payload as any).execution_id,
          error: (event.payload as any).error_message || 'Workflow error'
        })
      })
      this.tauriUnlisteners.push(workflowErrorUnlisten)

      // Listen for system notifications
      const notificationUnlisten = await listen<SystemNotification>('system-notification', (event) => {
        console.log('System notification event:', event.payload)
        this.emit('system_notification', event.payload)
      })
      this.tauriUnlisteners.push(notificationUnlisten)

      this.connected = true
      this.emit('connection_status', { status: 'connected', timestamp: new Date().toISOString() })
      console.log('✅ Tauri event listeners set up successfully')
    } catch (error) {
      console.error('Failed to set up Tauri event listeners:', error)
      this.connected = false
      throw error
    }
  }

  disconnect(): void {
    console.log('Removing Tauri event listeners...')
    // Unlisten from all Tauri events
    this.tauriUnlisteners.forEach(unlisten => unlisten())
    this.tauriUnlisteners = []
    this.listeners.clear()
    this.connected = false
    this.emit('connection_status', { status: 'disconnected', timestamp: new Date().toISOString() })
  }

  // Event subscription system
  on(event: string, callback: Function): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, [])
    }
    this.listeners.get(event)!.push(callback)
  }

  off(event: string, callback: Function): void {
    const listeners = this.listeners.get(event)
    if (listeners) {
      const index = listeners.indexOf(callback)
      if (index > -1) {
        listeners.splice(index, 1)
      }
    }
  }

  private emit(event: string, data: any): void {
    const listeners = this.listeners.get(event)
    if (listeners) {
      listeners.forEach(callback => {
        try {
          callback(data)
        } catch (error) {
          console.error(`Error in ${event} listener:`, error)
        }
      })
    }
  }

  // API methods
  requestScanProgress(_scanId: string): void {
    // With Tauri events, progress is automatically pushed from backend
    // No need to request - just listen for events
    console.log('Tauri event system automatically pushes progress updates')
  }

  sendPing(): void {
    // Tauri doesn't need ping/pong - it's a native IPC system
    console.log('Tauri IPC does not require ping/pong')
  }

  isConnected(): boolean {
    return this.connected
  }

  getConnectionState(): string {
    return this.connected ? 'connected' : 'disconnected'
  }
}

// Create singleton instance
export const websocketService = new WebSocketService()

// React hook for using WebSocket service
export const useWebSocket = () => {
  return {
    connect: () => websocketService.connect(),
    disconnect: () => websocketService.disconnect(),
    on: (event: string, callback: Function) => websocketService.on(event, callback),
    off: (event: string, callback: Function) => websocketService.off(event, callback),
    isConnected: websocketService.isConnected(),
    connectionState: websocketService.getConnectionState(),
    requestScanProgress: (scanId: string) => websocketService.requestScanProgress(scanId)
  }
}

export default websocketService
