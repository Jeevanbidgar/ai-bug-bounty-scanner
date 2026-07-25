/**
 * Tauri Event service for real-time communication
 * Replaces Socket.IO with Tauri's native event system
 */

import { appBridge } from '../bridge/appBridge'

type UnlistenFn = () => void

export interface ScanProgressUpdate {
  scan_id: string
  progress: number
  current_test: string | null
  status: string
  timestamp: string
}

export interface SystemNotification {
  notification_type: 'info' | 'success' | 'warning' | 'error'
  title: string
  message: string
  timestamp: string
}

export interface WorkflowStatusUpdate {
  execution_id: string
  status: string
  progress: number
  current_step: string | null
  timestamp: string
}

class TauriEventService {
  private listeners: Map<string, UnlistenFn[]> = new Map()
  private eventCallbacks: Map<string, Function[]> = new Map()

  async connect(): Promise<void> {
    // Set up event listeners for scan events
    await this.setupEventListener('scan:progress_update', (payload: ScanProgressUpdate) => {
      this.emit('scan_progress_update', payload)
    })

    await this.setupEventListener('scan:started', (payload: any) => {
      this.emit('scan_started', payload)
    })

    await this.setupEventListener('scan:completed', (payload: any) => {
      this.emit('scan_completed', payload)
    })

    await this.setupEventListener('scan:failed', (payload: any) => {
      this.emit('scan_failed', payload)
    })

    await this.setupEventListener('scan:error', (payload: any) => {
      this.emit('scan_error', payload)
    })

    await this.setupEventListener('system:notification', (payload: SystemNotification) => {
      this.emit('system_notification', payload)
    })

    // Set up workflow event listeners
    await this.setupEventListener('workflow:status_update', (payload: WorkflowStatusUpdate) => {
      this.emit('workflow_status_update', payload)
    })

    await this.setupEventListener('workflow:execution_started', (payload: any) => {
      this.emit('workflow_execution_started', payload)
    })

    await this.setupEventListener('workflow:execution_completed', (payload: any) => {
      this.emit('workflow_execution_completed', payload)
    })

    await this.setupEventListener('workflow:execution_failed', (payload: any) => {
      this.emit('workflow_execution_failed', payload)
    })

    await this.setupEventListener('workflow:stdout', (payload: any) => {
      this.emit('workflow_stdout', payload)
    })

    await this.setupEventListener('workflow:stderr', (payload: any) => {
      this.emit('workflow_stderr', payload)
    })

    console.log('Tauri event listeners initialized')
  }

  private async setupEventListener(event: string, callback: (payload: any) => void): Promise<void> {
    try {
      const unlisten = await appBridge.listen(event, callback)

      if (!this.listeners.has(event)) {
        this.listeners.set(event, [])
      }
      this.listeners.get(event)!.push(unlisten)
    } catch (error) {
      console.error(`Failed to set up listener for ${event}:`, error)
    }
  }

  disconnect(): void {
    // Unlisten from all Tauri events
    this.listeners.forEach((unlisteners) => {
      unlisteners.forEach((unlisten) => unlisten())
    })
    this.listeners.clear()
    this.eventCallbacks.clear()
    console.log('Tauri event listeners cleaned up')
  }

  // Event subscription system (similar to Socket.IO interface)
  on(event: string, callback: Function): void {
    if (!this.eventCallbacks.has(event)) {
      this.eventCallbacks.set(event, [])
    }
    this.eventCallbacks.get(event)!.push(callback)
  }

  off(event: string, callback: Function): void {
    const callbacks = this.eventCallbacks.get(event)
    if (callbacks) {
      const index = callbacks.indexOf(callback)
      if (index > -1) {
        callbacks.splice(index, 1)
      }
    }
  }

  private emit(event: string, data: any): void {
    const callbacks = this.eventCallbacks.get(event)
    if (callbacks) {
      callbacks.forEach((callback) => {
        try {
          callback(data)
        } catch (error) {
          console.error(`Error in ${event} callback:`, error)
        }
      })
    }
  }

  // Helper methods
  isConnected(): boolean {
    return this.listeners.size > 0
  }

  getConnectionState(): string {
    return this.listeners.size > 0 ? 'connected' : 'disconnected'
  }
}

// Create singleton instance
export const tauriEventService = new TauriEventService()

// React hook for using Tauri event service
export const useTauriEvents = () => {
  return {
    connect: () => tauriEventService.connect(),
    disconnect: () => tauriEventService.disconnect(),
    on: (event: string, callback: Function) => tauriEventService.on(event, callback),
    off: (event: string, callback: Function) => tauriEventService.off(event, callback),
    isConnected: tauriEventService.isConnected(),
    connectionState: tauriEventService.getConnectionState(),
  }
}

export default tauriEventService
