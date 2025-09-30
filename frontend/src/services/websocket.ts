/**
 * WebSocket service for real-time communication
 * Handles live progress updates, scan status changes, and system notifications
 */

import { io, Socket } from 'socket.io-client'

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

class WebSocketService {
  private socket: Socket | null = null
  // Removed unused reconnectAttempts property
  private maxReconnectAttempts = 5
  private reconnectDelay = 1000 // Start with 1 second
  private listeners: Map<string, Function[]> = new Map()

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        this.socket = io('http://localhost:8000', {
          transports: ['websocket', 'polling'],
          timeout: 10000,
          reconnection: true,
          reconnectionAttempts: this.maxReconnectAttempts,
          reconnectionDelay: this.reconnectDelay
        })

        this.socket.on('connect', () => {
          console.log('WebSocket connected')
          // Reset reconnection tracking
          this.emit('connection_status', { status: 'connected', timestamp: new Date().toISOString() })
          resolve()
        })

        this.socket.on('disconnect', (reason) => {
          console.log('WebSocket disconnected:', reason)
          this.emit('connection_status', { status: 'disconnected', reason, timestamp: new Date().toISOString() })
        })

        this.socket.on('connect_error', (error) => {
          console.error('WebSocket connection error:', error)
          reject(error)
        })

        // Handle scan progress updates
        this.socket.on('scan_progress_update', (data: ScanProgressUpdate) => {
          this.emit('scan_progress_update', data)
        })

        // Handle system notifications
        this.socket.on('system_notification', (notification: SystemNotification) => {
          this.emit('system_notification', notification)
        })

        // Handle scan completion
        this.socket.on('scan_completed', (data: { scan_id: string; result: any }) => {
          this.emit('scan_completed', data)
        })

        // Handle scan errors
        this.socket.on('scan_error', (data: { scan_id: string; error: string }) => {
          this.emit('scan_error', data)
        })

      } catch (error) {
        console.error('Failed to initialize WebSocket:', error)
        reject(error)
      }
    })
  }

  disconnect(): void {
    if (this.socket) {
      this.socket.disconnect()
      this.socket = null
    }
    this.listeners.clear()
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
  requestScanProgress(scanId: string): void {
    if (this.socket) {
      this.socket.emit('scan_progress_request', { scan_id: scanId })
    }
  }

  sendPing(): void {
    if (this.socket) {
      this.socket.emit('ping', { timestamp: new Date().toISOString() })
    }
  }

  isConnected(): boolean {
    return this.socket?.connected || false
  }

  getConnectionState(): string {
    if (!this.socket) return 'disconnected'
    return this.socket.connected ? 'connected' : 'connecting'
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
