import React, { useState, useEffect, useRef } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/Card'
import { Button } from './ui/Button'
import { Progress } from './ui/Progress'
import { Badge } from './ui/Badge'
import { 
  CheckCircle, 
  XCircle, 
  Loader2, 
  AlertCircle,
  Terminal,
  X
} from 'lucide-react'
import { useToolInstallationEvents } from '../hooks/useSystemEvents'

interface InstallationProgressProps {
  toolName: string
  onClose?: () => void
  onComplete?: (success: boolean) => void
}

interface LogEntry {
  timestamp: string
  message: string
  type: 'info' | 'error' | 'success' | 'warning'
}

export const InstallationProgress: React.FC<InstallationProgressProps> = ({
  toolName,
  onClose,
  onComplete
}) => {
  const [status, setStatus] = useState<'installing' | 'completed' | 'failed'>('installing')
  const [progress, setProgress] = useState(0)
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [resultMessage, setResultMessage] = useState<string>('')
  const scrollRef = useRef<HTMLDivElement>(null)

  // Auto-scroll to bottom when new logs are added
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [logs])

  // Listen to installation events
  useToolInstallationEvents(
    (name) => {
      if (name === toolName) {
        addLog('Installation started...', 'info')
        setProgress(10)
      }
    },
    (name, success, message) => {
      if (name === toolName) {
        setStatus(success ? 'completed' : 'failed')
        setProgress(100)
        setResultMessage(message)
        addLog(
          success ? 'Installation completed successfully!' : `Installation failed: ${message}`,
          success ? 'success' : 'error'
        )
        onComplete?.(success)
      }
    }
  )

  const addLog = (message: string, type: LogEntry['type'] = 'info') => {
    const entry: LogEntry = {
      timestamp: new Date().toLocaleTimeString(),
      message,
      type
    }
    setLogs(prev => [...prev, entry])
  }

  // Simulate installation progress (in real app, this would come from backend events)
  useEffect(() => {
    if (status === 'installing' && progress < 90) {
      const interval = setInterval(() => {
        setProgress(prev => {
          const next = prev + Math.random() * 10
          return next > 90 ? 90 : next
        })
      }, 1000)

      return () => clearInterval(interval)
    }
  }, [status, progress])

  // Add initial log
  useEffect(() => {
    addLog(`Preparing to install ${toolName}...`, 'info')
  }, [toolName])

  const getStatusIcon = () => {
    switch (status) {
      case 'installing':
        return <Loader2 className="h-5 w-5 animate-spin text-blue-500" />
      case 'completed':
        return <CheckCircle className="h-5 w-5 text-green-500" />
      case 'failed':
        return <XCircle className="h-5 w-5 text-red-500" />
    }
  }

  const getStatusBadge = () => {
    switch (status) {
      case 'installing':
        return <Badge variant="default">Installing</Badge>
      case 'completed':
        return <Badge variant="default" className="bg-green-500">Completed</Badge>
      case 'failed':
        return <Badge variant="destructive">Failed</Badge>
    }
  }

  const getLogIcon = (type: LogEntry['type']) => {
    switch (type) {
      case 'success':
        return <CheckCircle className="h-3 w-3 text-green-500" />
      case 'error':
        return <XCircle className="h-3 w-3 text-red-500" />
      case 'warning':
        return <AlertCircle className="h-3 w-3 text-yellow-500" />
      default:
        return <Terminal className="h-3 w-3 text-blue-500" />
    }
  }

  return (
    <Card className="w-full">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {getStatusIcon()}
            <div>
              <CardTitle>Installing {toolName}</CardTitle>
              <CardDescription className="flex items-center gap-2 mt-1">
                {getStatusBadge()}
                {status === 'installing' && (
                  <span className="text-sm">{Math.round(progress)}%</span>
                )}
              </CardDescription>
            </div>
          </div>
          {status !== 'installing' && onClose && (
            <Button variant="ghost" size="sm" onClick={onClose}>
              <X className="h-4 w-4" />
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Progress Bar */}
        {status === 'installing' && (
          <div className="space-y-2">
            <Progress value={progress} className="w-full" />
            <p className="text-sm text-muted-foreground">
              This may take a few minutes...
            </p>
          </div>
        )}

        {/* Result Message */}
        {status !== 'installing' && resultMessage && (
          <div
            className={`p-3 rounded-md ${
              status === 'completed'
                ? 'bg-green-50 dark:bg-green-950 border border-green-200 dark:border-green-800'
                : 'bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800'
            }`}
          >
            <p
              className={`text-sm ${
                status === 'completed'
                  ? 'text-green-700 dark:text-green-300'
                  : 'text-red-700 dark:text-red-300'
              }`}
            >
              {resultMessage}
            </p>
          </div>
        )}

        {/* Installation Logs */}
        <div className="space-y-2">
          <h4 className="text-sm font-medium">Installation Log</h4>
          <div className="h-[200px] w-full rounded-md border overflow-auto">
            <div ref={scrollRef} className="p-4 space-y-2">
              {logs.map((log, index) => (
                <div
                  key={index}
                  className="flex items-start gap-2 text-sm font-mono"
                >
                  <span className="text-muted-foreground text-xs">
                    {log.timestamp}
                  </span>
                  <div className="flex items-center gap-1">
                    {getLogIcon(log.type)}
                    <span
                      className={
                        log.type === 'error'
                          ? 'text-red-600 dark:text-red-400'
                          : log.type === 'success'
                          ? 'text-green-600 dark:text-green-400'
                          : log.type === 'warning'
                          ? 'text-yellow-600 dark:text-yellow-400'
                          : 'text-foreground'
                      }
                    >
                      {log.message}
                    </span>
                  </div>
                </div>
              ))}
              
              {/* Empty state */}
              {logs.length === 0 && (
                <div className="text-center text-muted-foreground py-8">
                  Waiting for installation logs...
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Actions */}
        {status !== 'installing' && (
          <div className="flex justify-end gap-2 pt-4">
            {onClose && (
              <Button variant="outline" onClick={onClose}>
                Close
              </Button>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
